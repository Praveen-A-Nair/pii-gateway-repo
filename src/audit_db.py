"""
Audit Database — PostgreSQL audit trail
All PII scrubbing events stored for compliance
"""

import json
import logging
import asyncpg
from pathlib import Path
from typing import Optional

logger = logging.getLogger("audit-db")


class AuditDatabase:
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.pool: Optional[asyncpg.Pool] = None

    async def init(self):
        """Create connection pool and tables"""
        try:
            self.pool = await asyncpg.create_pool(self.database_url, min_size=5, max_size=20)
            await self._create_tables()
            logger.info("✅ Audit DB connected")
        except Exception as e:
            logger.warning(f"⚠️  DB unavailable, using file fallback: {e}")
            self.pool = None

    async def _create_tables(self):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS pii_audit (
                    id              SERIAL PRIMARY KEY,
                    request_id      UUID NOT NULL,
                    timestamp       TIMESTAMPTZ NOT NULL,
                    user_id         TEXT,
                    department      TEXT,
                    client_ip       INET,
                    target_llm      TEXT,
                    pii_types       TEXT[],
                    pii_counts      JSONB,
                    original_len    INTEGER,
                    scrubbed_len    INTEGER,
                    created_at      TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_audit_department ON pii_audit(department);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON pii_audit(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON pii_audit(timestamp);
            """)

    async def log(self, entry: dict):
        """Write audit entry — DB with file fallback"""
        if self.pool:
            try:
                async with self.pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO pii_audit
                        (request_id, timestamp, user_id, department,
                         client_ip, target_llm, pii_types, pii_counts,
                         original_len, scrubbed_len)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    """,
                        entry["request_id"], entry["timestamp"],
                        entry["user_id"],    entry["department"],
                        entry["client_ip"],  entry["target_llm"],
                        entry["pii_types"],  json.dumps(entry["pii_counts"]),
                        entry["original_len"], entry["scrubbed_len"]
                    )
                return
            except Exception as e:
                logger.error(f"DB write failed, using file fallback: {e}")

        # File fallback (if DB unavailable)
        audit_log = Path(__file__).parent.parent / "audit.log"
        with open(str(audit_log), "a") as f:
            f.write(json.dumps(entry) + "\n")
