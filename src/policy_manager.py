"""
Policy Manager
Department-based PII policies stored in Redis
Admins update policies via REST API or admin dashboard
"""

import json
import logging
from typing import Optional

logger = logging.getLogger("policy-manager")

# ── Default Policies Per Department ─────────────────────────────
DEFAULT_POLICIES = {
    # HR — strictest: block all PII
    "HR": {
        "scrub_names":             True,
        "scrub_emails":            True,
        "block_on_pii":            False,   # scrub, don't block
        "max_requests_per_minute": 30,
        "block_all_llm":           False,
        "allowed_pii_types":       [],      # nothing allowed through
        "alert_on_types":          ["SSN", "CREDIT_CARD", "PASSPORT"],
    },

    # Finance — block credit cards and bank data
    "FINANCE": {
        "scrub_names":             True,
        "scrub_emails":            True,
        "block_on_pii":            False,
        "max_requests_per_minute": 60,
        "block_all_llm":           False,
        "allowed_pii_types":       [],
        "alert_on_types":          ["CREDIT_CARD", "IBAN", "BANK_ACCOUNT"],
    },

    # Engineering — relaxed (IPs allowed, API keys scrubbed)
    "ENGINEERING": {
        "scrub_names":             False,   # engineers can share names
        "scrub_emails":            True,
        "block_on_pii":            False,
        "max_requests_per_minute": 120,
        "block_all_llm":           False,
        "allowed_pii_types":       ["IP_ADDRESS"],  # IPs OK for devs
        "alert_on_types":          ["AWS_KEY", "PRIVATE_KEY", "PASSWORD"],
    },

    # Legal — block everything, high alert
    "LEGAL": {
        "scrub_names":             True,
        "scrub_emails":            True,
        "block_on_pii":            True,    # BLOCK don't scrub
        "max_requests_per_minute": 20,
        "block_all_llm":           False,
        "allowed_pii_types":       [],
        "alert_on_types":          ["SSN", "PASSPORT", "CREDIT_CARD", "MRN"],
    },

    # Marketing — moderate
    "MARKETING": {
        "scrub_names":             True,
        "scrub_emails":            True,
        "block_on_pii":            False,
        "max_requests_per_minute": 60,
        "block_all_llm":           False,
        "allowed_pii_types":       [],
        "alert_on_types":          ["EMAIL", "PHONE"],
    },

    # Default fallback for unknown departments
    "DEFAULT": {
        "scrub_names":             True,
        "scrub_emails":            True,
        "block_on_pii":            False,
        "max_requests_per_minute": 30,
        "block_all_llm":           False,
        "allowed_pii_types":       [],
        "alert_on_types":          [],
    }
}

# IP → Department mapping (replace with AD/LDAP lookup in production)
IP_DEPARTMENT_MAP = {
    "10.0.1.": "ENGINEERING",
    "10.0.2.": "HR",
    "10.0.3.": "FINANCE",
    "10.0.4.": "LEGAL",
    "10.0.5.": "MARKETING",
}


class PolicyManager:
    def __init__(self, redis_client):
        self.redis = redis_client

    async def get(self, department: str) -> dict:
        """Get policy for department — Redis first, then defaults"""
        cache_key = f"policy:{department.upper()}"

        # Try Redis cache first
        cached = await self.redis.get(cache_key)
        if cached:
            return json.loads(cached)

        # Fallback to default policies
        policy = DEFAULT_POLICIES.get(
            department.upper(),
            DEFAULT_POLICIES["DEFAULT"]
        )

        # Cache for 5 minutes
        await self.redis.setex(cache_key, 300, json.dumps(policy))
        return policy

    async def set(self, department: str, policy: dict):
        """Admin updates a department policy"""
        cache_key = f"policy:{department.upper()}"
        await self.redis.setex(cache_key, 300, json.dumps(policy))
        logger.info(f"📋 Policy updated for department: {department}")

    async def ip_to_department(self, ip: str) -> str:
        """Map client IP to department (replace with AD/LDAP in production)"""
        for prefix, dept in IP_DEPARTMENT_MAP.items():
            if ip.startswith(prefix):
                return dept
        return "DEFAULT"
