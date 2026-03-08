"""
Enterprise Central PII Gateway v3.0
- Handles 500+ concurrent users
- Presidio-powered PII scrubbing
- Department-based policies
- Full audit trail to PostgreSQL
- Redis caching for performance
- Health checks for load balancer

Certificate / TLS Modes (no Copilot breakage):
  MODE 1 — Corporate CA   : NGINX terminates TLS with corp CA cert
  MODE 2 — DNS Intercept  : Gateway presents per-domain cert (SNI)
  MODE 3 — Sidecar Agent  : Local agent sends pre-decrypted body here
  MODE 4 — Scrub-only API : Apps POST body directly, no TLS intercept
"""

import re
import json
import uuid
import ssl
import logging
import asyncio
import httpx
import redis.asyncio as redis
from datetime import datetime, timezone
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from pii_engine import EnterprisePIIEngine
from policy_manager import PolicyManager
from audit_db import AuditDatabase
from config import Settings

# ── Config ──────────────────────────────────────────────────────
settings = Settings()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler("/var/log/pii-gateway/gateway.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("pii-gateway")

# ── LLM Route Map ───────────────────────────────────────────────
# Add any new LLM domains here — used in DNS mode and proxy routing
LLM_ROUTES = {
    # Anthropic / Claude
    "api.anthropic.com":                    "https://api.anthropic.com",
    # OpenAI / ChatGPT
    "api.openai.com":                       "https://api.openai.com",
    # Google Gemini
    "generativelanguage.googleapis.com":    "https://generativelanguage.googleapis.com",
    # Cohere
    "api.cohere.ai":                        "https://api.cohere.ai",
    # ── GitHub Copilot (VS Code Chat) ────────────────────────────
    # Copilot Chat uses ALL of these — all must be listed
    "api.githubcopilot.com":                "https://api.githubcopilot.com",
    "copilot-proxy.githubusercontent.com":  "https://copilot-proxy.githubusercontent.com",
    "origin-tracker.githubusercontent.com": "https://origin-tracker.githubusercontent.com",
    "default.exp-tas.com":                  "https://default.exp-tas.com",
    # Azure OpenAI (used by Copilot Business/Enterprise internally)
    "eastus.api.cognitive.microsoft.com":   "https://eastus.api.cognitive.microsoft.com",
}

# ── Startup / Shutdown ──────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 PII Gateway starting up...")
    app.state.redis  = redis.from_url(settings.REDIS_URL, decode_responses=True)
    app.state.pii    = EnterprisePIIEngine()
    app.state.policy = PolicyManager(app.state.redis)
    app.state.audit  = AuditDatabase(settings.DATABASE_URL)
    await app.state.audit.init()
    logger.info("✅ PII Gateway ready")
    yield
    # Shutdown
    await app.state.redis.close()
    logger.info("🛑 PII Gateway shut down")


app = FastAPI(
    title="Enterprise PII Gateway",
    version="3.0.0",
    lifespan=lifespan
)

# ── TLS Mode Detection ──────────────────────────────────────────
# Set via environment variable TLS_MODE:
#   corp_ca   → NGINX handles TLS with corp CA cert (default)
#   dns       → Gateway presents SNI cert per LLM domain
#   sidecar   → Sidecar sends pre-decrypted body, no TLS intercept
#   scrub_api → Apps POST body directly to /scrub endpoint
TLS_MODE = settings.TLS_MODE  # default: "corp_ca"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth: identify user/department from request ─────────────────
async def get_user_context(request: Request) -> dict:
    """
    Identify user from:
    1. X-User-ID header (set by GPO/MDM on corporate machines)
    2. X-Department header
    3. Client IP → mapped to department via AD/LDAP
    """
    user_id    = request.headers.get("X-User-ID", "anonymous")
    department = request.headers.get("X-Department", "unknown")
    client_ip  = request.client.host

    # Fallback: IP → Department lookup (from your AD/LDAP)
    if department == "unknown":
        department = await request.app.state.policy.ip_to_department(client_ip)

    return {
        "user_id":    user_id,
        "department": department,
        "client_ip":  client_ip,
        "request_id": str(uuid.uuid4())
    }


# ── Health Check (for load balancer) ───────────────────────────
@app.get("/health")
async def health(request: Request):
    try:
        await request.app.state.redis.ping()
        return {"status": "healthy", "version": "2.0.0"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Unhealthy: {e}")


# ── Metrics endpoint ────────────────────────────────────────────
@app.get("/metrics")
async def metrics(request: Request):
    redis_client = request.app.state.redis
    return {
        "requests_total":    await redis_client.get("metrics:total") or 0,
        "pii_blocked_total": await redis_client.get("metrics:pii_found") or 0,
        "requests_blocked":  await redis_client.get("metrics:blocked") or 0,
        "tls_mode":          TLS_MODE,
    }


# ── MODE 4: Scrub-Only API ──────────────────────────────────────
# Apps POST raw body here → get back scrubbed body
# No TLS interception needed — apps call this before calling LLM
# Perfect for Copilot extensions and SDK integrations
@app.post("/scrub")
async def scrub_only(
    request: Request,
    user: dict = Depends(get_user_context)
):
    """
    Standalone scrub endpoint — no proxying.
    Apps send body here, get back PII-scrubbed version.
    Used by sidecar agents and SDK integrations.
    """
    body_bytes = await request.body()
    original_body = body_bytes.decode("utf-8") if body_bytes else ""
    policy = await request.app.state.policy.get(user["department"])

    scrubbed_body, pii_found = await asyncio.get_event_loop().run_in_executor(
        None, request.app.state.pii.scrub, original_body, policy
    )

    if pii_found:
        await request.app.state.redis.incr("metrics:pii_found")
        await request.app.state.audit.log({
            "request_id":   user["request_id"],
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "user_id":      user["user_id"],
            "department":   user["department"],
            "client_ip":    user["client_ip"],
            "target_llm":   "scrub-only",
            "pii_types":    list(pii_found.keys()),
            "pii_counts":   pii_found,
            "original_len": len(original_body),
            "scrubbed_len": len(scrubbed_body),
        })

    return JSONResponse({
        "scrubbed_body": scrubbed_body,
        "pii_found":     pii_found,
        "request_id":    user["request_id"],
    })


# ── Main Proxy Handler ──────────────────────────────────────────
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def proxy(
    request: Request,
    path: str,
    user: dict = Depends(get_user_context)
):
    # Skip internal endpoints
    if path in ("health", "metrics", "scrub"):
        raise HTTPException(status_code=404)

    request_id   = user["request_id"]
    redis_client = request.app.state.redis
    await redis_client.incr("metrics:total")

    # ── Determine Target LLM ─────────────────────────────────────
    # In DNS mode: Host header IS the real LLM domain
    # In corp_ca mode: Host header is the proxy domain, use X-Target header
    host = request.headers.get("x-target-host") or request.headers.get("host", "")
    base_url = LLM_ROUTES.get(host, "https://api.anthropic.com")
    target_url = f"{base_url}/{path}"

    # Read body
    body_bytes    = await request.body()
    original_body = body_bytes.decode("utf-8") if body_bytes else ""

    # ── Policy Check ─────────────────────────────────────────────
    policy = await request.app.state.policy.get(user["department"])

    if policy.get("block_all_llm"):
        await redis_client.incr("metrics:blocked")
        logger.warning(f"🚫 BLOCKED [{user['department']}] {user['user_id']} → {target_url}")
        return JSONResponse(
            status_code=403,
            content={"error": f"LLM access blocked for department: {user['department']}"}
        )

    # ── Rate Limiting ─────────────────────────────────────────────
    rate_key = f"rate:{user['user_id']}"
    current  = await redis_client.incr(rate_key)
    if current == 1:
        await redis_client.expire(rate_key, 60)

    max_rpm = policy.get("max_requests_per_minute", 60)
    if current > max_rpm:
        logger.warning(f"⏱️  RATE LIMIT [{user['user_id']}] {current}/{max_rpm} rpm")
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Try again in a minute."}
        )

    # ── PII Scrubbing ─────────────────────────────────────────────
    scrubbed_body, pii_found = await asyncio.get_event_loop().run_in_executor(
        None, request.app.state.pii.scrub, original_body, policy
    )

    if pii_found:
        await redis_client.incr("metrics:pii_found")
        logger.warning(
            f"🔴 PII SCRUBBED | id={request_id} | "
            f"user={user['user_id']} | dept={user['department']} | "
            f"types={list(pii_found.keys())} | mode={TLS_MODE}"
        )
        await request.app.state.audit.log({
            "request_id":   request_id,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "user_id":      user["user_id"],
            "department":   user["department"],
            "client_ip":    user["client_ip"],
            "target_llm":   base_url,
            "pii_types":    list(pii_found.keys()),
            "pii_counts":   pii_found,
            "original_len": len(original_body),
            "scrubbed_len": len(scrubbed_body),
        })

        if policy.get("block_on_pii"):
            return JSONResponse(
                status_code=400,
                content={
                    "error":      "Request blocked: PII detected",
                    "pii_types":  list(pii_found.keys()),
                    "request_id": request_id
                }
            )

    # ── Build outbound SSL context ────────────────────────────────
    # Always verify real LLM cert when connecting outbound
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations(settings.CORP_CA_BUNDLE)  # trust corp CA + public CAs

    # ── Forward Clean Request to LLM ─────────────────────────────
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in (
            "host", "content-length", "transfer-encoding",
            "x-target-host"               # strip internal routing header
        )
    }
    headers["X-PII-Gateway-ID"] = request_id
    headers["X-PII-Scrubbed"]   = "true" if pii_found else "false"
    headers["host"]              = host    # restore correct Host for LLM

    async with httpx.AsyncClient(verify=ssl_context, timeout=120.0) as client:
        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=scrubbed_body.encode("utf-8"),
                params=dict(request.query_params)
            )
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )
        except httpx.ConnectError as e:
            logger.error(f"Connection error → {target_url}: {e}")
            return JSONResponse(status_code=502, content={"error": "LLM API unreachable"})
        except httpx.TimeoutException:
            return JSONResponse(status_code=504, content={"error": "LLM API timeout"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "gateway:app",
        host="0.0.0.0",
        port=8080,
        workers=8,           # Scale to CPU cores
        log_level="info",
        access_log=True
    )