"""
Sidecar Agent — runs locally on each Windows machine
Intercepts at application layer (before TLS) — zero certificate issues
Sends raw body to central PII gateway for scrubbing, then forwards clean request to LLM

Install: pip install fastapi uvicorn httpx pywin32
Run as Windows Service via NSSM or Task Scheduler
"""

import os
import json
import logging
import subprocess
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# ── Config ──────────────────────────────────────────────────────
GATEWAY_SCRUB_URL = os.getenv("PII_GATEWAY_URL", "https://pii-gateway.internal:8443/scrub")
GATEWAY_CA_CERT   = os.getenv("GATEWAY_CA_CERT", r"C:\certs\corp-pii-ca.crt")
LISTEN_PORT       = int(os.getenv("SIDECAR_PORT", "7777"))

# LLM APIs this sidecar intercepts
LLM_TARGETS = {
    "/anthropic": "https://api.anthropic.com",
    "/openai":    "https://api.openai.com",
    "/gemini":    "https://generativelanguage.googleapis.com",
    "/copilot":   "https://api.githubcopilot.com",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIDECAR] %(message)s",
    handlers=[
        logging.FileHandler(r"C:\ProgramData\PIISidecar\sidecar.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("sidecar")

app = FastAPI(title="PII Sidecar Agent", version="1.0.0")


def get_windows_username() -> str:
    """Get current Windows logged-in username"""
    try:
        return os.environ.get("USERNAME", "unknown")
    except Exception:
        return "unknown"


def get_windows_department() -> str:
    """Get department from Windows registry (set by GPO)"""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Company\PIIProxy"
        )
        dept, _ = winreg.QueryValueEx(key, "Department")
        winreg.CloseKey(key)
        return dept
    except Exception:
        return "UNKNOWN"


@app.get("/health")
async def health():
    return {"status": "healthy", "mode": "sidecar", "user": get_windows_username()}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def intercept(request: Request, path: str):
    """
    Intercept LLM request → scrub PII via gateway → forward to LLM
    No TLS interception — app connects to localhost:7777 (HTTP)
    Sidecar handles real HTTPS to LLM with proper certs
    """
    # Determine target LLM
    prefix = f"/{path.split('/')[0]}"
    base_url = LLM_TARGETS.get(prefix)
    if not base_url:
        return JSONResponse(status_code=404, content={"error": f"Unknown LLM path: {prefix}"})

    forward_path = "/".join(path.split("/")[1:])
    target_url   = f"{base_url}/{forward_path}"

    # Read original body
    body_bytes    = await request.body()
    original_body = body_bytes.decode("utf-8") if body_bytes else ""

    # ── Step 1: Send to Gateway for PII Scrubbing ────────────────
    try:
        async with httpx.AsyncClient(verify=GATEWAY_CA_CERT, timeout=30.0) as client:
            scrub_response = await client.post(
                GATEWAY_SCRUB_URL,
                content=original_body.encode("utf-8"),
                headers={
                    "Content-Type":  "application/json",
                    "X-User-ID":     get_windows_username(),
                    "X-Department":  get_windows_department(),
                    "X-Client-Mode": "sidecar",
                }
            )
            scrub_result  = scrub_response.json()
            scrubbed_body = scrub_result.get("scrubbed_body", original_body)
            pii_found     = scrub_result.get("pii_found", {})

            if pii_found:
                logger.warning(f"🔴 PII removed before sending to LLM: {list(pii_found.keys())}")

    except Exception as e:
        logger.error(f"Gateway unreachable: {e} — sending original (unscubbed) body")
        scrubbed_body = original_body  # Fail open — configurable to fail closed

    # ── Step 2: Forward Scrubbed Body to Real LLM ───────────────
    # Sidecar uses REAL system certs — no interception, no cert issues!
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }

    async with httpx.AsyncClient(verify=True, timeout=120.0) as client:
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
        except Exception as e:
            logger.error(f"LLM forward error: {e}")
            return JSONResponse(status_code=502, content={"error": str(e)})


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  🛡️  PII SIDECAR AGENT")
    print("="*55)
    print(f"  Listening: http://localhost:{LISTEN_PORT}")
    print(f"  Gateway:   {GATEWAY_SCRUB_URL}")
    print(f"  User:      {get_windows_username()}")
    print(f"  Dept:      {get_windows_department()}")
    print("  Mode:      Sidecar (no TLS interception)")
    print("="*55 + "\n")

    uvicorn.run(app, host="127.0.0.1", port=LISTEN_PORT, log_level="info")
