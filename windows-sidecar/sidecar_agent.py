"""
PII Sidecar Agent v4.1 — mitmproxy based
"""

import os
import sys
import json
import logging
import subprocess
import urllib.request
from pathlib import Path

GATEWAY_SCRUB_URL = os.getenv("PII_GATEWAY_URL",   "http://localhost:8080/scrub")
LISTEN_PORT       = int(os.getenv("SIDECAR_PORT",  "7777"))
FAIL_CLOSED       = os.getenv("SIDECAR_FAIL_CLOSED", "true").lower() == "true"

log_dir = Path(os.getenv("PROGRAMDATA", ".")) / "PIISidecar"
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIDECAR] %(message)s",
    handlers=[
        logging.FileHandler(log_dir / "sidecar.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("sidecar")


def get_username():
    return os.environ.get("USERNAME", "unknown")


def get_department():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Company\PIIProxy")
        dept, _ = winreg.QueryValueEx(key, "Department")
        winreg.CloseKey(key)
        return dept
    except Exception:
        return "ENGINEERING"


def trust_mitmproxy_cert():
    """Install mitmproxy CA into Windows trusted root — needs to run once."""
    # mitmproxy stores certs in ~/.mitmproxy/
    mitm_dir  = Path.home() / ".mitmproxy"
    # .cer is DER format — what certutil needs
    cert_cer  = mitm_dir / "mitmproxy-ca-cert.cer"
    cert_pem  = mitm_dir / "mitmproxy-ca-cert.pem"

    cert_path = cert_cer if cert_cer.exists() else cert_pem if cert_pem.exists() else None

    if not cert_path:
        logger.warning(f"No cert found in {mitm_dir}")
        return False

    logger.info(f"Installing cert from {cert_path} into Windows trusted root...")
    try:
        result = subprocess.run(
            ["certutil", "-addstore", "-user", "Root", str(cert_path)],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logger.info("✅ mitmproxy CA cert trusted in Windows")
            return True
        else:
            logger.warning(f"certutil: {result.stdout.strip()} {result.stderr.strip()}")
            logger.warning("Try running PowerShell as Administrator and re-run this script")
            return False
    except FileNotFoundError:
        logger.error("certutil not found — run this in PowerShell as Administrator:")
        logger.error(f'  certutil -addstore -user Root "{cert_path}"')
        return False


# ── mitmproxy addon script ───────────────────────────────────────
ADDON_CODE = r'''
import json
import logging
import urllib.request
import os
from mitmproxy import http

GATEWAY_SCRUB_URL = os.getenv("PII_GATEWAY_URL", "http://localhost:8080/scrub")
FAIL_CLOSED       = os.getenv("SIDECAR_FAIL_CLOSED", "true").lower() == "true"

SCRUB_HOSTS = {
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.githubcopilot.com",
    "api.individual.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "copilot-telemetry.githubusercontent.com",
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PII] %(message)s")
logger = logging.getLogger("pii-addon")


def get_username():
    return os.environ.get("USERNAME", "unknown")


def get_department():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Company\PIIProxy")
        dept, _ = winreg.QueryValueEx(key, "Department")
        winreg.CloseKey(key)
        return dept
    except Exception:
        return "ENGINEERING"


def scrub(body: str):
    req = urllib.request.Request(
        GATEWAY_SCRUB_URL,
        data=body.encode("utf-8"),
        headers={
            "Content-Type":  "application/json",
            "X-User-ID":     get_username(),
            "X-Department":  get_department(),
            "X-Client-Mode": "mitmproxy-v4",
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return result["scrubbed_body"], result.get("pii_found", {})


class PIIScrubber:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if host not in SCRUB_HOSTS:
            return
        if flow.request.method not in ("POST", "PUT", "PATCH"):
            return

        body = flow.request.get_text(strict=False)
        if not body or not body.strip():
            return

        try:
            scrubbed, pii_found = scrub(body)
            if pii_found:
                logger.warning(
                    f"\U0001f534 PII REMOVED | user={get_username()} | "
                    f"host={host} | types={list(pii_found.keys())}"
                )
                flow.request.set_text(scrubbed)
            else:
                logger.info(f"\u2705 Clean | host={host} | path={flow.request.path}")
        except Exception as e:
            logger.error(f"Gateway error: {e}")
            if FAIL_CLOSED:
                logger.error(f"\U0001f6ab FAIL-CLOSED — blocking request to {host}")
                flow.response = http.Response.make(
                    503,
                    json.dumps({"error": "PII gateway unreachable. Request blocked."}),
                    {"Content-Type": "application/json"}
                )


addons = [PIIScrubber()]
'''

addon_path = log_dir / "pii_addon.py"
addon_path.write_text(ADDON_CODE, encoding="utf-8")


def generate_cert():
    """Run mitmdump briefly just to generate the CA cert files."""
    mitm_cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
    if mitm_cert.exists():
        logger.info("✅ mitmproxy cert already exists")
        return True

    logger.info("Generating mitmproxy CA cert (takes ~3 seconds)...")
    try:
        # Run mitmdump with a short timeout — it will generate certs then we kill it
        proc = subprocess.Popen(
            ["mitmdump", "--listen-port", "17777",   # use different port to avoid conflict
             "--quiet"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        import time
        time.sleep(4)   # give it time to generate cert
        proc.terminate()
        proc.wait(timeout=3)
    except Exception as e:
        logger.debug(f"Expected termination: {e}")

    if mitm_cert.exists():
        logger.info("✅ mitmproxy CA cert generated")
        return True
    else:
        logger.warning(f"Cert not found at {mitm_cert} — may need to run mitmdump manually")
        return False


def main():
    print("\n" + "="*60)
    print("  🛡️  PII SIDECAR AGENT v4.1 (mitmproxy)")
    print("="*60)
    print(f"  Proxy:       http://localhost:{LISTEN_PORT}")
    print(f"  Gateway:     {GATEWAY_SCRUB_URL}")
    print(f"  Fail-closed: {FAIL_CLOSED}")
    print(f"  User:        {get_username()}")
    print(f"  Department:  {get_department()}")
    print("="*60)

    # Check mitmproxy installed
    try:
        import mitmproxy
        try:
            from importlib.metadata import version as pkg_version
            v = pkg_version("mitmproxy")
        except Exception:
            v = "installed"
        logger.info(f"✅ mitmproxy {v} found")
    except ImportError:
        print("\n  ❌ mitmproxy not installed. Run:")
        print("     pip install mitmproxy")
        sys.exit(1)

    # Check gateway
    try:
        urllib.request.urlopen("http://localhost:8080/health", timeout=3)
        logger.info("✅ Gateway reachable at http://localhost:8080")
    except Exception:
        logger.warning("⚠️  Gateway not reachable — start it: cd src && python gateway.py")

    # Generate cert if needed
    mitm_cert_cer = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
    mitm_cert_pem = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

    if not mitm_cert_cer.exists() and not mitm_cert_pem.exists():
        generate_cert()
    else:
        logger.info("✅ mitmproxy cert already generated")

    # Trust cert in Windows
    trust_mitmproxy_cert()

    print(f"\n  🚀 Starting proxy on http://localhost:{LISTEN_PORT}")
    print("  Press Ctrl+C to stop\n")
    print("  VS Code settings.json should have:")
    print('  "http.proxy": "http://localhost:7777"')
    print('  "http.proxyStrictSSL": false\n')

    # Launch mitmdump — this replaces the current process
    cmd = [
        "mitmdump",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(LISTEN_PORT),
        "--script",      str(addon_path),
        "--set",         "ssl_insecure=true",
    ]
    logger.info(f"Running: {' '.join(cmd)}")

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n🛑 Sidecar stopped")


if __name__ == "__main__":
    main()