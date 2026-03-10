"""
PII Sidecar Agent v4.1 — mitmproxy based (macOS)
=================================================
Uses mitmproxy to intercept HTTPS traffic and scrub PII.

Install:
    pip3 install mitmproxy
    python3 sidecar_agent.py

VS Code settings.json:
    {
      "http.proxy": "http://localhost:7777",
      "http.proxyStrictSSL": false,
      "http.proxySupport": "override",
      "github.copilot.advanced": {
        "debug.overrideProxyUrl": "http://localhost:7777",
        "debug.testOverrideProxyUrl": "http://localhost:7777"
      }
    }

Auto-start on Mac login:
    cp com.company.piisidecar.plist ~/Library/LaunchAgents/
    launchctl load ~/Library/LaunchAgents/com.company.piisidecar.plist
"""

import os
import sys
import json
import logging
import subprocess
import urllib.request
from pathlib import Path

# ── Config ───────────────────────────────────────────────────────
GATEWAY_SCRUB_URL = os.getenv("PII_GATEWAY_URL",    "http://localhost:8080/scrub")
LISTEN_PORT       = int(os.getenv("SIDECAR_PORT",   "7777"))
FAIL_CLOSED       = os.getenv("SIDECAR_FAIL_CLOSED","true").lower() == "true"

# ── Log directory (macOS) ────────────────────────────────────────
log_dir = Path("/var/log/piisidecar")
try:
    log_dir.mkdir(parents=True, exist_ok=True)
except PermissionError:
    # Fallback to user home if /var/log not writable
    log_dir = Path.home() / "Library" / "Logs" / "PIISidecar"
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
    return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))


def get_department():
    """Read department from a config file or env var."""
    dept = os.environ.get("PII_DEPARTMENT")
    if dept:
        return dept
    config_file = Path("/etc/piisidecar/department")
    if config_file.exists():
        return config_file.read_text().strip()
    return "ENGINEERING"


def trust_mitmproxy_cert_mac():
    """
    Install mitmproxy CA cert into macOS System Keychain.
    Requires sudo — run once.
    """
    mitm_dir  = Path.home() / ".mitmproxy"
    cert_pem  = mitm_dir / "mitmproxy-ca-cert.pem"
    cert_cer  = mitm_dir / "mitmproxy-ca-cert.cer"
    cert_path = cert_pem if cert_pem.exists() else cert_cer if cert_cer.exists() else None

    if not cert_path:
        logger.warning(f"No mitmproxy cert found in {mitm_dir}")
        return False

    logger.info(f"Installing cert from {cert_path} into macOS System Keychain...")
    try:
        result = subprocess.run(
            [
                "sudo", "security", "add-trusted-cert",
                "-d", "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                str(cert_path)
            ],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            logger.info("✅ mitmproxy CA cert trusted in macOS System Keychain")
            return True
        else:
            logger.warning(f"security command output: {result.stdout} {result.stderr}")
            logger.warning("Try running manually:")
            logger.warning(f"  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert_path}")
            return False
    except FileNotFoundError:
        logger.error("security command not found — are you on macOS?")
        return False


# ── mitmproxy addon ──────────────────────────────────────────────
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
    return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))


def get_department():
    dept = os.environ.get("PII_DEPARTMENT")
    if dept:
        return dept
    from pathlib import Path
    config_file = Path("/etc/piisidecar/department")
    if config_file.exists():
        return config_file.read_text().strip()
    return "ENGINEERING"


def scrub(body: str):
    req = urllib.request.Request(
        GATEWAY_SCRUB_URL,
        data=body.encode("utf-8"),
        headers={
            "Content-Type":  "application/json",
            "X-User-ID":     get_username(),
            "X-Department":  get_department(),
            "X-Client-Mode": "mitmproxy-mac-v4",
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
    """Run mitmdump briefly to generate CA cert."""
    mitm_cert = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if mitm_cert.exists():
        logger.info("✅ mitmproxy cert already exists")
        return True

    logger.info("Generating mitmproxy CA cert...")
    try:
        import time
        proc = subprocess.Popen(
            ["mitmdump", "--listen-port", "17777", "--quiet"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(4)
        proc.terminate()
        proc.wait(timeout=3)
    except Exception as e:
        logger.debug(f"Expected termination: {e}")

    if mitm_cert.exists():
        logger.info("✅ mitmproxy CA cert generated")
        return True
    else:
        logger.warning("Cert not generated — try running mitmdump manually once")
        return False


def main():
    print("\n" + "="*60)
    print("  🛡️  PII SIDECAR AGENT v4.1 (mitmproxy) — macOS")
    print("="*60)
    print(f"  Proxy:       http://localhost:{LISTEN_PORT}")
    print(f"  Gateway:     {GATEWAY_SCRUB_URL}")
    print(f"  Fail-closed: {FAIL_CLOSED}")
    print(f"  User:        {get_username()}")
    print(f"  Department:  {get_department()}")
    print(f"  Log dir:     {log_dir}")
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
        print("     pip3 install mitmproxy")
        sys.exit(1)

    # Check gateway
    try:
        urllib.request.urlopen(f"http://localhost:8080/health", timeout=3)
        logger.info("✅ Gateway reachable at http://localhost:8080")
    except Exception:
        logger.warning("⚠️  Gateway not reachable — start it: cd src && python3 gateway.py")

    # Generate cert if needed
    mitm_cert_pem = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not mitm_cert_pem.exists():
        generate_cert()
    else:
        logger.info("✅ mitmproxy cert already generated")

    # Trust cert in macOS
    trust_mitmproxy_cert_mac()

    print(f"\n  🚀 Starting proxy on http://localhost:{LISTEN_PORT}")
    print("  Press Ctrl+C to stop\n")
    print("  Add to VS Code settings.json:")
    print('  "http.proxy": "http://localhost:7777"')
    print('  "http.proxyStrictSSL": false\n')

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
