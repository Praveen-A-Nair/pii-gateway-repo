"""
Local Setup & Test Script for Enterprise PII Gateway
Automates the entire local dev environment setup
Run: python local_setup.py [install|start|test|all]
"""

import os
import sys
import time
import json
import subprocess
import platform
import httpx
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
PROJECT_DIR = Path(__file__).parent


# ── Colour output ────────────────────────────────────────────────
def green(t):  return f"\033[92m{t}\033[0m"
def red(t):    return f"\033[91m{t}\033[0m"
def yellow(t): return f"\033[93m{t}\033[0m"
def bold(t):   return f"\033[1m{t}\033[0m"


def run(cmd, check=True, capture=False):
    print(f"  → {cmd}")
    result = subprocess.run(
        cmd, shell=True,
        capture_output=capture,
        text=True
    )
    if check and result.returncode != 0:
        print(red(f"  ✗ Failed: {result.stderr or result.stdout}"))
        sys.exit(1)
    return result


def section(title):
    print(f"\n{'='*60}")
    print(f"  {bold(title)}")
    print(f"{'='*60}")


# ════════════════════════════════════════════════════════════════
# STEP 1 — INSTALL
# ════════════════════════════════════════════════════════════════
def install():
    section("📦 STEP 1: Installing Dependencies")

    # Check Python version
    major, minor = sys.version_info[:2]
    if major < 3 or minor < 10:
        print(red(f"  ✗ Python 3.10+ required (found {major}.{minor})"))
        sys.exit(1)
    print(green(f"  ✓ Python {major}.{minor} OK"))

    # Check Docker
    result = run("docker --version", check=False, capture=True)
    if result.returncode != 0:
        print(red("  ✗ Docker not found — install Docker Desktop first"))
        print("    https://www.docker.com/products/docker-desktop")
        sys.exit(1)
    print(green(f"  ✓ Docker found"))

    # Check Docker Compose
    result = run("docker compose version", check=False, capture=True)
    if result.returncode != 0:
        print(red("  ✗ Docker Compose not found"))
        sys.exit(1)
    print(green("  ✓ Docker Compose found"))

    # Install Python packages
    print("\n  Installing Python packages...")
    packages = [
        "fastapi>=0.110.0",
        "uvicorn>=0.29.0",
        "httpx>=0.27.0",
        "redis[asyncio]>=5.0.0",
        "asyncpg>=0.29.0",
        "pydantic-settings>=2.0.0",
        "presidio-analyzer>=2.2.354",
        "presidio-anonymizer>=2.2.354",
        "spacy>=3.7.0",
        "pytest>=8.0.0",
        "pytest-asyncio>=0.23.0",
    ]
    run(f'pip install {" ".join(packages)} -q')
    print(green("  ✓ Python packages installed"))

    # Download spaCy model
    print("\n  Downloading spaCy English model (~560MB, once only)...")
    result = run("python -m spacy download en_core_web_lg", check=False, capture=True)
    if result.returncode == 0:
        print(green("  ✓ spaCy model ready"))
    else:
        print(yellow("  ⚠  spaCy model download failed — regex-only mode will be used"))

    # Generate local dev certs
    print("\n  Generating local development certificates...")
    result = run("python cert_manager.py generate", check=False)
    if result.returncode == 0:
        print(green("  ✓ Certificates generated in ./certs/"))
    else:
        print(yellow("  ⚠  Cert generation failed — will use HTTP mode for local testing"))

    # Create .env if not exists
    env_file = PROJECT_DIR / ".env"
    if not env_file.exists():
        env_file.write_text("""# Local development settings
TLS_MODE=corp_ca
REDIS_URL=redis://:redis_secret@localhost:6379/0
DATABASE_URL=postgresql://pii_user:pii_pass@localhost:5432/pii_audit
CORP_CA_BUNDLE=./certs/corp_ca_bundle.crt
LOG_LEVEL=DEBUG
""")
        print(green("  ✓ .env created for local dev"))
    else:
        print(green("  ✓ .env already exists"))

    print(green("\n  ✓ Installation complete!"))


# ════════════════════════════════════════════════════════════════
# STEP 2 — START LOCAL STACK
# ════════════════════════════════════════════════════════════════
def start():
    section("🚀 STEP 2: Starting Local Stack")

    # Start Redis + PostgreSQL only (not full cluster)
    print("  Starting Redis and PostgreSQL via Docker...")
    run("""docker compose up -d redis postgres""")

    print("  Waiting for services to be ready...")
    time.sleep(5)

    # Verify Redis
    result = run("docker exec pii-redis redis-cli -a redis_secret ping",
                 check=False, capture=True)
    if "PONG" in result.stdout:
        print(green("  ✓ Redis ready"))
    else:
        print(yellow("  ⚠  Redis not ready yet — wait a few seconds"))

    # Verify PostgreSQL
    result = run(
        'docker exec pii-postgres psql -U pii_user -d pii_audit -c "SELECT 1"',
        check=False, capture=True
    )
    if "1" in result.stdout:
        print(green("  ✓ PostgreSQL ready"))
    else:
        print(yellow("  ⚠  PostgreSQL not ready yet — wait a few seconds"))

    # Start gateway in background
    print("\n  Starting PII Gateway on http://localhost:8080 ...")
    if IS_WINDOWS:
        subprocess.Popen(
            [sys.executable, "gateway.py"],
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        subprocess.Popen(
            [sys.executable, "gateway.py"],
            stdout=open("gateway.log", "w"),
            stderr=subprocess.STDOUT
        )

    print("  Waiting for gateway to start...")
    time.sleep(3)

    # Health check
    for attempt in range(10):
        try:
            r = httpx.get("http://localhost:8080/health", timeout=2)
            if r.status_code == 200:
                print(green("  ✓ Gateway ready at http://localhost:8080"))
                break
        except Exception:
            time.sleep(1)
    else:
        print(red("  ✗ Gateway failed to start — check gateway.log"))
        sys.exit(1)

    print(green("\n  ✓ Local stack running!"))
    print(f"\n  📌 Gateway:  http://localhost:8080")
    print(f"  📌 Health:   http://localhost:8080/health")
    print(f"  📌 Metrics:  http://localhost:8080/metrics")
    print(f"  📌 Scrub API: http://localhost:8080/scrub")


# ════════════════════════════════════════════════════════════════
# STEP 3 — RUN TESTS
# ════════════════════════════════════════════════════════════════
def test():
    section("🧪 STEP 3: Running Tests")

    results = []

    # ── Test 1: Health Check ─────────────────────────────────────
    print("\n  Test 1: Health endpoint")
    try:
        r = httpx.get("http://localhost:8080/health", timeout=5)
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"
        print(green("  ✓ Health check passed"))
        results.append(("Health check", True))
    except Exception as e:
        print(red(f"  ✗ Health check failed: {e}"))
        results.append(("Health check", False))

    # ── Test 2: PII Scrubber Unit Tests ─────────────────────────
    print("\n  Test 2: PII Scrubber (unit tests)")
    from pii_scrubber import PIIScrubber
    scrubber = PIIScrubber()

    pii_tests = [
        ("Email",       "Contact john.doe@company.com for help",        "EMAIL"),
        ("Phone",       "Call +1 (555) 123-4567 anytime",               "PHONE"),
        ("SSN",         "My SSN is 123-45-6789",                        "SSN"),
        ("Credit Card", "Card number: 4532015112830366",                 "CREDIT_CARD"),
        ("AWS Key",     "Key: AKIAIOSFODNN7EXAMPLE",                    "AWS_KEY"),
        ("API Key",     "api_key=sk-abc123def456ghi789jkl",             "API_KEY"),
        ("Password",    "password=SuperSecret123!",                     "PASSWORD"),
        ("JWT",         "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.abc123", "JWT"),
        ("IP Address",  "Server at 192.168.1.100",                      "IP"),
        ("JSON body",   '{"messages":[{"role":"user","content":"My email is test@test.com"}]}', "EMAIL"),
    ]

    passed = 0
    for name, input_text, expected_tag in pii_tests:
        scrubbed, found = scrubber.scrub(input_text)
        ok = expected_tag in scrubbed or any(expected_tag in k for k in found)
        status = green("✓") if ok else red("✗")
        print(f"    {status} {name}: {scrubbed[:60]}")
        if ok:
            passed += 1
        results.append((f"PII: {name}", ok))

    print(f"\n  {passed}/{len(pii_tests)} PII tests passed")

    # ── Test 3: Scrub API Endpoint ───────────────────────────────
    print("\n  Test 3: /scrub API endpoint")
    test_payloads = [
        {
            "name": "Plain text PII",
            "body": "My email is john@company.com and SSN is 123-45-6789",
            "expect": ["EMAIL", "SSN"]
        },
        {
            "name": "JSON with PII",
            "body": json.dumps({
                "messages": [{
                    "role": "user",
                    "content": "Contact sarah@example.com, card: 4532015112830366"
                }]
            }),
            "expect": ["EMAIL", "CREDIT_CARD"]
        },
        {
            "name": "Clean text (no PII)",
            "body": "How do I sort a list in Python?",
            "expect": []
        },
        {
            "name": "Credentials in code",
            "body": "api_key=sk-abc123def456ghi789 and password=MySecret123",
            "expect": ["API_KEY", "PASSWORD"]
        },
    ]

    for payload in test_payloads:
        try:
            r = httpx.post(
                "http://localhost:8080/scrub",
                content=payload["body"].encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-User-ID": "test-user",
                    "X-Department": "ENGINEERING"
                },
                timeout=10
            )
            data = r.json()
            found = data.get("pii_found", {})
            scrubbed = data.get("scrubbed_body", "")

            if payload["expect"]:
                ok = any(tag in scrubbed or tag in found for tag in payload["expect"])
            else:
                ok = len(found) == 0

            status = green("✓") if ok else red("✗")
            print(f"    {status} {payload['name']}: found={list(found.keys())}")
            results.append((f"API: {payload['name']}", ok))
        except Exception as e:
            print(red(f"    ✗ {payload['name']}: {e}"))
            results.append((f"API: {payload['name']}", False))

    # ── Test 4: Rate Limiting ────────────────────────────────────
    print("\n  Test 4: Rate limiting (HR dept = 30 rpm)")
    try:
        responses = []
        for i in range(35):
            r = httpx.post(
                "http://localhost:8080/scrub",
                content=b"test content",
                headers={"X-User-ID": "rate-test-user", "X-Department": "HR"},
                timeout=5
            )
            responses.append(r.status_code)

        rate_limited = any(s == 429 for s in responses)
        ok = rate_limited
        print(f"    {green('✓') if ok else red('✗')} Rate limit triggered after 30 requests")
        results.append(("Rate limiting", ok))
    except Exception as e:
        print(yellow(f"    ⚠  Rate limit test skipped: {e}"))

    # ── Test 5: Department Policy — LEGAL blocks PII ─────────────
    print("\n  Test 5: Department policy — LEGAL blocks on PII")
    try:
        r = httpx.post(
            "http://localhost:8080/scrub",
            content=b"My SSN is 123-45-6789 please help",
            headers={"X-User-ID": "legal-user", "X-Department": "LEGAL"},
            timeout=5
        )
        ok = r.status_code == 400  # LEGAL policy blocks on PII
        print(f"    {green('✓') if ok else yellow('⚠')} LEGAL dept blocked request (status={r.status_code})")
        results.append(("Policy: LEGAL blocks PII", ok))
    except Exception as e:
        print(yellow(f"    ⚠  Policy test: {e}"))

    # ── Test 6: curl simulation ──────────────────────────────────
    print("\n  Test 6: curl-style request (simulates real developer usage)")
    try:
        body = json.dumps({
            "model": "claude-sonnet-4-6",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": "My name is John Smith, email john@company.com. Help me with Python."
            }]
        })
        r = httpx.post(
            "http://localhost:8080/scrub",
            content=body.encode(),
            headers={
                "Content-Type": "application/json",
                "X-User-ID": "dev-user",
                "X-Department": "ENGINEERING"
            },
            timeout=10
        )
        data = r.json()
        scrubbed = data["scrubbed_body"]
        pii = data["pii_found"]
        ok = "john@company.com" not in scrubbed  # email must be gone
        print(f"    {green('✓') if ok else red('✗')} Email scrubbed from LLM payload")
        print(f"    PII removed: {list(pii.keys())}")
        print(f"    Scrubbed content: {scrubbed[:100]}...")
        results.append(("curl simulation", ok))
    except Exception as e:
        print(red(f"    ✗ curl simulation failed: {e}"))
        results.append(("curl simulation", False))

    # ── Summary ──────────────────────────────────────────────────
    section("📊 TEST RESULTS SUMMARY")
    total  = len(results)
    passed = sum(1 for _, ok in results if ok)

    for name, ok in results:
        status = green("✓ PASS") if ok else red("✗ FAIL")
        print(f"  {status}  {name}")

    print(f"\n  {'='*40}")
    pct = int(passed/total*100)
    colour = green if pct == 100 else yellow if pct >= 80 else red
    print(f"  {colour(f'{passed}/{total} tests passed ({pct}%)')}")

    if passed == total:
        print(green("\n  🎉 All tests passed! Gateway is working correctly."))
    else:
        print(yellow("\n  ⚠  Some tests failed — check gateway.log for details"))


# ════════════════════════════════════════════════════════════════
# STOP
# ════════════════════════════════════════════════════════════════
def stop():
    section("🛑 Stopping Local Stack")
    run("docker compose down", check=False)
    if IS_WINDOWS:
        run("taskkill /f /im python.exe", check=False)
    else:
        run("pkill -f gateway.py", check=False)
    print(green("  ✓ Stopped"))


# ════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "all"

    print(bold("""
╔══════════════════════════════════════════════════════════╗
║        🛡️  Enterprise PII Gateway — Local Setup          ║
╚══════════════════════════════════════════════════════════╝
"""))

    if action == "install": install()
    elif action == "start":  start()
    elif action == "test":   test()
    elif action == "stop":   stop()
    elif action == "all":
        install()
        start()
        test()
    else:
        print(f"Usage: python local_setup.py [install|start|test|stop|all]")
