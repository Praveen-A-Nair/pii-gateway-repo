# 🧪 Local Setup & Testing Guide

Complete guide to run and test the Enterprise PII Gateway on your local machine.
No enterprise infrastructure needed — just Docker Desktop + Python 3.10+.

---

## ⚡ Quickest Start (3 commands)

```bash
# 1. Install everything
python local_setup.py install

# 2. Start local stack
python local_setup.py start

# 3. Run all tests
python local_setup.py test
```

---

## 📋 Prerequisites

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.10+ | python.org |
| Docker Desktop | Latest | docker.com |
| Git | Any | git-scm.com |

---

## 🔧 Manual Step-by-Step Setup

### Step 1 — Install Dependencies

```bash
pip install fastapi uvicorn httpx redis asyncpg pydantic-settings \
            presidio-analyzer presidio-anonymizer spacy \
            pytest pytest-asyncio

# Download AI model (560MB, one time only)
python -m spacy download en_core_web_lg
```

### Step 2 — Generate Local Certs

```bash
python cert_manager.py generate
# Creates ./certs/ with all certificates
```

### Step 3 — Create .env File

```bash
# Copy this into .env in the project root:
TLS_MODE=corp_ca
REDIS_URL=redis://:redis_secret@localhost:6379/0
DATABASE_URL=postgresql://pii_user:pii_pass@localhost:5432/pii_audit
CORP_CA_BUNDLE=./certs/corp_ca_bundle.crt
LOG_LEVEL=DEBUG
```

### Step 4 — Start Redis + PostgreSQL

```bash
docker compose -f docker-compose.local.yml up -d
```

### Step 5 — Start the Gateway

```bash
python gateway.py
# Gateway starts at http://localhost:8080
```

---

## 🧪 Test Methods

### Method 1 — Automated Test Runner

```bash
python local_setup.py test
```

Runs all tests and shows pass/fail summary.

### Method 2 — pytest (Detailed)

```bash
# Unit tests only (no gateway needed)
pytest tests/ -v -m "not integration"

# Integration tests (gateway must be running)
pytest tests/ -v -m integration

# All tests with coverage report
pytest tests/ -v --cov=. --cov-report=html
open htmlcov/index.html
```

### Method 3 — Manual curl Tests

```bash
# Test 1: Health check
curl http://localhost:8080/health

# Test 2: Scrub API — email detection
curl -X POST http://localhost:8080/scrub \
  -H "Content-Type: application/json" \
  -H "X-User-ID: testuser" \
  -H "X-Department: ENGINEERING" \
  -d "Contact john@company.com for support"

# Test 3: Scrub API — full LLM JSON body
curl -X POST http://localhost:8080/scrub \
  -H "Content-Type: application/json" \
  -H "X-User-ID: testuser" \
  -H "X-Department: ENGINEERING" \
  -d '{
    "model": "claude-sonnet-4-6",
    "messages": [{
      "role": "user",
      "content": "My SSN is 123-45-6789 and email is john@test.com. Help me."
    }]
  }'

# Test 4: Multiple PII types
curl -X POST http://localhost:8080/scrub \
  -H "X-Department: HR" \
  -d "Name: John Smith, Card: 4532015112830366, Phone: +1 555-123-4567"

# Test 5: Credentials detection
curl -X POST http://localhost:8080/scrub \
  -H "X-Department: ENGINEERING" \
  -d "api_key=sk-abc123def456 password=MySecret123 AKIAIOSFODNN7EXAMPLE"

# Test 6: Clean text (no PII — should pass through unchanged)
curl -X POST http://localhost:8080/scrub \
  -d "How do I sort a Python list in reverse order?"

# Test 7: Metrics
curl http://localhost:8080/metrics
```

### Method 4 — Python Script Test

```python
import httpx, json

BASE = "http://localhost:8080"

# Test scrub API
r = httpx.post(f"{BASE}/scrub",
    content=json.dumps({
        "messages": [{"role": "user",
                      "content": "My email john@co.com SSN 123-45-6789"}]
    }).encode(),
    headers={"X-User-ID": "dev", "X-Department": "ENGINEERING"}
)
result = r.json()
print("PII found:", result["pii_found"])
print("Scrubbed:", result["scrubbed_body"])
```

---

## 📊 Expected Test Output

```
============================================================
  📊 TEST RESULTS SUMMARY
============================================================
  ✓ PASS  Health check
  ✓ PASS  PII: Email
  ✓ PASS  PII: Phone
  ✓ PASS  PII: SSN
  ✓ PASS  PII: Credit Card
  ✓ PASS  PII: AWS Key
  ✓ PASS  PII: API Key
  ✓ PASS  PII: Password
  ✓ PASS  PII: JWT
  ✓ PASS  PII: IP Address
  ✓ PASS  PII: JSON body
  ✓ PASS  API: Plain text PII
  ✓ PASS  API: JSON with PII
  ✓ PASS  API: Clean text (no PII)
  ✓ PASS  API: Credentials in code
  ✓ PASS  Rate limiting
  ✓ PASS  Policy: LEGAL blocks PII
  ✓ PASS  curl simulation
  ========================================
  18/18 tests passed (100%)

  🎉 All tests passed! Gateway is working correctly.
```

---

## 🔍 Check What's Happening

```bash
# Live gateway logs
tail -f gateway.log

# Audit log (PII events)
tail -f audit.jsonl

# Redis — check rate limit counters
docker exec pii-redis redis-cli -a redis_secret KEYS "rate:*"

# Redis — check policy cache
docker exec pii-redis redis-cli -a redis_secret KEYS "policy:*"

# PostgreSQL — check audit records
docker exec pii-postgres psql -U pii_user -d pii_audit \
  -c "SELECT timestamp, user_id, department, pii_types FROM pii_audit ORDER BY timestamp DESC LIMIT 10;"
```

---

## 🛑 Stop Everything

```bash
python local_setup.py stop
# OR
docker compose -f docker-compose.local.yml down
pkill -f gateway.py
```

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| `Gateway not starting` | Check `gateway.log` — usually Redis not ready yet |
| `Presidio not found` | Run: `pip install presidio-analyzer presidio-anonymizer` |
| `spaCy model missing` | Run: `python -m spacy download en_core_web_lg` |
| `Redis connection refused` | Run: `docker compose -f docker-compose.local.yml up -d redis` |
| `Port 8080 in use` | Change port in `gateway.py` last line: `port=8081` |
| `Tests fail with 502` | Gateway isn't running — run `python gateway.py` first |
| `PII not detected` | Presidio model not loaded — check it's installed + model downloaded |

---

## 🚀 Test Against a Real LLM (Optional)

To test the full proxy flow (not just /scrub):

```bash
# Route curl through the gateway to real Anthropic API
curl --proxy http://localhost:8080 \
  https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -H "X-Target-Host: api.anthropic.com" \
  -d '{
    "model": "claude-haiku-4-5-20251001",
    "max_tokens": 100,
    "messages": [{
      "role": "user",
      "content": "My email is test@test.com. Say hello."
    }]
  }'

# The gateway will scrub test@test.com BEFORE it reaches Claude
```
