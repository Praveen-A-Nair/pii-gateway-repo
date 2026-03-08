# 🛡️ Enterprise PII Gateway

> Centralised PII scrubbing proxy for 500+ users. Intercepts ALL outbound LLM traffic,
> masks sensitive data before it reaches any AI model, and provides a full compliance audit trail.

[![CI](https://github.com/YOUR_ORG/pii-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_ORG/pii-gateway/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✅ What It Does

- **Intercepts** all outbound requests to Claude, GPT, Gemini, GitHub Copilot
- **Detects** 50+ PII types using Microsoft Presidio AI + custom regex patterns
- **Masks** PII before the request ever reaches the LLM (synchronous, blocking)
- **Enforces** per-department policies (HR, Finance, Legal, Engineering, Marketing)
- **Audits** every scrubbing event to PostgreSQL (stores types/counts — never raw PII)
- **Solves** TLS/certificate issues that break GitHub Copilot via 4 TLS modes

---

## 🚀 Quickstart (Local)

```bash
# 1. Clone
git clone https://github.com/YOUR_ORG/pii-gateway.git
cd pii-gateway

# 2. Install + start + test in one command
python scripts/local_setup.py all
```

See [docs/LOCAL_TESTING.md](docs/LOCAL_TESTING.md) for full local setup guide.

---

## 🏗️ Architecture

```
Corp Network (500+ users)
  Copilot / VS Code / curl / Apps
         ↓ (Firewall blocks direct LLM egress)
  NGINX Load Balancer
    ├── :443   → DNS Interception (transparent)
    ├── :8443  → Corp CA Mode (explicit proxy)
    ├── :7778  → Sidecar HTTP (no TLS intercept)
    └── :8444+ → Per-domain SNI certs
         ↓
  PII Gateway Cluster (3 HA nodes)
  Presidio AI + Regex → Redis → PostgreSQL
         ↓
  Clean traffic → LLM APIs
```

---

## 📁 Repository Structure

```
pii-gateway/
├── src/                        ← Core application
│   ├── gateway.py              ← FastAPI proxy (main entry point)
│   ├── pii_engine.py           ← Presidio AI + regex detection
│   ├── policy_manager.py       ← Per-department rules (Redis)
│   ├── audit_db.py             ← PostgreSQL audit trail
│   └── config.py               ← Settings + env vars
│
├── tests/
│   ├── test_gateway.py         ← Integration + API tests
│   └── test_pii_engine.py      ← PII unit tests
│
├── scripts/
│   ├── cert_manager.py         ← Generate certs + GPO commands
│   ├── local_setup.py          ← One-command local setup
│   └── setup_windows.py        ← Windows proxy configurator
│
├── windows-sidecar/
│   ├── sidecar_agent.py        ← Local Windows agent (TLS Mode 3)
│   └── README.md
│
├── docs/
│   └── LOCAL_TESTING.md        ← Full local testing guide
│
├── .github/
│   ├── workflows/ci.yml        ← GitHub Actions CI/CD
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── skills/enterprise-pii-gateway/
│       └── SKILL.md            ← Copilot/Claude Code skill
│
├── certs/                      ← Generated locally (gitignored)
│   └── .gitkeep
│
├── Dockerfile
├── docker-compose.yml          ← Production HA stack
├── docker-compose.local.yml    ← Local dev (Redis + PG only)
├── nginx.conf                  ← Load balancer (all 4 TLS modes)
├── requirements.txt
├── .env.example                ← Copy to .env (never commit .env)
└── .gitignore
```

---

## 🔐 4 TLS Modes

| Mode | How | Best For |
|------|-----|----------|
| `corp_ca` | Corp CA cert via GPO | Default — easiest setup |
| `dns` | DNS override + domain cert | Zero client config needed |
| `sidecar` | Local agent on each machine | Copilot cert pinning |
| `scrub_api` | Apps POST to `/scrub` directly | SDK integration |

```bash
# Set mode in .env
TLS_MODE=corp_ca   # or: dns, sidecar, scrub_api
```

---

## 🧪 Testing

```bash
# Unit tests (no infra needed)
pytest tests/test_pii_engine.py -v

# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov-report=html

# Manual curl test
curl -X POST http://localhost:8080/scrub \
  -H "X-Department: ENGINEERING" \
  -d "My email is john@company.com and SSN 123-45-6789"
```

---

## 🏢 Production Deploy

```bash
# 1. Generate certificates
python scripts/cert_manager.py generate

# 2. Get GPO deployment commands (Windows domain)
python scripts/cert_manager.py deploy

# 3. Configure .env
cp .env.example .env
# Edit .env with your Redis/DB passwords

# 4. Deploy full HA stack
TLS_MODE=corp_ca docker compose up -d

# 5. Verify
curl https://pii-gateway.internal:8443/health
```

---

## 🔒 What PII Is Detected

| Type | Example | Masked As |
|------|---------|-----------|
| Email | john@company.com | [EMAIL] |
| Phone | +1 555-123-4567 | [PHONE] |
| SSN | 123-45-6789 | [SSN] |
| Credit Card | 4532015112830366 | [CREDIT_CARD] |
| AWS Key | AKIAIOSFODNN7EXAMPLE | [AWS_KEY] |
| API Key | api_key=sk-abc123... | [API_KEY] |
| Password | password=Secret123 | [PASSWORD] |
| JWT Token | eyJ0eXAiOi... | [JWT] |
| IP Address | 192.168.1.100 | [IP] |
| Person Name* | John Smith | [NAME] |
| Location* | New York | [LOCATION] |

*AI-powered via Microsoft Presidio (runs 100% locally — zero data to Microsoft)

---

## 📋 Department Policies

| Department | Scrub Names | Block on PII | Rate Limit |
|------------|------------|--------------|------------|
| HR | ✅ | ❌ | 30/min |
| Finance | ✅ | ❌ | 60/min |
| Engineering | ❌ | ❌ | 120/min |
| Legal | ✅ | ✅ BLOCK | 20/min |
| Marketing | ✅ | ❌ | 60/min |

Update policies live (no restart):
```bash
redis-cli SET "policy:ENGINEERING" '{"max_requests_per_minute": 200}'
```

---

## 🛣️ Roadmap

- [ ] Response scrubbing (LLM output path)
- [ ] Base64/URL-encoded PII detection
- [ ] Streaming response support (SSE)
- [ ] Image redaction (multimodal LLMs)
- [ ] SIEM integration (Splunk/Sentinel)
- [ ] 4-eyes policy approval workflow
- [ ] GPU-accelerated Presidio inference

---

## 📄 License

MIT — see [LICENSE](LICENSE)
