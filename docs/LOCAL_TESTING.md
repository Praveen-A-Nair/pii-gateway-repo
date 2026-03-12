# 🧪 Local Setup & Testing Guide (Podman)

Complete guide to run and test the Enterprise PII Gateway on your local machine using Podman.

---

## ⚡ Quickest Start (3 commands)

```bash
# 1. Install everything
python scripts/local_setup.py install

# 2. Start local stack
python scripts/local_setup.py start

# 3. Run all tests
python scripts/local_setup.py test
```

---

## 📋 Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.10+ | python.org |
| Podman | 4.0+ | podman.io/getting-started/installation |
| podman-compose | Latest | `pip install podman-compose` |
| Git | Any | git-scm.com |

### Install Podman

**Windows:**
```powershell
winget install RedHat.Podman
winget install RedHat.Podman-Desktop
```

**macOS:**
```bash
brew install podman
podman machine init
podman machine start
```

**Linux (RHEL/Fedora/CentOS):**
```bash
sudo dnf install podman podman-compose
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install podman
pip install podman-compose
```

---

## 🔧 Manual Step-by-Step

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
pip install podman-compose

# Download AI model (560MB, one time only)
python -m spacy download en_core_web_lg
```

### Step 2 — Generate local certs

```bash
python scripts/cert_manager.py generate
```

### Step 3 — Create .env

```bash
cp .env.example .env
# .env is pre-configured for local dev — no changes needed
```

### Step 4 — Start Redis + PostgreSQL

```bash
podman-compose -f docker-compose.local.yml up -d

# Verify
podman ps
podman exec pii-redis redis-cli -a redis_secret ping   # → PONG
```

### Step 5 — Start the Gateway

```bash
cd src && python gateway.py
# Gateway starts at http://localhost:8080
```

---

## 🧪 Test Methods

### Method 1 — Automated runner
```bash
python scripts/local_setup.py test
```

### Method 2 — pytest
```bash
# Unit tests (no gateway needed)
pytest tests/test_pii_engine.py -v

# Integration tests (gateway must be running)
pytest tests/test_gateway.py -v -m integration

# All with coverage
pytest tests/ --cov=src --cov-report=html
```

### Method 3 — Manual curl
```bash
# Health check
curl http://localhost:8080/health

# Scrub email
curl -X POST http://localhost:8080/scrub \
  -H "X-User-ID: testuser" \
  -H "X-Department: ENGINEERING" \
  -d "Contact john@company.com for support"

# Scrub full LLM JSON body
curl -X POST http://localhost:8080/scrub \
  -H "Content-Type: application/json" \
  -H "X-User-ID: testuser" \
  -H "X-Department: ENGINEERING" \
  -d '{
    "model": "claude-sonnet-4-6",
    "messages": [{"role":"user","content":"My SSN is 123-45-6789. Help me."}]
  }'

# Multiple PII types
curl -X POST http://localhost:8080/scrub \
  -H "X-Department: HR" \
  -d "Card: 4532015112830366, Phone: +1 555-123-4567, Key: AKIAIOSFODNN7EXAMPLE"

# Metrics
curl http://localhost:8080/metrics
```

---

## 🔍 Inspect Running Containers

```bash
# List containers
podman ps

# Gateway logs
podman logs pii-gateway-1 -f

# Redis — check rate limit counters
podman exec pii-redis redis-cli -a redis_secret KEYS "rate:*"

# Redis — check policy cache
podman exec pii-redis redis-cli -a redis_secret KEYS "policy:*"

# PostgreSQL — audit records
podman exec pii-postgres psql -U pii_user -d pii_audit \
  -c "SELECT timestamp, user_id, department, pii_types FROM pii_audit ORDER BY timestamp DESC LIMIT 10;"
```

---

## 🚀 Full Production Stack (Podman)

```bash
# Build image
podman build -t pii-gateway:latest .

# Start full HA stack
TLS_MODE=corp_ca podman-compose up -d

# Check all containers
podman-compose ps

# Stop
podman-compose down
```

## 🔄 Podman vs Docker — Key Differences in This Project

| Feature | Docker | Podman (this project) |
|---------|--------|-----------------------|
| Daemon | Requires daemon | Daemonless ✅ |
| Root | Runs as root by default | Rootless by default ✅ |
| Compose file | `docker-compose.yml` | Same file, `podman-compose` |
| Image refs | Short names ok | Full registry path (`docker.io/redis:7`) |
| SELinux volumes | No `:z` needed | `:z` or `:Z` for SELinux hosts |
| systemd | Manual | Native `podman generate systemd` |
| Build file | `Dockerfile` | `Containerfile` (also reads Dockerfile) |

---

## 📌 Run Gateway as systemd Service (Linux)

```bash
# Generate systemd unit files from running containers
podman generate systemd --new --name pii-gateway-1 \
  > ~/.config/systemd/user/pii-gateway-1.service

# Enable and start
systemctl --user enable pii-gateway-1
systemctl --user start pii-gateway-1

# Check status
systemctl --user status pii-gateway-1
```

---

## 🛑 Stop Everything

```bash
python scripts/local_setup.py stop
# OR
podman-compose -f docker-compose.local.yml down
pkill -f gateway.py
```

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| `podman: command not found` | Install Podman: podman.io/getting-started/installation |
| `podman-compose: command not found` | `pip install podman-compose` |
| `image not found` | Images use full path: `docker.io/redis:7-alpine` |
| `permission denied on volume` | Add `:z` to volume mount in compose file |
| `port already in use` | `podman ps` → stop conflicting container |
| `Gateway not starting` | Check `gateway.log` — Redis might not be ready |
| `Presidio not found` | `pip install presidio-analyzer presidio-anonymizer` |
| `spaCy model missing` | `python -m spacy download en_core_web_lg` |
| `macOS: connection refused` | `podman machine start` (VM needed on macOS) |
