# Windows Sidecar Agent

Runs locally on each Windows machine. Eliminates all TLS certificate issues
by intercepting at the application layer — not the TLS layer.

## How It Works

```
App / Copilot / VS Code
        ↓ HTTP to localhost:7777
Sidecar Agent (this)
        ↓ POST /scrub to central gateway (mTLS)
PII Gateway → returns scrubbed body
        ↓ forwards to real LLM with native certs
Real LLM API (Anthropic / OpenAI / Copilot)
```

## Install

```bash
# Copy to machine
xcopy /E sidecar_agent.py C:\PIISidecar\

# Install dependencies
pip install fastapi uvicorn httpx

# Set corp cert path
set GATEWAY_CA_CERT=C:\certs\corp-pii-ca.crt
set PII_GATEWAY_URL=https://pii-gateway.internal:8443/scrub

# Run
python C:\PIISidecar\sidecar_agent.py
```

## Deploy via GPO (Enterprise)

```
Group Policy → Computer Config → Windows Settings
→ Scripts → Startup → Add:
  python C:\PIISidecar\sidecar_agent.py

Environment variables (set via GPO):
  HTTPS_PROXY     = http://localhost:7777
  PII_GATEWAY_URL = https://pii-gateway.internal:8443/scrub
  GATEWAY_CA_CERT = C:\certs\corp-pii-ca.crt
```

## Department Registry Key (set via GPO)

```
HKLM\SOFTWARE\Company\PIIProxy\Department = "ENGINEERING"
```
