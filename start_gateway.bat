@echo off
echo Starting PII Gateway...
set REDIS_URL=redis://:redis_secret@localhost:6379
set DATABASE_URL=postgresql://pii_user:pii_pass@localhost:5432/pii_audit
set PII_GATEWAY_HOST=0.0.0.0
set PII_GATEWAY_PORT=8080
cd C:\Users\psd16\pii-gateway-repo\pii-gateway-repo\src
python gateway.py