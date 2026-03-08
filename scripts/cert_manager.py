#!/usr/bin/env python3
"""
Certificate Manager for Enterprise PII Gateway
Handles all 4 TLS modes:
  1. Corp CA generation + GPO deployment
  2. DNS interception certs (per LLM domain)
  3. mTLS certs for sidecar agents
  4. CA bundle for outbound verification

Run: python cert_manager.py [generate|deploy|status]
"""

import os
import sys
import subprocess
import textwrap
from pathlib import Path

CERTS_DIR     = Path("./certs")
CORP_CA_NAME  = "PII-Gateway-Corp-CA"
GATEWAY_FQDN  = "pii-gateway.internal"

# LLM domains needing certs for DNS interception mode
LLM_DOMAINS = [
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.githubcopilot.com",
    "api.cohere.ai",
]


def run(cmd: str, check=True):
    print(f"  → {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"  ❌ Error: {result.stderr}")
        sys.exit(1)
    return result


def generate_all():
    """Generate all certificates needed for the gateway"""
    CERTS_DIR.mkdir(exist_ok=True)
    print("\n" + "="*60)
    print("  🔐 GENERATING ENTERPRISE PII GATEWAY CERTIFICATES")
    print("="*60)

    # ── Step 1: Corporate Root CA ──────────────────────────────
    print("\n📌 Step 1: Creating Corporate Root CA...")
    run(f"""openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
        -keyout {CERTS_DIR}/corp-ca.key \
        -out    {CERTS_DIR}/corp-ca.crt \
        -subj "/C=US/O=YourCompany/CN={CORP_CA_NAME}" \
        -extensions v3_ca""")
    print(f"  ✅ Corp CA: {CERTS_DIR}/corp-ca.crt")

    # ── Step 2: Gateway Certificate (signed by Corp CA) ────────
    print("\n📌 Step 2: Creating Gateway Certificate...")
    san = f"DNS:{GATEWAY_FQDN},DNS:localhost,IP:127.0.0.1"
    run(f"""openssl req -newkey rsa:2048 -nodes \
        -keyout {CERTS_DIR}/gateway.key \
        -out    {CERTS_DIR}/gateway.csr \
        -subj "/C=US/O=YourCompany/CN={GATEWAY_FQDN}" """)
    run(f"""openssl x509 -req -days 825 \
        -in      {CERTS_DIR}/gateway.csr \
        -CA      {CERTS_DIR}/corp-ca.crt \
        -CAkey   {CERTS_DIR}/corp-ca.key \
        -CAcreateserial \
        -out     {CERTS_DIR}/gateway.crt \
        -extfile <(echo "subjectAltName={san}") """)
    print(f"  ✅ Gateway cert: {CERTS_DIR}/gateway.crt")

    # ── Step 3: Per-Domain Certs (DNS Interception Mode) ───────
    print("\n📌 Step 3: Creating per-domain certs (DNS interception mode)...")
    for domain in LLM_DOMAINS:
        safe = domain.replace(".", "_")
        run(f"""openssl req -newkey rsa:2048 -nodes \
            -keyout {CERTS_DIR}/{safe}.key \
            -out    {CERTS_DIR}/{safe}.csr \
            -subj "/C=US/O=YourCompany/CN={domain}" """)
        run(f"""openssl x509 -req -days 825 \
            -in      {CERTS_DIR}/{safe}.csr \
            -CA      {CERTS_DIR}/corp-ca.crt \
            -CAkey   {CERTS_DIR}/corp-ca.key \
            -CAcreateserial \
            -out     {CERTS_DIR}/{safe}.crt \
            -extfile <(echo "subjectAltName=DNS:{domain}") """)
        print(f"  ✅ {domain}: {CERTS_DIR}/{safe}.crt")

    # ── Step 4: Sidecar mTLS Certs ─────────────────────────────
    print("\n📌 Step 4: Creating Sidecar mTLS CA...")
    run(f"""openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
        -keyout {CERTS_DIR}/sidecar-ca.key \
        -out    {CERTS_DIR}/sidecar-ca.crt \
        -subj "/C=US/O=YourCompany/CN=PII-Sidecar-CA" """)

    # ── Step 5: Corp CA Bundle (corp CA + public CAs) ───────────
    print("\n📌 Step 5: Creating CA bundle...")
    run(f"""cat {CERTS_DIR}/corp-ca.crt \
        /etc/ssl/certs/ca-certificates.crt \
        > {CERTS_DIR}/corp_ca_bundle.crt""", check=False)
    # Windows fallback
    if not Path(f"{CERTS_DIR}/corp_ca_bundle.crt").exists():
        import shutil
        shutil.copy(f"{CERTS_DIR}/corp-ca.crt", f"{CERTS_DIR}/corp_ca_bundle.crt")

    print(f"\n✅ All certificates generated in {CERTS_DIR}/")
    print("\n📋 Next Steps:")
    print(f"  1. Deploy corp-ca.crt via GPO to all machines")
    print(f"  2. Set NODE_EXTRA_CA_CERTS=C:\\certs\\corp-ca.crt via GPO")
    print(f"  3. Run: python cert_manager.py deploy (Windows GPO commands)")


def deploy_gpo_commands():
    """Print Windows GPO deployment commands"""
    print("\n" + "="*60)
    print("  📋 GPO DEPLOYMENT COMMANDS (Run as Domain Admin)")
    print("="*60)

    print("""
┌─────────────────────────────────────────────────────────┐
│  STEP 1: Deploy Corp CA to All Windows Machines via GPO │
└─────────────────────────────────────────────────────────┘
PowerShell (run on Domain Controller):

  # Import Corp CA into GPO
  Import-Certificate \\
    -FilePath ".\\certs\\corp-ca.crt" \\
    -CertStoreLocation "Cert:\\LocalMachine\\Root"

  # OR via Group Policy Management Console:
  # GPO → Computer Config → Windows Settings
  #     → Security Settings → Public Key Policies
  #     → Trusted Root Certification Authorities
  #     → Import corp-ca.crt

┌─────────────────────────────────────────────────────────┐
│  STEP 2: Set Environment Variables via GPO              │
└─────────────────────────────────────────────────────────┘
  # GPO → Computer Config → Preferences
  #     → Windows Settings → Environment

  NODE_EXTRA_CA_CERTS = C:\\certs\\corp-ca.crt
  HTTPS_PROXY         = https://pii-gateway.internal:8443
  HTTP_PROXY          = https://pii-gateway.internal:8443

  # This fixes GitHub Copilot (Node.js based)!

┌─────────────────────────────────────────────────────────┐
│  STEP 3: VS Code Settings via GPO                       │
└─────────────────────────────────────────────────────────┘
  Deploy this to: %APPDATA%\\Code\\User\\settings.json

  {
    "http.proxy": "https://pii-gateway.internal:8443",
    "http.proxyStrictSSL": true,
    "http.systemCertificates": true
  }

┌─────────────────────────────────────────────────────────┐
│  STEP 4: DNS Override (for DNS Interception Mode)       │
└─────────────────────────────────────────────────────────┘
  # On Windows DNS Server (or internal DNS):
  Add-DnsServerResourceRecordA \\
    -Name "api.anthropic"  -ZoneName "com" \\
    -IPv4Address "10.0.1.50"   # Your gateway IP

  Add-DnsServerResourceRecordA \\
    -Name "api.openai" -ZoneName "com" \\
    -IPv4Address "10.0.1.50"

┌─────────────────────────────────────────────────────────┐
│  STEP 5: Deploy Sidecar Agent via GPO (Optional)        │
└─────────────────────────────────────────────────────────┘
  # Deploy sidecar_agent.py via GPO startup script
  # GPO → Computer Config → Windows Settings
  #     → Scripts → Startup → Add sidecar_agent.bat

  # sidecar_agent.bat:
  @echo off
  cd C:\\PIISidecar
  python sidecar_agent.py
""")


def show_status():
    print("\n" + "="*60)
    print("  🔍 CERTIFICATE STATUS")
    print("="*60)
    certs = list(CERTS_DIR.glob("*.crt")) if CERTS_DIR.exists() else []
    if not certs:
        print("  ❌ No certificates found. Run: python cert_manager.py generate")
    for cert in certs:
        result = run(f"openssl x509 -in {cert} -noout -subject -enddate", check=False)
        print(f"\n  📄 {cert.name}")
        print(f"     {result.stdout.strip()}")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "status"

    if action == "generate":
        generate_all()
    elif action == "deploy":
        deploy_gpo_commands()
    elif action == "status":
        show_status()
    else:
        print(f"Usage: python cert_manager.py [generate|deploy|status]")
