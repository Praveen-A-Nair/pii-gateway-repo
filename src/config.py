"""Config — loads from environment variables"""
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    REDIS_URL:       str = "redis://redis:6379/0"
    DATABASE_URL:    str = "postgresql://pii_user:pii_pass@postgres:5432/pii_audit"
    LOG_LEVEL:       str = "INFO"

    # TLS Mode: corp_ca | dns | sidecar | scrub_api
    TLS_MODE:        str = "corp_ca"

    # Path to CA bundle (corp CA + public CAs combined)
    # Generate with: cat corp-ca.crt /etc/ssl/certs/ca-certificates.crt > corp_ca_bundle.crt
    CORP_CA_BUNDLE:  str = "/certs/corp_ca_bundle.crt"

    # mTLS for sidecar agents
    MTLS_CERT:       str = "/certs/gateway.crt"
    MTLS_KEY:        str = "/certs/gateway.key"
    MTLS_CLIENT_CA:  str = "/certs/sidecar-ca.crt"

    class Config:
        env_file = ".env"
