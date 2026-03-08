FROM python:3.12-slim

LABEL maintainer="your-team@company.com"
LABEL description="Enterprise PII Gateway — scrubs PII from all LLM traffic"

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy model (AI-powered PII detection)
RUN python -m spacy download en_core_web_lg

# Copy source code
COPY src/ ./

# Log directory
RUN mkdir -p /var/log/pii-gateway

# Non-root user for security
RUN useradd -m -u 1000 gateway
RUN chown -R gateway:gateway /app /var/log/pii-gateway
USER gateway

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["python", "gateway.py"]
