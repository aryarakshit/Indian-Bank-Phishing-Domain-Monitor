# Multi-stage Dockerfile for Indian Bank Phishing Domain Monitor
# Builder stage
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runner stage
FROM python:3.12-slim AS runner

LABEL maintainer="Arya Rakshit <aryarakshitgl@gmail.com>"
LABEL description="Real-time Certificate Transparency phishing monitor for Indian financial institutions"

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/home/phishmon/.local/bin:$PATH \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 -s /bin/bash phishmon

# Copy python packages from builder
COPY --from=builder /root/.local /home/phishmon/.local

# Copy application code
COPY src/ /app/src/
COPY pyproject.toml /app/
COPY .env.example /app/.env.example

# Create directories for persistent storage with proper ownership
RUN mkdir -p /app/reports /app/data \
    && chown -R phishmon:phishmon /app /home/phishmon

USER phishmon

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/stats || exit 1

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--stream"]
