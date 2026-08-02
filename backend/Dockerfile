# Multi-stage build: dependencies first, then a minimal runtime image.
# Build context: the repo root (so the Dockerfile can reference requirements).
#
#   docker build -f backend/Dockerfile -t dfir-backend:dev .

# ---- Stage 1: build wheels / collect deps ------------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

COPY backend/requirements.txt /requirements.txt
# psycopg2-binary ships prebuilt wheels; apscheduler/uvicorn need a C
# compiler only for source builds, so we install into a separate prefix.
RUN pip install --prefix=/install -r /requirements.txt

# ---- Stage 2: runtime ---------------------------------------------------
FROM python:3.12-slim AS runtime

# Non-root user for least privilege.
RUN groupadd --gid 1000 dfir && useradd --uid 1000 --gid dfir --create-home dfir

# System-level CA certs + tzdata for APScheduler; curl for the healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
    && rm -rf /var/lib/apt/lists/*

# Copy the isolated dependency tree from the builder stage.
COPY --from=builder /install /usr/local

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_URL=sqlite:///./dfir.db \
    AUTH_ENABLED=false

WORKDIR /app

# Copy application code (backend modules + migrations).
COPY backend/ /app/

RUN chown -R dfir:dfir /app && mkdir -p /app/iocs && chown -R dfir:dfir /app/iocs

USER dfir

# Healthcheck hits the liveness endpoint (no auth dependency).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Entrypoint applies pending Alembic migrations, then starts the API.
COPY backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
