#!/usr/bin/env sh
# Runs the DFIR backend inside its container: applies pending Alembic
# migrations, then executes the CMD (uvicorn). Fail-fast if migrations fail.
set -e

echo "[entrypoint] Applying database migrations..."
alembic upgrade head

echo "[entrypoint] Starting DFIR Ingest & Detection API..."
exec "$@"
