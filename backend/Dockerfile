# DFIR Backend — Ingest, Detection, Dashboard, Reporting
# Only the backend is containerized. The collector agent runs natively
# on real endpoints (Windows/Linux) — a container only sees its own
# namespace, so a containerized collector would report the container's
# processes, not the actual host's. See project docs for details.

FROM python:3.12-slim

# libyara + libmagic-ish build deps for yara-python; libpango/cairo not
# needed since reports use reportlab (pure Python), not weasyprint.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first so Docker's layer cache skips this step on code-only
# changes — meaningfully speeds up rebuilds during development.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# SQLite DB + generated PDF reports both live here — mounted as a
# volume in docker-compose.yml so data survives container restarts.
RUN mkdir -p /app/data /app/reports

ENV DFIR_DB_PATH=/app/data/dfir.db
ENV DFIR_REPORTS_DIR=/app/reports

EXPOSE 8000

# No --reload in the container image: reload's watcher process can
# double-initialize the background scheduler (see scheduler.py notes).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
