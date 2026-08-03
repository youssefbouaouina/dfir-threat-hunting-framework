"""
DFIR Ingest & Detection API
============================
Receives artifact batches from the collector agent (or from sample_data/
files via push_samples.py), stores them (SQLite by default, Postgres via
DATABASE_URL), and runs the detection pipeline on unprocessed artifacts.

Run:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Database schema is migration-managed (Alembic). `migrate_to_head()` applies
pending migrations at startup; `python -m alembic upgrade head` does the same
explicitly.

Endpoints:
    GET  /health              — liveness check (+ live counts for the dashboard)
    GET  /metrics             — Prometheus-style operational gauges (Phase 3)
    GET  /audit-logs          — analyst/admin action trail (Phase 3)
    POST /ingest               — accepts a JSON array of artifacts (one collector output file)
    GET  /artifacts            — query stored artifacts, filterable by host/artifact_type
    GET  /hosts                — list all hosts that have reported in
    POST /endpoints/enroll     — agent self-registration (Phase 2)
    GET  /endpoints            — managed endpoint inventory (Phase 2)
    GET  /dashboard            — analyst dashboard (Phase 3, served static)
"""
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

import ingest_queue
import schemas
from database import get_db
from detection_routes import router as detection_router
from endpoint_routes import router as endpoint_router
from logging_config import configure_logging
from scheduler import get_status, start_scheduler, stop_scheduler
from security import (
    TOKEN_TTL_SECONDS,
    authenticate_login,
    issue_token,
    rate_limit,
    require_admin,
    require_agent,
)
from services import audit_service, ingest_service, metrics_service, query_service

configure_logging()

logger = logging.getLogger(__name__)

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


def migrate_to_head() -> None:
    """Applies pending Alembic migrations so the schema matches the models.

    This is the migration-managed replacement for `Base.metadata.create_all`.
    It runs from anywhere by pointing Alembic at this backend's migration
    directory; DATABASE_URL (or the ini default) selects the target database.
    """
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config(os.path.join(_BACKEND_DIR, "alembic.ini"))
    alembic_cfg.set_main_option("script_location", os.path.join(_BACKEND_DIR, "migrations"))
    if os.getenv("DATABASE_URL"):
        alembic_cfg.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
    command.upgrade(alembic_cfg, "head")


migrate_to_head()


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="DFIR Ingest & Detection API", version="0.5.0", lifespan=lifespan)
app.include_router(detection_router)
app.include_router(endpoint_router)

# Baseline DoS resistance: cap the /ingest request body (H4). Applies even when
# auth is off so an open-lab instance cannot be flooded with oversized payloads.
_MAX_INGEST_BYTES = int(os.getenv("MAX_INGEST_BYTES", str(10 * 1024 * 1024)))
_INGEST_PATHS = {"/ingest"}


@app.middleware("http")
async def enforce_ingest_size(request: Request, call_next):
    """Rejects /ingest bodies larger than MAX_INGEST_BYTES with a 413.

    Uses the Content-Length header when present (no body read for oversized
    uploads); otherwise reads the body to measure it (Starlette caches the read
    so downstream handlers still see the body).
    """
    if request.method == "POST" and request.url.path in _INGEST_PATHS:
        length = request.headers.get("content-length")
        if length is not None:
            try:
                if int(length) > _MAX_INGEST_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds {_MAX_INGEST_BYTES} bytes"},
                    )
            except ValueError:
                pass
        else:
            body = await request.body()
            if len(body) > _MAX_INGEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body exceeds {_MAX_INGEST_BYTES} bytes"},
                )
    return await call_next(request)

# Phase 3: analyst dashboard — a lightweight server-rendered static app.
_STATIC_DIR = os.path.join(_BACKEND_DIR, "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/dashboard", StaticFiles(directory=_STATIC_DIR, html=True), name="dashboard")


@app.get("/scheduler/status", dependencies=[Depends(require_admin)])
def scheduler_status():
    return get_status()


@app.post("/auth/login", response_model=schemas.LoginResponse)
def login(body: schemas.LoginRequest):
    """Exchanges the admin API key for a short-lived bearer token (analyst access)."""
    if not authenticate_login(body.api_key):
        raise HTTPException(status_code=401, detail="Invalid admin API key")
    token = issue_token("admin")
    return schemas.LoginResponse(token=token, expires_in=TOKEN_TTL_SECONDS)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    """Liveness + a small payload of live counts for the dashboard header."""
    try:
        payload = metrics_service.health_payload(db)
    except Exception:  # noqa: BLE001 — health must stay cheap and never fail
        payload = {"status": "ok"}
    return payload


@app.get("/metrics", dependencies=[Depends(require_admin)])
def metrics(db: Session = Depends(get_db)):
    """Prometheus-style operational gauges (artifacts, detections, endpoints, runs)."""
    return metrics_service.metrics_text(db)


@app.get("/audit-logs", dependencies=[Depends(require_admin)])
def list_audit_logs(
    action: Optional[str] = Query(default=None),
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
):
    """Analyst/admin action trail (who did what, when)."""
    return audit_service.list_audit_logs(db, limit=limit, action=action)


@app.post(
    "/ingest",
    response_model=schemas.IngestResponse,
    dependencies=[Depends(rate_limit), Depends(require_agent)],
)
def ingest_artifacts(
    artifacts: List[schemas.ArtifactIn],
    response: Response,
    batch_id: Optional[str] = Query(default=None, description="Idempotency key for agent uploads"),
    db: Session = Depends(get_db),
):
    """Accepts a batch of artifacts. Synchronous by default; when the async
    ingest queue is enabled (INGEST_QUEUE_URL set) the batch is queued and
    this returns 202 Accepted instead of persisting inline."""
    if ingest_queue.queue_enabled():
        if ingest_queue.enqueue_artifacts(
            [a.model_dump(mode="json") for a in artifacts], batch_id=batch_id
        ):
            response.status_code = 202
            return schemas.IngestResponse(
                ingested=0,
                host=artifacts[0].host if artifacts else "",
                artifact_types=[a.artifact_type for a in artifacts],
                deduplicated=0,
                batch_id=batch_id,
                accepted=True,
                queued=len(artifacts),
            )
    try:
        return ingest_service.ingest_artifacts(db, artifacts, batch_id=batch_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get(
    "/artifacts",
    response_model=List[schemas.ArtifactOut],
    dependencies=[Depends(require_admin)],
)
def list_artifacts(
    host: Optional[str] = None,
    artifact_type: Optional[str] = None,
    collected_since: Optional[str] = None,
    collected_until: Optional[str] = None,
    processed: Optional[int] = Query(default=None, ge=0, le=1),
    limit: int = Query(default=50, le=500),
    before_id: Optional[int] = Query(
        default=None, gt=0, description="cursor: only ids < before_id"
    ),
    db: Session = Depends(get_db),
):
    return query_service.list_artifacts(
        db,
        host=host,
        artifact_type=artifact_type,
        collected_since=collected_since,
        collected_until=collected_until,
        processed=processed,
        limit=limit,
        before_id=before_id,
    )


@app.get("/hosts", dependencies=[Depends(require_admin)])
def list_hosts(db: Session = Depends(get_db)):
    return query_service.list_hosts(db)
