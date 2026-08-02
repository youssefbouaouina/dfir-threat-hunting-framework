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
    GET  /health              — liveness check
    POST /ingest               — accepts a JSON array of artifacts (one collector output file)
    GET  /artifacts            — query stored artifacts, filterable by host/artifact_type
    GET  /hosts                — list all hosts that have reported in
    POST /endpoints/enroll     — agent self-registration (Phase 2)
    GET  /endpoints            — managed endpoint inventory (Phase 2)
"""
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

import schemas
from database import get_db
from detection_routes import router as detection_router
from endpoint_routes import router as endpoint_router
from scheduler import get_status, start_scheduler, stop_scheduler
from security import (
    TOKEN_TTL_SECONDS,
    authenticate_login,
    issue_token,
    rate_limit,
    require_admin,
    require_agent,
)
from services import ingest_service, query_service

logging.basicConfig(level=logging.INFO)

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


app = FastAPI(title="DFIR Ingest & Detection API", version="0.4.0", lifespan=lifespan)
app.include_router(detection_router)
app.include_router(endpoint_router)


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
def health():
    return {"status": "ok"}


@app.post(
    "/ingest",
    response_model=schemas.IngestResponse,
    dependencies=[Depends(rate_limit), Depends(require_agent)],
)
def ingest_artifacts(
    artifacts: List[schemas.ArtifactIn],
    batch_id: Optional[str] = Query(default=None, description="Idempotency key for agent uploads"),
    db: Session = Depends(get_db),
):
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
    )


@app.get("/hosts", dependencies=[Depends(require_admin)])
def list_hosts(db: Session = Depends(get_db)):
    return query_service.list_hosts(db)
