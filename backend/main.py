"""
DFIR Ingest API
================
Receives artifact batches from the collector agent (or from sample_data/
files via push_samples.py) and stores them in SQLite for the detection
engine (Person B's side) to query.

Run:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Endpoints:
    GET  /health              — liveness check
    POST /ingest               — accepts a JSON array of artifacts (one collector output file)
    GET  /artifacts            — query stored artifacts, filterable by host/artifact_type
    GET  /hosts                 — list all hosts that have reported in
"""
import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

import models
import schemas
from database import Base, engine, get_db
from detection_routes import router as detection_router
from scheduler import start_scheduler, stop_scheduler, get_status
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

# Creates dfir.db and all tables on first run if they don't exist yet.
# Safe to call every startup — it's a no-op if tables already exist.
models.Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="DFIR Ingest & Detection API", version="0.3.0", lifespan=lifespan)
app.include_router(detection_router)


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
def ingest_artifacts(artifacts: List[schemas.ArtifactIn], db: Session = Depends(get_db)):
    try:
        return ingest_service.ingest_artifacts(db, artifacts)
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
