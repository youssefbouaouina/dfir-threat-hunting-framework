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
import json
import logging
from collections import Counter
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

import models
import schemas
from dashboard import router as dashboard_router
from database import engine, get_db
from detection_routes import router as detection_router
from endpoints import router as endpoints_router
from reports import router as reports_router
from scheduler import get_status, start_scheduler, stop_scheduler

logging.basicConfig(level=logging.INFO)

# Creates dfir.db and all tables on first run if they don't exist yet.
# Safe to call every startup — it's a no-op if tables already exist.
models.Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield
    stop_scheduler()


app = FastAPI(title="DFIR Ingest, Detection & Reporting", version="0.5.0", lifespan=lifespan)
app.include_router(detection_router)
app.include_router(reports_router)
app.include_router(endpoints_router)
app.include_router(dashboard_router)


@app.get("/scheduler/status")
def scheduler_status():
    return get_status()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ingest", response_model=schemas.IngestResponse)
def ingest_artifacts(artifacts: list[schemas.ArtifactIn], db: Session = Depends(get_db)):
    if not artifacts:
        raise HTTPException(status_code=400, detail="Empty artifact list")

    hostname = artifacts[0].host
    os_name = artifacts[0].os

    host_row = db.query(models.Host).filter(models.Host.hostname == hostname).first()
    if host_row is None:
        host_row = models.Host(hostname=hostname, os=os_name)
        db.add(host_row)
    else:
        host_row.os = os_name  # keep it current in case the OS field ever changes

    type_counter = Counter()
    for artifact in artifacts:
        db_artifact = models.Artifact(
            host=artifact.host,
            os=artifact.os,
            artifact_type=artifact.artifact_type,
            collected_at=artifact.collected_at,
            data=json.dumps(artifact.data),
        )
        db.add(db_artifact)
        type_counter[artifact.artifact_type] += 1

    db.commit()

    return schemas.IngestResponse(
        ingested=len(artifacts),
        host=hostname,
        artifact_types=list(type_counter.keys()),
    )


@app.get("/artifacts", response_model=list[schemas.ArtifactOut])
def list_artifacts(
    host: str | None = None,
    artifact_type: str | None = None,
    limit: int = Query(default=50, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(models.Artifact)
    if host:
        query = query.filter(models.Artifact.host == host)
    if artifact_type:
        query = query.filter(models.Artifact.artifact_type == artifact_type)
    rows = query.order_by(models.Artifact.id.desc()).limit(limit).all()

    return [
        schemas.ArtifactOut(
            id=row.id,
            host=row.host,
            os=row.os,
            artifact_type=row.artifact_type,
            collected_at=row.collected_at,
            data=json.loads(row.data),
            ingested_at=row.ingested_at,
            processed=row.processed,
        )
        for row in rows
    ]


@app.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    hosts = db.query(models.Host).all()
    return [
        {"id": h.id, "hostname": h.hostname, "os": h.os, "last_seen": h.last_seen}
        for h in hosts
    ]
