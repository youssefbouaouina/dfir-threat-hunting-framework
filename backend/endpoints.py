"""
Endpoint management API.

This is what "enrollment" means in this project's final design: rather
than an endpoint pushing a self-registration request to the backend
(the originally-planned model), the backend holds a small registry of
known endpoints and their SSH connection details, and reaches out to
them — for liveness checks, on-demand scans (this dashboard's per-
endpoint "Run Now"), and the hourly automated cycle.

This was a deliberate pivot from the earlier "self-enrolling agent"
plan once the actual requirement became clear: manual per-endpoint
triggering from the dashboard, and endpoint online/offline status,
both require the backend to be able to reach OUT to an endpoint, not
just receive pushes FROM one. A registry + SSH orchestration satisfies
both in one mechanism instead of building two separate systems.
"""
import os
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from database import get_db
from detection_routes import run_detection_job
from endpoint_orchestrator import check_liveness, run_remote_scan
from reports import generate_report

router = APIRouter()

BACKEND_PUSH_URL = os.getenv("BACKEND_PUSH_URL", "http://192.168.50.1:8000")


class EndpointCreate(BaseModel):
    name: str
    ip_address: str
    os: str
    ssh_port: int = 22
    ssh_username: str
    ssh_key_path: str
    remote_collector_path: str
    enabled: bool = True


def _endpoint_to_dict(e: models.Endpoint) -> dict:
    return {
        "id": e.id,
        "name": e.name,
        "ip_address": e.ip_address,
        "os": e.os,
        "ssh_port": e.ssh_port,
        "enabled": bool(e.enabled),
        "status": e.status,
        "last_error": e.last_error,
        "last_checked_at": str(e.last_checked_at) if e.last_checked_at else None,
        "last_scan_at": str(e.last_scan_at) if e.last_scan_at else None,
    }


@router.post("/endpoints")
def register_endpoint(payload: EndpointCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Endpoint).filter(models.Endpoint.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Endpoint '{payload.name}' already registered")

    row = models.Endpoint(
        name=payload.name,
        ip_address=payload.ip_address,
        os=payload.os,
        ssh_port=payload.ssh_port,
        ssh_username=payload.ssh_username,
        ssh_key_path=payload.ssh_key_path,
        remote_collector_path=payload.remote_collector_path,
        enabled=1 if payload.enabled else 0,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _endpoint_to_dict(row)


@router.get("/endpoints")
def list_endpoints(db: Session = Depends(get_db)):
    rows = db.query(models.Endpoint).order_by(models.Endpoint.id).all()
    return [_endpoint_to_dict(e) for e in rows]


@router.delete("/endpoints/{endpoint_id}")
def delete_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    db.delete(row)
    db.commit()
    return {"deleted": endpoint_id}


@router.post("/endpoints/{endpoint_id}/check")
def check_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    """On-demand liveness check — also called automatically by the fast liveness cycle."""
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    online, latency_ms = check_liveness(row.ip_address, row.ssh_port)
    row.status = "online" if online else "offline"
    if not online:
        row.last_error = f"SSH port {row.ssh_port} unreachable"
    row.last_checked_at = datetime.now(UTC)
    db.commit()

    return {"id": row.id, "status": row.status, "latency_ms": latency_ms}


@router.post("/endpoints/{endpoint_id}/run-now")
def run_endpoint_now(endpoint_id: int, db: Session = Depends(get_db)):
    """
    The dashboard's per-endpoint 'Run Now': SSH in, run the collector
    (which pushes its own results back to /ingest), then run detection
    and generate a report scoped to this one endpoint.

    The report is scoped to detections created during THIS run (since
    `run_started_at`), not the endpoint's entire detection history —
    otherwise, once continuous automated detection has already
    processed everything, a click here would just re-report old
    detections from a previous session, which is confusing and not
    what "run an investigation now" means.
    """
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    run_started_at = datetime.now(UTC)

    scan_result = run_remote_scan(
        ip_address=row.ip_address,
        port=row.ssh_port,
        username=row.ssh_username,
        key_path=row.ssh_key_path,
        remote_collector_path=row.remote_collector_path,
        push_url=BACKEND_PUSH_URL,
        os_type=row.os,
    )

    if not scan_result["success"]:
        row.status = "offline"
        row.last_error = scan_result.get("error") or scan_result.get("stderr") or "Unknown failure — no error captured"
        row.last_checked_at = datetime.now(UTC)
        db.commit()
        return {"endpoint": row.name, "scan": scan_result, "detect_result": None, "report": None}

    row.status = "online"
    row.last_error = None
    row.last_checked_at = datetime.now(UTC)
    row.last_scan_at = datetime.now(UTC)
    db.commit()

    detect_result = run_detection_job(db)
    report_result = generate_report(db, host=row.name, triggered_by="manual", since=run_started_at)

    return {"endpoint": row.name, "scan": scan_result, "detect_result": detect_result, "report": report_result}
