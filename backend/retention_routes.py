"""
Retention API routes — thin HTTP layer over the retention/archival engine.

Phase 4 (F3): operators can view the retention policy and eligibility counts
(GET /retention/status) and trigger an immediate sweep (POST /retention/run).
The sweep also runs on a schedule (see scheduler.py, retention_sweep job).
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from security import require_admin
from services import audit_service, retention_service

router = APIRouter(prefix="/retention", tags=["retention"])


@router.get("/status", dependencies=[Depends(require_admin)])
def retention_status(
    db: Session = Depends(get_db),
    artifact_days: Optional[int] = Query(default=None, ge=0),
    detection_days: Optional[int] = Query(default=None, ge=0),
    run_days: Optional[int] = Query(default=None, ge=0),
    audit_days: Optional[int] = Query(default=None, ge=0),
):
    """Current retention policy + rows currently eligible for archival."""
    overrides = {
        "artifacts": artifact_days,
        "detections": detection_days,
        "detection_runs": run_days,
        "audit_logs": audit_days,
    }
    days = {k: v for k, v in overrides.items() if v is not None} or None
    return retention_service.retention_status(db, days=days)


@router.post("/run", dependencies=[Depends(require_admin)])
def run_retention(
    db: Session = Depends(get_db),
    artifact_days: Optional[int] = Query(default=None, ge=0),
    detection_days: Optional[int] = Query(default=None, ge=0),
    run_days: Optional[int] = Query(default=None, ge=0),
    audit_days: Optional[int] = Query(default=None, ge=0),
):
    """Immediately archives + deletes rows older than the policy windows."""
    overrides = {
        "artifacts": artifact_days,
        "detections": detection_days,
        "detection_runs": run_days,
        "audit_logs": audit_days,
    }
    days = {k: v for k, v in overrides.items() if v is not None} or None
    result = retention_service.run_retention(db, days=days)
    audit_service.log_action(
        db,
        "run_retention",
        actor="admin",
        detail={"deleted": {k: v["deleted"] for k, v in result.items()}},
    )
    return result
