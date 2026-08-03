"""
Detection API routes — thin HTTP layer over services.detection_service.

All pipeline logic lives in run_detection_job() inside the service so the
scheduler and this route share one implementation. Reads delegate to the
same service module. Auth (admin/analyst) is enforced when AUTH_ENABLED=true.
Phase 3 adds the triage lifecycle endpoints (PATCH /detections/{id}).
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

import schemas
from database import get_db
from security import current_user, require_admin, require_role
from services import detection_service

router = APIRouter()


@router.post("/detect", dependencies=[Depends(require_admin)])
def run_detection(
    host: Optional[str] = None,
    rescan: bool = False,
    db: Session = Depends(get_db),
):
    """Manual trigger — same pipeline the scheduler runs automatically."""
    return detection_service.run_detection_job(db, host=host, rescan=rescan, trigger="manual")


@router.get("/detection-runs", dependencies=[Depends(require_admin)])
def list_detection_runs(
    status: Optional[str] = None,
    limit: int = 50,
    before_id: int = Query(default=None, gt=0, description="cursor: only ids < before_id"),
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Detection run history — when cycles ran, what triggered them, and the outcome."""
    return detection_service.list_detection_runs(
        db,
        status=status,
        limit=limit,
        before_id=before_id,
        hosts=_scope_hosts(db, user),
    )


def _scope_hosts(db, user: Optional[dict]) -> Optional[list]:
    """F4: resolves a user's team scope to an allowed hostname list (None = all)."""
    from services import query_service

    return query_service.scoped_hosts(db, user.get("team")) if user else None


@router.get("/detections", dependencies=[Depends(require_admin)])
def list_detections(
    host: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    before_id: int = Query(default=None, gt=0, description="cursor: only ids < before_id"),
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    return detection_service.list_detections(
        db,
        host=host,
        severity=severity,
        limit=limit,
        before_id=before_id,
        hosts=_scope_hosts(db, user),
    )


@router.get("/detections/summary", dependencies=[Depends(require_admin)])
def detections_summary(
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Feeds the dashboard's ATT&CK-coverage view (team-scoped for F4)."""
    return detection_service.detections_summary(db, hosts=_scope_hosts(db, user))


_can_triage = Depends(require_role("admin", "analyst"))


@router.patch("/detections/{detection_id}", dependencies=[_can_triage])
def update_triage(
    detection_id: int,
    body: schemas.DetectionTriageIn,
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Analyst triage: acknowledge, mark false/true positive, review (Phase 3)."""
    try:
        result = detection_service.triage_detection(
            db,
            detection_id,
            body.status,
            body.notes,
            actor=user.get("subject") if user else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return result
