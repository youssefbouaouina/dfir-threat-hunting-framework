"""
Incident (correlation) API routes — thin HTTP layer over the correlation engine.

Phase 4 (F2): incidents group detections into campaigns (same rule, multiple
hosts) and attack chains (multiple techniques, one host). These endpoints let
analysts list/recompute/triage incidents; the engine itself runs automatically
after every detection run.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

import schemas
from database import get_db
from security import require_admin
from services import correlation_service

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", dependencies=[Depends(require_admin)])
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    before_id: int = Query(default=None, gt=0, description="cursor: only ids < before_id"),
    db: Session = Depends(get_db),
):
    return correlation_service.list_incidents(
        db, status=status, severity=severity, limit=limit, before_id=before_id
    )


@router.get("/summary", dependencies=[Depends(require_admin)])
def incidents_summary(db: Session = Depends(get_db)):
    """Counts grouped by status/severity for the dashboard."""
    return correlation_service.incidents_summary(db)


@router.get("/{incident_id}", dependencies=[Depends(require_admin)])
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    result = correlation_service.get_incident(db, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.post("/recompute", dependencies=[Depends(require_admin)])
def recompute_incidents(db: Session = Depends(get_db)):
    """Manually rebuilds the incident view from current detections (idempotent)."""
    return correlation_service.recompute_incidents(db, actor="manual")


@router.patch("/{incident_id}", dependencies=[Depends(require_admin)])
def triage_incident(
    incident_id: int,
    body: schemas.IncidentTriageIn,
    db: Session = Depends(get_db),
):
    """Analyst decision on an incident: acknowledge, resolve, false-positive."""
    try:
        result = correlation_service.triage_incident(db, incident_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result
