"""
Detection API routes — thin HTTP layer over services.detection_service.

All pipeline logic lives in run_detection_job() inside the service so the
scheduler and this route share one implementation. Reads delegate to the
same service module. Auth (admin/analyst) is enforced when AUTH_ENABLED=true.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from security import require_admin
from services import detection_service

router = APIRouter()


@router.post("/detect", dependencies=[Depends(require_admin)])
def run_detection(
    host: str = None,
    rescan: bool = False,
    db: Session = Depends(get_db),
):
    """Manual trigger — same pipeline the scheduler runs automatically."""
    return detection_service.run_detection_job(db, host=host, rescan=rescan, trigger="manual")


@router.get("/detection-runs", dependencies=[Depends(require_admin)])
def list_detection_runs(status: str = None, limit: int = 50, db: Session = Depends(get_db)):
    """Detection run history — when cycles ran, what triggered them, and the outcome."""
    return detection_service.list_detection_runs(db, status=status, limit=limit)


@router.get("/detections", dependencies=[Depends(require_admin)])
def list_detections(host: str = None, severity: str = None, limit: int = 100, db: Session = Depends(get_db)):
    return detection_service.list_detections(db, host=host, severity=severity, limit=limit)


@router.get("/detections/summary", dependencies=[Depends(require_admin)])
def detections_summary(db: Session = Depends(get_db)):
    """Feeds the dashboard's ATT&CK-coverage view."""
    return detection_service.detections_summary(db)
