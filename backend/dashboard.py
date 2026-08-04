"""
Dashboard route — server-rendered HTML (Jinja2), queries the DB
directly rather than calling our own API over HTTP (simpler, faster,
no self-referential network calls).
"""
import os

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

import models
from database import get_db
from scheduler import get_status

router = APIRouter()

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    hosts = db.query(models.Host).all()
    total_artifacts = db.query(models.Artifact).count()
    total_detections = db.query(models.Detection).count()

    severity_rows = (
        db.query(models.Detection.severity, func.count(models.Detection.id))
        .group_by(models.Detection.severity)
        .all()
    )
    raw_severity_counts = {(s or "unknown"): c for s, c in severity_rows}
    # Fixed, meaningful order — always show all five categories (even at
    # zero) so the signal bar doesn't reflow/reorder as data changes.
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
    severity_counts = [(sev, raw_severity_counts.get(sev, 0)) for sev in SEVERITY_ORDER]

    technique_rows = (
        db.query(
            models.Detection.technique_id,
            models.Detection.technique_name,
            models.Detection.tactic,
            func.count(models.Detection.id),
        )
        .group_by(models.Detection.technique_id, models.Detection.technique_name, models.Detection.tactic)
        .order_by(func.count(models.Detection.id).desc())
        .all()
    )

    recent_detections = db.query(models.Detection).order_by(models.Detection.id.desc()).limit(15).all()
    reports = db.query(models.Report).order_by(models.Report.id.desc()).limit(10).all()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "hosts": hosts,
            "total_artifacts": total_artifacts,
            "total_detections": total_detections,
            "severity_counts": severity_counts,
            "technique_rows": technique_rows,
            "recent_detections": recent_detections,
            "reports": reports,
            "scheduler_status": get_status(),
        },
    )
