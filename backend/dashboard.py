"""
Dashboard route — server-rendered HTML (Jinja2), queries the DB
directly rather than calling our own API over HTTP (simpler, faster,
no self-referential network calls).
"""
import os

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

import models
from attack_chain import build_attack_chain, summary_recommendations
from database import get_db
from endpoints import EndpointCreate, register_endpoint
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
    endpoints = db.query(models.Endpoint).order_by(models.Endpoint.id).all()

    all_detections = db.query(models.Detection).all()
    attack_chain = build_attack_chain(all_detections)
    recommendations = summary_recommendations(all_detections)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "hosts": hosts,
            "endpoints": endpoints,
            "total_artifacts": total_artifacts,
            "total_detections": total_detections,
            "severity_counts": severity_counts,
            "technique_rows": technique_rows,
            "recent_detections": recent_detections,
            "reports": reports,
            "scheduler_status": get_status(),
            "attack_chain": attack_chain,
            "recommendations": recommendations,
            "endpoint_error": None,
            "endpoint_created": "Endpoint created" if request.query_params.get("created") == "1" else None,
        },
    )


@router.post("/dashboard/endpoints", response_class=HTMLResponse)
def dashboard_create_endpoint(
    request: Request,
    name: str = Form(...),
    os: str = Form("linux"),
    backend_type: str = Form("container"),
    image: str = Form(""),
    ip_address: str = Form(""),
    ssh_username: str = Form(""),
    ssh_key_path: str = Form(""),
    remote_collector_path: str = Form(""),
    ssh_port: int = Form(22),
    db: Session = Depends(get_db),
):
    """Form handler for the Add Endpoint panel. Reuses the API's registration
    logic (including endpoint-manager container creation) and redirects back to
    the dashboard, surfacing any error inline."""
    payload = EndpointCreate(
        name=name.strip(),
        os=os,
        backend_type=backend_type,
        image=image.strip() or None,
        ip_address=ip_address.strip() or None,
        ssh_username=ssh_username.strip() or None,
        ssh_key_path=ssh_key_path.strip() or None,
        remote_collector_path=remote_collector_path.strip() or None,
        ssh_port=ssh_port,
    )
    try:
        register_endpoint(payload, db)
        return RedirectResponse(url="/dashboard?created=1", status_code=303)
    except HTTPException as e:
        hosts = db.query(models.Host).all()
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "hosts": hosts,
                "endpoints": db.query(models.Endpoint).order_by(models.Endpoint.id).all(),
                "total_artifacts": db.query(models.Artifact).count(),
                "total_detections": db.query(models.Detection).count(),
                "severity_counts": [],
                "technique_rows": [],
                "recent_detections": [],
                "reports": db.query(models.Report).order_by(models.Report.id.desc()).limit(10).all(),
                "scheduler_status": get_status(),
                "attack_chain": {"tactics": [], "technique_count": 0},
                "recommendations": [],
                "endpoint_error": str(e.detail),
                "endpoint_created": None,
            },
        )
