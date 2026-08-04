"""
Report generation — produces a real PDF investigation report from
currently stored detections, and persists a record of every report
ever generated (this is what makes "report history" possible).

Two ways a report gets created:
  - Manually, via POST /reports/run-now (the dashboard's "Run
    Investigation Now" button — runs detection first, then reports)
  - Later: automatically after each scheduled detection cycle, if you
    want every automated sweep to also produce a report (left as an
    opt-in call from scheduler.py, not forced — see guide)
"""
import json
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from database import get_db
import models
from detection_routes import run_detection_job

router = APIRouter()

REPORTS_DIR = os.getenv("DFIR_REPORTS_DIR", "./reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def _styled_table(data, col_widths=None):
    t = Table(data, colWidths=col_widths)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ]
        )
    )
    return t


def _generate_pdf(report_id: str, detections: list, host_filter: str | None) -> str:
    filename = f"report_{report_id}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(filepath, pagesize=LETTER, title="DFIR Investigation Report")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("DFIR &amp; Threat Hunting Investigation Report", styles["Title"]),
        Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]),
        Paragraph(f"Scope: {host_filter or 'All monitored endpoints'}", styles["Normal"]),
        Spacer(1, 0.3 * inch),
        Paragraph(f"Total Detections: {len(detections)}", styles["Heading2"]),
    ]

    severity_counts, technique_counts, technique_info = {}, {}, {}
    for d in detections:
        severity_counts[d.severity or "unknown"] = severity_counts.get(d.severity or "unknown", 0) + 1
        technique_counts[d.technique_id or "unknown"] = technique_counts.get(d.technique_id or "unknown", 0) + 1
        technique_info[d.technique_id or "unknown"] = (d.technique_name or "-", d.tactic or "-")

    story.append(Paragraph("Severity Breakdown", styles["Heading3"]))
    story.append(_styled_table([["Severity", "Count"]] + [[k, str(v)] for k, v in sorted(severity_counts.items())]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("ATT&amp;CK Technique Coverage", styles["Heading3"]))
    tech_rows = [["Technique", "Name", "Tactic", "Count"]]
    for tid, count in sorted(technique_counts.items()):
        name, tactic = technique_info.get(tid, ("-", "-"))
        tech_rows.append([tid, name, tactic, str(count)])
    story.append(_styled_table(tech_rows))
    story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("Detection Detail", styles["Heading3"]))
    detail_rows = [["Host", "Rule", "Technique", "Severity", "Detected At"]]
    for d in detections[:100]:  # cap so a huge backlog doesn't produce an unreadable report
        detail_rows.append([d.host, d.rule_title, d.technique_id or "-", d.severity or "-", str(d.detected_at)])
    story.append(_styled_table(detail_rows, col_widths=[1.1 * inch, 2.2 * inch, 0.9 * inch, 0.8 * inch, 1.3 * inch]))

    doc.build(story)
    return filename


def generate_report(db: Session, host: str | None = None, triggered_by: str = "manual") -> dict:
    """Plain function (not a route) so it's reusable — called by the
    /reports/generate route, and internally by /reports/run-now."""
    query = db.query(models.Detection)
    if host:
        query = query.filter(models.Detection.host == host)
    detections = query.order_by(models.Detection.id.desc()).all()

    report_id = uuid.uuid4().hex[:12]
    pdf_filename = _generate_pdf(report_id, detections, host)

    severity_counts, technique_counts = {}, {}
    for d in detections:
        severity_counts[d.severity or "unknown"] = severity_counts.get(d.severity or "unknown", 0) + 1
        technique_counts[d.technique_id or "unknown"] = technique_counts.get(d.technique_id or "unknown", 0) + 1

    row = models.Report(
        run_id=report_id,
        host_filter=host,
        triggered_by=triggered_by,
        detections_count=len(detections),
        pdf_filename=pdf_filename,
        summary_json=json.dumps({"by_severity": severity_counts, "by_technique": technique_counts}),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {
        "report_id": row.run_id,
        "generated_at": str(row.generated_at),
        "detections_count": row.detections_count,
        "pdf_filename": row.pdf_filename,
    }


@router.post("/reports/generate")
def generate_report_route(host: str | None = None, db: Session = Depends(get_db)):
    return generate_report(db, host=host, triggered_by="manual")


@router.post("/reports/run-now")
def run_now(host: str | None = None, db: Session = Depends(get_db)):
    """The dashboard's 'Run Investigation Now' button: runs detection
    on whatever's currently unprocessed, then generates a fresh report
    reflecting the result — a single click, real live pipeline run."""
    detect_result = run_detection_job(db)
    report_result = generate_report(db, host=host, triggered_by="manual")
    return {"detect_result": detect_result, "report": report_result}


@router.get("/reports")
def list_reports(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.query(models.Report).order_by(models.Report.id.desc()).limit(min(limit, 200)).all()
    return [
        {
            "id": r.id,
            "run_id": r.run_id,
            "host_filter": r.host_filter,
            "triggered_by": r.triggered_by,
            "detections_count": r.detections_count,
            "generated_at": str(r.generated_at),
            "pdf_filename": r.pdf_filename,
            "summary": json.loads(r.summary_json),
        }
        for r in rows
    ]


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    row = db.query(models.Report).filter(models.Report.run_id == report_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    filepath = os.path.join(REPORTS_DIR, row.pdf_filename)
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="Report file missing on disk")
    return FileResponse(filepath, media_type="application/pdf", filename=row.pdf_filename)
