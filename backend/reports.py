"""
Report generation — produces a structured PDF investigation report from
currently stored detections, and persists a record of every report ever
generated (this is what makes "report history" possible).

Report layout (readable, analyst-oriented):
  1. Executive Summary            — total detections, hosts, severity breakdown
  2. Detection Sources            — which artifact type fed each finding
  3. Rules Involved               — every rule that fired, with technique + count
  4. ATT&CK Technique Coverage    — technique/tactic aggregation
  5. Endpoint Details             — registered endpoint metadata in scope
  6. Detection Detail             — one row per finding incl. matched-data preview

Two ways a report gets created:
  - Manually, via POST /reports/run-now (the dashboard's "Run
    Investigation Now" button — runs detection first, then reports)
  - Automatically after each orchestration cycle (scheduler.py)
"""
import json
import os
import uuid
from datetime import UTC, datetime
from html import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

import models
from database import get_db
from detection_routes import run_detection_job

router = APIRouter()

REPORTS_DIR = os.getenv("DFIR_REPORTS_DIR", "./reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Usable width on LETTER with default 0.75in margins is 468pt — keep tables
# within that so nothing overflows the page edge.
PAGE_WIDTH = 468

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_COLORS = {
    "critical": "#E5484D",
    "high": "#F2994A",
    "medium": "#B58900",
    "low": "#4FA3D1",
    "unknown": "#5B6472",
}

# "Where did this info come from" — one human-readable source line per artifact type.
ARTIFACT_SOURCE_LABELS = {
    "process": "Running process metadata (name, pid, cmdline) collected via psutil",
    "network": "Active TCP/UDP network connections collected via psutil",
    "persistence": "Persistence points: cron, rc.local, systemd units, registry Run keys, services",
    "scheduled_task": "Scheduled tasks: systemd timers, Windows Task Scheduler, cron entries",
    "log_event": "System logs: journalctl, Sysmon operational log, auditd (ausearch)",
    "file_scan": "Agent-side file hashing (SHA-256) and local YARA rule scan",
}


def _severity_color(sev: str | None) -> str:
    return SEVERITY_COLORS.get(sev or "unknown", SEVERITY_COLORS["unknown"])


def _styled_table(data, col_widths=None):
    t = Table(data, colWidths=col_widths)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return t


def _cell_style():
    return ParagraphStyle("cell", fontSize=7.5, leading=9.5)


def _p(text: str, style) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _severity_p(sev: str | None) -> Paragraph:
    style = ParagraphStyle(
        "sev_cell",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor(_severity_color(sev)),
        fontName="Helvetica-Bold",
    )
    return Paragraph(escape(sev or "unknown"), style)


def _matched_data_summary(data, artifact_type: str) -> str:
    """Turns a detection's stored matched_data JSON into a short, readable
    one-line preview — the specific fields an analyst wants per artifact type."""
    if not isinstance(data, dict):
        return str(data)[:200]

    def pick(*keys):
        return "; ".join(
            f"{k}={v}" for k in keys if (v := data.get(k)) not in (None, "")
        )

    if artifact_type == "process":
        text = pick("name", "pid", "ppid", "username")
        cmdline = data.get("cmdline")
        if cmdline:
            text += f"; cmdline={cmdline[:160]}"
        return text
    if artifact_type == "network":
        return pick("local_address", "remote_address", "status", "pid")
    if artifact_type == "persistence":
        return pick("type", "user", "entry", "key_path", "value_name", "unit", "state", "hive")
    if artifact_type == "scheduled_task":
        return pick("task_name", "status", "task_to_run", "run_as_user", "type", "raw")
    if artifact_type == "log_event":
        text = pick("source", "unit", "event_id", "message")
        return text[:200]
    if artifact_type == "file_scan":
        text = pick("path", "sha256", "size_bytes")
        matches = data.get("yara_matches")
        if matches:
            text += f"; yara_matches={[m.get('rule') for m in matches]}"
        return text
    return json.dumps(data)[:200]


def _section_header(number: int, title: str) -> Paragraph:
    return Paragraph(f"{number}. {title}", ParagraphStyle("h2", parent=getSampleStyleSheet()["Heading2"]))


def _generate_pdf(ctx: dict) -> str:
    """Builds the PDF story from a fully-computed context dict."""
    styles = getSampleStyleSheet()
    cell = _cell_style()
    story = []

    # ------------------------------------------------------------------ header
    story.append(Paragraph("DFIR &amp; Threat Hunting Investigation Report", styles["Title"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(
        _styled_table(
            [
                ["Report ID", "Generated (UTC)", "Triggered by", "Scope"],
                [
                    _p(ctx["report_id"], cell),
                    _p(ctx["generated_at"], cell),
                    _p(ctx["triggered_by"], cell),
                    _p(ctx["scope"], cell),
                ],
            ],
            col_widths=[0.9 * inch, 1.5 * inch, 0.8 * inch, 2.2 * inch],
        )
    )
    story.append(Spacer(1, 0.25 * inch))

    # ------------------------------------------------------ 1. executive summary
    story.append(KeepTogether([
        _section_header(1, "Executive Summary"),
        Paragraph(
            f"Total detections: {len(ctx['detections'])} across {len(ctx['hosts'])} host(s). "
            "Severity is a heuristic triage signal, not an authoritative verdict.",
            styles["Normal"],
        ),
        Spacer(1, 0.1 * inch),
        _styled_table(
            [["Severity", "Count"]]
            + [[_p(sev, cell), _p(str(ctx["summary"]["by_severity"].get(sev, 0)), cell)] for sev in SEVERITY_ORDER],
            col_widths=[1.5 * inch, 1.0 * inch],
        ),
    ]))
    story.append(PageBreak())

    # ------------------------------------------------ 2. detection sources
    sources = ctx["summary"]["by_artifact_type"]
    story.append(KeepTogether([
        _section_header(2, "Detection Sources (where the data came from)"),
        Paragraph(
            "Each detection below was produced from an artifact type collected on the "
            "endpoint and pushed to the backend /ingest API.",
            styles["Normal"],
        ),
        Spacer(1, 0.1 * inch),
        _styled_table(
            [["Artifact type", "Source description", "Findings"]]
            + [
                [
                    _p(atype, cell),
                    _p(ARTIFACT_SOURCE_LABELS.get(atype, "Unknown source"), cell),
                    _p(str(count), cell),
                ]
                for atype, count in sorted(sources.items(), key=lambda kv: -kv[1])
            ],
            col_widths=[1.0 * inch, 3.6 * inch, 0.8 * inch],
        ),
    ]))
    story.append(PageBreak())

    # ------------------------------------------------------ 3. rules involved
    by_rule = ctx["summary"]["by_rule"]
    story.append(KeepTogether([
        _section_header(3, "Rules Involved"),
        Paragraph(
            "Every detection rule that fired in this run, with its MITRE ATT&CK mapping, "
            "severity and how many times it matched.",
            styles["Normal"],
        ),
        Spacer(1, 0.1 * inch),
        _styled_table(
            [["Rule ID", "Rule title", "Technique", "Tactic", "Severity", "Detections"]]
            + [
                [
                    _p(rid, cell),
                    _p(info["title"], cell),
                    _p(info.get("technique_id") or "-", cell),
                    _p(info.get("tactic") or "-", cell),
                    _severity_p(info.get("severity")),
                    _p(str(info["count"]), cell),
                ]
                for rid, info in by_rule.items()
            ],
            col_widths=[0.9 * inch, 1.9 * inch, 0.7 * inch, 0.8 * inch, 0.6 * inch, 0.7 * inch],
        ),
    ]))
    story.append(PageBreak())

    # -------------------------------------------------- 4. att&ck coverage
    tech_counts = ctx["summary"]["by_technique"]
    technique_info = ctx["technique_info"]
    story.append(KeepTogether([
        _section_header(4, "ATT&amp;CK Technique Coverage"),
        Paragraph(
            "Technique IDs enriched from the local MITRE ATT&amp;CK mapping where available.",
            styles["Normal"],
        ),
        Spacer(1, 0.1 * inch),
        _styled_table(
            [["Technique", "Name", "Tactic", "Count"]]
            + [
                [
                    _p(tid, cell),
                    _p(technique_info.get(tid, ("-", "-"))[0], cell),
                    _p(technique_info.get(tid, ("-", "-"))[1], cell),
                    _p(str(count), cell),
                ]
                for tid, count in sorted(tech_counts.items(), key=lambda kv: -kv[1])
            ],
            col_widths=[0.9 * inch, 2.2 * inch, 1.0 * inch, 0.6 * inch],
        ),
    ]))
    story.append(PageBreak())

    # --------------------------------------------------- 5. endpoint details
    story.append(KeepTogether([
        _section_header(5, "Endpoint Details"),
        Paragraph(
            "Registered endpoints in scope. Artifact/detection records use the collector "
            "hostname; keep it aligned with the endpoint name so filtering stays consistent.",
            styles["Normal"],
        ),
        Spacer(1, 0.1 * inch),
    ]))
    if ctx["endpoints"]:
        story.append(
            _styled_table(
                [["Endpoint", "IP", "OS", "SSH port", "Status", "Last scan", "Last checked", "Last error"]]
                + [
                    [
                        _p(ep["name"], cell),
                        _p(ep.get("ip_address") or "-", cell),
                        _p(ep.get("os") or "-", cell),
                        _p(ep.get("ssh_port") or "-", cell),
                        _p(ep.get("status") or "unknown", cell),
                        _p(ep.get("last_scan_at") or "never", cell),
                        _p(ep.get("last_checked_at") or "-", cell),
                        _p(ep.get("last_error") or "-", cell),
                    ]
                    for ep in ctx["endpoints"]
                ],
                col_widths=[1.0 * inch, 0.9 * inch, 0.6 * inch, 0.5 * inch, 0.6 * inch, 1.0 * inch, 1.0 * inch, 1.5 * inch],
            )
        )
    else:
        story.append(
            _styled_table(
                [["Hostname", "OS", "Last seen"]]
                + [
                    [_p(h["hostname"], cell), _p(h.get("os") or "-", cell), _p(h.get("last_seen") or "-", cell)]
                    for h in ctx["hosts"]
                ],
                col_widths=[1.6 * inch, 1.0 * inch, 1.6 * inch],
            )
        )
    story.append(PageBreak())

    # -------------------------------------------------- 6. detection detail
    story.append(KeepTogether([
        _section_header(6, "Detection Detail"),
        Paragraph(
            "Every finding in this report, with the specific matched data that triggered it.",
            styles["Normal"],
        ),
        Spacer(1, 0.1 * inch),
    ]))
    detections = ctx["detections"]
    if detections:
        detail_rows = [
            ["Host", "Severity", "Rule", "Source (artifact type)", "Technique", "Detected at (UTC)", "Matched data"]
        ]
        for d in detections[:100]:
            detail_rows.append(
                [
                    _p(d.host, cell),
                    _severity_p(d.severity),
                    _p(d.rule_title, cell),
                    _p(d.artifact_type, cell),
                    _p(d.technique_id or "-", cell),
                    _p(str(d.detected_at), cell),
                    _p(_matched_data_summary(json.loads(d.matched_data), d.artifact_type), cell),
                ]
            )
        story.append(
            _styled_table(
                detail_rows,
                col_widths=[0.8 * inch, 0.6 * inch, 1.2 * inch, 0.9 * inch, 0.6 * inch, 1.0 * inch, 1.8 * inch],
            )
        )
    else:
        story.append(Paragraph("No detections in scope for this run.", styles["Normal"]))

    filename = f"report_{ctx['report_id']}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    doc = SimpleDocTemplate(filepath, pagesize=LETTER, title="DFIR Investigation Report",
                            rightMargin=0.75 * inch, leftMargin=0.75 * inch,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    doc.build(story)
    return filename


def generate_report(db: Session, host: str | None = None, triggered_by: str = "manual", since: datetime | None = None) -> dict:
    """Plain function (not a route) so it's reusable — called by the
    /reports/generate route, and internally by /reports/run-now.

    `since`, when given, scopes the report to detections created on or
    after that timestamp (used by the per-endpoint run-now flow so a
    click there reports THIS run's findings, not all history)."""
    query = db.query(models.Detection)
    if host:
        query = query.filter(models.Detection.host == host)
    if since is not None:
        if since.tzinfo is not None:
            # SQLite stores naive UTC datetimes; normalize the bound
            # so the comparison works regardless of the caller's tz.
            since = since.astimezone(UTC).replace(tzinfo=None)
        query = query.filter(models.Detection.detected_at >= since)
    detections = query.order_by(models.Detection.id.desc()).all()

    report_id = uuid.uuid4().hex[:12]

    severity_counts, technique_counts, rule_counts, artifact_counts = {}, {}, {}, {}
    technique_info = {}
    hosts = set()
    for d in detections:
        sev = d.severity or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        tid = d.technique_id or "unknown"
        technique_counts[tid] = technique_counts.get(tid, 0) + 1
        technique_info[tid] = (d.technique_name or "-", d.tactic or "-")
        rule_key = d.rule_id or "unknown"
        info = rule_counts.setdefault(
            rule_key,
            {"title": d.rule_title or rule_key, "severity": sev,
             "technique_id": d.technique_id, "tactic": d.tactic, "count": 0},
        )
        info["count"] += 1
        artifact_counts[d.artifact_type] = artifact_counts.get(d.artifact_type, 0) + 1
        hosts.add(d.host)

    # Endpoint registry metadata for the hosts in scope (if any are registered).
    if host:
        endpoints = db.query(models.Endpoint).filter(models.Endpoint.name == host).all()
    else:
        endpoints = db.query(models.Endpoint).all()
    endpoint_rows = []
    for ep in endpoints:
        endpoint_rows.append(
            {
                "name": ep.name,
                "ip_address": ep.ip_address,
                "os": ep.os,
                "ssh_port": ep.ssh_port,
                "status": ep.status,
                "last_scan_at": str(ep.last_scan_at) if ep.last_scan_at else None,
                "last_checked_at": str(ep.last_checked_at) if ep.last_checked_at else None,
                "last_error": ep.last_error,
            }
        )

    host_rows = []
    if hosts:
        for h in db.query(models.Host).filter(models.Host.hostname.in_(hosts)).all():
            host_rows.append(
                {"hostname": h.hostname, "os": h.os, "last_seen": str(h.last_seen) if h.last_seen else None}
            )

    ctx = {
        "report_id": report_id,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        "triggered_by": triggered_by,
        "scope": host or "All monitored endpoints",
        "detections": detections,
        "hosts": host_rows,
        "endpoints": endpoint_rows,
        "technique_info": technique_info,
        "summary": {
            "by_severity": severity_counts,
            "by_technique": technique_counts,
            "by_rule": rule_counts,
            "by_artifact_type": artifact_counts,
            "hosts": sorted(hosts),
        },
    }

    pdf_filename = _generate_pdf(ctx)

    row = models.Report(
        run_id=report_id,
        host_filter=host,
        triggered_by=triggered_by,
        detections_count=len(detections),
        pdf_filename=pdf_filename,
        summary_json=json.dumps(
            {
                "by_severity": severity_counts,
                "by_technique": technique_counts,
                "by_rule": rule_counts,
                "by_artifact_type": artifact_counts,
                "hosts": sorted(hosts),
            }
        ),
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
