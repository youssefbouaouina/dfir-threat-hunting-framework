"""Operations metrics for the DFIR backend (Phase 3 ops hardening).

A lightweight Prometheus-style text exposition generated from live database
counts — no external metrics library, no background collector. Endpoints
consume this via /metrics; CI smoke tests hit the same endpoint.
"""
import json

import models


def _fmt(name: str, help_text: str, value: int) -> str:
    return (
        f"# HELP {name} {help_text}\n"
        f"# TYPE {name} gauge\n"
        f"{name} {value}\n"
    )


def metrics_text(db) -> str:
    """Builds the /metrics payload (Prometheus text format, subset of gauges)."""
    counts = {
        "dfir_artifacts_total": db.query(models.Artifact).count(),
        "dfir_artifacts_unprocessed": db.query(models.Artifact)
        .filter(models.Artifact.processed == 0)
        .count(),
        "dfir_detections_total": db.query(models.Detection).count(),
        "dfir_detections_open": db.query(models.Detection)
        .filter(models.Detection.triage_status.in_(("new", "acknowledged")))
        .count(),
        "dfir_endpoints_total": db.query(models.Endpoint).count(),
        "dfir_endpoints_online": db.query(models.Endpoint)
        .filter(models.Endpoint.status == "online")
        .count(),
        "dfir_detection_runs_total": db.query(models.DetectionRun).count(),
        "dfir_pending_commands": db.query(models.PendingCommand)
        .filter(models.PendingCommand.status == "pending")
        .count(),
        "dfir_hosts_total": db.query(models.Host).count(),
    }

    lines = ["# DFIR Threat Hunting Framework — operational metrics"]
    for name, value in counts.items():
        help_text = name.replace("dfir_", "").replace("_", " ")
        lines.append(_fmt(name, help_text, value))

    return "\n".join(lines) + "\n"


def health_payload(db) -> dict:
    """A richer health view for the dashboard: live counts alongside liveness."""
    return {
        "status": "ok",
        "metrics": {
            "artifacts": db.query(models.Artifact).count(),
            "artifacts_unprocessed": db.query(models.Artifact)
            .filter(models.Artifact.processed == 0)
            .count(),
            "detections": db.query(models.Detection).count(),
            "endpoints": db.query(models.Endpoint).count(),
            "detection_runs": db.query(models.DetectionRun).count(),
            "hosts": db.query(models.Host).count(),
        },
        "summary": json.dumps(_summary_counts(db)),
    }


def _summary_counts(db) -> dict:
    rows = db.query(models.Detection).all()
    by_severity = {}
    for r in rows:
        by_severity[r.severity or "unknown"] = by_severity.get(r.severity or "unknown", 0) + 1
    return {"by_severity": by_severity}
