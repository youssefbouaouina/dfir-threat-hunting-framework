"""Materialized statistics (Phase 5 / F8).

Precomputes the expensive aggregations the dashboard and /detections/summary
would otherwise recompute on every request:

    detection_summary — total + by_severity/by_technique/by_host/by_triage
    health_counts     — artifacts/detections/endpoints/runs/hosts + unprocessed
    ioc_counts        — IOCs total/active + by_source/by_type

Each metric is stored as a StatsSnapshot row (JSON value + computed_at). A
scheduler job (stats_sweep) refreshes them on STATS_INTERVAL_SECONDS and
operators can force a recompute via POST /stats/recompute. This is the
portable stand-in for a Postgres materialized view: same "compute once, read
often" win, but works on SQLite.
"""
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import func

import models

logger = logging.getLogger(__name__)

METRICS = ("detection_summary", "health_counts", "ioc_counts")


def _detection_summary(db) -> dict:
    def _grouped(column) -> dict:
        rows = (
            db.query(column, func.count(models.Detection.id))
            .group_by(column)
            .all()
        )
        return {key or "unknown": n for key, n in rows}

    return {
        "total_detections": db.query(models.Detection).count(),
        "by_technique": _grouped(models.Detection.technique_id),
        "by_severity": _grouped(models.Detection.severity),
        "by_host": _grouped(models.Detection.host),
        "by_triage": _grouped(models.Detection.triage_status),
    }


def _health_counts(db) -> dict:
    return {
        "artifacts": db.query(models.Artifact).count(),
        "artifacts_unprocessed": db.query(models.Artifact)
        .filter(models.Artifact.processed == 0)
        .count(),
        "detections": db.query(models.Detection).count(),
        "endpoints": db.query(models.Endpoint).count(),
        "detection_runs": db.query(models.DetectionRun).count(),
        "hosts": db.query(models.Host).count(),
    }


def _ioc_counts(db) -> dict:
    def _grouped(column) -> dict:
        rows = (
            db.query(column, func.count(models.Ioc.id)).group_by(column).all()
        )
        return {key or "unknown": n for key, n in rows}

    return {
        "total": db.query(models.Ioc).count(),
        "active": db.query(models.Ioc).filter(models.Ioc.active == 1).count(),
        "by_source": _grouped(models.Ioc.source),
        "by_type": _grouped(models.Ioc.ioc_type),
    }


_COMPUTERS = {
    "detection_summary": _detection_summary,
    "health_counts": _health_counts,
    "ioc_counts": _ioc_counts,
}


def compute_all(db) -> dict:
    """Recomputes every metric and upserts its snapshot row; returns the result."""
    result: dict = {}
    now = datetime.now(timezone.utc)
    for metric, compute in _COMPUTERS.items():
        value = compute(db)
        row = db.query(models.StatsSnapshot).filter(models.StatsSnapshot.metric == metric).first()
        if row is None:
            row = models.StatsSnapshot(metric=metric, value=json.dumps(value), computed_at=now)
            db.add(row)
        else:
            row.value = json.dumps(value)
            row.computed_at = now
        result[metric] = value
    db.commit()
    return {"metrics": result, "computed_at": now.isoformat()}


def get_snapshot(db, metric: str) -> dict:
    """Reads one cached metric; recomputes on first use (cold start)."""
    if metric not in _COMPUTERS:
        raise ValueError(f"Unknown stats metric '{metric}' — must be one of {list(METRICS)}")
    row = db.query(models.StatsSnapshot).filter(models.StatsSnapshot.metric == metric).first()
    if row is None:
        value = _COMPUTERS[metric](db)
        db.add(
            models.StatsSnapshot(
                metric=metric,
                value=json.dumps(value),
                computed_at=datetime.now(timezone.utc),
            )
        )
        db.commit()
        return value
    return json.loads(row.value)


def snapshot_status(db) -> list:
    """Lists each metric with its cached value + last computed time."""
    rows = db.query(models.StatsSnapshot).order_by(models.StatsSnapshot.metric.asc()).all()
    return [
        {
            "metric": r.metric,
            "computed_at": str(r.computed_at) if r.computed_at else None,
            "value": json.loads(r.value),
        }
        for r in rows
    ]
