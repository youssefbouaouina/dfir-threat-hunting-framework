"""Detection pipeline business logic — the single source of truth for detection.

run_detection_job() is the one entry point used by both the background
scheduler and the manual POST /detect route, so the two trigger paths can
never drift. All engines (sigma, embedded YARA results, hash matching,
network IOC correlation) run against unprocessed artifacts, results are
persisted with ATT&CK enrichment, and scanned artifacts are marked
processed so a re-run does not duplicate work.
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func

import models
from attck_mapper import enrich_technique
from hash_checker import check_file_scan_artifacts
from ioc_correlation import correlate_network_artifacts
from services.audit_service import log_action
from services.correlation_service import recompute_incidents
from sigma_matcher import evaluate as evaluate_sigma
from sigma_matcher import load_rules as load_sigma_rules

logger = logging.getLogger(__name__)

SIGMA_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigma_rules"
)


def _row_to_artifact_dict(row) -> dict:
    return {
        "host": row.host,
        "os": row.os,
        "artifact_type": row.artifact_type,
        "collected_at": row.collected_at,
        "data": json.loads(row.data),
    }


def _persist_detection(db, d: dict) -> models.Detection:
    attck_info = enrich_technique(d["technique_id"]) if d.get("technique_id") else {}
    row = models.Detection(
        host=d.get("host"),
        rule_id=d.get("rule_id"),
        rule_title=d.get("rule_title"),
        technique_id=d.get("technique_id"),
        technique_name=attck_info.get("name"),
        tactic=attck_info.get("tactic"),
        artifact_type=d.get("artifact_type"),
        severity=d.get("severity", "unknown"),
        matched_data=json.dumps(d.get("matched_data", {})),
        triage_status="new",
    )
    db.add(row)
    return row


def run_detection_job(
    db, host: Optional[str] = None, rescan: bool = False, trigger: str = "manual"
) -> dict:
    """
    Runs the full detection pipeline against unprocessed artifacts.

    host:    restrict to a single host's artifacts (DFIR triage scoping).
    rescan:  also re-analyze artifacts already marked processed (used after
             rules are added or updated, so history is not a dead end).
    trigger: "manual" (API) or "scheduled" (scheduler) — recorded in run history.

    Every invocation is recorded as a DetectionRun row (the audit history),
    including failed cycles, so a broken run is visible instead of silent.
    """
    run = models.DetectionRun(trigger=trigger, host=host, rescan=1 if rescan else 0)
    db.add(run)
    db.commit()  # persist the run id first so a later rollback can't lose it

    try:
        query = db.query(models.Artifact)
        if host:
            query = query.filter(models.Artifact.host == host)
        if not rescan:
            query = query.filter(models.Artifact.processed == 0)
        unprocessed = query.all()
        artifacts = [_row_to_artifact_dict(row) for row in unprocessed]

        all_detections = []

        # 1. Sigma-style behavioral rules
        sigma_rules = load_sigma_rules(SIGMA_RULES_DIR)
        all_detections.extend(evaluate_sigma(sigma_rules, artifacts))

        # 2. YARA results embedded in file_scan artifacts by the collector
        for artifact in artifacts:
            if artifact["artifact_type"] != "file_scan":
                continue
            for match in artifact["data"].get("yara_matches", []):
                meta = match.get("meta", {})
                all_detections.append(
                    {
                        "rule_id": f"yara-{match['rule']}",
                        "rule_title": meta.get("description", match["rule"]),
                        "technique_id": meta.get("technique_id"),
                        "severity": str(meta.get("severity") or meta.get("level") or "high"),
                        "host": artifact["host"],
                        "artifact_type": "file_scan",
                        "matched_data": artifact["data"],
                    }
                )

        # 3. Known-bad hash matching
        all_detections.extend(check_file_scan_artifacts(artifacts))

        # 4. Network IOC correlation
        all_detections.extend(correlate_network_artifacts(artifacts))

        # Persist everything, then mark all scanned artifacts processed
        for d in all_detections:
            _persist_detection(db, d)
        now = datetime.now(timezone.utc)
        for row in unprocessed:
            row.processed = 1
            row.analyzed_at = now
            row.source_run_id = run.id

        run.artifacts_scanned = len(artifacts)
        run.detections_found = len(all_detections)
        run.by_severity = json.dumps(_count_by(all_detections, "severity"))
        run.by_technique = json.dumps(_count_by(all_detections, "technique_id"))
        run.status = "completed"
        run.finished_at = datetime.now(timezone.utc)
        db.commit()

        # Phase 4 (F5): alert on high/critical detections (fail-soft, opt-in).
        from services.notification_service import notify_detections

        try:
            notify_detections(all_detections)
        except Exception:  # noqa: BLE001 — notifications must never fail a detection run
            logger.warning(
                "Notification dispatch failed; detections are still persisted", exc_info=True
            )

        # Phase 4 (F2): refresh the correlation view so new detections are
        # grouped into campaign / attack-chain incidents immediately.
        try:
            recompute_incidents(db, actor=f"detection:{trigger}")
        except Exception:  # noqa: BLE001 — correlation must never fail a detection run
            logger.warning(
                "Incident correlation failed; detections are still persisted", exc_info=True
            )
            db.rollback()

        log_action(
            db,
            "run_detection",
            actor=trigger,
            detail={
                "run_id": run.id,
                "trigger": trigger,
                "host": host,
                "rescan": bool(rescan),
                "artifacts_scanned": len(artifacts),
                "detections_found": len(all_detections),
            },
        )

        return {
            "artifacts_scanned": len(artifacts),
            "detections_found": len(all_detections),
            "by_severity": _count_by(all_detections, "severity"),
            "by_technique": _count_by(all_detections, "technique_id"),
        }
    except Exception:
        # Roll back partial detection work but keep the run history visible.
        db.rollback()
        run.status = "failed"
        run.finished_at = datetime.now(timezone.utc)
        db.add(run)
        db.commit()
        raise


def _count_by(detections: list, field: str) -> dict:
    counts: dict = {}
    for d in detections:
        key = d.get(field) or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


def list_detections(
    db,
    host: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    before_id: Optional[int] = None,
    hosts: Optional[list] = None,
) -> list:
    """Returns detections newest-first, optionally filtered by host/severity.

    `before_id` is a cursor (id < before_id) so paging stays stable as new
    detections arrive. `hosts` (F4) is an allow-list from team scoping.
    """
    query = db.query(models.Detection)
    if host:
        query = query.filter(models.Detection.host == host)
    if hosts is not None:
        query = query.filter(models.Detection.host.in_(hosts))
    if severity:
        query = query.filter(models.Detection.severity == severity)
    if before_id is not None:
        query = query.filter(models.Detection.id < before_id)
    rows = query.order_by(models.Detection.id.desc()).limit(min(limit, 500)).all()

    return [
        {
            "id": r.id,
            "host": r.host,
            "rule_id": r.rule_id,
            "rule_title": r.rule_title,
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "artifact_type": r.artifact_type,
            "severity": r.severity,
            "matched_data": json.loads(r.matched_data),
            "detected_at": str(r.detected_at),
            "triage_status": r.triage_status or "new",
            "triage_notes": r.triage_notes,
            "triage_updated_at": str(r.triage_updated_at) if r.triage_updated_at else None,
            "triage_updated_by": r.triage_updated_by,
        }
        for r in rows
    ]


TRIAGE_STATUSES = ("new", "acknowledged", "false_positive", "true_positive", "reviewed")


def triage_detection(
    db,
    detection_id: int,
    status: str,
    notes: Optional[str] = None,
    actor: Optional[str] = None,
) -> Optional[dict]:
    """Records an analyst's triage decision on a detection (Phase 3).

    Moves the detection through the lifecycle: new -> acknowledged ->
    false_positive | true_positive | reviewed. Re-triaging is allowed (an
    analyst may change their mind); every change is audited. Returns None
    if the detection id is unknown.
    """
    if status not in TRIAGE_STATUSES:
        raise ValueError(f"Invalid triage status '{status}' — must be one of {TRIAGE_STATUSES}")

    row = db.query(models.Detection).filter(models.Detection.id == detection_id).first()
    if row is None:
        return None

    row.triage_status = status
    row.triage_notes = notes or row.triage_notes
    row.triage_updated_at = datetime.now(timezone.utc)
    row.triage_updated_by = actor or "unknown"
    db.commit()

    log_action(
        db,
        "triage_detection",
        actor=actor or "unknown",
        detail={"detection_id": detection_id, "status": status, "notes": notes},
    )

    return {
        "id": row.id,
        "triage_status": row.triage_status,
        "triage_notes": row.triage_notes,
        "triage_updated_at": str(row.triage_updated_at),
        "triage_updated_by": row.triage_updated_by,
    }


def list_detection_runs(
    db,
    limit: int = 50,
    status: Optional[str] = None,
    before_id: Optional[int] = None,
    hosts: Optional[list] = None,
) -> list:
    """Returns detection-run history (newest first), optionally filtered by status.

    `before_id` is a cursor (id < before_id) for stable paging. `hosts` (F4)
    is an allow-list from team scoping (runs scoped by their host field).
    """
    query = db.query(models.DetectionRun)
    if status:
        query = query.filter(models.DetectionRun.status == status)
    if hosts is not None:
        query = query.filter(models.DetectionRun.host.in_(hosts))
    if before_id is not None:
        query = query.filter(models.DetectionRun.id < before_id)
    rows = query.order_by(models.DetectionRun.id.desc()).limit(min(limit, 500)).all()

    return [
        {
            "id": r.id,
            "trigger": r.trigger,
            "status": r.status,
            "host": r.host,
            "rescan": r.rescan,
            "started_at": str(r.started_at),
            "finished_at": str(r.finished_at) if r.finished_at else None,
            "artifacts_scanned": r.artifacts_scanned,
            "detections_found": r.detections_found,
            "by_severity": json.loads(r.by_severity) if r.by_severity else {},
            "by_technique": json.loads(r.by_technique) if r.by_technique else {},
        }
        for r in rows
    ]


def detections_summary(db, hosts: Optional[list] = None) -> dict:
    """Aggregates detection counts by technique/severity/host (ATT&CK coverage view).

    Uses SQL GROUP BY so /detections/summary stays cheap as the table grows
    (M3): no full-table load into Python. `hosts` (F4) scopes to a team.
    """
    base = db.query(models.Detection)
    if hosts is not None:
        base = base.filter(models.Detection.host.in_(hosts))
    total = base.count()

    def _grouped(column) -> dict:
        query = db.query(column, func.count(models.Detection.id))
        if hosts is not None:
            query = query.filter(models.Detection.host.in_(hosts))
        rows = query.group_by(column).all()
        return {key or "unknown": n for key, n in rows}

    return {
        "total_detections": total,
        "by_technique": _grouped(models.Detection.technique_id),
        "by_severity": _grouped(models.Detection.severity),
        "by_host": _grouped(models.Detection.host),
        "by_triage": _grouped(models.Detection.triage_status),
    }
