"""Detection pipeline business logic — the single source of truth for detection.

run_detection_job() is the one entry point used by both the background
scheduler and the manual POST /detect route, so the two trigger paths can
never drift. All engines (sigma, embedded YARA results, hash matching,
network IOC correlation) run against unprocessed artifacts, results are
persisted with ATT&CK enrichment, and scanned artifacts are marked
processed so a re-run does not duplicate work.
"""
import json
import os
from datetime import datetime, timezone

import models
from attck_mapper import enrich_technique
from hash_checker import check_file_scan_artifacts
from ioc_correlation import correlate_network_artifacts
from sigma_matcher import evaluate as evaluate_sigma
from sigma_matcher import load_rules as load_sigma_rules

SIGMA_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigma_rules")


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
    )
    db.add(row)
    return row


def run_detection_job(db, host: str = None, rescan: bool = False, trigger: str = "manual") -> dict:
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
                all_detections.append(
                    {
                        "rule_id": f"yara-{match['rule']}",
                        "rule_title": match.get("meta", {}).get("description", match["rule"]),
                        "technique_id": match.get("meta", {}).get("technique_id"),
                        "severity": "high",
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
        for row in unprocessed:
            row.processed = 1

        run.artifacts_scanned = len(artifacts)
        run.detections_found = len(all_detections)
        run.by_severity = json.dumps(_count_by(all_detections, "severity"))
        run.by_technique = json.dumps(_count_by(all_detections, "technique_id"))
        run.status = "completed"
        run.finished_at = datetime.now(timezone.utc)
        db.commit()

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
    counts = {}
    for d in detections:
        key = d.get(field) or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


def list_detections(db, host: str = None, severity: str = None, limit: int = 100) -> list:
    """Returns detections newest-first, optionally filtered by host/severity."""
    query = db.query(models.Detection)
    if host:
        query = query.filter(models.Detection.host == host)
    if severity:
        query = query.filter(models.Detection.severity == severity)
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
        }
        for r in rows
    ]


def list_detection_runs(db, limit: int = 50, status: str = None) -> list:
    """Returns detection-run history (newest first), optionally filtered by status."""
    query = db.query(models.DetectionRun)
    if status:
        query = query.filter(models.DetectionRun.status == status)
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


def detections_summary(db) -> dict:
    """Aggregates detection counts by technique/severity/host (ATT&CK coverage view)."""
    rows = db.query(models.Detection).all()
    by_technique = {}
    by_severity = {}
    by_host = {}
    for r in rows:
        by_technique[r.technique_id or "unknown"] = by_technique.get(r.technique_id or "unknown", 0) + 1
        by_severity[r.severity or "unknown"] = by_severity.get(r.severity or "unknown", 0) + 1
        by_host[r.host] = by_host.get(r.host, 0) + 1
    return {
        "total_detections": len(rows),
        "by_technique": by_technique,
        "by_severity": by_severity,
        "by_host": by_host,
    }
