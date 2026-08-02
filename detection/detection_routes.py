"""
Detection API routes — matured/final version.

Runs the full detection pipeline against every unprocessed artifact:
  1. Sigma-style behavioral rules  -> process / persistence / scheduled_task / network
  2. YARA file-scan results        -> file_scan artifacts (scanned agent-side, results embedded)
  3. Known-bad hash matching        -> file_scan artifacts, against iocs/known_bad_hashes.txt
  4. Network IOC correlation        -> network artifacts, local blocklist + optional live feed

Every detection is persisted to the `detections` table (not recomputed
each call), enriched with ATT&CK technique name/tactic, and every
scanned artifact is marked processed=1 so a re-run doesn't duplicate work.

Designed as a self-contained APIRouter — wire into backend/main.py with:

    from detection_routes import router as detection_router
    app.include_router(detection_router)
"""
import json
import os

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
import models

from sigma_matcher import load_rules as load_sigma_rules, evaluate as evaluate_sigma
from hash_checker import check_file_scan_artifacts
from ioc_correlation import correlate_network_artifacts
from attck_mapper import enrich_technique

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIGMA_RULES_DIR = os.path.join(BASE_DIR, "sigma_rules")


def _row_to_artifact_dict(row) -> dict:
    return {
        "host": row.host,
        "os": row.os,
        "artifact_type": row.artifact_type,
        "collected_at": row.collected_at,
        "data": json.loads(row.data),
    }


def _persist_detection(db: Session, d: dict) -> models.Detection:
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


@router.post("/detect")
def run_detection(db: Session = Depends(get_db)):
    unprocessed = db.query(models.Artifact).filter(models.Artifact.processed == 0).all()
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
    db.commit()

    return {
        "artifacts_scanned": len(artifacts),
        "detections_found": len(all_detections),
        "by_severity": _count_by(all_detections, "severity"),
        "by_technique": _count_by(all_detections, "technique_id"),
    }


def _count_by(detections: list, field: str) -> dict:
    counts = {}
    for d in detections:
        key = d.get(field) or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


@router.get("/detections")
def list_detections(host: str = None, severity: str = None, limit: int = 100, db: Session = Depends(get_db)):
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


@router.get("/detections/summary")
def detections_summary(db: Session = Depends(get_db)):
    """Feeds the dashboard's ATT&CK-coverage view — technique/tactic counts across all stored detections."""
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
