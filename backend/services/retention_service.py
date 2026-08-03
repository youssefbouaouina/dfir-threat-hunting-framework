"""Storage retention/archival (Phase 4 / F3).

Runs a retention policy over the append-only history tables. For each table
with a configured window (RETENTION_DAYS_*), rows older than the cutoff are:

  1) appended to a monthly JSONL archive under RETENTION_ARCHIVE_DIR
     ({archive_dir}/{table}/YYYY-MM.jsonl),
  2) bulk-indexed into OpenSearch when OPENSEARCH_URL is set (fail-soft), and
  3) deleted from the database in batches of RETENTION_BATCH_SIZE.

Retention is OFF by default (all windows 0), preserving the open-lab/demo
behaviour; operators opt in to bound storage growth. Design notes:

  * The archive is the source of truth after deletion — if an OpenSearch sink
    fails the rows are still safe in JSONL, so a sink error never aborts the
    sweep.
  * Batches are ordered by ascending id and committed one at a time, so a
    crash mid-sweep only loses progress up to the last committed batch.
  * Deleting detections also removes their IncidentDetection links (membership
    is rebuilt idempotently by the correlation engine on the next run).
"""
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import requests

import models

logger = logging.getLogger(__name__)

# table name -> (model, the time column retention is measured against)
_TABLES: Dict[str, tuple] = {
    "artifacts": (models.Artifact, "ingested_at"),
    "detections": (models.Detection, "detected_at"),
    "detection_runs": (models.DetectionRun, "started_at"),
    "audit_logs": (models.AuditLog, "created_at"),
}


def _model_for(table: str):
    return _TABLES[table][0]


def _time_col_for(table: str) -> str:
    return _TABLES[table][1]

_WINDOW_ENV: Dict[str, str] = {
    "artifacts": "RETENTION_DAYS_ARTIFACTS",
    "detections": "RETENTION_DAYS_DETECTIONS",
    "detection_runs": "RETENTION_DAYS_DETECTION_RUNS",
    "audit_logs": "RETENTION_DAYS_AUDIT_LOGS",
}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def window_days(table: str) -> int:
    """Configured retention window (days) for a table; 0 = retention disabled."""
    return _env_int(_WINDOW_ENV[table], 0)


def _row_to_record(table: str, row) -> dict:
    """Serializes one ORM row into an archive record (datetimes -> ISO strings)."""
    record = {"_table": table}
    for col in row.__table__.columns:
        value = getattr(row, col.name)
        if isinstance(value, datetime):
            value = value.isoformat()
        record[col.name] = value
    return record


def _append_jsonl(table: str, records: List[dict], time_col: str, archive_dir: str) -> None:
    """Appends records to monthly JSONL files; one line per record."""
    by_month: Dict[str, List[dict]] = {}
    for rec in records:
        ts = rec.get(time_col) or ""
        month = ts[:7] if ts else "unknown"
        by_month.setdefault(month, []).append(rec)
    for month, lines in by_month.items():
        path = os.path.join(archive_dir, table, f"{month}.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(json.dumps(line) + "\n")


def _sink_opensearch(
    records: List[dict], url: str, index_prefix: str
) -> None:
    """Best-effort bulk index of archived records. Fail-soft, never raises."""
    if not url:
        return
    try:
        lines: List[str] = []
        for rec in records:
            index = f"{index_prefix}-{rec['_table']}"
            doc_id = f"{rec['_table']}-{rec['id']}"
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
            lines.append(json.dumps(rec))
        resp = requests.post(
            f"{url}/_bulk",
            data="\n".join(lines) + "\n",
            headers={"Content-Type": "application/x-ndjson"},
            timeout=10,
        )
        resp.raise_for_status()
    except Exception:  # noqa: BLE001 — the JSONL archive already holds the rows
        logger.warning("OpenSearch sink failed; archived rows are safe in JSONL", exc_info=True)


def _cleanup_links(db, table: str, ids: List[int]) -> None:
    """Drops cross-table links for rows being deleted (keeps referential sanity)."""
    if table == "detections":
        db.query(models.IncidentDetection).filter(
            models.IncidentDetection.detection_id.in_(ids)
        ).delete(synchronize_session=False)


def run_retention(
    db,
    days: Optional[Dict[str, int]] = None,
    archive_dir: Optional[str] = None,
    opensearch_url: Optional[str] = None,
    opensearch_index_prefix: Optional[str] = None,
    batch_size: Optional[int] = None,
) -> dict:
    """Enforces the retention policy; returns a per-table summary.

    Arguments default to the environment configuration so callers (scheduler,
    HTTP routes, tests) can either drive it via env or override explicitly.
    """
    days = days if days is not None else {t: window_days(t) for t in _TABLES}
    resolved_archive_dir: str = (
        archive_dir
        if archive_dir is not None
        else os.getenv("RETENTION_ARCHIVE_DIR", "./retention_archive")
    )
    url = (
        opensearch_url
        if opensearch_url is not None
        else os.getenv("OPENSEARCH_URL", "")
    ).rstrip("/")
    index_prefix: str = (
        opensearch_index_prefix
        if opensearch_index_prefix is not None
        else os.getenv("OPENSEARCH_INDEX_PREFIX", "dfir")
    )
    batch_size = batch_size or _env_int("RETENTION_BATCH_SIZE", 500)

    now = datetime.now(timezone.utc)
    summary: dict = {}
    for table in _TABLES:
        model = _model_for(table)
        time_col = _time_col_for(table)
        window = days.get(table, 0) or 0
        if window <= 0:
            summary[table] = {"enabled": False, "days": window, "archived": 0, "deleted": 0}
            continue

        cutoff = now - timedelta(days=window)
        col = getattr(model, time_col)
        archived = deleted = 0
        try:
            while True:
                batch = (
                    db.query(model)
                    .filter(col < cutoff)
                    .order_by(model.id.asc())
                    .limit(batch_size)
                    .all()
                )
                if not batch:
                    break
                records = [_row_to_record(table, row) for row in batch]
                _append_jsonl(table, records, time_col, resolved_archive_dir)
                _sink_opensearch(records, url, index_prefix)
                ids = [row.id for row in batch]
                _cleanup_links(db, table, ids)
                db.query(model).filter(model.id.in_(ids)).delete(synchronize_session=False)
                db.commit()
                archived += len(records)
                deleted += len(ids)
        except Exception:  # noqa: BLE001 — one table must not kill the whole sweep
            logger.exception("Retention failed for table %s", table)
            db.rollback()
        summary[table] = {
            "enabled": True,
            "days": window,
            "archived": archived,
            "deleted": deleted,
        }
    return summary


def retention_status(
    db, days: Optional[Dict[str, int]] = None
) -> dict:
    """Read-only view of the policy and how many rows are currently eligible."""
    days = days if days is not None else {t: window_days(t) for t in _TABLES}
    now = datetime.now(timezone.utc)
    tables = {}
    for table in _TABLES:
        model = _model_for(table)
        time_col = _time_col_for(table)
        window = days.get(table, 0) or 0
        if window <= 0:
            tables[table] = {"enabled": False, "days": window, "eligible": 0}
            continue
        col = getattr(model, time_col)
        cutoff = now - timedelta(days=window)
        eligible = db.query(model).filter(col < cutoff).count()
        tables[table] = {"enabled": True, "days": window, "eligible": eligible}
    return {
        "archive_dir": os.getenv("RETENTION_ARCHIVE_DIR", "./retention_archive"),
        "opensearch_enabled": bool(os.getenv("OPENSEARCH_URL", "")),
        "opensearch_index_prefix": os.getenv("OPENSEARCH_INDEX_PREFIX", "dfir"),
        "tables": tables,
    }
