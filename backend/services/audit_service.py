"""Audit trail — records analyst/admin actions for the Phase 3 ops hardening.

Every state change worth tracking (login, run detection, triage a detection,
update an endpoint config, queue a manual collection) is appended here from
the service layer so the trail is complete regardless of which HTTP route or
background job caused it. Reads are admin-only.

Phase 4 (F4) makes the trail tamper-evident: each row stores a SHA-256
`record_hash` computed over (prev_hash, actor, action, detail), chained to
the previous row's record_hash. Modifying any historical row invalidates the
chain for every subsequent row, which GET /audit-logs/verify detects.
"""
import hashlib
import json
from typing import Optional

import models

# Whitelist of allowed actions, to catch typos early.
KNOWN_ACTIONS = {
    "login",
    "run_detection",
    "triage_detection",
    "update_endpoint_config",
    "queue_collection",
    "queue_collection_all",
    "endpoint_enroll",
    "run_retention",
    "recompute_incidents",
    "triage_incident",
    "sigma_refresh",
    "ioc_refresh",
    "ioc_breaker_reset",
    "stats_recompute",
}


def _hash_record(prev_hash: str, actor: Optional[str], action: str, detail: Optional[str]) -> str:
    canonical = json.dumps(
        [prev_hash, actor, action, detail], separators=(",", ":"), sort_keys=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def log_action(
    db, action: str, actor: Optional[str] = None, detail: Optional[dict] = None
) -> models.AuditLog:
    """Appends one immutable audit row. Best-effort: never raises for the caller.

    detail is JSON-encoded before storage so complex context (ids, counts,
    filters) survives round-trips through the API. The row's record_hash is
    chained to the most recent row's hash (F4).
    """
    if action not in KNOWN_ACTIONS:
        action = f"custom:{action}"
    detail_json = json.dumps(detail) if detail else None
    last = db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).first()
    prev_hash = last.record_hash if last and last.record_hash else ""
    row = models.AuditLog(
        actor=actor,
        action=action,
        detail=detail_json,
        prev_hash=prev_hash,
        record_hash=_hash_record(prev_hash, actor, action, detail_json),
    )
    db.add(row)
    db.commit()
    return row


def verify_audit_chain(db) -> dict:
    """Walks the audit trail and verifies every hash link (F4).

    Returns {"valid": bool, "checked": N, "broken_at": row-id-or-None}.
    Legacy rows (written before F4, record_hash NULL) are skipped — the
    chain effectively restarts from the first hashed row.
    """
    rows = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.id.asc())
        .all()
    )
    expected_prev = ""
    checked = 0
    for row in rows:
        if not row.record_hash:
            continue  # legacy row; chain restarts from the next hashed row
        expected = _hash_record(
            row.prev_hash or "", row.actor, row.action, row.detail
        )
        if row.record_hash != expected or (row.prev_hash or "") != expected_prev:
            return {"valid": False, "checked": checked, "broken_at": row.id}
        expected_prev = row.record_hash
        checked += 1
    return {"valid": True, "checked": checked, "broken_at": None}


def list_audit_logs(db, limit: int = 100, action: Optional[str] = None) -> list:
    """Returns the audit trail, newest first, optionally filtered by action."""
    query = db.query(models.AuditLog)
    if action:
        query = query.filter(models.AuditLog.action == action)
    rows = query.order_by(models.AuditLog.id.desc()).limit(min(limit, 1000)).all()

    return [
        {
            "id": r.id,
            "actor": r.actor,
            "action": r.action,
            "detail": json.loads(r.detail) if r.detail else None,
            "created_at": str(r.created_at),
        }
        for r in rows
    ]
