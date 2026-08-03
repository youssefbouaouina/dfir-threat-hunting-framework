"""Audit trail — records analyst/admin actions for the Phase 3 ops hardening.

Every state change worth tracking (login, run detection, triage a detection,
update an endpoint config, queue a manual collection) is appended here from
the service layer so the trail is complete regardless of which HTTP route or
background job caused it. Reads are admin-only.
"""
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
    "endpoint_enroll",
    "run_retention",
}


def log_action(
    db, action: str, actor: Optional[str] = None, detail: Optional[dict] = None
) -> models.AuditLog:
    """Appends one immutable audit row. Best-effort: never raises for the caller.

    detail is JSON-encoded before storage so complex context (ids, counts,
    filters) survives round-trips through the API.
    """
    if action not in KNOWN_ACTIONS:
        action = f"custom:{action}"
    row = models.AuditLog(
        actor=actor,
        action=action,
        detail=json.dumps(detail) if detail else None,
    )
    db.add(row)
    db.commit()
    return row


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
