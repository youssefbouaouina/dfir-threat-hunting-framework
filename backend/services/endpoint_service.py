"""Endpoint inventory business logic — enrollment, health, and agent config.

Phase 2: replaces the passive `hosts` view with a managed endpoint inventory.
Agents enroll themselves (registering hostname/os/version), the backend stores
an enrollment token hash, and agents poll their per-endpoint config on each
collection cycle. The passive `Host` table still gets refreshed on ingest for
backwards compatibility.
"""
import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import models
from services.audit_service import log_action

logger = logging.getLogger("dfir.endpoint_service")

DEFAULT_CONFIG = {
    "collectors": ["processes", "network", "persistence", "scheduled_tasks", "logs", "file_scan"],
    "interval_seconds": 300,
}


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def enroll_endpoint(
    db, hostname: str, os_name: str, agent_version: Optional[str] = None
) -> dict:
    """Registers (or refreshes) an endpoint and returns its id + agent config.

    Re-enrollment with the same hostname updates os/version/status and returns
    the same endpoint id — the flow is idempotent.

    A one-time enrollment token is issued **only on first enrollment** (when no
    hash is stored yet) and returned in the payload; the backend keeps only the
    SHA-256 hash, so a lost token cannot be recovered and requires re-enrollment.
    """
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.hostname == hostname).first()
    is_first = endpoint is None or not endpoint.enrollment_token_hash

    if endpoint is None:
        endpoint = models.Endpoint(hostname=hostname, os=os_name, agent_version=agent_version)
        db.add(endpoint)
    else:
        endpoint.os = os_name
        endpoint.agent_version = agent_version or endpoint.agent_version

    token = None
    if is_first:
        token = secrets.token_urlsafe(32)
        endpoint.enrollment_token_hash = _hash_token(token)

    endpoint.status = "online"
    endpoint.last_seen = datetime.now(timezone.utc)
    db.commit()

    config = json.loads(endpoint.config_json) if endpoint.config_json else dict(DEFAULT_CONFIG)

    log_action(
        db,
        "endpoint_enroll",
        actor=hostname,
        detail={"endpoint_id": endpoint.id, "os": endpoint.os, "issued_token": bool(token)},
    )

    return {
        "id": endpoint.id,
        "hostname": endpoint.hostname,
        "os": endpoint.os,
        "agent_version": endpoint.agent_version,
        "status": endpoint.status,
        "last_seen": endpoint.last_seen,
        "config": config,
        "enrollment_token": token,
    }


def update_endpoint_config(
    db,
    endpoint_id: int,
    collectors: Optional[list] = None,
    interval_seconds: Optional[int] = None,
) -> Optional[dict]:
    """Admin edits a single endpoint's agent config (Phase 3 dashboard control).

    Only the provided fields change; unset fields keep their current value
    (which defaults to DEFAULT_CONFIG for a fresh endpoint). Returns None if
    the endpoint id is unknown.
    """
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if endpoint is None:
        return None

    config = json.loads(endpoint.config_json) if endpoint.config_json else dict(DEFAULT_CONFIG)
    if collectors is not None:
        config["collectors"] = collectors
    if interval_seconds is not None:
        if interval_seconds < 10:
            raise ValueError("interval_seconds must be at least 10")
        config["interval_seconds"] = interval_seconds

    endpoint.config_json = json.dumps(config)
    db.commit()

    log_action(
        db,
        "update_endpoint_config",
        actor="admin",
        detail={"endpoint_id": endpoint_id, "config": config},
    )

    return {
        "id": endpoint.id,
        "hostname": endpoint.hostname,
        "os": endpoint.os,
        "agent_version": endpoint.agent_version,
        "status": endpoint.status,
        "last_seen": endpoint.last_seen,
        "registered_at": endpoint.registered_at,
        "config": config,
    }


def queue_collection(db, endpoint_id: int, actor: str = "admin") -> Optional[dict]:
    """Queues a 'run_collection' pending command for an endpoint (Phase 3).

    The dashboard's "Run collection now" button calls this; the agent picks
    the command up on its next poll and reports back via complete_command().
    Returns None if the endpoint id is unknown.
    """
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if endpoint is None:
        return None

    cmd = models.PendingCommand(
        hostname=endpoint.hostname,
        command="run_collection",
        status="pending",
    )
    db.add(cmd)
    db.commit()

    log_action(
        db,
        "queue_collection",
        actor=actor,
        detail={"endpoint_id": endpoint_id, "hostname": endpoint.hostname, "command_id": cmd.id},
    )

    return {
        "command_id": cmd.id,
        "hostname": endpoint.hostname,
        "command": "run_collection",
        "status": "pending",
    }


def poll_pending_commands(db, hostname: str) -> list:
    """Returns the pending commands for an endpoint and marks them picked up.

    Called by the agent on each poll cycle; commands are returned once
    (pending -> picked_up) so a retry doesn't re-run a collection.
    """
    now = datetime.now(timezone.utc)
    rows = (
        db.query(models.PendingCommand)
        .filter(models.PendingCommand.hostname == hostname)
        .filter(models.PendingCommand.status == "pending")
        .order_by(models.PendingCommand.id.asc())
        .all()
    )
    for row in rows:
        row.status = "picked_up"
        row.picked_up_at = now
    db.commit()

    return [
        {
            "id": r.id,
            "hostname": r.hostname,
            "command": r.command,
            "params": json.loads(r.params) if r.params else None,
            "status": r.status,
        }
        for r in rows
    ]


def complete_command(
    db, command_id: int, status: str = "completed", result: Optional[dict] = None
) -> Optional[dict]:
    """Agent reports the outcome of a picked-up command (marks it done).

    Returns None if the command id is unknown.
    """
    row = db.query(models.PendingCommand).filter(models.PendingCommand.id == command_id).first()
    if row is None:
        return None

    row.status = status
    row.result = json.dumps(result) if result else None
    row.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {"command_id": row.id, "status": row.status}


def list_endpoints(db, limit: int = 100, team: Optional[str] = None) -> list:
    """Returns the managed endpoint inventory, newest registration first.

    `team` (F4) scopes the inventory to a single team when provided.
    """
    query = db.query(models.Endpoint)
    if team:
        query = query.filter(models.Endpoint.team == team)
    rows = query.order_by(models.Endpoint.id.desc()).limit(min(limit, 500)).all()
    return [
        {
            "id": r.id,
            "hostname": r.hostname,
            "os": r.os,
            "agent_version": r.agent_version,
            "status": r.status,
            "last_seen": r.last_seen,
            "registered_at": r.registered_at,
            "team": r.team,
            "config": json.loads(r.config_json) if r.config_json else dict(DEFAULT_CONFIG),
        }
        for r in rows
    ]


def _touch_endpoint(db, hostname: str) -> None:
    """Refreshes the endpoint's heartbeat timestamp (its status flips back to online)."""
    endpoint = (
        db.query(models.Endpoint).filter(models.Endpoint.hostname == hostname).first()
    )
    if endpoint is None:
        return
    endpoint.status = "online"
    endpoint.last_seen = datetime.now(timezone.utc)
    db.commit()


def get_endpoint_config(db, hostname: str) -> dict:
    """Returns the collection config an agent should follow for its hostname.

    Doubles as the agent's heartbeat: any poll refreshes last_seen, so the
    offline sweep (mark_offline_stale) can rely on it.
    """
    _touch_endpoint(db, hostname)
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.hostname == hostname).first()
    if endpoint is None:
        return dict(DEFAULT_CONFIG)
    return json.loads(endpoint.config_json) if endpoint.config_json else dict(DEFAULT_CONFIG)


def mark_offline_stale(db, stale_after_seconds: int = 900) -> int:
    """Marks endpoints that stopped polling 'offline' (M6).

    An endpoint whose last_seen is older than `stale_after_seconds` (default
    15 min = 3x the default 5-min poll interval) is flipped to offline.
    Returns the number of endpoints transitioned online -> offline.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)
    stale = (
        db.query(models.Endpoint)
        .filter(models.Endpoint.status == "online")
        .filter(
            models.Endpoint.last_seen.is_(None)
            | (models.Endpoint.last_seen < cutoff)
        )
        .all()
    )
    for endpoint in stale:
        endpoint.status = "offline"
    if stale:
        db.commit()
        logger.info(
            "Marked %d endpoint(s) offline (last poll > %ss ago)",
            len(stale),
            stale_after_seconds,
        )
    return len(stale)
