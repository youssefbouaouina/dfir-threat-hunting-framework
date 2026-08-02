"""Endpoint inventory business logic — enrollment, health, and agent config.

Phase 2: replaces the passive `hosts` view with a managed endpoint inventory.
Agents enroll themselves (registering hostname/os/version), the backend stores
an enrollment token hash, and agents poll their per-endpoint config on each
collection cycle. The passive `Host` table still gets refreshed on ingest for
backwards compatibility.
"""
import hashlib
import json
import secrets
from datetime import datetime, timezone

import models

DEFAULT_CONFIG = {
    "collectors": ["processes", "network", "persistence", "scheduled_tasks", "logs", "file_scan"],
    "interval_seconds": 300,
}


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def enroll_endpoint(db, hostname: str, os_name: str, agent_version: str = None) -> dict:
    """Registers (or refreshes) an endpoint and returns its id + agent config.

    Re-enrollment with the same hostname updates os/version/status and returns
    the same endpoint id — the flow is idempotent.
    """
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.hostname == hostname).first()
    if endpoint is None:
        endpoint = models.Endpoint(hostname=hostname, os=os_name, agent_version=agent_version)
        db.add(endpoint)
    else:
        endpoint.os = os_name
        endpoint.agent_version = agent_version or endpoint.agent_version

    if not endpoint.enrollment_token_hash:
        token = secrets.token_urlsafe(32)
        endpoint.enrollment_token_hash = _hash_token(token)

    endpoint.status = "online"
    endpoint.last_seen = datetime.now(timezone.utc)
    db.commit()

    config = json.loads(endpoint.config_json) if endpoint.config_json else dict(DEFAULT_CONFIG)

    return {
        "id": endpoint.id,
        "hostname": endpoint.hostname,
        "os": endpoint.os,
        "agent_version": endpoint.agent_version,
        "status": endpoint.status,
        "last_seen": endpoint.last_seen,
        "config": config,
    }


def list_endpoints(db, limit: int = 100) -> list:
    """Returns the managed endpoint inventory, newest registration first."""
    rows = (
        db.query(models.Endpoint)
        .order_by(models.Endpoint.id.desc())
        .limit(min(limit, 500))
        .all()
    )
    return [
        {
            "id": r.id,
            "hostname": r.hostname,
            "os": r.os,
            "agent_version": r.agent_version,
            "status": r.status,
            "last_seen": r.last_seen,
            "registered_at": r.registered_at,
            "config": json.loads(r.config_json) if r.config_json else dict(DEFAULT_CONFIG),
        }
        for r in rows
    ]


def get_endpoint_config(db, hostname: str) -> dict:
    """Returns the collection config an agent should follow for its hostname."""
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.hostname == hostname).first()
    if endpoint is None:
        return dict(DEFAULT_CONFIG)
    return json.loads(endpoint.config_json) if endpoint.config_json else dict(DEFAULT_CONFIG)
