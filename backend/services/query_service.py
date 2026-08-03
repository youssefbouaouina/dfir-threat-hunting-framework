"""Read/query business logic — artifact and host lookups for the API.

Centralized so the thin endpoints only validate params and hand off here,
and so new filters (time windows, processed state) are testable in one place.
"""
import json

import models


def list_artifacts(
    db,
    host=None,
    artifact_type=None,
    collected_since=None,
    collected_until=None,
    processed=None,
    limit=50,
    before_id=None,
) -> list:
    """Returns up to `limit` artifacts (newest first), applying optional filters.

    `before_id` is an optional cursor: only artifacts with id < before_id are
    returned, so paging by the last id seen never drifts when new rows arrive.
    """
    query = db.query(models.Artifact)
    if host:
        query = query.filter(models.Artifact.host == host)
    if artifact_type:
        query = query.filter(models.Artifact.artifact_type == artifact_type)
    if collected_since:
        query = query.filter(models.Artifact.collected_at >= collected_since)
    if collected_until:
        query = query.filter(models.Artifact.collected_at <= collected_until)
    if processed is not None:
        query = query.filter(models.Artifact.processed == processed)
    if before_id is not None:
        query = query.filter(models.Artifact.id < before_id)

    rows = query.order_by(models.Artifact.id.desc()).limit(limit).all()

    return [
        {
            "id": row.id,
            "host": row.host,
            "os": row.os,
            "artifact_type": row.artifact_type,
            "collected_at": row.collected_at,
            "data": json.loads(row.data),
            "ingested_at": row.ingested_at,
            "processed": row.processed,
        }
        for row in rows
    ]


def list_hosts(db) -> list:
    """Returns every host that has ever reported in, newest last_seen first."""
    hosts = db.query(models.Host).order_by(models.Host.last_seen.desc()).all()
    return [
        {"id": h.id, "hostname": h.hostname, "os": h.os, "last_seen": h.last_seen}
        for h in hosts
    ]
