"""Ingest business logic — persists artifact batches and refreshes host state.

Kept out of the route handler so /ingest stays thin and the logic is
unit-testable without the HTTP layer. Raises ValueError on an empty batch;
the route maps that to HTTP 400.

Phase 2: idempotent batches. An agent may pass a `batch_id` (a per-run
identifier it generates); if the same batch for the same host was already
ingested, the re-post is a no-op and the response reports `deduplicated`.
"""
import json
from collections import Counter
from typing import Optional

import models
import schemas


def ingest_artifacts(
    db, artifacts: list, batch_id: Optional[str] = None
) -> schemas.IngestResponse:
    """Stores a batch of artifacts, upserting the reporting host in one commit.

    batch_id: optional idempotency key. When provided, a previous ingestion of
    the same (host, batch_id) is detected and the batch is skipped.
    """
    if not artifacts:
        raise ValueError("Empty artifact list")

    hostname = artifacts[0].host
    os_name = artifacts[0].os

    if batch_id:
        existing = (
            db.query(models.Artifact)
            .filter(models.Artifact.host == hostname)
            .filter(models.Artifact.agent_batch_id == batch_id)
            .first()
        )
        if existing:
            return schemas.IngestResponse(
                ingested=0,
                host=hostname,
                artifact_types=[],
                deduplicated=1,
                batch_id=batch_id,
            )

    host_row = db.query(models.Host).filter(models.Host.hostname == hostname).first()
    if host_row is None:
        host_row = models.Host(hostname=hostname, os=os_name)
        db.add(host_row)
    else:
        host_row.os = os_name  # keep it current in case the OS field ever changes

    type_counter: Counter = Counter()
    for artifact in artifacts:
        db.add(
            models.Artifact(
                host=artifact.host,
                os=artifact.os,
                artifact_type=artifact.artifact_type,
                collected_at=artifact.collected_at,
                data=json.dumps(artifact.data),
                agent_batch_id=batch_id,
            )
        )
        type_counter[artifact.artifact_type] += 1

    db.commit()

    return schemas.IngestResponse(
        ingested=len(artifacts),
        host=hostname,
        artifact_types=list(type_counter.keys()),
        deduplicated=0,
        batch_id=batch_id,
    )
