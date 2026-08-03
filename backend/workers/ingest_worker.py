"""
Async ingest worker (Phase 4 / F1).

Consumes artifact batches from the Redis ingest queue (see `ingest_queue`) and
persists each one through the exact same `ingest_service.ingest_artifacts`
used by the synchronous /ingest path — so batch_id idempotency, host upserts,
and response shapes are identical.

Run with the queue configured and the same DATABASE_URL as the API:

    INGEST_QUEUE_URL=redis://redis:6379/0 \
    DATABASE_URL=postgresql+psycopg2://dfir:dfir@db:5432/dfir \
    python -m workers.ingest_worker

The loop is crash-tolerant: a failed batch is logged (and left unacked), Redis
hiccups just pause the poll, and a KeyboardInterrupt stops cleanly.
"""
import logging
import time
from typing import Dict, List, Optional

import schemas
from database import SessionLocal
from ingest_queue import dequeue_batch, queue_enabled
from logging_config import configure_logging

logger = logging.getLogger("dfir.ingest_worker")


def persist_batch(artifacts: List[Dict], batch_id: Optional[str] = None) -> schemas.IngestResponse:
    """Persists one dequeued batch and returns the ingest summary.

    Exposed as a module-level function so unit tests can drive it with a
    session-scoped DB without running the blocking loop.
    """
    from services import ingest_service

    parsed = [schemas.ArtifactIn(**artifact) for artifact in artifacts]
    db = SessionLocal()
    try:
        return ingest_service.ingest_artifacts(db, parsed, batch_id=batch_id)
    finally:
        db.close()


def process_one() -> bool:
    """Pops and persists a single batch. Returns True if a batch was handled."""
    payload = dequeue_batch()
    if not payload:
        return False
    batch_id = payload.get("batch_id")
    artifacts = payload.get("artifacts", [])
    try:
        summary = persist_batch(artifacts, batch_id=batch_id)
        logger.info("Persisted batch %s: %s", batch_id, summary)
    except Exception as exc:  # noqa: BLE001 — one bad batch must not kill the worker
        logger.exception("Failed to persist batch %s: %s", batch_id, exc)
    return True


def run_loop(interval_seconds: float = 0.5) -> None:
    """Blocks forever draining the ingest queue."""
    configure_logging()
    logger.info("Ingest worker started (queue enabled=%s)", queue_enabled())
    while True:
        try:
            process_one()
            time.sleep(interval_seconds)
        except KeyboardInterrupt:
            logger.info("Ingest worker stopped by signal")
            break


if __name__ == "__main__":
    run_loop()
