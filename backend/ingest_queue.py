"""
Redis-backed async ingest queue (Phase 4 / F1).

A thin, fail-soft queue used by /ingest when INGEST_QUEUE_URL is configured.
The API enqueues a serialized artifact batch and returns 202; a standalone
worker (`python -m workers.ingest_worker`) drains the queue and persists each
batch through the same `ingest_service.ingest_artifacts` used by the
synchronous path, so idempotency (batch_id dedup) and host upserts behave
identically.

When the queue is disabled (INGEST_QUEUE_URL unset) or Redis is unreachable,
the caller falls back to synchronous persistence — preserving the single-
process open-lab behavior. Nothing here requires a running Redis unless
`queue_enabled()` is True.
"""
import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

INGEST_QUEUE_URL: Optional[str] = os.getenv("INGEST_QUEUE_URL") or None
INGEST_QUEUE_KEY: str = os.getenv("INGEST_QUEUE_KEY", "dfir:ingest")
INGEST_QUEUE_BLOCK_SECONDS: int = int(os.getenv("INGEST_QUEUE_BLOCK_SECONDS", "5"))

_client = None  # lazily-initialized redis client (importing redis is optional)


def queue_enabled() -> bool:
    """True when INGEST_QUEUE_URL is configured (async mode is active)."""
    return INGEST_QUEUE_URL is not None


def _redis_client():
    """Returns a lazily-created redis client, or None if the queue is disabled."""
    global _client
    if not queue_enabled():
        return None
    if _client is None:
        import redis

        _client = redis.Redis.from_url(INGEST_QUEUE_URL, decode_responses=True)
    return _client


def enqueue_artifacts(artifacts: List[Dict], batch_id: Optional[str] = None) -> bool:
    """Pushes a batch onto the ingest queue. Returns True on success.

    Fail-soft: any Redis error (including client setup) is logged and False is
    returned so the route can fall back to synchronous persistence rather than
    dropping the batch.
    """
    message = json.dumps({"batch_id": batch_id, "artifacts": artifacts})
    try:
        client = _redis_client()
        if client is None:
            return False
        client.rpush(INGEST_QUEUE_KEY, message)
        return True
    except Exception as exc:  # noqa: BLE001 — queue must never crash the API
        logger.warning("Enqueue failed (%s); falling back to sync ingest", exc)
        return False


def dequeue_batch() -> Optional[Dict]:
    """Blocks for up to INGEST_QUEUE_BLOCK_SECONDS and returns one batch dict.

    Returns None on timeout or on any Redis error (the worker loop just keeps
    polling). Artifacts come back as plain dicts ready for Pydantic parsing.
    """
    try:
        client = _redis_client()
        if client is None:
            return None
        _key, raw = client.blpop(INGEST_QUEUE_KEY, timeout=INGEST_QUEUE_BLOCK_SECONDS)
        if raw is None:
            return None
        return json.loads(raw)
    except (TypeError, ValueError):
        return None
    except Exception as exc:  # noqa: BLE001 — worker must survive Redis hiccups
        logger.warning("Dequeue failed (%s); retrying", exc)
        return None
