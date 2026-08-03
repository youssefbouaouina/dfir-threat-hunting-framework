"""Tests for Phase 4 (F1): async ingest queue + worker persistence."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import ingest_queue


class _FakeRedis:
    """Minimal list-based stand-in for the redis client the queue module uses."""

    def __init__(self):
        self.store = []

    def rpush(self, key, value):
        self.store.append(value)
        return len(self.store)

    def blpop(self, key, timeout=None):
        if not self.store:
            return None
        return key, self.store.pop(0)


@pytest.fixture(autouse=True)
def _isolate_queue(monkeypatch):
    """Ensure tests never touch a real Redis and always start clean."""
    monkeypatch.setattr(ingest_queue, "INGEST_QUEUE_URL", "redis://localhost:6379/0")
    monkeypatch.setattr(ingest_queue, "_client", None)
    monkeypatch.setattr(ingest_queue, "INGEST_QUEUE_BLOCK_SECONDS", 1)
    yield
    monkeypatch.setattr(ingest_queue, "INGEST_QUEUE_URL", None)
    monkeypatch.setattr(ingest_queue, "_client", None)


def test_queue_disabled_by_default():
    ingest_queue.INGEST_QUEUE_URL = None
    assert ingest_queue.queue_enabled() is False
    assert ingest_queue.enqueue_artifacts([{"a": 1}]) is False


def test_enqueue_then_dequeue_roundtrip(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(ingest_queue, "_redis_client", lambda: fake)

    ok = ingest_queue.enqueue_artifacts([{"host": "h", "os": "linux"}], batch_id="run-1")
    assert ok is True
    assert len(fake.store) == 1

    payload = ingest_queue.dequeue_batch()
    assert payload["batch_id"] == "run-1"
    assert payload["artifacts"] == [{"host": "h", "os": "linux"}]


def test_enqueue_falls_back_when_redis_errors(monkeypatch):
    def _boom():
        raise RuntimeError("redis down")

    monkeypatch.setattr(ingest_queue, "_redis_client", _boom)
    assert ingest_queue.enqueue_artifacts([{"host": "h"}]) is False


def test_dequeue_returns_none_on_timeout(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(ingest_queue, "_redis_client", lambda: fake)
    assert ingest_queue.dequeue_batch() is None


def test_worker_persists_batch(db_session, monkeypatch, tmp_path):
    """The worker persists a queued batch through the real ingest service."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import models
    import workers.ingest_worker as worker

    engine = create_engine(
        f"sqlite:///{tmp_path}/worker.db", connect_args={"check_same_thread": False}
    )
    models.Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine)

    monkeypatch.setattr(worker, "SessionLocal", testing_session)

    summary = worker.persist_batch(
        [
            {
                "host": "edge-w",
                "os": "linux",
                "collected_at": "2026-01-01T00:00:00Z",
                "artifact_type": "process",
                "data": {"name": "ps"},
            }
        ],
        batch_id="async-run-1",
    )

    assert summary.ingested == 1
    assert summary.host == "edge-w"

    db = testing_session()
    try:
        from models import Artifact

        assert db.query(Artifact).count() == 1
        assert db.query(Artifact).first().agent_batch_id == "async-run-1"
    finally:
        db.close()


def test_worker_process_one_no_op_when_queue_empty(monkeypatch):
    import workers.ingest_worker as worker

    monkeypatch.setattr(worker, "dequeue_batch", lambda: None)
    assert worker.process_one() is False


def test_api_returns_202_when_queue_enabled(client, monkeypatch):
    """/ingest returns 202 Accepted (not persisted inline) when the queue is on."""
    calls = {}

    def fake_enqueue(artifacts, batch_id=None):
        calls["artifacts"] = artifacts
        calls["batch_id"] = batch_id
        return True

    monkeypatch.setattr(ingest_queue, "queue_enabled", lambda: True)
    monkeypatch.setattr(ingest_queue, "enqueue_artifacts", fake_enqueue)

    artifact = {
        "host": "edge-q",
        "os": "linux",
        "collected_at": "2026-01-01T00:00:00Z",
        "artifact_type": "process",
        "data": {"name": "ps"},
    }
    resp = client.post("/ingest", json=[artifact], params={"batch_id": "q-1"})

    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] is True
    assert body["queued"] == 1
    assert body["ingested"] == 0
    assert calls["batch_id"] == "q-1"
    assert calls["artifacts"][0]["data"]["name"] == "ps"

    # Nothing persisted yet — the worker does that.
    assert client.get("/artifacts").json() == []


def test_api_falls_back_to_sync_when_queue_enqueue_fails(client, monkeypatch):
    monkeypatch.setattr(ingest_queue, "queue_enabled", lambda: True)
    monkeypatch.setattr(ingest_queue, "enqueue_artifacts", lambda artifacts, batch_id=None: False)

    artifact = {
        "host": "edge-s",
        "os": "linux",
        "collected_at": "2026-01-01T00:00:00Z",
        "artifact_type": "process",
        "data": {"name": "ps"},
    }
    resp = client.post("/ingest", json=[artifact], params={"batch_id": "s-1"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] is False
    assert body["ingested"] == 1


def test_api_sync_default_when_queue_disabled(client, monkeypatch):
    monkeypatch.setattr(ingest_queue, "queue_enabled", lambda: False)

    artifact = {
        "host": "edge-sync",
        "os": "linux",
        "collected_at": "2026-01-01T00:00:00Z",
        "artifact_type": "process",
        "data": {"name": "ps"},
    }
    resp = client.post("/ingest", json=[artifact])

    assert resp.status_code == 200
    assert resp.json()["ingested"] == 1
