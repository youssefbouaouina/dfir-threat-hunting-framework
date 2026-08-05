"""Tests for Phase 5 / F8 — circuit breakers, materialized stats, k8s manifests."""
import pytest
import yaml

from services import intel_service, stats_service
from services.circuit_breaker import CircuitBreaker, CircuitOpenError

# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

def test_breaker_closed_passes_and_recovers():
    breaker = CircuitBreaker("t", failure_threshold=2, reset_timeout_seconds=0)
    calls = {"n": 0}

    def ok():
        calls["n"] += 1
        return 42

    assert breaker.call(ok) == 42
    assert breaker.state == "closed"
    assert breaker.failure_count == 0


def test_breaker_trips_after_threshold_and_fails_fast():
    breaker = CircuitBreaker("t", failure_threshold=2, reset_timeout_seconds=60)
    calls = {"n": 0}

    def boom():
        calls["n"] += 1
        raise OSError("down")

    for _ in range(2):
        with pytest.raises(OSError):
            breaker.call(boom)
    assert breaker.state == "open"

    # fast-fail: the dependency is NOT called while the circuit is open
    with pytest.raises(CircuitOpenError):
        breaker.call(boom)
    assert calls["n"] == 2
    assert breaker.status()["state"] == "open"


def test_breaker_half_open_probe_recovers():
    breaker = CircuitBreaker("t", failure_threshold=1, reset_timeout_seconds=0)

    def boom():
        raise OSError("down")

    def ok():
        return "ok"

    with pytest.raises(OSError):
        breaker.call(boom)
    assert breaker.state == "open"

    # timeout elapsed (0) -> next call is a probe; success closes the circuit
    assert breaker.call(ok) == "ok"
    assert breaker.state == "closed"
    assert breaker.failure_count == 0


def test_breaker_manual_reset():
    breaker = CircuitBreaker("t", failure_threshold=1, reset_timeout_seconds=60)

    def boom():
        raise OSError("down")

    with pytest.raises(OSError):
        breaker.call(boom)
    assert breaker.state == "open"
    breaker.reset()
    assert breaker.state == "closed"
    assert breaker.failure_count == 0


# ---------------------------------------------------------------------------
# Feed circuit breakers wired into intel refresh
# ---------------------------------------------------------------------------

def test_intel_feed_breaker_skips_open_feed(db_session, monkeypatch):
    trip = {"n": 0}

    def boom():
        trip["n"] += 1
        raise OSError("down")

    def ok():
        return [
            {
                "value": "8.8.4.4",
                "ioc_type": "ip",
                "source": "feodo-tracker",
                "confidence": 85,
                "last_seen": None,
            }
        ]

    monkeypatch.setattr(
        intel_service,
        "_FETCHERS",
        {"feodo": boom, "urlhaus": ok},
    )
    monkeypatch.setattr(
        intel_service,
        "_BREAKERS",
        {
            "feodo": CircuitBreaker(
                "ioc-feed-feodo", failure_threshold=3, reset_timeout_seconds=300
            ),
            "urlhaus": CircuitBreaker(
                "ioc-feed-urlhaus", failure_threshold=3, reset_timeout_seconds=300
            ),
        },
    )

    # three failures trip the feodo breaker
    for _ in range(3):
        intel_service.refresh_all_feeds(db_session)
    assert intel_service._BREAKERS["feodo"].state == "open"
    assert trip["n"] == 3

    # next refresh: feodo fails fast (recorded as 'circuit open'), urlhaus still works
    summary = intel_service.refresh_all_feeds(db_session)
    assert summary["feeds"]["feodo"]["error"] == "circuit open"
    assert trip["n"] == 3  # dependency not called again
    assert summary["feeds"]["urlhaus"]["fetched"] == 1

    # breaker status surfaces in /iocs/status payload
    status = intel_service.ioc_status(db_session)
    assert status["breakers"]["feodo"]["state"] == "open"


def test_reset_breaker_unknown_feed_returns_false():
    assert intel_service.reset_breaker("nonsense") is False
    assert intel_service.reset_breaker("feodo") is True


# ---------------------------------------------------------------------------
# Materialized stats
# ---------------------------------------------------------------------------

def test_stats_compute_and_cold_start(db_session):
    import json

    import models

    db_session.add(
        models.Artifact(
            host="h1", os="linux", artifact_type="process",
            collected_at="2026-01-01T00:00:00Z",
            data=json.dumps({"cmdline": "ls"}),
        )
    )
    db_session.add(
        models.Detection(
            host="h1", rule_id="r1", rule_title="t", artifact_type="process",
            severity="high", matched_data="{}", technique_id="T1059",
        )
    )
    db_session.commit()

    result = stats_service.compute_all(db_session)
    summary = result["metrics"]["detection_summary"]
    assert summary["total_detections"] == 1
    assert summary["by_severity"] == {"high": 1}
    assert result["metrics"]["health_counts"]["artifacts"] == 1

    # second compute is idempotent (upsert, not duplicate)
    stats_service.compute_all(db_session)
    assert db_session.query(models.StatsSnapshot).count() == 3  # three metrics

    # cached read matches
    cached = stats_service.get_snapshot(db_session, "detection_summary")
    assert cached["total_detections"] == 1


def test_stats_snapshot_cold_start_writes_row(db_session):
    value = stats_service.get_snapshot(db_session, "health_counts")
    assert "artifacts" in value
    rows = stats_service.snapshot_status(db_session)
    assert len(rows) == 1
    assert rows[0]["metric"] == "health_counts"
    assert rows[0]["value"] == value


def test_stats_unknown_metric_raises(db_session):
    with pytest.raises(ValueError):
        stats_service.get_snapshot(db_session, "nope")


# ---------------------------------------------------------------------------
# F8 API routes
# ---------------------------------------------------------------------------

def test_stats_routes(client):
    summary = client.get("/stats/summary").json()
    assert "snapshots" in summary
    assert client.post("/stats/recompute").status_code == 200

    metric = client.get("/stats/summary?metric=health_counts").json()
    assert "health_counts" in metric

    resp = client.get("/stats/summary?metric=nope")
    assert resp.status_code == 400


def test_ioc_breaker_reset_route(client, monkeypatch):
    monkeypatch.setattr(
        intel_service,
        "_BREAKERS",
        {"feodo": CircuitBreaker("ioc-feed-feodo", failure_threshold=1, reset_timeout_seconds=60)},
    )

    def boom():
        raise OSError("down")

    with pytest.raises(OSError):
        intel_service._BREAKERS["feodo"].call(boom)

    resp = client.post("/iocs/breakers/reset?feed=feodo")
    assert resp.status_code == 200
    assert resp.json()["state"] == "closed"

    assert client.post("/iocs/breakers/reset?feed=nope").status_code == 400


def test_stats_recompute_is_audited(client):
    client.post("/stats/recompute")
    logs = client.get("/audit-logs").json()
    assert any(entry["action"] == "stats_recompute" for entry in logs)


# ---------------------------------------------------------------------------
# k8s manifests parse as valid YAML
# ---------------------------------------------------------------------------

def test_k8s_manifests_are_valid_yaml():
    import os

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    k8s_dir = os.path.join(repo_root, "k8s")
    files = [
        f for f in os.listdir(k8s_dir)
        if f.endswith(".yaml") and not f.startswith("secret.example")
    ]
    assert files, "no k8s manifests found"
    kinds = []
    for fname in files:
        with open(os.path.join(k8s_dir, fname), encoding="utf-8") as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
        assert docs, f"{fname} is empty"
        for doc in docs:
            assert doc.get("apiVersion") and doc.get("kind"), f"{fname} missing apiVersion/kind"
            kinds.append(doc["kind"])
    assert "Deployment" in kinds
    assert "HorizontalPodAutoscaler" in kinds
    assert "PodDisruptionBudget" in kinds
    assert "StatefulSet" in kinds
