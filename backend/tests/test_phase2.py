"""Tests for Phase 2: endpoint inventory, enroll flow, and idempotent ingest."""
import json


def test_enroll_creates_endpoint_and_config(client):
    resp = client.post(
        "/endpoints/enroll",
        json={"hostname": "edge-01", "os": "windows", "agent_version": "3.0"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["hostname"] == "edge-01"
    assert body["status"] == "online"
    assert body["config"]["interval_seconds"] == 300

    endpoints = client.get("/endpoints").json()
    assert len(endpoints) == 1


def test_enroll_is_idempotent_per_hostname(client):
    payload = {"hostname": "edge-01", "os": "linux", "agent_version": "3.0"}
    first = client.post("/endpoints/enroll", json=payload).json()
    second = client.post("/endpoints/enroll", json=payload).json()
    assert first["id"] == second["id"]
    assert len(client.get("/endpoints").json()) == 1


def test_endpoint_config_poll(client):
    client.post(
        "/endpoints/enroll",
        json={"hostname": "edge-01", "os": "linux", "agent_version": "3.0"},
    )
    cfg = client.get("/endpoints/config", params={"hostname": "edge-01"}).json()
    assert cfg["hostname"] == "edge-01"
    assert "processes" in cfg["collectors"]


def test_endpoint_config_defaults_for_unknown_host(client):
    cfg = client.get("/endpoints/config", params={"hostname": "ghost"}).json()
    assert cfg["interval_seconds"] == 300


def test_ingest_batch_id_deduplicates(client):
    artifact = {
        "host": "edge-01",
        "os": "linux",
        "collected_at": "2026-01-01T00:00:00Z",
        "artifact_type": "process",
        "data": {"name": "ps", "cmdline": "ps -ef"},
    }
    first = client.post("/ingest", json=[artifact], params={"batch_id": "run-1"}).json()
    assert first["ingested"] == 1
    assert first["deduplicated"] == 0

    second = client.post("/ingest", json=[artifact], params={"batch_id": "run-1"}).json()
    assert second["ingested"] == 0
    assert second["deduplicated"] == 1

    # A different batch id is a fresh upload.
    third = client.post("/ingest", json=[artifact], params={"batch_id": "run-2"}).json()
    assert third["ingested"] == 1
    assert third["deduplicated"] == 0

    assert len(client.get("/artifacts").json()) == 2


def test_analyzed_at_and_source_run_id_populated(db_session, monkeypatch, tmp_path):
    import models
    from services import detection_service

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r1.yml").write_text(
        "title: t\nid: rule-001\nartifact_type: process\ncondition:\n  cmdline_contains: ['-enc']\n"
    )
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(rules))

    db_session.add(
        models.Artifact(
            host="h",
            os="linux",
            artifact_type="process",
            collected_at="2026-01-01T00:00:00Z",
            data=json.dumps({"cmdline": "powershell -enc AA"}),
        )
    )
    db_session.commit()

    result = detection_service.run_detection_job(db_session, trigger="scheduled")
    assert result["artifacts_scanned"] == 1

    artifact = db_session.query(models.Artifact).first()
    assert artifact.processed == 1
    assert artifact.analyzed_at is not None
    assert artifact.source_run_id is not None
