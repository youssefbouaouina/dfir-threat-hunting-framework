"""API-level tests exercising the FastAPI routes via TestClient."""
import pytest

from services import detection_service

PROCESS_ARTIFACT = {
    "host": "desk-01",
    "os": "windows",
    "collected_at": "2026-01-01T00:00:00Z",
    "artifact_type": "process",
    "data": {"name": "powershell.exe", "cmdline": "powershell.exe -enc AA=="},
}

RULE_YAML = """title: Suspicious PowerShell EncodedCommand
id: rule-001
artifact_type: process
technique_id: T1059.001
severity: high
condition:
  cmdline_contains: ["-enc"]
"""


@pytest.fixture()
def rules_dir(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule001.yml").write_text(RULE_YAML)
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(rules))
    return str(rules)


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert "metrics" in body  # Phase 3: live counts for the dashboard header


def test_ingest_round_trip(client):
    resp = client.post("/ingest", json=[PROCESS_ARTIFACT])
    assert resp.status_code == 200
    assert resp.json()["ingested"] == 1

    hosts = client.get("/hosts").json()
    assert [h["hostname"] for h in hosts] == ["desk-01"]

    artifacts = client.get("/artifacts").json()
    assert len(artifacts) == 1
    assert artifacts[0]["processed"] == 0


def test_ingest_empty_rejected(client):
    resp = client.post("/ingest", json=[])
    assert resp.status_code == 400


def test_detect_endpoint_round_trip(client, rules_dir):
    client.post("/ingest", json=[PROCESS_ARTIFACT])

    resp = client.post("/detect")
    assert resp.status_code == 200
    body = resp.json()
    assert body["artifacts_scanned"] == 1
    assert body["detections_found"] == 1

    summary = client.get("/detections/summary").json()
    assert summary["total_detections"] == 1


def test_detect_rescan(client, rules_dir):
    client.post("/ingest", json=[PROCESS_ARTIFACT])
    assert client.post("/detect").json()["detections_found"] == 1

    # Second scan without rescan: nothing new.
    assert client.post("/detect").json()["artifacts_scanned"] == 0

    # With rescan: artifact re-analyzed and a second Detection created.
    body = client.post("/detect?rescan=true").json()
    assert body["artifacts_scanned"] == 1
    detections = client.get("/detections").json()
    assert len(detections) == 2


def test_detect_host_scope(client, rules_dir):
    other = dict(PROCESS_ARTIFACT, host="server-02")
    client.post("/ingest", json=[PROCESS_ARTIFACT, other])

    body = client.post("/detect?host=desk-01").json()
    assert body["artifacts_scanned"] == 1


def test_detection_runs_history(client, rules_dir):
    client.post("/ingest", json=[PROCESS_ARTIFACT])
    client.post("/detect")

    runs = client.get("/detection-runs").json()
    assert len(runs) == 1
    assert runs[0]["trigger"] == "manual"
    assert runs[0]["status"] == "completed"
    assert runs[0]["detections_found"] == 1


def test_artifacts_filters(client):
    later = dict(PROCESS_ARTIFACT, collected_at="2026-02-01T00:00:00Z")
    other = {
        "host": "server-02",
        "os": "linux",
        "collected_at": "2026-03-01T00:00:00Z",
        "artifact_type": "network",
        "data": {"remote_address": "1.1.1.1:443"},
    }
    client.post("/ingest", json=[PROCESS_ARTIFACT, later, other])

    assert len(client.get("/artifacts").json()) == 3
    assert len(client.get("/artifacts", params={"artifact_type": "process"}).json()) == 2
    assert len(client.get("/artifacts", params={"host": "server-02"}).json()) == 1
    since = client.get("/artifacts", params={"collected_since": "2026-02-01T00:00:00Z"}).json()
    assert len(since) == 2
    processed = client.get("/artifacts", params={"processed": 1}).json()
    assert processed == []
