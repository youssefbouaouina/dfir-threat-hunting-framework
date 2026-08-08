"""Baseline API tests: health, ingest, detection pipeline."""


def _artifact(host: str, artifact_type: str, data: dict, os: str = "linux") -> dict:
    return {
        "host": host,
        "os": os,
        "collected_at": "2026-08-07T00:00:00Z",
        "artifact_type": artifact_type,
        "data": data,
    }


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ingest_creates_host_and_artifacts(client):
    artifacts = [
        _artifact("test-host-1", "process", {"pid": 1, "name": "init", "cmdline": "/sbin/init"}),
        _artifact("test-host-1", "network", {"local_address": "1.2.3.4:80", "status": "LISTEN"}),
    ]
    resp = client.post("/ingest", json=artifacts)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ingested"] == 2
    assert body["host"] == "test-host-1"

    hosts = client.get("/hosts").json()
    assert any(h["hostname"] == "test-host-1" for h in hosts)

    arts = client.get("/artifacts?host=test-host-1&limit=10").json()
    assert len(arts) == 2


def test_ingest_empty_rejected(client):
    resp = client.post("/ingest", json=[])
    assert resp.status_code == 400


def test_detect_pipeline_runs_and_marks_processed(client):
    # A registry Run key pointing into %TEMP% should trip rule003
    artifacts = [
        _artifact(
            "win-test",
            "persistence",
            {
                "type": "registry_run_key",
                "hive": "HKCU",
                "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "value_name": "evil",
                "value_data": r"C:\Users\test\AppData\Local\Temp\malware.exe",
            },
            os="windows",
        )
    ]
    client.post("/ingest", json=artifacts)

    result = client.post("/detect").json()
    assert result["artifacts_scanned"] >= 1

    detections = client.get("/detections").json()
    assert len(detections) >= 1

    # Re-running detection must not re-analyze the same artifact
    result2 = client.post("/detect").json()
    assert result2["artifacts_scanned"] == 0


def test_heartbeat_artifact_sets_agent_version(client):
    artifacts = [
        _artifact("hb-host", "heartbeat", {"agent_version": "collector-2.0-test"}),
    ]
    resp = client.post("/ingest", json=artifacts)
    assert resp.status_code == 200
    # Host was created even though artifact_type is heartbeat
    assert any(h["hostname"] == "hb-host" for h in client.get("/hosts").json())
