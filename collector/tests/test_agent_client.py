"""Tests for the Phase 2 collector agent client (push/enroll/daemon helpers)."""
import json

from agent_client import make_batch_id, push_folder


def _write_batch(tmp_path, name="batch-abc", count=2):
    folder = tmp_path / name
    folder.mkdir(exist_ok=True)
    artifacts = [
        {
            "host": "agent-host",
            "os": "linux",
            "collected_at": "2026-01-01T00:00:00Z",
            "artifact_type": "process",
            "data": {"name": f"proc-{i}", "cmdline": f"cmd {i}"},
        }
        for i in range(count)
    ]
    (folder / "processes.json").write_text(json.dumps(artifacts))
    return str(folder)


def test_make_batch_id_is_unique():
    assert make_batch_id() != make_batch_id()


def test_push_folder_sends_batch_id(monkeypatch, tmp_path):
    calls = {}

    def fake_post_json(url, headers=None, data=None, params=None, timeout=None):
        calls["url"] = url
        calls["params"] = params
        calls["body"] = data
        return 200, {"ingested": len(data), "deduplicated": 0, "host": "agent-host"}

    monkeypatch.setattr("agent_client._post_json", fake_post_json)
    folder = _write_batch(tmp_path)
    summary = push_folder(folder, "http://backend:8000", api_key="key-1")

    assert summary["ingested"] == 2
    assert calls["params"] == {"batch_id": "batch-abc"}
    assert calls["url"].endswith("/ingest")


def test_push_folder_skips_non_json(tmp_path):
    folder = tmp_path / "mixed"
    folder.mkdir()
    (folder / "readme.txt").write_text("not json")
    summary = push_folder(str(folder), "http://backend:8000")
    assert summary["files"] == 0


def test_push_folder_handles_connection_error(monkeypatch, tmp_path):
    def fake_post_json(url, headers=None, data=None, params=None, timeout=None):
        return None, {"error": "boom"}

    monkeypatch.setattr("agent_client._post_json", fake_post_json)
    folder = _write_batch(tmp_path)
    summary = push_folder(folder, "http://backend:8000")
    assert summary["errors"] == 1
