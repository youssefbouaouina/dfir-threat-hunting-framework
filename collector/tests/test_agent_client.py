"""Tests for the Phase 2/3 collector agent client (push/enroll/daemon/commands)."""
import json

import pytest

from agent_client import complete_command, make_batch_id, poll_pending_commands, push_folder


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


def test_poll_pending_commands_returns_list(monkeypatch):
    """Phase 3: agent polls for manual-trigger commands (fail-soft)."""
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        return _FakeResp([{"id": 1, "command": "run_collection", "status": "picked_up"}])

    monkeypatch.setattr("agent_client.requests.get", fake_get)
    cmds = poll_pending_commands("http://backend:8000", "edge-01", api_key="k")
    assert len(cmds) == 1
    assert cmds[0]["command"] == "run_collection"
    assert captured["url"].endswith("/endpoints/commands")
    assert captured["params"] == {"hostname": "edge-01"}


def test_poll_pending_commands_fails_soft(monkeypatch):
    from requests.exceptions import ConnectionError as RequestsConnError

    def fake_get(url, params=None, headers=None, timeout=None):
        raise RequestsConnError("network down")

    monkeypatch.setattr("agent_client.requests.get", fake_get)
    assert poll_pending_commands("http://backend:8000", "edge-01") == []


def test_complete_command_reports_result(monkeypatch):
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _FakeResp({"command_id": 1, "status": "completed"})

    monkeypatch.setattr("agent_client.requests.post", fake_post)
    out = complete_command(
        "http://backend:8000", 1, api_key="k", status="completed", result={"files": 6}
    )
    assert out["status"] == "completed"
    assert captured["url"].endswith("/endpoints/commands/1/complete")
    assert captured["json"] == {"status": "completed", "result": {"files": 6}}


def test_get_endpoint_config_returns_collectors(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        return _FakeResp(
            {
                "hostname": "edge-01",
                "interval_seconds": 120,
                "collectors": ["processes", "network"],
            }
        )

    monkeypatch.setattr("agent_client.requests.get", fake_get)
    from agent_client import get_endpoint_config

    cfg = get_endpoint_config("http://backend:8000", "edge-01", api_key="k")
    assert cfg["interval_seconds"] == 120
    assert cfg["collectors"] == ["processes", "network"]
    assert captured["url"].endswith("/endpoints/config")


def test_daemon_loop_honors_backend_collectors_and_interval(monkeypatch, tmp_path):
    """H2: the daemon passes the backend's collector list to run_collection and
    sleeps for the backend's interval instead of the CLI default."""
    import collector_agent  # noqa: F401  (module must be importable for daemon_loop)

    calls = {"only": None, "intervals": []}

    def fake_config(api_url, hostname, api_key=None):
        return {"interval_seconds": 42, "collectors": ["processes", "network"]}

    def fake_run_collection(output_dir="output", only=None, yara_rules_dir=None):
        calls["only"] = only
        return str(tmp_path / "run")

    def fake_push_folder(folder, api_url, api_key=None):
        return {"files": 1, "ingested": 1}

    def fake_poll(api_url, hostname, api_key=None):
        return []

    def fake_sleep(seconds):
        calls["intervals"].append(seconds)
        raise KeyboardInterrupt  # stop the infinite daemon loop after one cycle

    monkeypatch.setattr("agent_client.get_endpoint_config", fake_config)
    monkeypatch.setattr("agent_client.poll_pending_commands", fake_poll)
    monkeypatch.setattr("collector_agent.run_collection", fake_run_collection)
    monkeypatch.setattr("agent_client.push_folder", fake_push_folder)
    monkeypatch.setattr("time.sleep", fake_sleep)
    monkeypatch.setattr("socket.gethostname", lambda: "edge-01")

    from agent_client import daemon_loop

    with pytest.raises(KeyboardInterrupt):
        daemon_loop("http://backend:8000", interval=300)

    assert calls["only"] == ["processes", "network"]
    assert calls["intervals"] == [42]


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    @property
    def status_code(self):
        return 200

    def json(self):
        return self._payload
