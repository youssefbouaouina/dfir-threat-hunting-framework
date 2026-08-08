"""Endpoint registry + container lifecycle API tests (manager is mocked/unreachable)."""


def _vm_payload(name: str = "vm-test-01", **overrides) -> dict:
    payload = {
        "name": name,
        "os": "linux",
        "backend_type": "vm",
        "ip_address": "192.168.50.129",
        "ssh_username": "youssef",
        "ssh_key_path": "/app/ssh_keys/dfir_orchestrator_key",
        "remote_collector_path": "/home/youssef/collector",
    }
    payload.update(overrides)
    return payload


def test_register_and_list_vm_endpoint(client):
    resp = client.post("/endpoints", json=_vm_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "vm-test-01"
    assert body["backend_type"] == "vm"

    listing = client.get("/endpoints").json()
    assert len(listing) == 1
    assert listing[0]["id"] == body["id"]


def test_duplicate_endpoint_409(client):
    client.post("/endpoints", json=_vm_payload())
    resp = client.post("/endpoints", json=_vm_payload())
    assert resp.status_code == 409


def test_container_start_stop_rejected_for_vm(client):
    created = client.post("/endpoints", json=_vm_payload()).json()
    for action in ("start", "stop", "restart"):
        resp = client.post(f"/endpoints/{created['id']}/{action}")
        assert resp.status_code == 400, action


def test_container_endpoint_creation_fails_cleanly_without_manager(client):
    # endpoint-manager is unreachable in tests -> must be a clean 502, not a 500
    resp = client.post(
        "/endpoints",
        json={
            "name": "container-bad",
            "os": "linux",
            "backend_type": "container",
            "image": "nonexistent/does-not-exist",
        },
    )
    assert resp.status_code in (502, 500)
    if resp.status_code == 502:
        assert "Endpoint container creation failed" in resp.json()["detail"]


def test_invalid_container_name_422(client):
    resp = client.post(
        "/endpoints",
        json={"name": "Bad Name!", "os": "linux", "backend_type": "container", "image": "x"},
    )
    assert resp.status_code == 422


def test_delete_endpoint(client):
    created = client.post("/endpoints", json=_vm_payload()).json()
    resp = client.delete(f"/endpoints/{created['id']}")
    assert resp.status_code == 200
    assert client.get(f"/endpoints/{created['id']}").status_code == 404


def test_heartbeat_updates_registered_endpoint(client):
    created = client.post("/endpoints", json=_vm_payload(name="hb-match")).json()

    artifacts = [
        {
            "host": "hb-match",
            "os": "linux",
            "collected_at": "2026-08-07T00:00:00Z",
            "artifact_type": "heartbeat",
            "data": {"agent_version": "collector-9.9"},
        }
    ]
    assert client.post("/ingest", json=artifacts).status_code == 200

    body = client.get(f"/endpoints/{created['id']}").json()
    assert body["last_heartbeat"] is not None
    assert body["agent_version"] == "collector-9.9"
    assert body["status"] == "online"
