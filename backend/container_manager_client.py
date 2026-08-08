"""
Client for the endpoint-manager service.

The endpoint-manager is a separate, isolated container that is the ONLY component
with Docker socket access. The backend never sees the socket; it talks to the
manager over the private compose network using a shared bearer token.

The manager exposes a deliberately narrow, allow-listed API (create/start/stop/
restart/status/exec/remove/list). This keeps a backend compromise from becoming
host root — the blast radius is limited to the manager's allow-list.
"""
import logging
import os

import requests

logger = logging.getLogger("dfir.endpoint_manager")

MANAGER_BASE_URL = os.getenv("ENDPOINT_MANAGER_URL", "http://endpoint-manager:8001")
MANAGER_TOKEN = os.getenv("ENDPOINT_MANAGER_TOKEN", "")
MANAGER_NETWORK = os.getenv("ENDPOINT_MANAGER_NETWORK", "dfir-internal")

ENDPOINT_IMAGE = os.getenv(
    "ENDPOINT_IMAGE",
    "ghcr.io/dfir-threat-hunting-framework/framework-endpoint-linux:latest",
)
ENDPOINT_PUSH_URL = os.getenv("ENDPOINT_PUSH_URL", "http://backend:8000")

MANAGER_TIMEOUT_SECONDS = 300  # a full collector run inside the container can take a while


class EndpointManagerError(Exception):
    """Raised when the endpoint-manager rejects or fails an operation."""


def _call(method: str, path: str, **kwargs) -> dict:
    url = f"{MANAGER_BASE_URL}{path}"
    try:
        resp = requests.request(
            method,
            url,
            headers={"Authorization": f"Bearer {MANAGER_TOKEN}"},
            timeout=MANAGER_TIMEOUT_SECONDS,
            **kwargs,
        )
    except requests.exceptions.RequestException as e:
        raise EndpointManagerError(f"endpoint-manager unreachable at {MANAGER_BASE_URL}: {e}") from e
    if resp.status_code >= 400:
        raise EndpointManagerError(
            f"endpoint-manager {method} {path}: HTTP {resp.status_code} {resp.text[:300]}"
        )
    try:
        return resp.json()
    except ValueError:
        return {"ok": resp.status_code < 400}


def create_endpoint_container(name: str, image: str | None = None, env: dict | None = None) -> dict:
    """Ask the manager to create (but not necessarily start) an endpoint container."""
    payload = {
        "name": name,
        "image": image or ENDPOINT_IMAGE,
        "network": MANAGER_NETWORK,
        "env": env or {},
    }
    return _call("POST", "/containers", json=payload)


def start_container(name: str) -> dict:
    return _call("POST", f"/containers/{name}/start")


def stop_container(name: str) -> dict:
    return _call("POST", f"/containers/{name}/stop")


def restart_container(name: str) -> dict:
    return _call("POST", f"/containers/{name}/restart")


def remove_container(name: str, force: bool = True) -> dict:
    return _call("DELETE", f"/containers/{name}?force={'true' if force else 'false'}")


def container_status(name: str) -> dict:
    return _call("GET", f"/containers/{name}")


def container_exists(name: str) -> bool:
    try:
        container_status(name)
        return True
    except EndpointManagerError:
        return False


def exec_collector(name: str, push_url: str | None = None) -> dict:
    """Run the collector inside the endpoint container via docker exec."""
    payload = {"push_url": push_url or ENDPOINT_PUSH_URL}
    return _call("POST", f"/containers/{name}/exec", json=payload)
