"""
Agent-to-backend client for the DFIR collector.

Phase 2 automation: lets the collector push its collected folders straight to
the backend API (instead of the manual sample_data/ copy + push_samples.py
replay), register itself through the enroll flow, poll its per-endpoint config,
and send each collection run as an idempotent batch (batch_id = run dir name).

All network calls are fail-soft: a lost API key, unreachable backend, or a
non-200 response logs a warning and does not crash a daemon collection loop.
"""
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logger = logging.getLogger("dfir.collector.agent_client")


def _post_json(
    url: str, headers: dict, data: list, params: dict = None, timeout: int = 30
) -> tuple:
    """POSTs a JSON body, returning (status_code, json) — raises on connection error."""
    try:
        resp = requests.post(url, headers=headers, json=data, params=params, timeout=timeout)
        return resp.status_code, resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("Request to %s failed: %s", url, exc)
        return None, {"error": str(exc)}


def get_endpoint_config(api_url: str, hostname: str, api_key: str = None) -> dict:
    """Polls the backend for this endpoint's collection config (fail-soft)."""
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        resp = requests.get(
            f"{api_url.rstrip('/')}/endpoints/config",
            params={"hostname": hostname},
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("Config poll failed for %s: %s", hostname, exc)
    return {}


def enroll(
    api_url: str,
    hostname: str,
    os_name: str,
    api_key: str = None,
    agent_version: str = None,
) -> dict:
    """Registers this endpoint with the backend and returns the endpoint record."""
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        resp = requests.post(
            f"{api_url.rstrip('/')}/endpoints/enroll",
            headers=headers,
            json={
                "hostname": hostname,
                "os": os_name,
                "agent_version": agent_version,
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            return resp.json()
        logger.warning("Enroll returned %s: %s", resp.status_code, resp.text)
    except requests.exceptions.RequestException as exc:
        logger.warning("Enroll failed: %s", exc)
    return {}


def push_folder(folder_path: str, api_url: str, api_key: str = None, batch_id: str = None) -> dict:
    """Pushes every *.json artifact file in a folder to /ingest as one batch.

    batch_id defaults to the folder's basename (a per-run id), so re-pushing
    the same folder is a no-op on the backend. Returns a summary dict.
    """
    api_url = api_url.rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    batch_id = batch_id or os.path.basename(folder_path.rstrip(os.sep))
    summary = {"files": 0, "ingested": 0, "deduplicated": 0, "errors": 0}

    for fname in sorted(os.listdir(folder_path)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(folder_path, fname)
        try:
            with open(path, encoding="utf-8") as f:
                artifacts = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Skipping %s: %s", path, exc)
            summary["errors"] += 1
            continue
        if not isinstance(artifacts, list) or not artifacts:
            continue

        status, body = _post_json(
            f"{api_url}/ingest",
            headers=headers,
            data=artifacts,
            params={"batch_id": batch_id},
            timeout=60,
        )
        summary["files"] += 1
        if status == 200 and isinstance(body, dict):
            summary["ingested"] += body.get("ingested", 0)
            summary["deduplicated"] += body.get("deduplicated", 0)
        else:
            summary["errors"] += 1
            logger.warning("Ingest of %s returned %s: %s", fname, status, body)

    return summary


def daemon_loop(
    api_url: str,
    api_key: str = None,
    interval: int = 300,
    yara_rules_dir: str = None,
) -> None:
    """Runs collect + push on a fixed cadence until interrupted."""
    from collector_agent import run_collection

    logger.info(
        "Agent daemon started — collecting + pushing every %s seconds to %s", interval, api_url
    )
    while True:
        try:
            run_dir = run_collection(output_dir="output", yara_rules_dir=yara_rules_dir)
            summary = push_folder(run_dir, api_url, api_key)
            logger.info("Push summary: %s", summary)
        except Exception as exc:  # noqa: BLE001 — daemon must survive any collector failure
            logger.error("Collection/push cycle failed: %s", exc)
        time.sleep(max(interval, 10))


def make_batch_id() -> str:
    """Unique id for one collection run, e.g. '2026-08-02T04:20:00Z_demo-host'.

    Uses microsecond precision plus a short random suffix so two runs started
    in the same second still get distinct, idempotent batch ids.
    """
    import secrets
    import socket

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return f"{stamp}_{socket.gethostname()}_{secrets.token_hex(3)}"
