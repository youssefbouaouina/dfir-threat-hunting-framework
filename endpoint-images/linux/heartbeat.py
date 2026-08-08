#!/usr/bin/env python3
"""Lightweight heartbeat artifact pushed by the endpoint image. Lets the backend
record agent_version + last_heartbeat for the registered endpoint without the
full collection cost. Importable-free on purpose (runs from the image's stdlib)."""
import json
import socket
import sys
import time
import urllib.request

PUSH_URL = sys.argv[1] if len(sys.argv) > 1 else "http://backend:8000"

artifact = {
    "host": socket.gethostname(),
    "os": "linux",
    "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "artifact_type": "heartbeat",
    "data": {"agent_version": "collector-2.0-endpoint-image"},
}

try:
    req = urllib.request.Request(
        f"{PUSH_URL}/ingest",
        data=json.dumps([artifact]).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status != 200:
            sys.exit(1)
except Exception:
    sys.exit(1)
