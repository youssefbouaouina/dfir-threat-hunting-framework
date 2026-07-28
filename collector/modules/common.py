"""
Shared helpers for all collector modules.
Every artifact gets wrapped in the standard schema defined in SCHEMA.md:
    {
        "host": "...",
        "os": "windows" | "linux",
        "collected_at": "ISO8601 UTC timestamp",
        "artifact_type": "process | network | persistence | scheduled_task | log_event",
        "data": { ... artifact-specific fields ... }
    }
"""
import json
import os
import platform
import socket
from datetime import datetime, timezone


def get_hostname() -> str:
    return socket.gethostname()


def get_os() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    return system


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def wrap_artifact(artifact_type: str, data: dict) -> dict:
    """Wraps a single artifact's data in the standard schema envelope."""
    return {
        "host": get_hostname(),
        "os": get_os(),
        "collected_at": now_iso(),
        "artifact_type": artifact_type,
        "data": data,
    }


def write_json(filepath: str, records: list) -> None:
    """Writes a list of wrapped artifacts to a JSON file, creating dirs as needed."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)
    print(f"[+] Wrote {len(records)} record(s) to {filepath}")
