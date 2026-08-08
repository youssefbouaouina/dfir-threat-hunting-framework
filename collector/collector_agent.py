#!/usr/bin/env python3
"""
DFIR Lightweight Collector Agent — v2
Adds file_scan (hashing + local YARA) on top of v1's five modules.

file_scan needs the executable paths discovered by processes.py and
persistence.py, so it runs *after* those two rather than in the same
uniform loop as the others.

Usage:
    python collector_agent.py
    python collector_agent.py --output C:\\temp\\dfir_out
    python collector_agent.py --yara-rules ..\\detection\\yara_rules
    python collector_agent.py --only processes,network
    python collector_agent.py --push-url http://192.168.50.1:8000
        (collects AND pushes each artifact type straight to the
        backend's /ingest, in addition to writing local files —
        this is what removes the manual sample_data/ copy step for
        live/orchestrated runs)
"""
import argparse
import os
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.common import get_hostname, write_json
from modules.processes import collect_processes
from modules.network import collect_network
from modules.persistence import collect_persistence
from modules.scheduled_tasks import collect_scheduled_tasks
from modules.logs import collect_logs
from modules.file_scan import collect_file_scans


CORE_COLLECTORS = {
    "processes": ("processes.json", collect_processes),
    "network": ("network.json", collect_network),
    "persistence": ("persistence.json", collect_persistence),
    "scheduled_tasks": ("scheduled_tasks.json", collect_scheduled_tasks),
    "logs": ("logs.json", collect_logs),
}


def _push_records(push_url: str, records: list, artifact_type: str) -> None:
    """POSTs one artifact batch straight to /ingest. Failure here never
    stops the rest of the collection run — a network hiccup on one
    artifact type shouldn't lose everything else collected in this pass."""
    if not records:
        return
    try:
        resp = requests.post(f"{push_url}/ingest", json=records, timeout=15)
        if resp.status_code == 200:
            print(f"[>] Pushed {len(records)} {artifact_type} record(s) to {push_url}")
        else:
            print(f"[!] Push failed for {artifact_type}: HTTP {resp.status_code} — {resp.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Push failed for {artifact_type}: {e}")


def _extract_exe_paths(process_records: list, persistence_records: list, scheduled_task_records: list = None) -> set:
    """Pulls every plausible executable path out of already-collected
    process, persistence and scheduled-task artifacts, so file_scan knows
    what to hash/scan.

    Sources, in priority order:
      - process records: their exe path
      - persistence value_data: registry Run-key style values
      - persistence entry lines: crontab/rc.local lines, where the first
        absolute path token after the schedule columns is the target
      - scheduled_task records: task_to_run / raw command fields
    """
    paths = set()

    def _add_if_absolute(candidate: str):
        candidate = candidate.strip('"')
        if not candidate:
            return
        if os.path.isabs(candidate) or (len(candidate) > 2 and candidate[1] == ":"):
            paths.add(candidate)

    for record in process_records:
        exe = record.get("data", {}).get("exe")
        if exe:
            paths.add(exe)

    for record in persistence_records:
        data = record.get("data", {})
        # Registry Run key values often look like: "C:\path\app.exe" -silent
        # Take a naive best-effort first token if it looks like a real path.
        value_data = data.get("value_data")
        if isinstance(value_data, str) and value_data:
            _add_if_absolute(value_data.split(" ")[0])
        # crontab / rc.local lines: the schedule is the leading columns
        # (m h dom mon dow [user]), everything after is the command.
        entry = data.get("entry")
        if isinstance(entry, str) and entry.strip():
            tokens = entry.split()
            # cron: >=6 tokens with the 6th being a user or command
            if len(tokens) >= 6:
                command_tokens = tokens[5:] if not data.get("type") == "rc.local" else tokens
                for tok in command_tokens:
                    if tok.startswith("/") or (len(tok) > 2 and tok[1] == ":"):
                        _add_if_absolute(tok.split("(")[0].strip())
                        break

    for record in (scheduled_task_records or []):
        data = record.get("data", {})
        for field in ("task_to_run", "raw", "command"):
            val = data.get(field)
            if isinstance(val, str) and val:
                _add_if_absolute(val.split(" ")[0])

    return paths


def run_collection(output_dir: str = "output", only: list = None, yara_rules_dir: str = None, push_url: str = None) -> str:
    hostname = get_hostname()
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_dir = os.path.join(output_dir, f"{date_str}_{hostname}")

    print(f"[*] Starting collection on {hostname}")
    print(f"[*] Output directory: {run_dir}")
    if push_url:
        print(f"[*] Will push directly to: {push_url}")

    targets = only if only else list(CORE_COLLECTORS.keys()) + ["file_scan"]

    collected = {}  # key -> records, needed so file_scan can reuse processes/persistence

    for key in ["processes", "persistence"]:
        if key in targets:
            filename, func = CORE_COLLECTORS[key]
            print(f"[*] Running: {key}")
            try:
                records = func()
                collected[key] = records
                write_json(os.path.join(run_dir, filename), records)
                if push_url:
                    _push_records(push_url, records, key)
            except Exception as e:
                print(f"[!] Collector '{key}' failed: {e}")
                collected[key] = []

    for key in ["network", "scheduled_tasks", "logs"]:
        if key in targets:
            filename, func = CORE_COLLECTORS[key]
            print(f"[*] Running: {key}")
            try:
                records = func()
                if key == "scheduled_tasks":
                    # file_scan reuses scheduled-task paths, so keep them in memory.
                    collected[key] = records
                write_json(os.path.join(run_dir, filename), records)
                if push_url:
                    _push_records(push_url, records, key)
            except Exception as e:
                print(f"[!] Collector '{key}' failed: {e}")

    if "file_scan" in targets:
        print("[*] Running: file_scan")
        try:
            exe_paths = _extract_exe_paths(
                collected.get("processes", []),
                collected.get("persistence", []),
                collected.get("scheduled_tasks", []),
            )
            print(f"[*] {len(exe_paths)} unique executable path(s) to hash/scan")
            records = collect_file_scans(exe_paths, yara_rules_dir=yara_rules_dir)
            write_json(os.path.join(run_dir, "file_scan.json"), records)
            if push_url:
                _push_records(push_url, records, "file_scan")
        except Exception as e:
            print(f"[!] Collector 'file_scan' failed: {e}")

    print(f"[+] Collection complete. Output written to: {run_dir}")
    return run_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DFIR Lightweight Collector Agent v2")
    parser.add_argument("--output", default="output", help="Output directory (default: ./output)")
    parser.add_argument("--only", default=None, help="Comma-separated subset of collectors to run")
    parser.add_argument(
        "--yara-rules", default=None,
        help="Path to a folder of .yar/.yara rules for file_scan to use (e.g. ../detection/yara_rules)"
    )
    parser.add_argument(
        "--push-url", default=None,
        help="Backend base URL to push results to directly, e.g. http://192.168.50.1:8000"
    )
    args = parser.parse_args()

    only_list = args.only.split(",") if args.only else None
    run_collection(output_dir=args.output, only=only_list, yara_rules_dir=args.yara_rules, push_url=args.push_url)
