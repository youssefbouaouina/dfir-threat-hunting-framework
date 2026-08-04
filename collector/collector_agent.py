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
"""
import argparse
import os
import sys
from datetime import datetime, timezone

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


def _extract_exe_paths(process_records: list, persistence_records: list) -> set:
    """Pulls every plausible executable path out of already-collected
    process and persistence artifacts, so file_scan knows what to hash/scan."""
    paths = set()

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
            candidate = value_data.strip('"').split(" ")[0].strip('"')
            if os.path.isabs(candidate) or (len(candidate) > 2 and candidate[1] == ":"):
                paths.add(candidate)

    return paths


def run_collection(output_dir: str = "output", only: list = None, yara_rules_dir: str = None) -> str:
    hostname = get_hostname()
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_dir = os.path.join(output_dir, f"{date_str}_{hostname}")

    print(f"[*] Starting collection on {hostname}")
    print(f"[*] Output directory: {run_dir}")

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
            except Exception as e:
                print(f"[!] Collector '{key}' failed: {e}")
                collected[key] = []

    for key in ["network", "scheduled_tasks", "logs"]:
        if key in targets:
            filename, func = CORE_COLLECTORS[key]
            print(f"[*] Running: {key}")
            try:
                records = func()
                write_json(os.path.join(run_dir, filename), records)
            except Exception as e:
                print(f"[!] Collector '{key}' failed: {e}")

    if "file_scan" in targets:
        print("[*] Running: file_scan")
        try:
            exe_paths = _extract_exe_paths(
                collected.get("processes", []), collected.get("persistence", [])
            )
            print(f"[*] {len(exe_paths)} unique executable path(s) to hash/scan")
            records = collect_file_scans(exe_paths, yara_rules_dir=yara_rules_dir)
            write_json(os.path.join(run_dir, "file_scan.json"), records)
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
    args = parser.parse_args()

    only_list = args.only.split(",") if args.only else None
    run_collection(output_dir=args.output, only=only_list, yara_rules_dir=args.yara_rules)
