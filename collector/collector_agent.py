#!/usr/bin/env python3
"""
DFIR Lightweight Collector Agent — v3
Adds Phase 2 automation on top of v2: direct push to the backend API
(--api-url/--api-key), agent self-enrollment (--enroll), a --daemon loop that
collects + pushes on a fixed interval, and idempotent batch uploads.

file_scan needs the executable paths discovered by processes.py and
persistence.py, so it runs *after* those two rather than in the same
uniform loop as the others.

Usage:
    python collector_agent.py
    python collector_agent.py --output C:\\temp\\dfir_out
    python collector_agent.py --yara-rules ..\\detection\\yara_rules
    python collector_agent.py --only processes,network
    python collector_agent.py --api-url http://127.0.0.1:8000 --api-key <key>
    python collector_agent.py --api-url http://127.0.0.1:8000 --api-key <key> \
        --daemon --interval 300
"""
import argparse
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.common import get_hostname, write_json
from modules.file_scan import collect_file_scans
from modules.logs import collect_logs
from modules.network import collect_network
from modules.persistence import collect_persistence
from modules.processes import collect_processes
from modules.scheduled_tasks import collect_scheduled_tasks

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


def run_collection(
    output_dir: str = "output", only: list = None, yara_rules_dir: str = None
) -> str:
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
    parser = argparse.ArgumentParser(description="DFIR Lightweight Collector Agent v3")
    parser.add_argument("--output", default="output", help="Output directory (default: ./output)")
    parser.add_argument(
        "--only", default=None, help="Comma-separated subset of collectors to run"
    )
    parser.add_argument(
        "--yara-rules", default=None,
        help="Path to a folder of .yar/.yara rules for file_scan to use "
             "(e.g. ../detection/yara_rules)"
    )
    parser.add_argument(
        "--api-url", default=os.getenv("DFIR_API_URL"),
        help="Backend base URL to push artifacts to (e.g. http://127.0.0.1:8000)"
    )
    parser.add_argument(
        "--api-key", default=os.getenv("DFIR_API_KEY"),
        help="Agent Bearer API key for the backend (AUTH_ENABLED=true)"
    )
    parser.add_argument(
        "--enroll", action="store_true",
        help="Register this endpoint with the backend before collecting"
    )
    parser.add_argument(
        "--daemon", action="store_true",
        help="Loop forever: collect + push every --interval seconds"
    )
    parser.add_argument(
        "--interval", type=int, default=int(os.getenv("COLLECT_INTERVAL_SECONDS", "300")),
        help="Daemon collection interval in seconds (default 300)"
    )
    args = parser.parse_args()

    only_list = args.only.split(",") if args.only else None

    if args.api_url:
        from agent_client import daemon_loop, enroll, get_endpoint_config, push_folder
        from modules.common import get_os

        if args.enroll:
            enroll(
                args.api_url, get_hostname(), get_os(), args.api_key, agent_version="3.0"
            )

        if args.daemon:
            daemon_loop(
                args.api_url, args.api_key, interval=args.interval, yara_rules_dir=args.yara_rules
            )
        else:
            cfg = get_endpoint_config(args.api_url, get_hostname(), args.api_key)
            run_dir = run_collection(
                output_dir=args.output, only=only_list, yara_rules_dir=args.yara_rules
            )
            batch_id = run_dir.replace(os.sep, "-")
            summary = push_folder(run_dir, args.api_url, args.api_key, batch_id=batch_id)
            print(f"[+] Push summary: {summary}")
    else:
        run_collection(output_dir=args.output, only=only_list, yara_rules_dir=args.yara_rules)
