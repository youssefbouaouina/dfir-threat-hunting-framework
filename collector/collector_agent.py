#!/usr/bin/env python3
"""
DFIR Lightweight Collector Agent
=================================
Runs all artifact collection modules and writes results to dated,
per-host JSON files under an output directory. Output follows the
sample_data/ naming convention from the shared workflow guide:

    output/<YYYY-MM-DD>_<hostname>/processes.json
    output/<YYYY-MM-DD>_<hostname>/network.json
    output/<YYYY-MM-DD>_<hostname>/persistence.json
    output/<YYYY-MM-DD>_<hostname>/scheduled_tasks.json
    output/<YYYY-MM-DD>_<hostname>/logs.json

Usage:
    python collector_agent.py                  # writes to ./output
    python collector_agent.py --output C:\\temp\\dfir_out
    python collector_agent.py --only processes,network   # run a subset

Run elevated (Administrator / sudo) for full visibility into other
users' processes, network connections, and system logs.
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


COLLECTORS = {
    "processes": ("processes.json", collect_processes),
    "network": ("network.json", collect_network),
    "persistence": ("persistence.json", collect_persistence),
    "scheduled_tasks": ("scheduled_tasks.json", collect_scheduled_tasks),
    "logs": ("logs.json", collect_logs),
}


def run_collection(output_dir: str = "output", only: list = None) -> str:
    hostname = get_hostname()
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_dir = os.path.join(output_dir, f"{date_str}_{hostname}")

    print(f"[*] Starting collection on {hostname}")
    print(f"[*] Output directory: {run_dir}")

    targets = only if only else list(COLLECTORS.keys())

    for key in targets:
        if key not in COLLECTORS:
            print(f"[!] Unknown collector '{key}', skipping. Valid: {list(COLLECTORS.keys())}")
            continue
        filename, collector_func = COLLECTORS[key]
        print(f"[*] Running: {key}")
        try:
            records = collector_func()
            write_json(os.path.join(run_dir, filename), records)
        except Exception as e:
            # Never let one collector's failure kill the whole run —
            # partial artifact coverage is still useful for an investigation.
            print(f"[!] Collector '{key}' failed: {e}")

    print(f"[+] Collection complete. Output written to: {run_dir}")
    return run_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DFIR Lightweight Collector Agent")
    parser.add_argument(
        "--output", default="output",
        help="Output directory (default: ./output)"
    )
    parser.add_argument(
        "--only", default=None,
        help="Comma-separated subset of collectors to run, e.g. processes,network"
    )
    args = parser.parse_args()

    only_list = args.only.split(",") if args.only else None
    run_collection(output_dir=args.output, only=only_list)
