"""
Pushes every JSON file in a sample_data/<date>_<hostname>/ folder to the
running ingest API. This is how you'll routinely feed your collected
artifacts into the backend once the API is running (VM-collected data ->
sample_data/ -> this script -> API -> SQLite).

Usage:
    python push_samples.py ../sample_data/2026-07-29_win10-vm01
    python push_samples.py ../sample_data/2026-07-29_win10-vm01 --url http://192.168.50.128:8000
"""
import argparse
import json
import os
import sys

import requests


def push_folder(folder_path: str, api_url: str) -> None:
    if not os.path.isdir(folder_path):
        print(f"[!] Folder not found: {folder_path}")
        sys.exit(1)

    json_files = sorted(f for f in os.listdir(folder_path) if f.endswith(".json"))
    if not json_files:
        print(f"[!] No JSON files found in {folder_path}")
        sys.exit(1)

    for filename in json_files:
        filepath = os.path.join(folder_path, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            artifacts = json.load(f)

        if not artifacts:
            print(f"[*] {filename}: empty, skipping")
            continue

        try:
            resp = requests.post(f"{api_url}/ingest", json=artifacts, timeout=30)
        except requests.exceptions.ConnectionError:
            print(f"[!] Could not reach {api_url} — is the API running? (uvicorn main:app)")
            sys.exit(1)

        if resp.status_code == 200:
            result = resp.json()
            print(f"[+] {filename}: ingested {result['ingested']} records for host {result['host']}")
        else:
            print(f"[!] {filename}: failed ({resp.status_code}) — {resp.text}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Push sample_data JSON files to the ingest API")
    parser.add_argument("folder", help="Path to a sample_data/<date>_<hostname>/ folder")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Ingest API base URL")
    args = parser.parse_args()

    push_folder(args.folder, args.url)
