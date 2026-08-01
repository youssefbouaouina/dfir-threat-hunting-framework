import argparse
import hashlib
import json
import platform
import socket
import uuid
from datetime import datetime, timezone

import psutil



def sha256_of_file(path, chunk_size=65536):
    """Compute the SHA256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) :
        return None

def collect_process():
    artifacts = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try: 
            info = proc.info
            exe_path = info.get('exe') or ""
            cmdline = " ".join(info.get("cmdline") or [])
            artifact = {
                "pid": info.get("pid"),
                "name": info.get("name"),
                "exe": exe_path,
                "cmdline": cmdline,
                "sha256": sha256_of_file(exe_path) if exe_path else None
            }
            artifacts.append(artifact)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return artifacts


def build_scan_result(process_artifacts):
    return {
        "scan_id": str(uuid.uuid4()),
        "host": {
            "hostname": socketgethostname(),
            "os": platform.system().lower(),
            "os_version": platform.version(),
            "ip_addresses": _get_local_ips(),
        },
    "scan_start": datetime.now(timezone.utc).isoformat(),
    "collector_version": "0.1.0",
    "artifact_type": "process",
    "artifacts": process_artifacts,
    
    }

def _get_local_ips():
    try:
        hostname = socket.gethostname()
        return list({ip for ip in socket.gethostbyname_ex(hostname)[2]})
    except socket.gaierror:
        return []

def main():
    parser = argparse.ArgumentParser(description="List running process as json")
    parser.add_argument("--out", help="write json to file instead of stdout", default=None)
    args = parser.parse_args()
    process = collect_processes()
    result = build_scan_result(processes)
    output = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        print(f"wrote {len(processes)} processes to {args.out}")
    else:
        print(output)
if __name__ == "__main__":
    main()
        