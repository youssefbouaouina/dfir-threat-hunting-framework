"""
Agent-side file scanning: hashes and YARA-scans the actual executable
files referenced by collected processes and persistence entries.

WHY THIS RUNS ON THE ENDPOINT, NOT THE BACKEND:
The backend never receives raw files from remote hosts — only JSON
metadata. Shipping files over the network doesn't scale and isn't how
real EDR/DFIR agents work. Instead, this module does the actual file
inspection locally, on the machine where the file lives, and reports
only the *result* (a hash + which YARA rules matched) as a normal
artifact — same ingest pipeline as everything else.

Output artifact_type: "file_scan"
    {
        "path": "C:\\Windows\\Temp\\update.exe",
        "sha256": "...",
        "size_bytes": 123456,
        "yara_matches": [{"rule": "...", "tags": [...], "meta": {...}}]
    }
"""
import hashlib
import os

from .common import wrap_artifact

try:
    import yara
except ImportError:
    yara = None


def _sha256_of_file(filepath: str, chunk_size: int = 65536) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _load_yara_rules(rules_dir: str):
    if yara is None or not os.path.isdir(rules_dir):
        return None
    rule_files = {
        os.path.splitext(f)[0]: os.path.join(rules_dir, f)
        for f in os.listdir(rules_dir)
        if f.endswith((".yar", ".yara"))
    }
    if not rule_files:
        return None
    return yara.compile(filepaths=rule_files)


def collect_file_scans(exe_paths: set, yara_rules_dir: str = None, max_file_mb: int = 50) -> list:
    """
    exe_paths: a set of executable paths gathered from other collector
    modules (processes.py, persistence.py) — pass these in from
    collector_agent.py so this module doesn't need to re-derive them.
    """
    records = []
    compiled_rules = _load_yara_rules(yara_rules_dir) if yara_rules_dir else None
    max_bytes = max_file_mb * 1024 * 1024

    for path in exe_paths:
        if not path or not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
            if size > max_bytes:
                # Skip hashing huge files (e.g. accidental match on a VM disk
                # image) — keeps a "lightweight" agent lightweight.
                continue

            sha256 = _sha256_of_file(path)
            yara_matches = []
            if compiled_rules is not None:
                try:
                    matches = compiled_rules.match(path)
                    yara_matches = [
                        {"rule": str(m.rule), "tags": list(m.tags), "meta": dict(m.meta)}
                        for m in matches
                    ]
                except Exception as e:
                    print(f"[!] YARA scan failed for {path}: {e}")

            data = {
                "path": path,
                "sha256": sha256,
                "size_bytes": size,
                "yara_matches": yara_matches,
            }
            records.append(wrap_artifact("file_scan", data))
        except (PermissionError, OSError):
            continue

    return records


if __name__ == "__main__":
    import json
    # Standalone smoke test: scan this file's own directory for .py files
    here = os.path.dirname(os.path.abspath(__file__))
    test_paths = {os.path.join(here, f) for f in os.listdir(here) if f.endswith(".py")}
    print(json.dumps(collect_file_scans(test_paths)[:1], indent=2, default=str))
