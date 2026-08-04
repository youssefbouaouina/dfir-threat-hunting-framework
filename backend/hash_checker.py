"""
Checks file_scan artifact hashes against a locally maintained known-bad
hash list. This is intentionally offline-first — no dependency on a
live feed to function during a demo or on an air-gapped VM. Update
iocs/known_bad_hashes.txt with real feed data (e.g. periodic exports
from MalwareBazaar/AbuseCH) as a separate maintenance task.

File format (iocs/known_bad_hashes.txt):
    <sha256><whitespace># optional description>
    # lines starting with # are comments
"""
import os

DEFAULT_HASH_LIST = os.path.join(os.path.dirname(__file__), "iocs", "known_bad_hashes.txt")

_cache = {}


def load_known_bad_hashes(path: str = DEFAULT_HASH_LIST) -> dict:
    if path in _cache:
        return _cache[path]

    hashes = {}
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                sha256 = parts[0].lower()
                description = parts[1].lstrip("#").strip() if len(parts) > 1 else ""
                hashes[sha256] = description

    _cache[path] = hashes
    return hashes


def check_file_scan_artifacts(artifacts: list, hash_list_path: str = DEFAULT_HASH_LIST) -> list:
    """
    artifacts: list of wrapped artifact dicts with artifact_type == 'file_scan'
    Returns a list of detection dicts for any sha256 matching the known-bad list.
    """
    known_bad = load_known_bad_hashes(hash_list_path)
    detections = []

    for artifact in artifacts:
        if artifact.get("artifact_type") != "file_scan":
            continue
        data = artifact.get("data", {})
        sha256 = (data.get("sha256") or "").lower()
        if sha256 in known_bad:
            detections.append(
                {
                    "rule_id": "hash-match",
                    "rule_title": f"Known malicious file hash ({known_bad[sha256] or 'unlabeled'})",
                    "technique_id": "T1204",
                    "severity": "critical",
                    "host": artifact.get("host"),
                    "artifact_type": "file_scan",
                    "matched_data": data,
                }
            )

    return detections


if __name__ == "__main__":
    # Manual test: use the EICAR hash from our earlier confirmed test run
    test_artifacts = [
        {
            "host": "test-host",
            "os": "linux",
            "artifact_type": "file_scan",
            "collected_at": "2026-07-30T00:00:00Z",
            "data": {
                "path": "/tmp/fake_endpoint/suspicious_test.exe",
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "size_bytes": 68,
                "yara_matches": [],
            },
        }
    ]
    print(check_file_scan_artifacts(test_artifacts))
