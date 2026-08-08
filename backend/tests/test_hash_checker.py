"""
Unit tests for the known-bad hash checker (hash_checker.py): loading the
local IOC list and flagging a file_scan artifact whose sha256 matches.
"""
import os

import hash_checker

HASH_LIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "iocs", "known_bad_hashes.txt")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _file_scan_artifact(sha256: str, path: str = "C:\\Temp\\x.exe") -> dict:
    return {
        "host": "test-host",
        "os": "windows",
        "artifact_type": "file_scan",
        "collected_at": "2026-01-01T00:00:00Z",
        "data": {"path": path, "sha256": sha256, "size_bytes": 68, "yara_matches": []},
    }


def test_known_bad_list_is_not_empty():
    assert hash_checker.load_known_bad_hashes(HASH_LIST)


def test_eicar_hash_match():
    hits = hash_checker.check_file_scan_artifacts([_file_scan_artifact(EICAR_SHA256)])
    assert len(hits) == 1
    assert hits[0]["rule_id"] == "hash-match"
    assert hits[0]["severity"] == "critical"
    assert hits[0]["matched_data"]["sha256"] == EICAR_SHA256


def test_benign_hash_no_match():
    hits = hash_checker.check_file_scan_artifacts([_file_scan_artifact("0" * 64)])
    assert hits == []


def test_mixed_artifacts_only_file_scan_considered():
    art = _file_scan_artifact(EICAR_SHA256)
    other = {"artifact_type": "process", "data": {}}
    assert len(hash_checker.check_file_scan_artifacts([art, other])) == 1