"""Tests for hash_checker — known-bad hash matching against a local list."""
from hash_checker import check_file_scan_artifacts, load_known_bad_hashes

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _artifact(sha256):
    return {
        "host": "h",
        "os": "linux",
        "artifact_type": "file_scan",
        "collected_at": "x",
        "data": {"path": "/tmp/a", "sha256": sha256},
    }


def test_load_known_bad_hashes_parses_file(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text(f"# comment\n{EICAR} EICAR test file\n")
    hashes = load_known_bad_hashes(str(path))
    assert hashes == {EICAR: "EICAR test file"}


def test_match_produces_critical_detection(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text(f"{EICAR} EICAR\n")
    detections = check_file_scan_artifacts([_artifact(EICAR), _artifact("0" * 64)], str(path))
    assert len(detections) == 1
    assert detections[0]["rule_id"] == "hash-match"
    assert detections[0]["severity"] == "critical"
    assert detections[0]["technique_id"] == "T1204"


def test_no_match_when_file_absent(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text(f"{EICAR}\n")
    assert check_file_scan_artifacts([_artifact("0" * 64)], str(path)) == []


def test_missing_hash_list_returns_empty(tmp_path):
    assert check_file_scan_artifacts([_artifact(EICAR)], str(tmp_path / "nope.txt")) == []
