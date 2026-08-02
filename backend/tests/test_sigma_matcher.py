"""Tests for sigma_matcher — rule loading/validation and condition evaluation."""
import pytest

from sigma_matcher import evaluate, load_rules

VALID_RULE = """title: Suspicious PowerShell EncodedCommand
id: rule-001
artifact_type: process
technique_id: T1059.001
severity: high
condition:
  cmdline_contains: ["-EncodedCommand", "-enc"]
"""

DUPLICATE_RULE = """title: Duplicate rule id
id: rule-001
artifact_type: process
condition:
  cmdline_contains: ["-enc"]
"""

MISSING_KEYS_RULE = """title: No condition or id
artifact_type: process
"""


@pytest.fixture()
def rules_dir(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule001_valid.yml").write_text(VALID_RULE)
    (rules / "rule002_missing.yml").write_text(MISSING_KEYS_RULE)
    (rules / "rule003_duplicate.yml").write_text(DUPLICATE_RULE)
    (rules / "bad_yaml.yml").write_text(": : : [")
    return str(rules)


def test_loads_valid_rules_only_and_dedupes(rules_dir):
    rules = load_rules(rules_dir)
    assert [r["id"] for r in rules] == ["rule-001"]


def test_evaluate_contains_case_insensitive():
    rule = {
        "id": "r1",
        "title": "t",
        "artifact_type": "process",
        "condition": {"cmdline_contains": ["-ENCODEDcommand"]},
    }
    artifacts = [
        {
            "host": "h",
            "os": "linux",
            "artifact_type": "process",
            "collected_at": "x",
            "data": {"cmdline": "powershell.exe -encodedcommand AA=="},
        }
    ]
    detections = evaluate([rule], artifacts)
    assert len(detections) == 1
    assert detections[0]["rule_id"] == "r1"


def test_evaluate_exact_and_list_match():
    rule = {
        "id": "r2",
        "title": "t",
        "artifact_type": "persistence",
        "condition": {"type": "rc.local"},
    }
    list_rule = {
        "id": "r3",
        "title": "t",
        "artifact_type": "process",
        "condition": {"name": ["cmd.exe", "powershell.exe"]},
    }
    artifacts = [
        {
            "host": "h",
            "os": "windows",
            "artifact_type": "persistence",
            "collected_at": "x",
            "data": {"type": "rc.local", "content": "#!/bin/sh"},
        },
        {
            "host": "h",
            "os": "windows",
            "artifact_type": "process",
            "collected_at": "x",
            "data": {"name": "powershell.exe"},
        },
        {
            "host": "h",
            "os": "windows",
            "artifact_type": "process",
            "collected_at": "x",
            "data": {"name": "explorer.exe"},
        },
    ]
    detections = evaluate([rule, list_rule], artifacts)
    rule_ids = {d["rule_id"] for d in detections}
    assert rule_ids == {"r2", "r3"}


def test_evaluate_ignores_wrong_artifact_type():
    rule = {
        "id": "r4",
        "title": "t",
        "artifact_type": "network",
        "condition": {"status": "ESTABLISHED"},
    }
    artifacts = [
        {
            "host": "h",
            "os": "windows",
            "artifact_type": "process",
            "collected_at": "x",
            "data": {"status": "ESTABLISHED"},
        }
    ]
    assert evaluate([rule], artifacts) == []
