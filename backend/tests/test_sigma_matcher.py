"""
Unit tests for the Sigma-inspired behavioral matcher (sigma_matcher.py).

Covers: rule loading, every supported condition operator, the exact
regression scenario from TUNING-1 (rule-005 false positive on the
built-in \\Microsoft\\Windows\\Workplace Join\\Recovery-Check task, whose
task_to_run '%SystemRoot%\\System32\\dsregcmd.exe /checkrecovery'
contains the substring 'cmd.exe /c').
"""
import os

import pytest

from sigma_matcher import _has_word, _matches_condition, evaluate, load_rules

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigma_rules")


def _artifact(atype: str, data: dict) -> dict:
    return {"host": "test-host", "os": "windows", "artifact_type": atype, "collected_at": "2026-01-01T00:00:00Z", "data": data}


# ---------------------------------------------------------------- rule loading


def test_all_rules_load():
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 15
    ids = {r.get("id") for r in rules}
    assert "rule-001" in ids and "rule-015" in ids


def test_loaded_rules_have_required_fields():
    for rule in load_rules(RULES_DIR):
        if not rule.get("id"):
            continue  # auxiliary/dev rule files
        assert rule.get("title"), rule
        assert rule.get("artifact_type"), rule
        assert rule.get("condition"), rule


# ---------------------------------------------------------------- operators


def test_exact_match_operator():
    condition = {"status": "STOPPED"}
    assert _matches_condition({"status": "STOPPED"}, condition)
    assert not _matches_condition({"status": "Running"}, condition)


def test_list_match_operator():
    condition = {"status": ["STOPPED", "Disabled"]}
    assert _matches_condition({"status": "Disabled"}, condition)
    assert not _matches_condition({"status": "Running"}, condition)


def test_contains_operator_substring():
    condition = {"cmdline_contains": ["-EncodedCommand"]}
    assert _matches_condition({"cmdline": "powershell -EncodedCommand ABC"}, condition)
    assert not _matches_condition({"cmdline": "powershell -Command ABC"}, condition)


def test_contains_is_case_insensitive():
    condition = {"cmdline_contains": ["-encodedcommand"]}
    assert _matches_condition({"cmdline": "powershell -EncodedCommand ABC"}, condition)


# ------------------------------------------------- TUNING-1 regression: _has_word


def test_has_word_basic_and_prefix():
    assert _has_word("run cmd.exe /c x", "cmd.exe")
    assert _has_word("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell")
    assert _has_word("mshta.exe foo", "mshta")


def test_has_word_does_not_match_substring_inside_other_token():
    # %SystemRoot%\System32\dsregcmd.exe /checkrecovery — the old
    # substring 'contains' operator matched "cmd.exe /c" here (TUNING-1).
    assert not _has_word("%SystemRoot%\\System32\\dsregcmd.exe /checkrecovery", "cmd.exe /c")
    assert not _has_word("dsregcmd.exe /checkrecovery", "cmd.exe")
    assert not _has_word("powershellise.exe", "powershell")


def test_rule005_false_positive_regression():
    """The exact built-in task that caused the FP must NOT fire rule-005;
    a genuinely script-interpreter task must fire it."""
    rule = next(r for r in load_rules(RULES_DIR) if r["id"] == "rule-005")

    benign_artifact = _artifact(
        "scheduled_task",
        {"task_name": "\\Microsoft\\Windows\\Workplace Join\\Recovery-Check", "task_to_run": "%SystemRoot%\\System32\\dsregcmd.exe /checkrecovery", "status": "Ready"},
    )
    assert evaluate([rule], [benign_artifact]) == []

    evil_artifact = _artifact(
        "scheduled_task",
        {"task_name": "\\EvilUpdateTask", "task_to_run": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -nop -enc UwB0AGEAcgB0...", "status": "Ready"},
    )
    hits = evaluate([rule], [evil_artifact])
    assert len(hits) == 1 and hits[0]["rule_id"] == "rule-005"


def test_rule005_still_catches_cmd_and_mshta():
    rule = next(r for r in load_rules(RULES_DIR) if r["id"] == "rule-005")
    for task in [
        {"task_to_run": "cmd.exe /c exit"},
        {"task_to_run": "mshta vbscript:createobject(\"wscript.shell\")"},
        {"task_to_run": "wscript.exe C:\\Users\\x\\eval.vbs"},
    ]:
        hits = evaluate([rule], [_artifact("scheduled_task", task)])
        assert len(hits) == 1, task


# ---------------------------------------------------------------- evaluate()


def test_evaluate_returns_expected_shape():
    rule = {"id": "rule-x", "title": "T", "artifact_type": "process", "technique_id": "T0000", "severity": "high", "condition": {"cmdline_contains": ["-enc"]}}
    hits = evaluate([rule], [_artifact("process", {"cmdline": "powershell -enc ABC"})])
    assert hits[0]["rule_id"] == "rule-x"
    assert hits[0]["technique_id"] == "T0000"
    assert hits[0]["severity"] == "high"
    assert hits[0]["host"] == "test-host"
    assert hits[0]["matched_data"]["cmdline"] == "powershell -enc ABC"


def test_evaluate_ignores_other_artifact_types():
    rule = {"id": "rule-x", "artifact_type": "process", "condition": {"cmdline_contains": ["-enc"]}}
    assert evaluate([rule], [_artifact("persistence", {"cmdline": "-enc"})]) == []


@pytest.mark.parametrize(
    "value,term,expected",
    [
        ("cmd.exe /c exit", "cmd.exe", True),
        ("C:\\tools\\cmd.exe", "cmd.exe", True),
        ("dsregcmd.exe", "cmd.exe", False),
        ("dsregcmd.exe /checkrecovery", "cmd.exe /c", False),
        ("powershell.exe -nop", "powershell", True),
        ("powershellise.exe", "powershell", False),
        ("wscript.exe", "wscript", True),
        ("mshta", "mshta", True),
    ],
)
def test_has_word_table(value, term, expected):
    assert _has_word(value, term) is expected