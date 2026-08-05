"""Tests for the pySigma engine (sigma_engine) and the SigmaHQ pipeline (sigma_service)."""
import os

import pytest
from sigma.rule import SigmaRule

from services import sigma_service
from sigma_engine import evaluate, load_rules, summarize

NATIVE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigma_rules", "native"
)

ENCODED_RULE = """title: Suspicious PowerShell EncodedCommand
id: c1a3f4e2-9b7d-4a5e-8f2b-1c6d9e0a3b4c
status: test
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - "-EncodedCommand"
      - "-enc"
  condition: selection
tags:
  - attack.t1059.001
"""


def _make_rule(yaml_text: str):
    return SigmaRule.from_yaml(yaml_text)


def _proc(cmdline, name="powershell.exe", exe=r"C:\Windows\System32\powershell.exe"):
    return {
        "host": "h1",
        "os": "windows",
        "artifact_type": "process",
        "collected_at": "x",
        "data": {"name": name, "exe": exe, "cmdline": cmdline},
    }


def test_load_rules_skips_invalid_and_dedupes(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a_valid.yml").write_text(ENCODED_RULE)
    (rules_dir / "b_duplicate.yml").write_text(ENCODED_RULE.replace("high", "medium"))
    (rules_dir / "c_bad.yml").write_text(": : : [")
    rules = load_rules(str(rules_dir))
    assert len(rules) == 1
    assert str(rules[0].id) == "c1a3f4e2-9b7d-4a5e-8f2b-1c6d9e0a3b4c"


def test_summarize_counts_mapped():
    rule = _make_rule(ENCODED_RULE)
    summary = summarize([rule])
    assert summary["total"] == 1
    assert summary["mapped"] == 1


def test_evaluate_contains_case_insensitive():
    rule = _make_rule(ENCODED_RULE)
    detections = evaluate([rule], [_proc("powershell.exe -ENCODEDCOMMAND AA==")])
    assert len(detections) == 1
    d = detections[0]
    assert d["rule_id"] == "c1a3f4e2-9b7d-4a5e-8f2b-1c6d9e0a3b4c"
    assert d["severity"] == "high"
    assert d["technique_id"] == "T1059.001"
    assert d["host"] == "h1"


def test_evaluate_ignores_wrong_artifact_type():
    rule = _make_rule(ENCODED_RULE)
    artifact = {
        "host": "h1",
        "os": "windows",
        "artifact_type": "network",
        "collected_at": "x",
        "data": {"cmdline": "-EncodedCommand AA=="},
    }
    assert evaluate([rule], [artifact]) == []


def test_evaluate_unmapped_logsource_ignored():
    rule = _make_rule(
        ENCODED_RULE.replace(
            "  category: process_creation",
            "  category: image_load",
        )
    )
    assert evaluate([rule], [_proc("-EncodedCommand")]) == []


def test_evaluate_not_filter():
    rule = _make_rule(
        """title: T
id: 11111111-2222-4333-8444-555555555555
status: test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'EncodedCommand'
  filter:
    Image: 'C:\\Windows\\explorer.exe'
  condition: selection and not filter
"""
    )
    assert evaluate([rule], [_proc("powershell -EncodedCommand x")])
    assert evaluate(
        [rule], [_proc("powershell -EncodedCommand x", exe=r"C:\Windows\explorer.exe")]
    ) == []


def test_evaluate_selector_1_of():
    rule = _make_rule(
        """title: T
id: 11111111-2222-4333-8444-666666666666
status: test
level: low
logsource:
  category: process_creation
detection:
  selection_a:
    CommandLine|contains: 'whoami'
  selection_b:
    CommandLine|contains: 'systeminfo'
  condition: 1 of selection_*
"""
    )
    assert len(evaluate([rule], [_proc("whoami /all")])) == 1
    assert len(evaluate([rule], [_proc("systeminfo")])) == 1
    assert evaluate([rule], [_proc("dir")]) == []


def test_evaluate_regex_modifier():
    rule = _make_rule(
        """title: T
id: 11111111-2222-4333-8444-888888888888
status: test
level: low
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|re: '^powershell.*-enc .*'
  condition: selection
"""
    )
    assert len(evaluate([rule], [_proc("powershell.exe -enc SQBFAFgA")])) == 1
    assert evaluate([rule], [_proc("cmd.exe /c dir")]) == []


def test_evaluate_cidr():
    rule = _make_rule(
        """title: T
id: 11111111-2222-4333-8444-aaaaaaaaaaaa
status: test
level: low
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp|cidr: '203.0.113.0/24'
  condition: selection
"""
    )
    artifact = {
        "host": "h1",
        "os": "windows",
        "artifact_type": "network",
        "collected_at": "x",
        "data": {"remote_address": "203.0.113.66"},
    }
    assert len(evaluate([rule], [artifact])) == 1
    artifact["data"]["remote_address"] = "8.8.8.8"
    assert evaluate([rule], [artifact]) == []


def test_evaluate_numeric_compare():
    rule = _make_rule(
        """title: T
id: 11111111-2222-4333-8444-999999999999
status: test
level: low
logsource:
  category: file_event
detection:
  selection:
    FileSize|gte: 1000000
  condition: selection
"""
    )
    artifact = {
        "host": "h1",
        "os": "windows",
        "artifact_type": "file_scan",
        "collected_at": "x",
        "data": {"path": "x", "size_bytes": 2000000},
    }
    assert len(evaluate([rule], [artifact])) == 1
    artifact["data"]["size_bytes"] = 100
    assert evaluate([rule], [artifact]) == []


def test_shipped_native_rules_all_parse():
    """CI guard for F6: every committed native rule must load and map."""
    rules = load_rules(NATIVE_DIR)
    assert len(rules) >= 6
    assert all(r.id for r in rules)
    summary = summarize(rules)
    assert summary["unmapped"] == 0


# ---------------------------------------------------------------------------
# sigma_service pipeline
# ---------------------------------------------------------------------------

COMPATIBLE = """title: Compatible process rule
id: 22222222-3333-4444-8555-666666666666
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'mimikatz'
  condition: selection
"""

UNMAPPED = """title: Unmapped logsource
id: 22222222-3333-4444-8555-777777777777
status: stable
level: low
logsource:
  category: driver_load
detection:
  selection:
    ImageLoaded|endswith: '.sys'
  condition: selection
"""

UNMAPPED_FIELD = """title: Field we don't collect
id: 22222222-3333-4444-8555-888888888888
status: stable
level: low
logsource:
  category: process_creation
detection:
  selection:
    Hashes|contains: 'abc'
  condition: selection
"""

DEPRECATED = """title: Deprecated
id: 22222222-3333-4444-8555-999999999999
status: deprecated
level: low
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'x'
  condition: selection
"""


@pytest.fixture()
def source_dir(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "compatible.yml").write_text(COMPATIBLE)
    (src / "unmapped_logsrc.yml").write_text(UNMAPPED)
    (src / "unmapped_field.yml").write_text(UNMAPPED_FIELD)
    (src / "deprecated.yml").write_text(DEPRECATED)
    (src / "broken.yml").write_text(": : : [")
    monkeypatch.setattr(sigma_service, "LOCAL_SOURCE_DIR", str(src))
    return str(src)


def test_refresh_imports_only_compatible(source_dir, tmp_path):
    target = tmp_path / "target"
    summary = sigma_service.refresh_sigma_rules(source="local", target_dir=str(target))
    assert summary["scanned"] == 5
    assert summary["imported"] == 1
    assert summary["skipped_invalid"] == 1
    assert summary["skipped_deprecated"] == 1
    assert summary["skipped_unmapped"] == 2
    imported = [f for f in os.listdir(str(target)) if f.startswith("sigmahq_")]
    assert imported == ["sigmahq_22222222-3333-4444-8555-666666666666.yml"]
    assert os.path.isfile(os.path.join(str(target), sigma_service.REFRESH_MARKER))


def test_refresh_dedupes_by_id(source_dir, tmp_path):
    with open(os.path.join(source_dir, "compatible_dup.yml"), "w", encoding="utf-8") as f:
        f.write(COMPATIBLE.replace("stable", "test"))
    target = tmp_path / "target"
    summary = sigma_service.refresh_sigma_rules(source="local", target_dir=str(target))
    assert summary["imported"] == 1
    assert summary["skipped_duplicate"] == 1
    imported = [f for f in os.listdir(str(target)) if f.startswith("sigmahq_")]
    assert len(imported) == 1


def test_get_refresh_status_records_last_refresh(source_dir, tmp_path):
    target = tmp_path / "target"
    sigma_service.refresh_sigma_rules(source="local", target_dir=str(target))
    status = sigma_service.get_refresh_status(target_dir=str(target))
    assert status["last_refresh"] is not None
    assert status["current_rule_count"] == 1
    assert status["summary"]["imported"] == 1


def test_refresh_unknown_source_raises():
    with pytest.raises(ValueError):
        sigma_service.refresh_sigma_rules(source="nonsense")


# ---------------------------------------------------------------------------
# Full-pipeline integration: native rules fire through run_detection_job
# ---------------------------------------------------------------------------


def test_native_rules_fire_through_detection_service(db_session, monkeypatch, tmp_path):
    """F6 integration: with the legacy matcher empty, the pySigma engine alone
    produces the detection when run_detection_job runs."""
    import json

    import models
    from services import detection_service

    empty = tmp_path / "empty_rules"
    empty.mkdir()
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(empty))
    # NATIVE_SIGMA_RULES_DIR already points at the committed native rules dir.

    db_session.add(
        models.Artifact(
            host="h1",
            os="windows",
            artifact_type="process",
            collected_at="2026-01-01T00:00:00Z",
            data=json.dumps(
                {
                    "cmdline": "powershell.exe -EncodedCommand SQBFAFgA",
                    "exe": r"C:\Windows\System32\powershell.exe",
                }
            ),
        )
    )
    db_session.commit()

    result = detection_service.run_detection_job(db_session, trigger="manual")
    assert result["artifacts_scanned"] == 1
    assert result["detections_found"] == 1

    det = db_session.query(models.Detection).first()
    assert det.rule_id == "c1a3f4e2-9b7d-4a5e-8f2b-1c6d9e0a3b4c"
    assert det.severity == "high"
    assert det.technique_id == "T1059.001"
