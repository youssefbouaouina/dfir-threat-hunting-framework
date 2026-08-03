"""Service-level tests for the detection pipeline (run history, processed lifecycle)."""
import json

import pytest

import models
from services import detection_service

RULE_YAML = """title: Suspicious PowerShell EncodedCommand
id: rule-001
artifact_type: process
technique_id: T1059.001
severity: high
condition:
  cmdline_contains: ["-enc"]
"""


@pytest.fixture()
def svc(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule001.yml").write_text(RULE_YAML)
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(rules))
    return detection_service


def _add_artifact(db, cmdline, host="h1", artifact_type="process"):
    artifact = models.Artifact(
        host=host,
        os="linux",
        artifact_type=artifact_type,
        collected_at="2026-01-01T00:00:00Z",
        data=json.dumps({"cmdline": cmdline}),
    )
    db.add(artifact)
    db.commit()
    return artifact


def test_run_detection_persists_detection_and_history(db_session, svc):
    artifact = _add_artifact(db_session, "powershell.exe -enc AAAA")
    result = svc.run_detection_job(db_session, trigger="manual")

    assert result["artifacts_scanned"] == 1
    assert result["detections_found"] == 1

    db_session.refresh(artifact)
    assert artifact.processed == 1

    runs = db_session.query(models.DetectionRun).all()
    assert len(runs) == 1
    assert runs[0].status == "completed"
    assert runs[0].trigger == "manual"
    assert runs[0].detections_found == 1


def test_no_rescan_does_not_repeat(db_session, svc):
    _add_artifact(db_session, "powershell.exe -enc AAAA")
    assert svc.run_detection_job(db_session)["artifacts_scanned"] == 1
    assert svc.run_detection_job(db_session)["artifacts_scanned"] == 0


def test_rescan_reanalyzes_processed_artifacts(db_session, svc):
    _add_artifact(db_session, "powershell.exe -enc AAAA")
    svc.run_detection_job(db_session)
    result = svc.run_detection_job(db_session, rescan=True)
    assert result["artifacts_scanned"] == 1
    assert result["detections_found"] == 1
    assert db_session.query(models.Detection).count() == 2


def test_host_scope_limits_scan(db_session, svc):
    _add_artifact(db_session, "powershell.exe -enc AAAA", host="h1")
    _add_artifact(db_session, "powershell.exe -enc BBBB", host="h2")
    result = svc.run_detection_job(db_session, host="h1")
    assert result["artifacts_scanned"] == 1
    remaining = (
        db_session.query(models.Artifact).filter(models.Artifact.processed == 0).count()
    )
    assert remaining == 1  # h2 untouched


def test_failed_run_is_recorded(db_session, svc, monkeypatch):
    _add_artifact(db_session, "powershell.exe -enc AAAA")

    def boom(*args, **kwargs):
        raise RuntimeError("engine failure")

    monkeypatch.setattr(svc, "evaluate_sigma", boom)
    with pytest.raises(RuntimeError):
        svc.run_detection_job(db_session)

    runs = db_session.query(models.DetectionRun).all()
    assert len(runs) == 1
    assert runs[0].status == "failed"


def test_yara_severity_from_rule_meta(db_session, svc):
    """M1: YARA severity should come from rule meta.severity/level, not a hardcoded 'high'."""
    artifact = models.Artifact(
        host="h1",
        os="linux",
        artifact_type="file_scan",
        collected_at="2026-01-01T00:00:00Z",
        data=json.dumps(
            {
                "yara_matches": [
                    {
                        "rule": "EvilRule",
                        "meta": {"description": "bad stuff", "severity": "critical"},
                    },
                    {"rule": "OtherRule", "meta": {"level": "medium"}},
                    {"rule": "BareRule"},
                ]
            }
        ),
    )
    db_session.add(artifact)
    db_session.commit()

    svc.run_detection_job(db_session)

    detections = {d.rule_id: d.severity for d in db_session.query(models.Detection).all()}
    assert detections["yara-EvilRule"] == "critical"
    assert detections["yara-OtherRule"] == "medium"
    assert detections["yara-BareRule"] == "high"  # no meta -> default
