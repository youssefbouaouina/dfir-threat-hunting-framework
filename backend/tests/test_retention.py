"""Tests for Phase 4 (F3): retention/archival — JSONL + OpenSearch sink."""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import models

OLD = datetime(2020, 1, 1, tzinfo=timezone.utc)
RECENT = datetime.now(timezone.utc) - timedelta(days=1)


def _add_artifact(db, ts=RECENT, host="host-a", processed=1):
    row = models.Artifact(
        host=host,
        os="linux",
        artifact_type="process",
        collected_at=ts.isoformat(),
        data=json.dumps({"cmdline": ["sh", "-c", "evil"]}),
        ingested_at=ts,
        processed=processed,
    )
    db.add(row)
    return row


def _add_detection(db, ts=RECENT):
    row = models.Detection(
        host="host-a",
        rule_id="rule-1",
        rule_title="Suspicious",
        severity="high",
        artifact_type="process",
        matched_data=json.dumps({"x": 1}),
        detected_at=ts,
    )
    db.add(row)
    return row


def _add_run(db, ts=RECENT):
    row = models.DetectionRun(trigger="scheduled", status="completed", started_at=ts)
    db.add(row)
    return row


def _add_audit(db, ts=RECENT):
    row = models.AuditLog(actor="admin", action="run_detection", created_at=ts)
    db.add(row)
    return row


def test_retention_disabled_by_default(db_session, tmp_path):
    from services import retention_service

    _add_artifact(db_session, OLD)
    _add_detection(db_session, OLD)
    db_session.commit()

    days = {t: 0 for t in retention_service._TABLES}
    summary = retention_service.run_retention(db_session, days=days, archive_dir=str(tmp_path))

    assert all(not v["enabled"] for v in summary.values())
    assert db_session.query(models.Artifact).count() == 1
    assert db_session.query(models.Detection).count() == 1


def test_retention_archives_and_deletes_old_artifacts(db_session, tmp_path):
    from services import retention_service

    old = _add_artifact(db_session, OLD)
    fresh = _add_artifact(db_session, RECENT)
    db_session.commit()
    old_id, fresh_id = old.id, fresh.id

    summary = retention_service.run_retention(
        db_session, days={"artifacts": 30}, archive_dir=str(tmp_path)
    )

    assert summary["artifacts"]["enabled"]
    assert summary["artifacts"]["deleted"] == 1
    assert db_session.query(models.Artifact).filter(models.Artifact.id == old_id).count() == 0
    assert db_session.query(models.Artifact).filter(models.Artifact.id == fresh_id).count() == 1


def test_jsonl_archive_contains_archived_record(db_session, tmp_path):
    from services import retention_service

    _add_artifact(db_session, OLD)
    db_session.commit()

    retention_service.run_retention(
        db_session, days={"artifacts": 30}, archive_dir=str(tmp_path)
    )

    files = list((tmp_path / "artifacts").glob("*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["_table"] == "artifacts"
    assert record["host"] == "host-a"


def test_retention_deletes_incident_links_with_detections(db_session, tmp_path):
    import models
    from services import correlation_service, retention_service

    # two techniques on one host -> an attack-chain incident
    det_old = _add_detection(db_session, OLD)
    det_old.technique_id = "T1055"
    db_session.add(
        models.Detection(
            host="host-a",
            rule_id="rule-2",
            rule_title="Second",
            technique_id="T1078",
            severity="high",
            artifact_type="process",
            matched_data=json.dumps({"x": 2}),
            detected_at=OLD,
        )
    )
    db_session.commit()
    correlation_service.recompute_incidents(db_session)

    incident = db_session.query(models.Incident).first()
    assert incident is not None
    det_old_id = det_old.id
    link = db_session.query(models.IncidentDetection).filter(
        models.IncidentDetection.detection_id == det_old_id
    ).first()
    assert link is not None

    retention_service.run_retention(
        db_session, days={"detections": 30}, archive_dir=str(tmp_path)
    )

    assert db_session.query(models.Detection).count() == 0
    assert (
        db_session.query(models.IncidentDetection)
        .filter(models.IncidentDetection.detection_id == det_old_id)
        .count()
        == 0
    )


def test_opensearch_sink_called_when_configured(db_session, tmp_path):
    from services import retention_service

    _add_detection(db_session, OLD)
    db_session.commit()

    with patch("services.retention_service.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.raise_for_status.return_value = None
        retention_service.run_retention(
            db_session,
            days={"detections": 30},
            archive_dir=str(tmp_path),
            opensearch_url="https://os.example:9200",
        )

    mock_post.assert_called_once()
    bulk_body = mock_post.call_args.kwargs["data"]
    assert '{"index": {"_index": "dfir-detections"' in bulk_body
    assert '"rule_id": "rule-1"' in bulk_body


def test_opensearch_failure_does_not_block_archival(db_session, tmp_path):
    from services import retention_service

    _add_detection(db_session, OLD)
    db_session.commit()

    with patch(
        "services.retention_service.requests.post",
        side_effect=RuntimeError("sink down"),
    ):
        summary = retention_service.run_retention(
            db_session,
            days={"detections": 30},
            archive_dir=str(tmp_path),
            opensearch_url="https://os.example:9200",
        )

    assert summary["detections"]["deleted"] == 1
    assert db_session.query(models.Detection).count() == 0
    files = list((tmp_path / "detections").glob("*.jsonl"))
    assert len(files) == 1


def test_retention_handles_all_tables(db_session, tmp_path):
    from services import retention_service

    _add_artifact(db_session, OLD)
    _add_detection(db_session, OLD)
    _add_run(db_session, OLD)
    _add_audit(db_session, OLD)
    db_session.commit()

    days = {t: 30 for t in retention_service._TABLES}
    summary = retention_service.run_retention(db_session, days=days, archive_dir=str(tmp_path))

    assert all(v["enabled"] and v["deleted"] == 1 for v in summary.values())
    assert db_session.query(models.Artifact).count() == 0
    assert db_session.query(models.Detection).count() == 0
    assert db_session.query(models.DetectionRun).count() == 0
    assert db_session.query(models.AuditLog).count() == 0


def test_retention_status_reports_eligibility(db_session, tmp_path):
    from services import retention_service

    _add_artifact(db_session, OLD)
    _add_artifact(db_session, RECENT)
    db_session.commit()

    status = retention_service.retention_status(
        db_session, days={"artifacts": 30}
    )

    assert status["tables"]["artifacts"]["enabled"]
    assert status["tables"]["artifacts"]["eligible"] == 1
    assert status["tables"]["detections"]["enabled"] is False


def test_retention_api_run_endpoint(client, db_session, monkeypatch, tmp_path):
    """POST /retention/run archives+deletes and records an audit action."""
    monkeypatch.setenv("RETENTION_DAYS_ARTIFACTS", "30")

    _add_artifact(db_session, OLD)
    _add_artifact(db_session, RECENT)
    db_session.commit()

    resp = client.post("/retention/run")
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["artifacts"]["deleted"] == 1
    assert summary["artifacts"]["enabled"]

    # audit trail records the manual run
    logs = client.get("/audit-logs").json()
    assert any(log["action"] == "run_retention" for log in logs)

    # status endpoint reflects post-run state
    status = client.get(
        "/retention/status",
        params={"artifact_days": 30, "detection_days": 0, "run_days": 0, "audit_days": 0},
    ).json()
    assert status["tables"]["artifacts"]["eligible"] == 0
