"""Tests for Phase 4 (F5): scan-all, endpoint reports, criticality, notifications."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# ---------------------------------------------------------------------------
# Endpoint scan-all + per-endpoint report
# ---------------------------------------------------------------------------


def _enroll(client, hostname, os_name="linux", team=None):
    return client.post(
        "/endpoints/enroll",
        json={"hostname": hostname, "os": os_name, "agent_version": "3.0"},
    )


def test_scan_all_queues_command_for_every_endpoint(client, db_session):
    _enroll(client, "host-a")
    _enroll(client, "host-b")

    resp = client.post("/endpoints/scan-all")
    assert resp.status_code == 200
    body = resp.json()
    assert body["endpoints_targeted"] == 2
    assert len(body["queued"]) == 2
    assert {c["hostname"] for c in body["queued"]} == {"host-a", "host-b"}

    import models

    commands = db_session.query(models.PendingCommand).all()
    assert len(commands) == 2
    assert all(c.command == "run_collection" for c in commands)
    assert all(c.status == "pending" for c in commands)


def test_scan_all_noop_without_endpoints(client):
    resp = client.post("/endpoints/scan-all")
    assert resp.status_code == 200
    body = resp.json()
    assert body["endpoints_targeted"] == 0
    assert body["queued"] == []


def test_scan_all_is_audited(client, db_session):
    import models

    _enroll(client, "host-a")
    client.post("/endpoints/scan-all")

    audit = (
        db_session.query(models.AuditLog)
        .filter(models.AuditLog.action == "queue_collection_all")
        .all()
    )
    assert len(audit) == 1


def test_endpoint_report_aggregates(client, db_session, monkeypatch, tmp_path):
    import models
    from services import detection_service

    _enroll(client, "host-a")
    endpoint_id = db_session.query(models.Endpoint).first().id

    # Seed artifacts + a detection run for the host.
    rules = tmp_path / "rules"
    rules.mkdir()
    rule_yaml = (
        "title: t\nid: rule-001\nseverity: high\n"
        "artifact_type: process\ncondition:\n  cmdline_contains: ['-enc']\n"
    )
    (rules / "r1.yml").write_text(rule_yaml)
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(rules))
    db_session.add(
        models.Artifact(
            host="host-a",
            os="linux",
            artifact_type="process",
            collected_at="2026-01-01T00:00:00Z",
            data=json.dumps({"cmdline": "powershell -enc AA"}),
        )
    )
    db_session.commit()
    detection_service.run_detection_job(db_session, host="host-a", trigger="manual")

    resp = client.get(f"/endpoints/{endpoint_id}/report")
    assert resp.status_code == 200
    report = resp.json()

    assert report["endpoint"]["hostname"] == "host-a"
    assert report["endpoint"]["criticality"] == "standard"
    assert report["artifacts"]["total"] == 1
    assert report["artifacts"]["by_type"] == {"process": 1}
    assert report["detections"]["total"] == 1
    assert report["detections"]["by_severity"] == {"high": 1}
    assert report["run_history"][0]["artifacts_scanned"] == 1


def test_endpoint_report_unknown_id_404(client):
    resp = client.get("/endpoints/99999/report")
    assert resp.status_code == 404


def test_scan_all_unknown_route_not_confused_with_report(client):
    """/scan-all is exact, not an endpoint-id route — both coexist."""
    resp = client.post("/endpoints/scan-all")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Criticality: update + correlation amplification
# ---------------------------------------------------------------------------


def test_update_endpoint_criticality(client, db_session):
    import models

    _enroll(client, "host-a")
    endpoint_id = db_session.query(models.Endpoint).first().id

    resp = client.put(
        f"/endpoints/{endpoint_id}/config", json={"criticality": "critical"}
    )
    assert resp.status_code == 200
    assert resp.json()["criticality"] == "critical"


def test_update_endpoint_criticality_invalid(client, db_session):
    import models

    _enroll(client, "host-a")
    endpoint_id = db_session.query(models.Endpoint).first().id

    resp = client.put(
        f"/endpoints/{endpoint_id}/config", json={"criticality": "super-important"}
    )
    assert resp.status_code == 400


def test_critical_host_amplifies_chain_incident(db_session):
    """A chain on a critical host escalates even without 3-technique depth."""
    import models
    from services import correlation_service

    _add_detection(db_session, "crown-jewel", "rule-1", "One", "T1055", "medium")
    _add_detection(db_session, "crown-jewel", "rule-2", "Two", "T1059.001", "medium")
    db_session.add(
        models.Endpoint(
            hostname="crown-jewel",
            os="linux",
            criticality="critical",
        )
    )
    db_session.commit()

    correlation_service.recompute_incidents(db_session)

    incident = db_session.query(models.Incident).first()
    assert incident is not None
    # medium + critical host (+2 bump) -> critical, even though only 2 techniques
    assert incident.severity == "critical"


def test_standard_host_chain_not_amplified(db_session):
    import models
    from services import correlation_service

    _add_detection(db_session, "plain-host", "rule-1", "One", "T1055", "medium")
    _add_detection(db_session, "plain-host", "rule-2", "Two", "T1059.001", "medium")
    db_session.commit()

    correlation_service.recompute_incidents(db_session)

    incident = db_session.query(models.Incident).first()
    # 2 techniques, no escalation, standard host -> stays medium
    assert incident is not None
    assert incident.severity == "medium"


def _add_detection(db, host, rule_id, rule_title, technique_id, severity):
    import models

    db.add(
        models.Detection(
            host=host,
            rule_id=rule_id,
            rule_title=rule_title,
            technique_id=technique_id,
            severity=severity,
            artifact_type="process",
            matched_data=json.dumps({"x": 1}),
        )
    )


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class _FakePost:
    def __init__(self):
        self.sent = []
        self.fail = False

    def __call__(self, url, headers=None, data=None, timeout=None):
        if self.fail:
            raise RuntimeError("webhook down")
        self.sent.append((url, headers, data))
        return _FakeResponse(200)

    @property
    def last_payload(self):
        return json.loads(self.sent[-1][2])


class _FakeResponse:
    def __init__(self, status):
        self.status_code = status

    def raise_for_status(self):
        pass


@pytest.fixture()
def no_notify(monkeypatch):
    """Ensure the pipeline doesn't fire real notifications during these tests."""
    for var in ("NOTIFY_WEBHOOK_URL", "NOTIFY_SMTP_HOST", "NOTIFY_EMAIL_TO"):
        monkeypatch.delenv(var, raising=False)


def test_notify_skipped_when_disabled(monkeypatch, no_notify):
    from services import notification_service

    assert notification_service.notifications_enabled() is False
    # nothing raised, nothing sent
    notification_service.notify_detections(
        [{"severity": "critical", "rule_id": "r1", "host": "h"}]
    )


def test_notify_detection_threshold(monkeypatch):
    from services import notification_service

    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "http://wh")
    fake = _FakePost()
    monkeypatch.setattr(notification_service.requests, "post", fake)

    notification_service.notify_detections(
        [
            {"severity": "low", "rule_id": "r-low", "host": "h1"},
            {"severity": "critical", "rule_id": "r-crit", "host": "h2"},
        ]
    )

    assert len(fake.sent) == 1  # only the critical one fires
    payload = fake.last_payload
    assert payload["event"] == "dfir.detection"
    assert payload["severity"] == "critical"
    assert payload["detail"]["rule_id"] == "r-crit"


def test_notify_detection_webhook_failure_is_soft(monkeypatch, no_notify):
    from services import notification_service

    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "http://wh")
    fake = _FakePost()
    fake.fail = True
    monkeypatch.setattr(notification_service.requests, "post", fake)

    # must not raise
    notification_service.notify_detections(
        [{"severity": "high", "rule_id": "r1", "host": "h"}]
    )


def test_notify_endpoint_offline(monkeypatch):
    from services import notification_service

    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "http://wh")
    fake = _FakePost()
    monkeypatch.setattr(notification_service.requests, "post", fake)

    notification_service.notify_endpoint_offline(["edge-1", "edge-2"])

    assert len(fake.sent) == 1
    payload = fake.last_payload
    assert payload["event"] == "dfir.endpoint_offline"
    assert payload["detail"]["hostnames"] == ["edge-1", "edge-2"]


def test_notify_offline_skipped_when_empty(monkeypatch, no_notify):
    from services import notification_service

    notification_service.notify_endpoint_offline([])  # no-op, no raise


# ---------------------------------------------------------------------------
# Detection worker
# ---------------------------------------------------------------------------


def test_detection_worker_sweep_runs_pipeline(db_session, monkeypatch, tmp_path):
    import models
    import workers.detection_worker as worker
    from services import detection_service

    rules = tmp_path / "rules"
    rules.mkdir()
    rule_yaml = (
        "title: t\nid: rule-001\nseverity: high\n"
        "artifact_type: process\ncondition:\n  cmdline_contains: ['-enc']\n"
    )
    (rules / "r1.yml").write_text(rule_yaml)
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(rules))

    db_session.add(
        models.Artifact(
            host="worker-host",
            os="linux",
            artifact_type="process",
            collected_at="2026-01-01T00:00:00Z",
            data=json.dumps({"cmdline": "powershell -enc AA"}),
        )
    )
    db_session.commit()

    result = worker.run_one_sweep(db=db_session)

    assert result is not None
    assert result["artifacts_scanned"] == 1
    assert result["detections_found"] == 1

    run = db_session.query(models.DetectionRun).first()
    assert run.trigger == "worker"
    assert run.status == "completed"


def test_detection_worker_sweep_noop_when_nothing_unprocessed(db_session):
    import workers.detection_worker as worker

    assert worker.run_one_sweep(db=db_session) is None


def test_detection_worker_owns_session_when_none_passed(monkeypatch):
    """run_one_sweep() with no db opens and closes its own SessionLocal."""
    import workers.detection_worker as worker

    class _FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def close(self):
            self.closed = True

    fake = _FakeSession()
    monkeypatch.setattr(worker, "SessionLocal", lambda: fake)
    monkeypatch.setattr(worker, "run_detection_job", lambda db, trigger="worker": None)

    result = worker.run_one_sweep()
    assert result is None
    assert fake.closed is True
