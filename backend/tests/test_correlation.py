"""Tests for Phase 4 (F2): correlation engine — campaigns, chains, severity."""
import json
from datetime import datetime, timezone


def _add_detection(db, host, rule_id, rule_title, technique_id, severity, detected_at=None):
    import models

    row = models.Detection(
        host=host,
        rule_id=rule_id,
        rule_title=rule_title,
        technique_id=technique_id,
        severity=severity,
        artifact_type="process",
        matched_data=json.dumps({"x": 1}),
        detected_at=detected_at or datetime.now(timezone.utc),
    )
    db.add(row)
    return row


def test_campaign_rule_across_hosts_creates_incident(db_session):
    import models
    from services import correlation_service

    _add_detection(db_session, "host-a", "rule-001", "Suspicious PS", "T1059.001", "high")
    _add_detection(db_session, "host-b", "rule-001", "Suspicious PS", "T1059.001", "high")
    _add_detection(db_session, "host-c", "rule-001", "Suspicious PS", "T1059.001", "high")
    db_session.commit()

    result = correlation_service.recompute_incidents(db_session)
    assert result["incidents"] == 1

    incident = db_session.query(models.Incident).first()
    assert incident.signature == "campaign:rule-001"
    assert incident.host_count == 3
    assert incident.detection_count == 3
    assert incident.title == "Suspicious PS across 3 hosts"
    # 3 hosts -> escalated one level from high to critical
    assert incident.severity == "critical"
    assert incident.technique_ids is not None


def test_single_rule_single_host_does_not_incident(db_session):
    import models
    from services import correlation_service

    _add_detection(db_session, "host-a", "rule-001", "Solo hit", "T1059.001", "high")
    db_session.commit()

    result = correlation_service.recompute_incidents(db_session)
    assert result["incidents"] == 0
    assert db_session.query(models.Incident).count() == 0


def test_attack_chain_single_host_multiple_techniques(db_session):
    import models
    from services import correlation_service

    _add_detection(
        db_session, "host-x", "rule-1", "One", "T1055", "medium",
        datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    _add_detection(
        db_session, "host-x", "rule-2", "Two", "T1059.001", "high",
        datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    _add_detection(
        db_session, "host-x", "rule-3", "Three", "T1078", "high",
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    db_session.commit()

    result = correlation_service.recompute_incidents(db_session)
    assert result["incidents"] == 1

    incident = db_session.query(models.Incident).first()
    assert incident.signature == "chain:host-x"
    assert incident.title == "Attack chain on host-x (3 techniques)"
    assert incident.host_count == 1
    assert incident.detection_count == 3
    # 3 techniques -> escalated one level from high to critical
    assert incident.severity == "critical"
    techniques = json.loads(incident.technique_ids)
    assert techniques == ["T1055", "T1059.001", "T1078"]


def test_single_technique_host_does_not_chain(db_session):
    from services import correlation_service

    _add_detection(db_session, "host-x", "rule-1", "One", "T1055", "medium")
    _add_detection(db_session, "host-x", "rule-1b", "One b", "T1055", "medium")
    db_session.commit()

    result = correlation_service.recompute_incidents(db_session)
    assert result["incidents"] == 0


def test_members_disjoint_between_campaign_and_chain(db_session):
    """A detection claimed by a campaign incident is excluded from a chain."""
    import models
    from services import correlation_service

    # campaign: rule-001 across host-a + host-b (T1059.001)
    _add_detection(db_session, "host-a", "rule-001", "Camp", "T1059.001", "high")
    _add_detection(db_session, "host-b", "rule-001", "Camp", "T1059.001", "high")
    # host-a chain: T1055 + T1078 (host-a's campaign detection excluded)
    _add_detection(
        db_session, "host-a", "rule-2", "Chain1", "T1055", "medium",
        datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    _add_detection(
        db_session, "host-a", "rule-3", "Chain2", "T1078", "medium",
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    db_session.commit()

    result = correlation_service.recompute_incidents(db_session)
    assert result["incidents"] == 2

    campaign = db_session.query(models.Incident).filter(
        models.Incident.signature == "campaign:rule-001"
    ).first()
    chain = db_session.query(models.Incident).filter(
        models.Incident.signature == "chain:host-a"
    ).first()
    assert campaign.detection_count == 2
    assert chain.detection_count == 2

    # membership is disjoint
    link = models.IncidentDetection
    campaign_ids = {
        r.detection_id
        for r in db_session.query(link).filter(link.incident_id == campaign.id).all()
    }
    chain_ids = {
        r.detection_id
        for r in db_session.query(link).filter(link.incident_id == chain.id).all()
    }
    assert campaign_ids.isdisjoint(chain_ids)


def test_recompute_is_idempotent_and_preserves_triage(db_session):
    import models
    from services import correlation_service

    _add_detection(db_session, "host-a", "rule-001", "Camp", "T1059.001", "high")
    _add_detection(db_session, "host-b", "rule-001", "Camp", "T1059.001", "high")
    db_session.commit()

    correlation_service.recompute_incidents(db_session)
    incident = db_session.query(models.Incident).first()
    incident.status = "resolved"
    db_session.commit()

    correlation_service.recompute_incidents(db_session)

    incidents = db_session.query(models.Incident).all()
    assert len(incidents) == 1
    assert incidents[0].status == "resolved"  # triage preserved across recompute
    assert incidents[0].detection_count == 2


def test_stale_incident_removed_when_detections_change(db_session):
    import models
    from services import correlation_service

    _add_detection(db_session, "host-a", "rule-001", "Camp", "T1059.001", "high")
    _add_detection(db_session, "host-b", "rule-001", "Camp", "T1059.001", "high")
    db_session.commit()
    correlation_service.recompute_incidents(db_session)
    assert db_session.query(models.Incident).count() == 1

    # Now only one host has the rule -> campaign dissolves.
    db_session.query(models.Detection).filter(models.Detection.host == "host-b").delete()
    db_session.commit()
    correlation_service.recompute_incidents(db_session)
    assert db_session.query(models.Incident).count() == 0


def test_triage_incident_status_validation(db_session):
    import pytest

    from services import correlation_service

    with pytest.raises(ValueError):
        correlation_service.triage_incident(db_session, 1, "bogus")


def test_api_incident_flow(client, db_session, monkeypatch, tmp_path):
    """End-to-end: run detection on multi-host artifacts -> /incidents shows a campaign."""
    import models
    from services import detection_service

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r1.yml").write_text(
        "title: t\nid: rule-001\nartifact_type: process\ncondition:\n  cmdline_contains: ['-enc']\n"
    )
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(rules))

    for host in ("host-a", "host-b"):
        db_session.add(
            models.Artifact(
                host=host,
                os="linux",
                artifact_type="process",
                collected_at="2026-01-01T00:00:00Z",
                data=json.dumps({"cmdline": "powershell -enc AA"}),
            )
        )
    db_session.commit()

    detection_service.run_detection_job(db_session, trigger="manual")

    resp = client.get("/incidents")
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) == 1
    assert incidents[0]["host_count"] == 2
    assert incidents[0]["signature"] == "campaign:rule-001"

    # summary + detail + triage round-trip
    summary = client.get("/incidents/summary").json()
    assert summary["total_incidents"] == 1

    detail = client.get(f"/incidents/{incidents[0]['id']}").json()
    assert len(detail["detections"]) == 2

    triaged = client.patch(
        f"/incidents/{incidents[0]['id']}", json={"status": "acknowledged"}
    ).json()
    assert triaged["status"] == "acknowledged"


def test_api_recompute_endpoint(client, db_session, monkeypatch, tmp_path):
    import models
    from services import detection_service

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r1.yml").write_text(
        "title: t\nid: rule-001\nartifact_type: process\ncondition:\n  cmdline_contains: ['-enc']\n"
    )
    monkeypatch.setattr(detection_service, "SIGMA_RULES_DIR", str(rules))

    for host in ("host-a", "host-b", "host-c"):
        db_session.add(
            models.Artifact(
                host=host,
                os="linux",
                artifact_type="process",
                collected_at="2026-01-01T00:00:00Z",
                data=json.dumps({"cmdline": "powershell -enc AA"}),
            )
        )
    db_session.commit()

    detection_service.run_detection_job(db_session, trigger="manual")

    resp = client.post("/incidents/recompute")
    assert resp.status_code == 200
    assert resp.json()["incidents"] >= 1
