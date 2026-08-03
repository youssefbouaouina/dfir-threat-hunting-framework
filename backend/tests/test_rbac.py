"""Tests for Phase 4 (F4): RBAC roles, team scoping, immutable audit chain."""
import json
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

import models
import security
from services import audit_service


@pytest.fixture(autouse=True)
def _enable_auth(monkeypatch):
    monkeypatch.setattr(security, "AUTH_ENABLED", True)
    monkeypatch.setattr(security, "ADMIN_API_KEY", "admin-key")
    monkeypatch.setattr(security, "AGENT_API_KEYS", {"agent-key": "agent-01"})
    monkeypatch.setattr(
        security,
        "HUMAN_API_KEYS",
        {
            "analyst-key": {"role": "analyst", "team": "soc-team-1"},
            "viewer-key": {"role": "viewer", "team": "red-team"},
            "global-analyst": {"role": "analyst", "team": None},
        },
    )
    monkeypatch.setattr(security, "_RATE_LIMIT_ENABLED", False)


def _creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_issue_token_carries_role_and_team():
    token = security.issue_token("alice", role="analyst", team="soc-team-1")
    payload = security._decode_token(token)
    assert payload["role"] == "analyst"
    assert payload["team"] == "soc-team-1"


def test_current_user_resolves_role_keys():
    assert security.current_user(_creds("analyst-key"))["role"] == "analyst"
    assert security.current_user(_creds("analyst-key"))["team"] == "soc-team-1"
    assert security.current_user(_creds("viewer-key"))["role"] == "viewer"


def test_require_role_enforces_membership():
    analyst = security.current_user(_creds("analyst-key"))
    viewer = security.current_user(_creds("viewer-key"))

    # call the built dependency directly with the user dict
    assert security.require_role("admin", "analyst")(user=analyst) == analyst
    with pytest.raises(HTTPException) as exc:
        security.require_role("admin")(user=viewer)
    assert exc.value.status_code == 403
    # auth-off open mode: None user passes through (no role gate)
    assert security.require_role("admin")(user=None) is None


def test_authenticate_login_returns_role_and_team():
    assert security.authenticate_login("admin-key") == {"role": "admin", "team": None}
    assert security.authenticate_login("analyst-key")["role"] == "analyst"
    assert security.authenticate_login("analyst-key")["team"] == "soc-team-1"
    assert security.authenticate_login("nope") == {}


def test_scoped_hosts_limits_team_to_their_endpoints(db_session):
    from services import query_service

    db_session.add(models.Endpoint(hostname="soc-01", os="linux", team="soc-team-1"))
    db_session.add(models.Endpoint(hostname="soc-02", os="linux", team="soc-team-1"))
    db_session.add(models.Endpoint(hostname="red-01", os="linux", team="red-team"))
    db_session.commit()

    hosts = query_service.scoped_hosts(db_session, "soc-team-1")
    assert sorted(hosts) == ["soc-01", "soc-02"]
    assert query_service.scoped_hosts(db_session, None) is None


def test_detections_scoped_by_team_hosts(db_session):
    from services import detection_service, query_service

    db_session.add(models.Endpoint(hostname="soc-01", os="linux", team="soc-team-1"))
    db_session.add(models.Endpoint(hostname="red-01", os="linux", team="red-team"))
    for host in ("soc-01", "red-01"):
        db_session.add(
            models.Detection(
                host=host,
                rule_id=f"rule-{host}",
                rule_title="T",
                artifact_type="process",
                matched_data=json.dumps({}),
                detected_at=datetime.now(timezone.utc),
            )
        )
    db_session.commit()

    team_hosts = query_service.scoped_hosts(db_session, "soc-team-1")
    rows = detection_service.list_detections(db_session, hosts=team_hosts)
    assert [r["host"] for r in rows] == ["soc-01"]

    summary = detection_service.detections_summary(db_session, hosts=team_hosts)
    assert summary["total_detections"] == 1


def test_artifacts_scoped_by_team_hosts(db_session):
    from services import query_service

    db_session.add(models.Endpoint(hostname="soc-01", os="linux", team="soc-team-1"))
    db_session.add(models.Endpoint(hostname="red-01", os="linux", team="red-team"))
    for host in ("soc-01", "red-01"):
        db_session.add(
            models.Artifact(
                host=host,
                os="linux",
                artifact_type="process",
                collected_at="2026-01-01T00:00:00Z",
                data=json.dumps({"cmdline": ["x"]}),
            )
        )
    db_session.commit()

    team_hosts = query_service.scoped_hosts(db_session, "soc-team-1")
    rows = query_service.list_artifacts(db_session, hosts=team_hosts)
    assert [r["host"] for r in rows] == ["soc-01"]


def test_incidents_scoped_by_member_hosts(db_session):
    from services import correlation_service, query_service

    db_session.add(models.Endpoint(hostname="soc-01", os="linux", team="soc-team-1"))
    db_session.add(models.Endpoint(hostname="red-01", os="linux", team="red-team"))
    for host in ("soc-01", "red-01"):
        db_session.add(
            models.Detection(
                host=host,
                rule_id="rule-001",
                rule_title="Camp",
                technique_id="T1059.001",
                artifact_type="process",
                matched_data=json.dumps({}),
                detected_at=datetime.now(timezone.utc),
            )
        )
    db_session.commit()
    correlation_service.recompute_incidents(db_session)
    assert db_session.query(models.Incident).count() == 1

    team_hosts = query_service.scoped_hosts(db_session, "soc-team-1")
    rows = correlation_service.list_incidents(db_session, hosts=team_hosts)
    assert len(rows) == 1  # incident spans both hosts but touches soc-01

    other_hosts = query_service.scoped_hosts(db_session, "unrelated-team")
    assert correlation_service.list_incidents(db_session, hosts=other_hosts) == []


def test_endpoints_list_scoped_by_team(db_session):
    from services import endpoint_service

    db_session.add(models.Endpoint(hostname="soc-01", os="linux", team="soc-team-1"))
    db_session.add(models.Endpoint(hostname="red-01", os="linux", team="red-team"))
    db_session.commit()

    rows = endpoint_service.list_endpoints(db_session, team="soc-team-1")
    assert [r["hostname"] for r in rows] == ["soc-01"]
    assert rows[0]["team"] == "soc-team-1"


def test_audit_chain_links_and_verifies(db_session):
    audit_service.log_action(db_session, "login", actor="admin", detail={"x": 1})
    audit_service.log_action(db_session, "run_detection", actor="admin")
    audit_service.log_action(db_session, "triage_detection", actor="alice", detail={"id": 5})

    assert db_session.query(models.AuditLog).count() == 3
    result = audit_service.verify_audit_chain(db_session)
    assert result["valid"] is True
    assert result["checked"] == 3

    rows = db_session.query(models.AuditLog).order_by(models.AuditLog.id.asc()).all()
    assert rows[1].prev_hash == rows[0].record_hash
    assert rows[2].prev_hash == rows[1].record_hash
    assert rows[0].record_hash != rows[1].record_hash


def test_audit_chain_detects_tampering(db_session):
    audit_service.log_action(db_session, "login", actor="admin")
    audit_service.log_action(db_session, "run_detection", actor="admin")
    db_session.commit()

    first = db_session.query(models.AuditLog).order_by(models.AuditLog.id.asc()).first()
    first.detail = json.dumps({"tampered": True})
    db_session.commit()

    result = audit_service.verify_audit_chain(db_session)
    assert result["valid"] is False
    assert result["broken_at"] == first.id


def test_audit_verify_skips_legacy_rows(db_session):
    legacy = models.AuditLog(actor="admin", action="login", detail=None)
    db_session.add(legacy)
    db_session.commit()
    audit_service.log_action(db_session, "run_detection", actor="admin")

    result = audit_service.verify_audit_chain(db_session)
    assert result["valid"] is True
    assert result["checked"] == 1  # only the hashed row is verified


def test_login_endpoint_returns_role(client):
    resp = client.post("/auth/login", json={"api_key": "admin-key"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "admin"


def test_audit_verify_endpoint(client):
    resp = client.get("/audit-logs/verify", headers={"Authorization": "Bearer admin-key"})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
