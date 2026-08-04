"""Tests for Phase 3: dashboard controls, triage lifecycle, audit log, metrics.

Covers the new analyst-facing surface: detection triage (PATCH), endpoint
config editing + "run collection now" command queue (polled by the agent),
the audit trail, and the /metrics + /health payloads.
"""
import json


def _seed_detection(client, host="h1"):
    artifact = {
        "host": host,
        "os": "linux",
        "collected_at": "2026-01-01T00:00:00Z",
        "artifact_type": "process",
        "data": {"cmdline": "powershell -enc AAA"},
    }
    client.post("/ingest", json=[artifact])
    return client.post("/detect").json()


def test_detection_triage_lifecycle(client):
    _seed_detection(client)
    det = client.get("/detections").json()[0]
    assert det["triage_status"] == "new"

    r = client.patch(
        f"/detections/{det['id']}", json={"status": "acknowledged", "notes": "checking"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["triage_status"] == "acknowledged"
    assert body["triage_notes"] == "checking"

    r = client.patch(f"/detections/{det['id']}", json={"status": "false_positive"})
    assert r.json()["triage_status"] == "false_positive"

    detail = client.get("/detections").json()[0]
    assert detail["triage_notes"] == "checking"
    assert detail["triage_updated_by"] is not None


def test_detection_triage_rejects_invalid_status(client):
    _seed_detection(client)
    det = client.get("/detections").json()[0]
    r = client.patch(f"/detections/{det['id']}", json={"status": "definitely_bad"})
    assert r.status_code == 400


def test_detection_triage_missing_detection(client):
    assert client.patch("/detections/9999", json={"status": "reviewed"}).status_code == 404


def test_summary_includes_triage(client):
    _seed_detection(client)
    summary = client.get("/detections/summary").json()
    assert summary["by_triage"]["new"] == 1


def test_summary_aggregates_match_grouped_counts(client):
    """M3: summary uses SQL GROUP BY — counts must match seeded data."""
    _seed_detection(client, host="h1")
    artifact = {
        "host": "h2",
        "os": "linux",
        "collected_at": "2026-01-01T00:00:00Z",
        "artifact_type": "process",
        "data": {"cmdline": "powershell -enc BBB"},
    }
    client.post("/ingest", json=[artifact])
    client.post("/detect")

    summary = client.get("/detections/summary").json()
    assert summary["total_detections"] == 2
    assert summary["by_host"] == {"h1": 1, "h2": 1}
    assert summary["by_severity"]["high"] == 2

    # /health's embedded summary uses the same aggregation path.
    health = client.get("/health").json()
    assert json.loads(health["summary"])["by_severity"]["high"] == 2


def test_endpoint_config_edit_and_collection_trigger(client):
    client.post("/endpoints/enroll", json={"hostname": "edge-02", "os": "linux"})
    ep = client.get("/endpoints").json()[0]

    r = client.put(
        f"/endpoints/{ep['id']}/config",
        json={"interval_seconds": 60, "collectors": ["processes"]},
    )
    assert r.status_code == 200
    assert r.json()["config"]["interval_seconds"] == 60
    assert r.json()["config"]["collectors"] == ["processes"]

    # Agent picks up the edited config
    cfg = client.get("/endpoints/config", params={"hostname": "edge-02"}).json()
    assert cfg["interval_seconds"] == 60

    # Dashboard queues "run collection now"
    queued = client.post(f"/endpoints/{ep['id']}/run-collection").json()
    assert queued["command"] == "run_collection"
    assert queued["status"] == "pending"

    # Agent polls, gets the command, reports completion
    cmds = client.get("/endpoints/commands", params={"hostname": "edge-02"}).json()
    assert len(cmds) == 1
    assert cmds[0]["command"] == "run_collection"
    done = client.post(
        f"/endpoints/commands/{cmds[0]['id']}/complete",
        json={"status": "completed", "result": {"files": 6}},
    ).json()
    assert done["status"] == "completed"

    # Command is not returned again on the next poll
    assert client.get("/endpoints/commands", params={"hostname": "edge-02"}).json() == []


def test_endpoint_config_rejects_small_interval(client):
    client.post("/endpoints/enroll", json={"hostname": "edge-02", "os": "linux"})
    ep = client.get("/endpoints").json()[0]
    r = client.put(f"/endpoints/{ep['id']}/config", json={"interval_seconds": 1})
    assert r.status_code == 400


def test_metrics_endpoint(client):
    _seed_detection(client)
    client.post("/endpoints/enroll", json={"hostname": "edge-03", "os": "linux"})
    resp = client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "dfir_artifacts_total" in text
    assert "dfir_detections_total" in text
    assert "dfir_endpoints_total" in text


def test_audit_log_records_actions(client):
    _seed_detection(client)
    det = client.get("/detections").json()[0]
    client.patch(f"/detections/{det['id']}", json={"status": "true_positive"})
    logs = client.get("/audit-logs").json()
    actions = {entry["action"] for entry in logs}
    assert "run_detection" in actions
    assert "triage_detection" in actions
    run_log = next(entry for entry in logs if entry["action"] == "run_detection")
    assert run_log["detail"]["detections_found"] >= 0


def test_cursor_pagination_no_drift(client):
    """M4: before_id cursor pages through stable snapshots (no page drift)."""
    for i in range(5):
        client.post(
            "/ingest",
            json=[
                {
                    "host": "h1",
                    "os": "linux",
                    "collected_at": "2026-01-01T00:00:00Z",
                    "artifact_type": "process",
                    "data": {"cmdline": f"cmd-{i}"},
                }
            ],
        )

    page1 = client.get("/artifacts", params={"limit": 2}).json()
    assert [a["id"] for a in page1] == [5, 4]  # newest first

    page2 = client.get("/artifacts", params={"limit": 2, "before_id": page1[-1]["id"]}).json()
    assert [a["id"] for a in page2] == [3, 2]

    page3 = client.get("/artifacts", params={"limit": 2, "before_id": page2[-1]["id"]}).json()
    assert [a["id"] for a in page3] == [1]

    # All pages together are disjoint and cover the whole set.
    seen = [a["id"] for p in (page1, page2, page3) for a in p]
    assert sorted(seen) == [1, 2, 3, 4, 5]
    assert len(seen) == len(set(seen))


def test_detections_cursor_pagination(client):
    """M4: /detections honors the before_id cursor too."""
    for host in ("h1", "h2", "h3", "h4"):
        _seed_detection(client, host=host)

    page1 = client.get("/detections", params={"limit": 2}).json()
    assert len(page1) == 2
    page2 = client.get(
        "/detections", params={"limit": 2, "before_id": page1[-1]["id"]}
    ).json()
    assert len(page2) == 2
    page3 = client.get(
        "/detections", params={"limit": 2, "before_id": page2[-1]["id"]}
    ).json()
    assert len(page3) == 0

    seen = [d["id"] for p in (page1, page2, page3) for d in p]
    assert sorted(seen) == list(range(1, 5))


def test_dashboard_static_served(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "DFIR / OPERATIONS REPORT" in resp.text


def test_config_poll_refreshes_heartbeat(client):
    """M6: the agent's config poll doubles as a heartbeat (status back online)."""
    client.post("/endpoints/enroll", json={"hostname": "edge-04", "os": "linux"})
    ep = client.get("/endpoints").json()[0]
    assert ep["status"] == "online"

    # First poll
    client.get("/endpoints/config", params={"hostname": "edge-04"})
    ep = client.get("/endpoints").json()[0]
    assert ep["status"] == "online"
    assert ep["last_seen"] is not None


def test_mark_offline_stale_flips_stale_endpoints(db_session):
    """M6: endpoints whose last poll is older than the threshold go offline."""
    import json
    from datetime import datetime, timedelta, timezone

    import models
    from services import endpoint_service

    now = datetime.now(timezone.utc)
    fresh = models.Endpoint(
        hostname="fresh",
        os="linux",
        status="online",
        last_seen=now - timedelta(seconds=60),
        config_json=json.dumps(endpoint_service.DEFAULT_CONFIG),
    )
    stale = models.Endpoint(
        hostname="stale",
        os="linux",
        status="online",
        last_seen=now - timedelta(hours=24),
        config_json=json.dumps(endpoint_service.DEFAULT_CONFIG),
    )
    db_session.add_all([fresh, stale])
    db_session.commit()

    flipped = endpoint_service.mark_offline_stale(db_session, stale_after_seconds=900)
    assert flipped == 1

    db_session.refresh(fresh)
    db_session.refresh(stale)
    assert fresh.status == "online"
    assert stale.status == "offline"


def test_heartbeat_restores_offline_endpoint(client, db_session):
    """M6: a config poll after being marked offline flips the endpoint back online."""
    from datetime import datetime, timedelta, timezone

    import models
    from services import endpoint_service

    client.post("/endpoints/enroll", json={"hostname": "edge-05", "os": "linux"})
    ep = db_session.query(models.Endpoint).filter(models.Endpoint.hostname == "edge-05").first()
    ep.status = "offline"
    ep.last_seen = datetime.now(timezone.utc) - timedelta(hours=24)
    db_session.commit()

    # The poll touches last_seen and restores online status.
    client.get("/endpoints/config", params={"hostname": "edge-05"})

    db_session.expire_all()
    ep = db_session.query(models.Endpoint).filter(models.Endpoint.hostname == "edge-05").first()
    assert ep.status == "online"
    assert endpoint_service.list_endpoints(db_session)[0]["status"] == "online"
