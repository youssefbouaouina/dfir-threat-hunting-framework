"""Tests for ioc_correlation — local blocklist + live-feed network correlation."""
import pytest

import ioc_correlation
from ioc_correlation import _extract_ip, correlate_network_artifacts


def _network_artifact(remote_address):
    return {
        "host": "h",
        "os": "linux",
        "artifact_type": "network",
        "collected_at": "x",
        "data": {"remote_address": remote_address, "status": "ESTABLISHED"},
    }


def test_extract_ip():
    assert _extract_ip("203.0.113.66:443") == "203.0.113.66"
    assert _extract_ip("") == ""
    assert _extract_ip(None) == ""


def test_blocklist_hit(monkeypatch):
    monkeypatch.setattr(
        ioc_correlation, "load_local_blocklist", lambda path="": {"203.0.113.66": "test"}
    )
    monkeypatch.setattr(ioc_correlation, "check_abuseipdb", lambda ip: {})
    detections = correlate_network_artifacts([_network_artifact("203.0.113.66:443")])
    assert len(detections) == 1
    assert detections[0]["rule_id"] == "ioc-local-blocklist"
    assert detections[0]["severity"] == "high"


def test_private_address_skipped(monkeypatch):
    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", lambda path="": {})
    spy = {"calls": 0}

    def fake_lookup(ip):
        spy["calls"] += 1
        return {}

    monkeypatch.setattr(ioc_correlation, "check_abuseipdb", fake_lookup)
    detections = correlate_network_artifacts([_network_artifact("192.168.1.5:443")])
    assert detections == []
    assert spy["calls"] == 0  # no live lookup burned on RFC1918 space


def test_live_feed_high_severity(monkeypatch):
    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", lambda path="": {})
    monkeypatch.setattr(
        ioc_correlation,
        "check_abuseipdb",
        lambda ip: {"source": "AbuseIPDB", "score": 90, "ip": ip},
    )
    detections = correlate_network_artifacts([_network_artifact("8.8.8.8:443")])
    assert len(detections) == 1
    assert detections[0]["rule_id"] == "ioc-abuseipdb"
    assert detections[0]["severity"] == "high"


def test_live_feed_low_score_is_medium(monkeypatch):
    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", lambda path="": {})
    monkeypatch.setattr(
        ioc_correlation,
        "check_abuseipdb",
        lambda ip: {"source": "AbuseIPDB", "score": 60, "ip": ip},
    )
    detections = correlate_network_artifacts([_network_artifact("9.9.9.9:443")])
    assert detections[0]["severity"] == "medium"


def test_parseable_ip_only(monkeypatch):
    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", lambda path="": {})
    monkeypatch.setattr(
        ioc_correlation, "check_abuseipdb", lambda ip: pytest.fail("should not look up")
    )
    assert correlate_network_artifacts([_network_artifact("not-an-ip:80")]) == []
