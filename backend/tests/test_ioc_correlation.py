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


def test_urlhaus_hit(monkeypatch):
    """M2: a URLhaus host hit produces a detection."""
    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", lambda path="": {})
    monkeypatch.setattr(
        ioc_correlation,
        "check_urlhaus",
        lambda ip: {"source": "URLhaus", "score": 5, "ip": ip},
    )
    detections = correlate_network_artifacts([_network_artifact("7.7.7.7:443")])
    assert len(detections) == 1
    assert detections[0]["rule_id"] == "ioc-urlhaus"
    assert detections[0]["severity"] == "medium"


def test_otx_hit(monkeypatch):
    """M2: an OTX pulse hit produces a detection."""
    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", lambda path="": {})
    monkeypatch.setattr(
        ioc_correlation,
        "check_otx",
        lambda ip: {"source": "OTX", "score": 100, "ip": ip},
    )
    detections = correlate_network_artifacts([_network_artifact("6.6.6.6:443")])
    assert len(detections) == 1
    assert detections[0]["rule_id"] == "ioc-otx"
    assert detections[0]["severity"] == "high"


def test_live_checker_order_first_hit_wins(monkeypatch):
    """M2: _live_lookup returns the first checker that hits."""
    monkeypatch.setattr(ioc_correlation, "check_abuseipdb", lambda ip: {})
    monkeypatch.setattr(
        ioc_correlation, "check_urlhaus", lambda ip: {"source": "URLhaus", "score": 1, "ip": ip}
    )
    result = ioc_correlation._live_lookup("8.8.8.8")
    assert result["source"] == "URLhaus"


def test_feodo_refresh_writes_blocklist_file(tmp_path, monkeypatch):
    """M2: refresh_feodo_blocklist downloads the CSV and writes iocs/feodo_ips.txt."""
    csv = (
        "# Feodo Tracker IP Blocklist\n"
        "2026-08-01,91.203.5.103,8080,TrickBot\n"
        "2026-08-01,91.203.5.104,443,Emotet\n"
    )

    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            return None

        @property
        def text(self):
            return csv

    def fake_get(url, timeout):
        assert url == ioc_correlation.FEODO_CSV_URL
        return FakeResp()

    monkeypatch.setattr(ioc_correlation.requests, "get", fake_get)
    out = tmp_path / "feodo_ips.txt"
    n = ioc_correlation.refresh_feodo_blocklist(str(out))
    assert n == 2
    lines = out.read_text(encoding="utf-8").splitlines()
    assert "91.203.5.103 feodo-tracker" in lines
    assert "91.203.5.104 feodo-tracker" in lines


def test_feodo_refresh_fails_soft(tmp_path, monkeypatch):
    """M2: a failed download does not crash — returns 0."""
    def boom(url, timeout):
        raise ioc_correlation.requests.exceptions.ConnectionError("no network")

    monkeypatch.setattr(ioc_correlation.requests, "get", boom)
    assert ioc_correlation.refresh_feodo_blocklist(str(tmp_path / "feodo_ips.txt")) == 0


def test_load_all_blocklists_merges(tmp_path, monkeypatch):
    """M2: load_all_blocklists merges curated + feodo files."""
    curated = tmp_path / "malicious.txt"
    curated.write_text("203.0.113.66 demo\n", encoding="utf-8")
    feodo = tmp_path / "feodo.txt"
    feodo.write_text("91.203.5.103 feodo-tracker\n", encoding="utf-8")
    monkeypatch.setattr(ioc_correlation, "LOCAL_BLOCKLIST_PATH", str(curated))
    monkeypatch.setattr(ioc_correlation, "FEODO_BLOCKLIST_PATH", str(feodo))
    merged = ioc_correlation.load_all_blocklists()
    assert set(merged) == {"203.0.113.66", "91.203.5.103"}
