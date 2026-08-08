"""
Unit tests for the local IOC/blocklist correlation layer
(ioc_correlation.py) — the offline part of the network-intel pipeline.
"""
import ioc_correlation


def _network_artifact(remote: str) -> dict:
    return {
        "host": "test-host",
        "os": "windows",
        "artifact_type": "network",
        "collected_at": "2026-01-01T00:00:00Z",
        "data": {"local_address": "10.0.0.5:50000", "remote_address": remote, "status": "ESTABLISHED"},
    }


def test_local_blocklist_loads():
    entries = ioc_correlation.load_local_blocklist()
    assert len(entries) > 0


def test_extract_ip():
    assert ioc_correlation._extract_ip("1.2.3.4:4444") == "1.2.3.4"
    assert ioc_correlation._extract_ip("") == ""


def test_private_ip_skipped_for_live_layer():
    assert ioc_correlation._is_private_or_local("192.168.50.10")
    assert ioc_correlation._is_private_or_local("10.0.0.1")
    assert ioc_correlation._is_private_or_local("127.0.0.1")
    assert not ioc_correlation._is_private_or_local("8.8.8.8")


def test_public_blocklisted_ip_correlated(monkeypatch, tmp_path):
    blocklist_file = tmp_path / "malicious_ips.txt"
    blocklist_file.write_text("# comment\n203.0.113.66 test C2 node\n8.8.8.8 meh\n")
    blocklist = {"203.0.113.66": "test C2 node"}
    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", lambda: blocklist)

    hits = ioc_correlation.correlate_network_artifacts(
        [_network_artifact("203.0.113.66:4444"), _network_artifact("8.8.8.8:443")]
    )
    assert len(hits) == 1
    assert hits[0]["rule_id"] == "ioc-local-blocklist"
    assert hits[0]["technique_id"] == "T1071"
    assert hits[0]["matched_data"]["remote_address"] == "203.0.113.66:4444"


def test_private_ip_never_flagged_by_live_layer(monkeypatch):
    def empty_blocklist() -> dict:
        return {}

    monkeypatch.setattr(ioc_correlation, "load_local_blocklist", empty_blocklist)
    hits = ioc_correlation.correlate_network_artifacts([_network_artifact("192.168.1.1:22")])
    assert hits == []