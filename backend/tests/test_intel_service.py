"""Tests for services/intel_service — F7 IOC feed automation + STIX/TAXII export."""
from services import intel_service
from services.intel_service import (
    _parse_malwarebazaar,
    _parse_otx,
    _parse_urlhaus_csv,
    _stix_pattern,
    export_stix_bundle,
    refresh_all_feeds,
)


def test_parse_urlhaus_csv():
    csv = (
        "id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n"
        "123,2026-08-01 10:00:00,http://evil.example/a.exe,online,malware,emotet,http://x,rep\n"
        "124,2026-08-01 11:00:00,http://evil2.example/b,online,,,http://x,rep\n"
    )
    iocs = _parse_urlhaus_csv(csv)
    assert len(iocs) == 2
    assert iocs[0]["value"] == "http://evil.example/a.exe"
    assert iocs[0]["ioc_type"] == "url"
    assert iocs[0]["source"] == "urlhaus"
    assert iocs[0]["threat"] == "malware"
    assert iocs[1]["threat"] is None


def test_parse_urlhaus_csv_skips_garbage_rows():
    assert _parse_urlhaus_csv("a,b\n,,,\n") == []


def test_parse_malwarebazaar():
    payload = {
        "data": [
            {
                "sha256_hash": "AA" * 32,
                "sha1_hash": "BB" * 20,
                "md5_hash": "CC" * 16,
                "signature": "TrickBot",
                "first_seen": "2026-08-01 09:00:00",
                "tags": ["exe", "bot"],
            },
            {"sha256_hash": "  ", "signature": "", "first_seen": None},
        ]
    }
    iocs = _parse_malwarebazaar(payload)
    assert len(iocs) == 3
    hashes = {i["ioc_type"]: i["value"] for i in iocs}
    assert hashes["hash_sha256"] == ("aa" * 32).lower()
    assert hashes["hash_md5"] == ("cc" * 16).lower()
    assert hashes["hash_sha1"] == ("bb" * 20).lower()
    assert iocs[0]["threat"] == "TrickBot"


def test_parse_otx():
    payload = {
        "results": [
            {
                "name": "APT-29 IOC",
                "modified": "2026-08-01T00:00:00",
                "indicators": [
                    {"type": "IPv4", "indicator": "203.0.113.7"},
                    {"type": "domain", "indicator": "evil.example.com"},
                    {"type": "URL", "indicator": "http://evil.example/x"},
                    {"type": "FileHash-SHA256", "indicator": "AA" * 32},
                    {"type": "unknown-type", "indicator": "skip-me"},
                ],
            }
        ]
    }
    iocs = _parse_otx(payload)
    types = {i["ioc_type"] for i in iocs}
    assert types == {"ip", "domain", "url", "hash_sha256"}
    assert iocs[0]["source"] == "otx"
    assert iocs[0]["threat"] == "APT-29 IOC"


def test_parse_feodo_ips(monkeypatch):
    monkeypatch.setattr(
        intel_service,
        "load_local_blocklist",
        lambda path: {"91.203.5.103": "feodo-tracker", "91.203.5.104": "feodo-tracker"},
    )
    iocs = intel_service._parse_feodo_ips()
    assert len(iocs) == 2
    assert iocs[0]["ioc_type"] == "ip"
    assert iocs[0]["source"] == "feodo-tracker"


def test_stix_pattern_per_type():
    assert _stix_pattern({"value": "1.2.3.4", "ioc_type": "ip"}) == "[ipv4-addr:value = '1.2.3.4']"
    assert (
        _stix_pattern({"value": "2001:db8::1", "ioc_type": "ip"})
        == "[ipv6-addr:value = '2001:db8::1']"
    )
    assert (
        _stix_pattern({"value": "evil.example.com", "ioc_type": "domain"})
        == "[domain-name:value = 'evil.example.com']"
    )
    assert (
        _stix_pattern({"value": "http://evil.example/a", "ioc_type": "url"})
        == "[url:value = 'http://evil.example/a']"
    )
    assert (
        _stix_pattern({"value": "AA", "ioc_type": "hash_sha256"})
        == "[file:hashes.'SHA-256' = 'AA']"
    )
    # quotes are escaped per STIX pattern grammar
    assert _stix_pattern({"value": "o'brien.example", "ioc_type": "domain"}) == (
        "[domain-name:value = 'o''brien.example']"
    )


def test_export_stix_bundle():
    iocs = [
        {
            "value": "1.2.3.4",
            "ioc_type": "ip",
            "source": "feodo-tracker",
            "threat": "TrickBot",
            "description": "bot",
            "first_seen": "2026-08-01T00:00:00Z",
            "last_seen": "2026-08-02T00:00:00Z",
        },
        {
            "value": "evil.example.com",
            "ioc_type": "domain",
            "source": "otx",
            "threat": None,
            "description": None,
            "first_seen": None,
            "last_seen": None,
        },
    ]
    bundle = export_stix_bundle(iocs)
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    objects = bundle["objects"]
    identity = objects[0]
    assert identity["type"] == "identity"
    indicators = objects[1:]
    assert len(indicators) == 2
    for ind in indicators:
        assert ind["type"] == "indicator"
        assert ind["pattern_type"] == "stix"
        assert ind["spec_version"] == "2.1"
        assert ind["labels"] == ["malicious-activity"]
        assert ind["created_by_ref"] == identity["id"]
    assert indicators[0]["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert indicators[1]["pattern"] == "[domain-name:value = 'evil.example.com']"


def test_taxii_envelopes():
    disc = intel_service.taxii_discovery(host="http://x")
    assert disc["api_roots"] == ["http://x/taxii/"]
    root = intel_service.taxii_api_root(host="http://x")
    assert root["versions"] == ["taxii-2.1"]
    colls = intel_service.taxii_collections(host="http://x")
    assert colls["collections"][0]["can_read"] is True
    assert colls["collections"][0]["can_write"] is False
    objs = intel_service.taxii_objects(
        [
            {
                "value": "1.2.3.4",
                "ioc_type": "ip",
                "source": "feodo",
                "threat": None,
                "description": None,
            }
        ]
    )
    assert objs["more"] is False
    assert any(o["type"] == "indicator" for o in objs["objects"])


# ---------------------------------------------------------------------------
# DB-backed upsert + refresh
# ---------------------------------------------------------------------------

def test_upsert_dedupes_by_value_type_source(db_session):
    first = intel_service._upsert_ioc(
        db_session,
        {"value": "1.2.3.4", "ioc_type": "ip", "source": "feodo-tracker",
         "threat": "A", "confidence": 50, "last_seen": "2026-08-01T00:00:00Z"},
    )
    second = intel_service._upsert_ioc(
        db_session,
        {"value": "1.2.3.4", "ioc_type": "ip", "source": "feodo-tracker",
         "threat": "B", "confidence": 90, "last_seen": "2026-08-02T00:00:00Z"},
    )
    assert (first, second) == ("inserted", "updated")
    db_session.commit()
    rows = intel_service.list_iocs(db_session)
    assert len(rows) == 1
    assert rows[0]["threat"] == "B"
    assert rows[0]["confidence"] == 90
    assert rows[0]["last_seen"].startswith("2026-08-02")


def test_refresh_all_feeds_upserts_and_returns_summary(db_session, monkeypatch):
    monkeypatch.setattr(
        intel_service,
        "_FETCHERS",
        {
            "feodo": lambda: [{"value": "5.6.7.8", "ioc_type": "ip", "source": "feodo-tracker",
                               "confidence": 85, "last_seen": None}],
            "urlhaus": lambda: [{"value": "http://bad.example/x", "ioc_type": "url",
                                 "source": "urlhaus", "confidence": 80, "last_seen": None}],
        },
    )
    summary = refresh_all_feeds(db_session)
    assert summary["total_inserted"] == 2
    assert summary["feeds"]["feodo"]["inserted"] == 1
    assert summary["feeds"]["urlhaus"]["inserted"] == 1

    # second run: same values -> updated, not inserted
    summary = refresh_all_feeds(db_session)
    assert summary["total_inserted"] == 0
    assert summary["total_updated"] == 2
    assert intel_service.ioc_status(db_session)["total"] == 2


def test_refresh_fails_soft_per_feed(db_session, monkeypatch):
    def boom():
        raise OSError("no network")

    monkeypatch.setattr(
        intel_service,
        "_FETCHERS",
        {
            "feodo": boom,
            "urlhaus": lambda: [{"value": "http://ok.example/y", "ioc_type": "url",
                                 "source": "urlhaus", "confidence": 80, "last_seen": None}],
        },
    )
    summary = refresh_all_feeds(db_session)
    assert summary["feeds"]["feodo"]["error"] is not None
    assert summary["feeds"]["urlhaus"]["inserted"] == 1
    assert summary["total_inserted"] == 1


def test_otx_without_key_is_skipped_not_error(monkeypatch):
    monkeypatch.setattr(intel_service, "OTX_API_KEY", None)
    assert intel_service._fetch_otx() == []


def test_list_filters_and_lookup(db_session):
    intel_service._upsert_ioc(db_session, {"value": "1.1.1.1", "ioc_type": "ip",
                                           "source": "feodo-tracker", "confidence": 50})
    intel_service._upsert_ioc(db_session, {"value": "bad.example", "ioc_type": "domain",
                                           "source": "otx", "confidence": 50})
    intel_service._upsert_ioc(db_session, {"value": "2.2.2.2", "ioc_type": "ip",
                                           "source": "urlhaus", "confidence": 50, "active": 0})
    db_session.commit()

    ips = intel_service.list_iocs(db_session, ioc_type="ip")
    assert {i["value"] for i in ips} == {"1.1.1.1", "2.2.2.2"}
    feodo = intel_service.list_iocs(db_session, source="feodo-tracker")
    assert [i["value"] for i in feodo] == ["1.1.1.1"]
    active = intel_service.list_iocs(db_session, active=1)
    assert {i["value"] for i in active} == {"1.1.1.1", "bad.example"}

    assert intel_service.lookup_ioc(db_session, "2.2.2.2") is None  # inactive
    assert intel_service.lookup_ioc(db_session, "1.1.1.1")["source"] == "feodo-tracker"

    status = intel_service.ioc_status(db_session)
    assert status["total"] == 3
    assert status["active"] == 2
    assert status["by_type"] == {"ip": 2, "domain": 1}


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

def test_ioc_routes_round_trip(client, monkeypatch):
    def fake_refresh(db, feeds=None):
        intel_service._upsert_ioc(db, {"value": "3.3.3.3", "ioc_type": "ip",
                                       "source": "feodo-tracker", "threat": "X", "confidence": 85})
        db.commit()
        return {
            "feeds": {"feodo": {"source": "feodo", "fetched": 1, "inserted": 1,
                                "updated": 0, "error": None}},
            "total_inserted": 1,
            "total_updated": 0,
        }

    monkeypatch.setattr(intel_service, "refresh_all_feeds", fake_refresh)

    assert client.post("/iocs/refresh").status_code == 200

    iocs = client.get("/iocs").json()
    assert len(iocs) == 1
    assert iocs[0]["value"] == "3.3.3.3"

    status = client.get("/iocs/status").json()
    assert status["total"] == 1
    assert status["by_source"] == {"feodo-tracker": 1}

    bundle = client.get("/iocs/export/stix").json()
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert any(o["type"] == "indicator" for o in bundle["objects"])


def test_ioc_refresh_unknown_feed_400(client):
    resp = client.post("/iocs/refresh?feeds=bogus")
    assert resp.status_code == 400


def test_taxii_endpoints(client, db_session):
    intel_service._upsert_ioc(db_session, {"value": "4.4.4.4", "ioc_type": "ip",
                                           "source": "feodo-tracker", "confidence": 85})
    db_session.commit()

    disc = client.get("/taxii/").json()
    assert disc["api_roots"] == ["http://testserver/taxii/"]

    root = client.get("/taxii/api").json()
    assert root["versions"] == ["taxii-2.1"]

    colls = client.get("/taxii/api/collections").json()
    collection_id = colls["collections"][0]["id"]

    objs = client.get(f"/taxii/api/collections/{collection_id}/objects").json()
    assert objs["more"] is False
    indicators = [o for o in objs["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    assert indicators[0]["pattern"] == "[ipv4-addr:value = '4.4.4.4']"

    assert client.get("/taxii/api/collections/nope/objects").status_code == 404


def test_ioc_refresh_is_audited(client, monkeypatch):
    monkeypatch.setattr(
        intel_service,
        "refresh_all_feeds",
        lambda db, feeds=None: {"feeds": {}, "total_inserted": 0, "total_updated": 0},
    )
    client.post("/iocs/refresh")
    logs = client.get("/audit-logs").json()
    assert any(entry["action"] == "ioc_refresh" for entry in logs)
