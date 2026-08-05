"""Automated IOC feed ingestion + STIX/TAXII export (Phase 5 / F7).

Fetches public threat-intel feeds on a schedule (and on demand via
POST /iocs/refresh), upserts the indicators into the `iocs` table, and
exposes them to external platforms:

  * Feodo Tracker    — IP blocklist CSV (also kept as iocs/feodo_ips.txt so
                       the existing offline local-blocklist detection layer
                       keeps working unchanged).
  * URLhaus          — recent malicious URLs CSV (public, no key required).
  * MalwareBazaar    — recent malware samples JSON (public get_recent, no key).
  * AlienVault OTX   — subscribed pulses (requires OTX_API_KEY; skipped without).

Design rules (matching the rest of the framework):
  * Offline-first & fail-soft. Every fetcher raises on transport/parse errors
    and refresh_all_feeds() catches per-feed so one dead feed never aborts the
    refresh or crashes the scheduler. Feeds with no credentials are skipped,
    not errored.
  * Idempotent upsert. Rows are keyed by (value, ioc_type, source): re-seen
    indicators update last_seen/confidence/threat instead of duplicating.
  * Testable. Fetchers take text/JSON already read from the wire in unit tests
    via monkeypatched requests, exactly like ioc_correlation.

STIX 2.1 / TAXII 2.1 export is generated inline (no stix2 dependency): the
bundle + TAXII envelopes are plain dicts whose shape matches the specs, so
they are fully testable and never fail on a missing optional library.
"""
import csv as _csv
import io as _io
import ipaddress
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import requests

import models
from ioc_correlation import FEODO_BLOCKLIST_PATH, load_local_blocklist, refresh_feodo_blocklist
from services.circuit_breaker import CircuitBreaker, CircuitOpenError

logger = logging.getLogger(__name__)

ALL_FEEDS = ("feodo", "urlhaus", "malwarebazaar", "otx")

# Circuit breakers per feed (F8): a feed that keeps failing trips its breaker
# and stops being contacted until it recovers, so a dead upstream never slows
# the refresh job or burns egress on every cycle.
_FEED_FAILURE_THRESHOLD = int(os.getenv("IOC_FEED_FAILURE_THRESHOLD", "3"))
_FEED_RESET_TIMEOUT_SECONDS = int(os.getenv("IOC_FEED_RESET_TIMEOUT_SECONDS", "300"))

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_API_KEY = os.getenv("OTX_API_KEY")

# STIX pattern mapping per ioc_type (the `file:hashes` keys are quoted for the
# dashed SHA names, which the STIX 2.1 pattern grammar requires).
_STIX_PATTERN_TYPES = {
    "ip": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "hash_md5": "file:hashes.MD5",
    "hash_sha1": "file:hashes.'SHA-1'",
    "hash_sha256": "file:hashes.'SHA-256'",
}


# ---------------------------------------------------------------------------
# Feed parsers (pure functions over already-fetched payloads)
# ---------------------------------------------------------------------------

def _parse_urlhaus_csv(text: str) -> list:
    """Parses the URLhaus recent-CSV into IOC dicts (URL indicators).

    The feed's first line is a header row; DictReader skips it and maps each
    row to named fields so we never mistake it for an indicator.
    """
    iocs = []
    reader = _csv.DictReader(_io.StringIO(text))
    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        iocs.append(
            {
                "value": url,
                "ioc_type": "url",
                "source": "urlhaus",
                "threat": (row.get("threat") or "").strip() or None,
                "confidence": 80,
                "last_seen": (row.get("dateadded") or "").strip() or None,
            }
        )
    return iocs


def _parse_malwarebazaar(data: dict) -> list:
    """Parses the MalwareBazaar get_recent response into IOC dicts (hashes)."""
    iocs = []
    for item in data.get("data", []) or []:
        if not isinstance(item, dict):
            continue
        sha256 = (item.get("sha256_hash") or "").strip().lower()
        family = (item.get("signature") or "").strip() or None
        first_seen = item.get("first_seen")
        if sha256:
            iocs.append(
                {
                    "value": sha256,
                    "ioc_type": "hash_sha256",
                    "source": "malwarebazaar",
                    "threat": family,
                    "confidence": 90,
                    "last_seen": first_seen,
                    "description": item.get("tags") or None,
                }
            )
        md5 = (item.get("md5_hash") or "").strip().lower()
        if md5:
            iocs.append(
                {
                    "value": md5,
                    "ioc_type": "hash_md5",
                    "source": "malwarebazaar",
                    "threat": family,
                    "confidence": 90,
                    "last_seen": first_seen,
                }
            )
        sha1 = (item.get("sha1_hash") or "").strip().lower()
        if sha1:
            iocs.append(
                {
                    "value": sha1,
                    "ioc_type": "hash_sha1",
                    "source": "malwarebazaar",
                    "threat": family,
                    "confidence": 90,
                    "last_seen": first_seen,
                }
            )
    return iocs


def _otx_type_to_ioc_type(raw_type: str) -> Optional[str]:
    mapping = {
        "IPv4": "ip",
        "IPv6": "ipv6",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-SHA256": "hash_sha256",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA1": "hash_sha1",
    }
    return mapping.get(raw_type)


def _parse_otx(data: dict) -> list:
    """Parses an OTX pulses/subscribed response into IOC dicts."""
    iocs = []
    for pulse in data.get("results", []) or []:
        if not isinstance(pulse, dict):
            continue
        name = (pulse.get("name") or "").strip() or None
        for ind in pulse.get("indicators", []) or []:
            if not isinstance(ind, dict):
                continue
            ioc_type = _otx_type_to_ioc_type(str(ind.get("type") or ""))
            if not ioc_type:
                continue
            value = (ind.get("indicator") or "").strip()
            if not value:
                continue
            iocs.append(
                {
                    "value": value,
                    "ioc_type": ioc_type,
                    "source": "otx",
                    "threat": name,
                    "confidence": 70,
                    "last_seen": pulse.get("modified"),
                    "description": pulse.get("description"),
                }
            )
    return iocs


def _parse_feodo_ips() -> list:
    """Reads iocs/feodo_ips.txt (written by refresh_feodo_blocklist) into IOCs."""
    iocs = []
    for ip in load_local_blocklist(FEODO_BLOCKLIST_PATH):
        iocs.append(
            {
                "value": ip,
                "ioc_type": "ip",
                "source": "feodo-tracker",
                "threat": None,
                "confidence": 85,
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
        )
    return iocs


# ---------------------------------------------------------------------------
# Fetchers (thin HTTP wrappers; raise on failure, caller fails soft)
# ---------------------------------------------------------------------------

def _fetch_urlhaus() -> list:
    resp = requests.get(URLHAUS_CSV_URL, timeout=15)
    resp.raise_for_status()
    return _parse_urlhaus_csv(resp.text)


def _fetch_malwarebazaar() -> list:
    resp = requests.post(
        MALWAREBAZAAR_API_URL, data={"query": "get_recent", "limit": "100"}, timeout=15
    )
    resp.raise_for_status()
    return _parse_malwarebazaar(resp.json())


def _fetch_otx() -> list:
    if not OTX_API_KEY:
        return []
    resp = requests.get(
        OTX_PULSES_URL,
        params={"limit": 50},
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        timeout=15,
    )
    resp.raise_for_status()
    return _parse_otx(resp.json())


def _fetch_feodo() -> list:
    # refresh_feodo_blocklist writes iocs/feodo_ips.txt (keeps the offline
    # local-blocklist detection layer working) and returns 0 on any failure.
    if refresh_feodo_blocklist() == 0:
        return []
    return _parse_feodo_ips()


_FETCHERS = {
    "feodo": _fetch_feodo,
    "urlhaus": _fetch_urlhaus,
    "malwarebazaar": _fetch_malwarebazaar,
    "otx": _fetch_otx,
}

_BREAKERS = {
    name: CircuitBreaker(
        name=f"ioc-feed-{name}",
        failure_threshold=_FEED_FAILURE_THRESHOLD,
        reset_timeout_seconds=_FEED_RESET_TIMEOUT_SECONDS,
    )
    for name in ALL_FEEDS
}


# ---------------------------------------------------------------------------
# Upsert + refresh orchestration
# ---------------------------------------------------------------------------

def _upsert_ioc(db, ioc: dict) -> str:
    """Inserts or updates one IOC row; returns 'inserted' or 'updated'."""
    value = ioc["value"].strip()
    ioc_type = ioc.get("ioc_type") or "ip"
    source = ioc.get("source") or "manual"
    last_seen = _parse_ts(ioc.get("last_seen"))
    first_seen = _parse_ts(ioc.get("first_seen")) or last_seen

    existing = (
        db.query(models.Ioc)
        .filter(
            models.Ioc.value == value,
            models.Ioc.ioc_type == ioc_type,
            models.Ioc.source == source,
        )
        .first()
    )
    if existing:
        existing.last_seen = last_seen or existing.last_seen
        existing.threat = ioc.get("threat") or existing.threat
        existing.confidence = int(ioc.get("confidence", existing.confidence))
        if ioc.get("description"):
            existing.description = ioc["description"]
        existing.active = 1
        return "updated"

    db.add(
        models.Ioc(
            value=value,
            ioc_type=ioc_type,
            source=source,
            threat=ioc.get("threat"),
            confidence=int(ioc.get("confidence", 50)),
            description=ioc.get("description"),
            first_seen=first_seen,
            last_seen=last_seen,
            active=int(ioc.get("active", 1)),
        )
    )
    return "inserted"


def _parse_ts(value: Optional[str]):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def refresh_all_feeds(db, feeds: Optional[tuple] = None) -> dict:
    """Fetches + upserts every configured feed; returns a per-feed summary.

    Fail-soft per feed: a network/parse error records {'error': ...} instead
    of aborting the whole refresh. Unrecognized feed names are skipped.
    """
    feeds = tuple(feeds) if feeds else ALL_FEEDS
    summary: dict[str, Any] = {"feeds": {}, "total_inserted": 0, "total_updated": 0}
    for name in feeds:
        if name not in _FETCHERS:
            continue
        entry: dict[str, Any] = {
            "source": name, "fetched": 0, "inserted": 0, "updated": 0, "error": None
        }
        try:
            iocs = _BREAKERS[name].call(_FETCHERS[name])
            entry["fetched"] = len(iocs)
            for ioc in iocs:
                action = _upsert_ioc(db, ioc)
                if action == "inserted":
                    entry["inserted"] += 1
                    summary["total_inserted"] += 1
                else:
                    entry["updated"] += 1
                    summary["total_updated"] += 1
        except CircuitOpenError:
            entry["error"] = "circuit open"
            logger.warning("Intel feed %s skipped: circuit open", name)
        except Exception as exc:  # noqa: BLE001 — one feed must not kill the refresh
            entry["error"] = str(exc)
            logger.warning("Intel feed %s failed: %s", name, exc)
        summary["feeds"][name] = entry
    db.commit()
    return summary


def get_breaker_status() -> dict:
    """Per-feed circuit-breaker states (for /iocs/status)."""
    return {name: breaker.status() for name, breaker in _BREAKERS.items()}


def reset_breaker(name: str) -> bool:
    """Manually closes a tripped breaker (admin override). Returns False if unknown."""
    if name not in _BREAKERS:
        return False
    _BREAKERS[name].reset()
    return True


# ---------------------------------------------------------------------------
# Queries + status
# ---------------------------------------------------------------------------

def list_iocs(
    db,
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    active: Optional[int] = None,
    limit: int = 100,
    before_id: Optional[int] = None,
) -> list:
    """Returns IOCs newest-first, optionally filtered by type/source/active."""
    query = db.query(models.Ioc)
    if ioc_type:
        query = query.filter(models.Ioc.ioc_type == ioc_type)
    if source:
        query = query.filter(models.Ioc.source == source)
    if active is not None:
        query = query.filter(models.Ioc.active == active)
    if before_id is not None:
        query = query.filter(models.Ioc.id < before_id)
    rows = query.order_by(models.Ioc.id.desc()).limit(min(limit, 500)).all()
    return [_ioc_to_dict(r) for r in rows]


def _ioc_to_dict(row) -> dict:
    return {
        "id": row.id,
        "value": row.value,
        "ioc_type": row.ioc_type,
        "source": row.source,
        "threat": row.threat,
        "confidence": row.confidence,
        "description": row.description,
        "first_seen": str(row.first_seen) if row.first_seen else None,
        "last_seen": str(row.last_seen) if row.last_seen else None,
        "active": row.active,
    }


def ioc_status(db) -> dict:
    """Aggregated counts by source/type + active total (for /iocs/status)."""
    def _grouped(column) -> dict:
        from sqlalchemy import func

        rows = (
            db.query(column, func.count(models.Ioc.id)).group_by(column).all()
        )
        return {key or "unknown": n for key, n in rows}

    return {
        "total": db.query(models.Ioc).count(),
        "active": db.query(models.Ioc).filter(models.Ioc.active == 1).count(),
        "by_source": _grouped(models.Ioc.source),
        "by_type": _grouped(models.Ioc.ioc_type),
        "breakers": get_breaker_status(),
    }


def lookup_ioc(db, value: str, ioc_type: Optional[str] = None) -> Optional[dict]:
    """Finds an active IOC by value (optionally constrained to an ioc_type)."""
    query = db.query(models.Ioc).filter(models.Ioc.value == value, models.Ioc.active == 1)
    if ioc_type:
        query = query.filter(models.Ioc.ioc_type == ioc_type)
    row = query.order_by(models.Ioc.id.desc()).first()
    return _ioc_to_dict(row) if row else None


# ---------------------------------------------------------------------------
# STIX 2.1 + TAXII 2.1 export
# ---------------------------------------------------------------------------

def _normalize_ip_type(ioc_type: str, value: str) -> str:
    if ioc_type not in ("ip", "ipv6"):
        return ioc_type
    try:
        if ipaddress.ip_address(value).version == 6:
            return "ipv6"
    except ValueError:
        pass
    return "ip"


def _stix_pattern(ioc: dict) -> str:
    """Builds a STIX 2.1 indicator pattern for one IOC row."""
    ioc_type = _normalize_ip_type(ioc["ioc_type"], ioc["value"])
    prop = _STIX_PATTERN_TYPES.get(ioc_type)
    if not prop:
        # Unknown indicator types become a domain-name fallback only when the
        # value looks like a hostname; otherwise emit a generic URL pattern.
        prop = "url:value" if "/" in ioc["value"] else "domain-name:value"
    escaped = ioc["value"].replace("'", "''")
    return f"[{prop} = '{escaped}']"


def _stix_ts(value) -> str:
    """Formats a datetime or ISO-8601 string as a STIX timestamp (UTC, ms)."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def export_stix_bundle(iocs: list, identity_name: str = "DFIR Threat Hunting Framework") -> dict:
    """Serializes IOC rows into a STIX 2.1 bundle (spec_version '2.1')."""
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, identity_name)}"
    identity = {
        "type": "identity",
        "id": identity_id,
        "spec_version": "2.1",
        "name": identity_name,
        "identity_class": "organization",
        "created": _stix_ts(None),
        "modified": _stix_ts(None),
    }
    objects = [identity]
    for ioc in iocs:
        ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, ioc['value'] + ioc['source'])}"
        created = _stix_ts(ioc.get("first_seen"))
        modified = _stix_ts(ioc.get("last_seen"))
        indicator = {
            "type": "indicator",
            "id": ind_id,
            "spec_version": "2.1",
            "created": created,
            "modified": modified,
            "name": ioc.get("threat") or ioc["value"],
            "description": ioc.get("description") or f"{ioc['source']} IOC",
            "pattern": _stix_pattern(ioc),
            "pattern_type": "stix",
            "valid_from": created,
            "labels": ["malicious-activity"],
            "created_by_ref": identity_id,
        }
        objects.append(indicator)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


# TAXII 2.1 collection identifiers (stable per deployment).
_TAXII_COLLECTION_ID = "collection--1"  # single 'iocs' collection


def taxii_discovery(host: str = "") -> dict:
    return {
        "title": "DFIR Threat Hunting Framework TAXII 2.1",
        "description": "Serves the framework's persisted IOC set as STIX 2.1 indicators.",
        "contact": "dfir-admin@example.invalid",
        "default": f"{host}/taxii/",
        "api_roots": [f"{host}/taxii/"],
    }


def taxii_api_root(host: str = "") -> dict:
    return {
        "title": "DFIR IOC collection",
        "description": "Automated intel-feed indicators (Feodo, URLhaus, MalwareBazaar, OTX).",
        "versions": ["taxii-2.1"],
        "max_content_length": 10485760,
        "url": f"{host}/taxii/",
    }


def taxii_collections(host: str = "") -> dict:
    return {
        "collections": [
            {
                "id": _TAXII_COLLECTION_ID,
                "title": "iocs",
                "description": "All active indicators in the iocs table.",
                "can_read": True,
                "can_write": False,
                "media_types": ["application/taxii+json;version=2.1"],
                "url": f"{host}/taxii/collections/{_TAXII_COLLECTION_ID}/",
            }
        ]
    }


def taxii_objects(iocs: list) -> dict:
    """TAXII 2.1 'Get Objects' response — the STIX objects with a `more` flag."""
    bundle = export_stix_bundle(iocs)
    return {"more": False, "objects": bundle["objects"]}
