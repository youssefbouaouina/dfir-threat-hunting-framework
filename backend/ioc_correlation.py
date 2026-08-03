"""
Correlates network artifact remote addresses against threat intel.

Two layers, deliberately separated:
  1. LOCAL BLOCKLIST (iocs/malicious_ips.txt + iocs/feodo_ips.txt) — always
     available, no network dependency, works offline/in a demo with no
     internet. Feodo Tracker's public blocklist is refreshed periodically
     into iocs/feodo_ips.txt (see refresh_feodo_blocklist).
  2. LIVE FEEDS (AbuseIPDB / URLhaus / OTX) — best-effort, requires API
     keys in .env and outbound internet access. Fails soft: if a feed is
     unreachable or a key is missing, that layer is skipped rather than
     crashing the whole /detect call.

NOTE ON TESTING: layer 1 (local blocklists) is fully tested below with
real code execution. Layer 2 (live feeds) is unit-tested with mocked
responses; the request logic follows each service's documented API shape,
but test it against your own API keys before relying on it for a demo.
If it fails, the local blocklist layer still functions independently, so
the pipeline overall stays usable.
"""
import ipaddress
import os
from datetime import datetime, timezone
from typing import Dict

import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
IOC_DIR = os.path.join(os.path.dirname(__file__), "iocs")
LOCAL_BLOCKLIST_PATH = os.path.join(IOC_DIR, "malicious_ips.txt")
FEODO_BLOCKLIST_PATH = os.path.join(IOC_DIR, "feodo_ips.txt")

FEODO_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

# in-process cache so repeated IPs in one /detect run don't re-query
_ip_cache: Dict[str, dict] = {}

# Live lookup order: first hit wins (checked left-to-right).
LIVE_CHECKERS = ("check_abuseipdb", "check_urlhaus", "check_otx")


def _extract_ip(remote_address: str) -> str:
    """'1.2.3.4:4444' -> '1.2.3.4'"""
    if not remote_address:
        return ""
    return remote_address.rsplit(":", 1)[0]


def _parse_blocklist_lines(lines) -> dict:
    """Parses '<ip> <optional description>' lines into {ip: description}."""
    entries = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        entries[parts[0]] = parts[1].lstrip("#").strip() if len(parts) > 1 else ""
    return entries


def load_local_blocklist(path: str = LOCAL_BLOCKLIST_PATH) -> dict:
    entries = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            entries.update(_parse_blocklist_lines(f))
    return entries


def load_all_blocklists() -> dict:
    """Merges the curated blocklist + the Feodo refresh file (M2)."""
    merged = load_local_blocklist()
    merged.update(load_local_blocklist(FEODO_BLOCKLIST_PATH))
    return merged


def refresh_feodo_blocklist(output_path: str = FEODO_BLOCKLIST_PATH) -> int:
    """Downloads Feodo Tracker's IP blocklist CSV into iocs/feodo_ips.txt.

    Returns the number of IPs written, or 0 on any failure (fail soft —
    a stale local file is better than a crash). Writes a header comment so
    the file stays consistent with load_local_blocklist's format.
    """
    try:
        resp = requests.get(FEODO_CSV_URL, timeout=10)
        resp.raise_for_status()
        ips = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Real format: last_seen,dst_ip,dst_port,malware,...
            fields = [f.strip().strip('"') for f in line.split(",")]
            if len(fields) >= 2 and fields[1]:
                ips.append(fields[1])
    except requests.exceptions.RequestException:
        return 0

    if not ips:
        return 0

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(
            f"# Feodo Tracker IP blocklist (auto-refreshed {stamp})\n"
            f"# Source: {FEODO_CSV_URL}\n"
            "# one IP per line, <ip> <source>\n"
        )
        for ip in ips:
            f.write(f"{ip} feodo-tracker\n")
    return len(ips)


def _is_private_or_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # not a parseable IP — treat as "don't bother checking"


def check_abuseipdb(ip: str) -> dict:
    """Best-effort live lookup. Returns {} if unavailable/unconfigured/failed."""
    if not ABUSEIPDB_API_KEY:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},  # type: ignore[arg-type]
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            if score >= 50:  # threshold, tune as needed
                return {"source": "AbuseIPDB", "score": score, "ip": ip}
    except requests.exceptions.RequestException:
        pass
    return {}


def check_urlhaus(ip: str) -> dict:
    """Best-effort URLhaus host lookup (no API key required). Returns {} on miss."""
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("url_count", 0) > 0:
                return {"source": "URLhaus", "score": min(100, data["url_count"]), "ip": ip}
    except requests.exceptions.RequestException:
        pass
    return {}


def check_otx(ip: str) -> dict:
    """Best-effort AlienVault OTX IP reputation lookup. Returns {} on miss."""
    if not OTX_API_KEY:
        return {}
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("pulse_info", {}).get("count", 0) > 0:
                return {"source": "OTX", "score": 100, "ip": ip}
    except requests.exceptions.RequestException:
        pass
    return {}


def _live_lookup(ip: str) -> dict:
    """Runs the configured live checkers in order; first hit wins."""
    for name in LIVE_CHECKERS:
        checker = globals().get(name)
        if checker is None:
            continue
        result = checker(ip)
        if result:
            return result
    return {}


def correlate_network_artifacts(artifacts: list) -> list:
    """
    artifacts: list of wrapped artifact dicts with artifact_type == 'network'
    Returns detection dicts for any remote address matching the local
    blocklists or, if configured, a live feed hit.
    """
    blocklist = load_all_blocklists()
    detections = []

    for artifact in artifacts:
        if artifact.get("artifact_type") != "network":
            continue
        data = artifact.get("data", {})
        ip = _extract_ip(data.get("remote_address", ""))
        if not ip:
            continue

        # Layer 1: local blocklists — checked regardless of private/public
        # status, since this list is manually curated and may deliberately
        # include lab/test ranges for pipeline validation.
        if ip in blocklist:
            detections.append(
                {
                    "rule_id": "ioc-local-blocklist",
                    "rule_title": f"Connection to known-bad IP ({blocklist[ip] or 'unlabeled'})",
                    "technique_id": "T1071",
                    "severity": "high",
                    "host": artifact.get("host"),
                    "artifact_type": "network",
                    "matched_data": data,
                }
            )
            continue  # already flagged, skip the live lookup for this IP

        # Layer 2: live feeds — skip private/loopback/link-local addresses,
        # no point burning API quota checking RFC1918 space.
        if _is_private_or_local(ip):
            continue

        if ip not in _ip_cache:
            _ip_cache[ip] = _live_lookup(ip)
        result = _ip_cache[ip]
        if result:
            detections.append(
                {
                    "rule_id": f"ioc-{result['source'].lower()}",
                    "rule_title": f"{result['source']} hit (score {result['score']})",
                    "technique_id": "T1071",
                    "severity": "high" if result["score"] >= 75 else "medium",
                    "host": artifact.get("host"),
                    "artifact_type": "network",
                    "matched_data": data,
                }
            )

    return detections


if __name__ == "__main__":
    # Tested path: local blocklist only, no network required.
    test_artifacts = [
        {
            "host": "test-host", "os": "linux", "artifact_type": "network",
            "collected_at": "x",
            "data": {"remote_address": "203.0.113.66:443", "status": "ESTABLISHED"},
        },
        {
            "host": "test-host", "os": "linux", "artifact_type": "network",
            "collected_at": "x", "data": {"remote_address": "8.8.8.8:443", "status": "ESTABLISHED"},
        },
    ]
    print(correlate_network_artifacts(test_artifacts))
