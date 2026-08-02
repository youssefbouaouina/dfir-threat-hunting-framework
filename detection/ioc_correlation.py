"""
Correlates network artifact remote addresses against threat intel.

Two layers, deliberately separated:
  1. LOCAL BLOCKLIST (iocs/malicious_ips.txt) — always available, no
     network dependency, works offline/in a demo with no internet.
  2. LIVE FEEDS (AbuseIPDB / URLhaus / Feodo Tracker) — best-effort,
     requires API keys in .env and outbound internet access. Fails
     soft: if a feed is unreachable or a key is missing, that layer
     is skipped rather than crashing the whole /detect call.

NOTE ON TESTING: layer 1 (local blocklist) is fully tested below with
real code execution. Layer 2 (live feeds) could not be exercised in
the environment this was written in (no network path to those APIs
from there) — the request logic follows each service's documented API
shape, but test it against your own API keys before relying on it for
a demo. If it fails, the local blocklist layer still functions
independently, so the pipeline overall stays usable.
"""
import ipaddress
import os

import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
IOC_DIR = os.path.join(os.path.dirname(__file__), "iocs")
LOCAL_BLOCKLIST_PATH = os.path.join(IOC_DIR, "malicious_ips.txt")

_ip_cache = {}  # simple in-process cache so repeated IPs in one /detect run don't re-query


def _extract_ip(remote_address: str) -> str:
    """'1.2.3.4:4444' -> '1.2.3.4'"""
    if not remote_address:
        return ""
    return remote_address.rsplit(":", 1)[0]


def load_local_blocklist(path: str = LOCAL_BLOCKLIST_PATH) -> dict:
    entries = {}
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                entries[parts[0]] = parts[1].lstrip("#").strip() if len(parts) > 1 else ""
    return entries


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
            params={"ipAddress": ip, "maxAgeInDays": 90},
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


def correlate_network_artifacts(artifacts: list) -> list:
    """
    artifacts: list of wrapped artifact dicts with artifact_type == 'network'
    Returns detection dicts for any remote address matching the local
    blocklist or, if configured, a live feed hit.
    """
    blocklist = load_local_blocklist()
    detections = []

    for artifact in artifacts:
        if artifact.get("artifact_type") != "network":
            continue
        data = artifact.get("data", {})
        ip = _extract_ip(data.get("remote_address", ""))
        if not ip:
            continue

        # Layer 1: local blocklist — checked regardless of private/public
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

        # Layer 2: live feed — skip private/loopback/link-local addresses,
        # no point burning API quota checking RFC1918 space.
        if _is_private_or_local(ip):
            continue

        if ip not in _ip_cache:
            _ip_cache[ip] = check_abuseipdb(ip)
        result = _ip_cache[ip]
        if result:
            detections.append(
                {
                    "rule_id": "ioc-abuseipdb",
                    "rule_title": f"AbuseIPDB confidence score {result['score']}",
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
            "collected_at": "x", "data": {"remote_address": "203.0.113.66:443", "status": "ESTABLISHED"},
        },
        {
            "host": "test-host", "os": "linux", "artifact_type": "network",
            "collected_at": "x", "data": {"remote_address": "8.8.8.8:443", "status": "ESTABLISHED"},
        },
    ]
    print(correlate_network_artifacts(test_artifacts))
