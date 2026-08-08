"""
Attack-chain reconstruction & visualization support.

The PDF's §4.3 asks for "reconstruction and visualization of the attack
chain based on identified techniques". This module turns the set of
detected techniques into an ordered, ATT&CK-tactic-aware chain:

  reconnaissance -> resource-development -> initial-access -> execution
  -> persistence -> privilege-escalation -> defense-evasion
  -> credential-access -> discovery -> lateral-movement -> collection
  -> command-and-control -> exfiltration -> impact

Techniques are grouped under their kill-chain tactic, in that canonical
order, so an analyst can read the chain left-to-right like a timeline of
how an incident may have unfolded. Because a single detection carries one
technique but no guarantee of the "true" order of attacker actions, the
chain is presented as an *ordered hypothesis*, not a confirmed timeline —
the ordering is tactic-based, ties broken by first-detected time.
"""
from datetime import UTC, datetime

# Canonical ATT&CK Enterprise tactic order (phase_name values as they appear
# in kill_chain_phases in the STIX bundle). Extra entries are tolerated; the
# dict lookups below just won't find a rank for unknown tactic names.
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]
TACTIC_RANK = {name: i for i, name in enumerate(TACTIC_ORDER)}

UNKNOWN_TACTIC = "unknown"
UNKNOWN_RANK = len(TACTIC_ORDER)


def _tactic_rank(tactic: str | None) -> int:
    return TACTIC_RANK.get(tactic or UNKNOWN_TACTIC, UNKNOWN_RANK)


def _parse_dt(value) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=UTC)


def build_attack_chain(detections: list) -> dict:
    """Build the ordered attack chain from detection records.

    `detections` items may be ORM objects or dicts — anything exposing
    technique_id, severity, host, tactic, and a detected_at timestamp.
    Returns a dict ready for the dashboard template / PDF report:

        {
          "tactics": [ {tactic, label, techniques: [ {technique_id, name,
                       severity, hosts, count, first_seen} ] }, ... ],
          "covered_tactic_names": [...],
          "technique_count": N,
        }
    """
    by_technique: dict[str, dict] = {}

    def _field(d, key):
        return getattr(d, key, None) if not isinstance(d, dict) else d.get(key)

    for det in detections:
        tid = _field(det, "technique_id") or "unknown"
        if tid == "unknown":
            continue
        node = by_technique.setdefault(
            tid,
            {
                "technique_id": tid,
                "name": _field(det, "technique_name"),
                "tactic": _field(det, "tactic"),
                "severity": _field(det, "severity"),
                "hosts": set(),
                "count": 0,
                "first_seen": None,
            },
        )
        node["count"] += 1
        host = _field(det, "host")
        if host:
            node["hosts"].add(host)
        dt = _parse_dt(_field(det, "detected_at"))
        if node["first_seen"] is None or dt < node["first_seen"]:
            node["first_seen"] = dt

    # Sort techniques within a tactic by (severity rank, first_seen) so the
    # most concerning finding leads each phase.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    sorted_techniques = sorted(
        by_technique.values(),
        key=lambda n: (
            _tactic_rank(n["tactic"]),
            severity_rank.get(n["severity"], 4),
            n["first_seen"] or datetime.min.replace(tzinfo=UTC),
        ),
    )

    tactics: dict[str, dict] = {}
    for node in sorted_techniques:
        tactic = node["tactic"] or UNKNOWN_TACTIC
        bucket = tactics.setdefault(
            tactic, {"tactic": tactic, "techniques": [], "technique_count": 0}
        )
        bucket["techniques"].append(
            {
                "technique_id": node["technique_id"],
                "name": node["name"] or node["technique_id"],
                "severity": node["severity"] or "unknown",
                "hosts": sorted(node["hosts"]),
                "count": node["count"],
                "first_seen": node["first_seen"].isoformat() if node["first_seen"] else None,
            }
        )
        bucket["technique_count"] += 1

    # Fill in missing tactic names from the STIX mapper so labels are readable.
    ordered_tactics = []
    for tactic in sorted(tactics, key=lambda t: _tactic_rank(t)):
        bucket = tactics[tactic]
        label = _tactic_label(tactic)
        ordered_tactics.append(
            {
                "tactic": tactic,
                "label": label,
                "techniques": bucket["techniques"],
                "technique_count": bucket["technique_count"],
            }
        )

    return {
        "tactics": ordered_tactics,
        "covered_tactic_names": [t["tactic"] for t in ordered_tactics],
        "technique_count": len(by_technique),
        "ordered": True,
    }


def _tactic_label(tactic: str) -> str:
    """Human-friendly tactic label (reconnaissance -> Reconnaissance)."""
    if tactic == UNKNOWN_TACTIC:
        return "Unmapped"
    words = tactic.replace("-", " ").replace("_", " ")
    return words.title() or tactic


def recommended_actions(detections: list) -> list:
    """Best-effort recommended actions derived from the current findings.

    The PDF asks the dashboard/report to surface "recommended actions".
    These are heuristic containment/investigation steps mapped from the
    techniques that fired (a small curated map) with severity-driven
    triage fallbacks — NOT authoritative incident-response guidance.
    """
    technique_map = {
        "T1059": "Review execution of scripts/interpreters (PowerShell, bash, cmd). "
                 "Capture the process command line and parent process for every hit.",
        "T1566": "Verify whether the phishing email/delivery artifact reached users; "
                 "block the sender/IOC and quarantine any delivered payload.",
        "T1547": "Audit the boot/login persistence entry (registry Run key, launchd, "
                 "startup folder). Remove it only after evidence is captured.",
        "T1053": "Audit the scheduled task/job; check its trigger, target command and "
                 "run-as account. Disable if not business-approved.",
        "T1071": "Isolate the host from the network; review the established connection "
                 "and capture a memory snapshot before re-enabling.",
        "T1562": "Verify whether logging/AV controls were disabled or bypassed; restore "
                 "them and check for other signs of defense evasion.",
        "T1482": "Investigate the credential access event; rotate affected credentials "
                 "and check for lateral movement from this host.",
        "T1027": "Triage obfuscated content (encoded/compressed payloads). Decode in an "
                 "isolated environment and add resulting hashes as IOCs.",
    }
    findings = []
    for det in detections:
        tid = getattr(det, "technique_id", None) if not isinstance(det, dict) else det.get("technique_id")
        base = (tid or "").split(".")[0]
        if base in technique_map:
            findings.append(
                {
                    "technique_id": tid,
                    "technique_name": getattr(det, "technique_name", None) if not isinstance(det, dict) else det.get("technique_name"),
                    "action": technique_map[base],
                }
            )
    return findings


def summary_recommendations(detections: list) -> list:
    """A short, dashboard-friendly list of recommended actions (deduped)."""
    seen = set()
    out = []
    for r in recommended_actions(detections):
        if r["action"] in seen:
            continue
        seen.add(r["action"])
        out.append(r)
    return out[:10]
