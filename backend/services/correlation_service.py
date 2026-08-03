"""Correlation engine (Phase 4 / F2).

Groups stored detections into incidents so an analyst sees the campaign, not
just a flat list of hits:

  * Campaign: the same rule_id fires on multiple hosts -> lateral movement /
    scanning pattern (e.g. the same YARA/Sigma rule hitting 3 endpoints).
  * Attack chain: one host produces detections across >= 2 distinct ATT&CK
    techniques -> a kill chain unfolding on that box.

Both strategies share one rebuild routine (`recompute_incidents`) which is
idempotent and signature-keyed: re-running it never duplicates incidents and
preserves triage state on the incidents themselves (only members, severity,
counts, and technique chains are refreshed). Detections are never deleted —
incidents are a derived view over them.
"""
import json
from typing import Dict, List, Optional

import models
from services.audit_service import log_action

INCIDENT_STATUSES = ("open", "acknowledged", "resolved", "false_positive")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def _severity_rank(severity: Optional[str]) -> int:
    if not severity:
        return _SEVERITY_RANK["unknown"] if "unknown" in _SEVERITY_RANK else 0
    return _SEVERITY_RANK.get(severity.lower(), 0)


def _max_severity(detections: list) -> str:
    return _RANK_TO_SEVERITY[max(_severity_rank(d.get("severity")) for d in detections)]


def _escalate(severity: str, hosts: int, techniques: int) -> str:
    """Escalates severity for spread (many hosts) or depth (long chain)."""
    rank = _SEVERITY_RANK.get(severity.lower(), 0)
    if hosts >= 3:
        rank += 1  # lateral movement across 3+ hosts is more serious
    if techniques >= 3:
        rank += 1  # a 3+ technique chain suggests active hands-on-keyboard
    return _RANK_TO_SEVERITY[min(rank, _SEVERITY_RANK["critical"])]


def _detections_to_dicts(db) -> List[dict]:
    rows = db.query(models.Detection).all()
    return [
        {
            "id": r.id,
            "host": r.host,
            "rule_id": r.rule_id,
            "rule_title": r.rule_title,
            "technique_id": r.technique_id,
            "tactic": r.tactic,
            "severity": r.severity or "unknown",
            "detected_at": r.detected_at,
        }
        for r in rows
    ]


def _campaign_groups(detections: List[dict]) -> Dict[str, List[dict]]:
    """Groups detections by rule_id that appear on >= 2 distinct hosts."""
    groups: Dict[str, List[dict]] = {}
    for d in detections:
        if not d.get("rule_id"):
            continue
        groups.setdefault(d["rule_id"], []).append(d)
    return {
        rid: members
        for rid, members in groups.items()
        if len({m["host"] for m in members}) >= 2
    }


def _chain_groups(detections: List[dict]) -> Dict[str, List[dict]]:
    """Groups detections by host that show >= 2 distinct techniques."""
    groups: Dict[str, List[dict]] = {}
    for d in detections:
        groups.setdefault(d["host"], []).append(d)
    return {
        host: members
        for host, members in groups.items()
        if len({m.get("technique_id") for m in members if m.get("technique_id")}) >= 2
    }


def _build_incidents(detections: List[dict]) -> List[dict]:
    """Derives incident definitions (signature, members, aggregates) from detections."""
    incidents: List[dict] = []

    for rid, members in _campaign_groups(detections).items():
        incidents.append(_derive_incident("campaign", rid, members))

    chain_members = {m["id"] for inc in incidents for m in inc["members"]}
    for host, members in _chain_groups(detections).items():
        # A detection already claimed by a campaign incident is excluded from a
        # chain incident — keep the member sets disjoint for clean grouping.
        unclaimed = [m for m in members if m["id"] not in chain_members]
        if len({m.get("technique_id") for m in unclaimed if m.get("technique_id")}) >= 2:
            incidents.append(_derive_incident("chain", host, unclaimed))

    return incidents


def _derive_incident(kind: str, key: str, members: List[dict]) -> dict:
    """Turns a correlated member list into an incident definition dict."""
    hosts = sorted({m["host"] for m in members})
    techniques = [
        m["technique_id"]
        for m in sorted(members, key=lambda m: m["detected_at"])
        if m.get("technique_id")
    ]
    base_severity = _max_severity(members)
    severity = _escalate(base_severity, len(hosts), len(set(techniques)))

    if kind == "campaign":
        title = f"{members[0]['rule_title'] or members[0]['rule_id']} across {len(hosts)} hosts"
        signature = f"campaign:{key}"
    else:
        title = f"Attack chain on {hosts[0]} ({len(set(techniques))} techniques)"
        signature = f"chain:{key}"

    first = min(m["detected_at"] for m in members)
    last = max(m["detected_at"] for m in members)

    return {
        "signature": signature,
        "title": title,
        "severity": severity,
        "members": members,
        "host_count": len(hosts),
        "detection_count": len(members),
        "technique_ids": list(dict.fromkeys(techniques)),
        "tactic": _dominant_tactic(members),
        "hosts": hosts,
        "first_seen": first,
        "last_seen": last,
    }


def _dominant_tactic(members: List[dict]) -> Optional[str]:
    counts: Dict[str, int] = {}
    for m in members:
        if m.get("tactic"):
            counts[m["tactic"]] = counts.get(m["tactic"], 0) + 1
    if not counts:
        return None
    return max(counts, key=lambda k: counts[k])


def recompute_incidents(db, actor: str = "system") -> dict:
    """Rebuilds incidents idempotently from all stored detections.

    Incidents are signature-keyed, so a re-run refreshes aggregates in place
    (preserving any analyst triage) instead of duplicating rows. Member link
    rows are rebuilt each time so the grouping always matches current state.
    """
    detections = _detections_to_dicts(db)
    definitions = _build_incidents(detections)

    existing = {i.signature: i for i in db.query(models.Incident).all()}
    new_signatures = {d["signature"] for d in definitions}

    for definition in definitions:
        inc = existing.get(definition["signature"])
        if inc is None:
            inc = models.Incident(signature=definition["signature"])
            db.add(inc)
        inc.title = definition["title"]
        inc.severity = definition["severity"]
        inc.host_count = definition["host_count"]
        inc.detection_count = definition["detection_count"]
        inc.technique_ids = json.dumps(definition["technique_ids"])
        inc.tactic = definition["tactic"]
        inc.hosts = json.dumps(definition["hosts"])
        inc.first_seen = definition["first_seen"]
        inc.last_seen = definition["last_seen"]
        db.flush()
        incident_id: int = inc.id  # type: ignore[assignment]
        _refresh_members(db, incident_id, definition["members"])

    for signature, inc in existing.items():
        if signature not in new_signatures:
            db.query(models.IncidentDetection).filter(
                models.IncidentDetection.incident_id == inc.id
            ).delete()
            db.delete(inc)

    db.commit()

    log_action(
        db,
        "recompute_incidents",
        actor=actor,
        detail={"incidents": len(definitions), "detections_considered": len(detections)},
    )

    return {"incidents": len(definitions), "detections_considered": len(detections)}


def _refresh_members(db, incident_id: int, members: List[dict]) -> None:
    """Replaces an incident's detection links to match the current grouping."""
    db.query(models.IncidentDetection).filter(
        models.IncidentDetection.incident_id == incident_id
    ).delete()
    for m in members:
        db.add(models.IncidentDetection(incident_id=incident_id, detection_id=m["id"]))


def list_incidents(
    db,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    before_id: Optional[int] = None,
    hosts: Optional[List[str]] = None,
) -> list:
    """Returns incidents newest-first, optionally filtered by status/severity.

    `hosts` (F4) is a team-scope allow-list: an incident is visible if at
    least one of its member detections belongs to an allowed host.
    """
    query = db.query(models.Incident)
    if status:
        query = query.filter(models.Incident.status == status)
    if severity:
        query = query.filter(models.Incident.severity == severity)
    if hosts is not None:
        link = models.IncidentDetection
        scoped_incident_ids = (
            db.query(link.incident_id)
            .join(models.Detection, models.Detection.id == link.detection_id)
            .filter(models.Detection.host.in_(hosts))
            .distinct()
            .subquery()
        )
        query = query.filter(models.Incident.id.in_(scoped_incident_ids))
    if before_id is not None:
        query = query.filter(models.Incident.id < before_id)
    rows = query.order_by(models.Incident.id.desc()).limit(min(limit, 500)).all()
    return [_incident_to_dict(r) for r in rows]


def get_incident(db, incident_id: int) -> Optional[dict]:
    """Returns one incident including its member detections."""
    row = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if row is None:
        return None
    result = _incident_to_dict(row)
    link = models.IncidentDetection
    member_ids = [
        r.detection_id
        for r in db.query(link).filter(link.incident_id == row.id).order_by(link.id).all()
    ]
    result["detections"] = _detections_by_ids(db, member_ids)
    return result


def _detections_by_ids(db, ids: List[int]) -> List[dict]:
    if not ids:
        return []
    rows = db.query(models.Detection).filter(models.Detection.id.in_(ids)).all()
    by_id = {r.id: r for r in rows}
    return [
        {
            "id": r.id,
            "host": r.host,
            "rule_id": r.rule_id,
            "rule_title": r.rule_title,
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "severity": r.severity,
            "triage_status": r.triage_status or "new",
        }
        for r in (by_id.get(i) for i in ids)
        if r is not None
    ]


def _incident_to_dict(r: models.Incident) -> dict:
    return {
        "id": r.id,
        "signature": r.signature,
        "title": r.title,
        "severity": r.severity,
        "status": r.status or "open",
        "host_count": r.host_count,
        "detection_count": r.detection_count,
        "technique_ids": json.loads(r.technique_ids) if r.technique_ids else [],
        "tactic": r.tactic,
        "hosts": json.loads(r.hosts) if r.hosts else [],
        "first_seen": str(r.first_seen) if r.first_seen else None,
        "last_seen": str(r.last_seen) if r.last_seen else None,
    }


def triage_incident(
    db,
    incident_id: int,
    status: str,
    actor: Optional[str] = None,
) -> Optional[dict]:
    """Sets an incident's triage status (open/acknowledged/resolved/false_positive)."""
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Invalid incident status '{status}' — must be one of {INCIDENT_STATUSES}")

    row = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if row is None:
        return None

    row.status = status
    db.commit()

    log_action(
        db,
        "triage_incident",
        actor=actor or "unknown",
        detail={"incident_id": incident_id, "status": status},
    )

    return {"id": row.id, "status": row.status}


def incidents_summary(db) -> dict:
    """Dashboard-facing counts grouped by status and severity."""
    from sqlalchemy import func

    def _grouped(column) -> dict:
        rows = db.query(column, func.count(models.Incident.id)).group_by(column).all()
        return {key or "unknown": n for key, n in rows}

    return {
        "total_incidents": db.query(models.Incident).count(),
        "by_status": _grouped(models.Incident.status),
        "by_severity": _grouped(models.Incident.severity),
    }
