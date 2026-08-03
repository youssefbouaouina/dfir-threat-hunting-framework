"""
SQLAlchemy table models.

endpoints       — managed endpoint inventory (replaces the passive hosts table):
                  enrollment tokens, agent version, health status, per-endpoint config.
hosts           — legacy passive table of every host that has ever reported in
                  (kept for backwards compatibility with the /hosts endpoint).
artifacts       — one row per collected artifact (process, network conn,
                  persistence entry, scheduled task, or log event)
detections      — one row per detection result from the pipeline
detection_runs  — one row per detection-pipeline cycle (run history)
audit_logs      — one row per analyst/admin action (Phase 3: audit trail)
pending_commands — one row per "run collection now" instruction queued for an agent
                  (Phase 3: manual trigger from the dashboard)

The `processed` flag on Artifact is there for Person B: the detection
engine can query WHERE processed = 0, run YARA/Sigma/correlation against
those rows, then flip them to processed = 1 so it never re-analyzes the
same artifact twice. `analyzed_at` records when it happened (Phase 2:
keeps history and enables rescan).
"""
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

from database import Base


class Endpoint(Base):
    """A managed endpoint (enrolled agent) — the Phase 2 inventory model.

    Supersedes the passive `Host` table: an endpoint is registered through
    the enroll flow, carries an enrollment token hash, a health status, and
    an editable per-endpoint collection config (JSON).
    """
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, unique=True, index=True, nullable=False)
    os = Column(String, nullable=False)
    agent_version = Column(String, nullable=True)
    status = Column(String, default="offline")  # online | offline
    last_seen = Column(DateTime(timezone=True), nullable=True)
    enrollment_token_hash = Column(String, nullable=True)
    config_json = Column(Text, nullable=True)  # JSON-encoded collector config
    registered_at = Column(DateTime(timezone=True), server_default=func.now())
    # Phase 4 (F4): team ownership — RBAC scope for analysts/viewers. Hosts are
    # keyed by hostname, so team scoping of detections/artifacts resolves
    # hostname -> endpoint -> team through this column.
    team = Column(String, default="default", index=True)


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, unique=True, index=True, nullable=False)
    os = Column(String, nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True, index=True)
    host = Column(String, index=True, nullable=False)
    os = Column(String, nullable=False)
    artifact_type = Column(String, index=True, nullable=False)
    collected_at = Column(String, nullable=False)   # ISO8601 string, as produced by the collector
    data = Column(Text, nullable=False)              # JSON-encoded artifact-specific fields
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())
    processed = Column(Integer, default=0)            # 0 = not yet analyzed, 1 = analyzed
    analyzed_at = Column(DateTime(timezone=True), nullable=True)  # when processed flipped to 1
    source_run_id = Column(Integer, nullable=True, index=True)  # detection run that analyzed it
    agent_batch_id = Column(String, nullable=True, index=True)  # idempotency key for agent uploads


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    host = Column(String, index=True, nullable=False)
    rule_id = Column(String, index=True, nullable=False)
    rule_title = Column(String, nullable=False)
    technique_id = Column(String, index=True, nullable=True)
    technique_name = Column(String, nullable=True)
    tactic = Column(String, nullable=True)
    artifact_type = Column(String, nullable=False)
    severity = Column(String, nullable=True)
    matched_data = Column(Text, nullable=False)  # JSON-encoded artifact data that triggered this
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    # Phase 3 — triage lifecycle: new -> acknowledged -> false_positive | true_positive | reviewed
    triage_status = Column(
        String, default="new"
    )  # new | acknowledged | false_positive | true_positive | reviewed
    triage_notes = Column(Text, nullable=True)
    triage_updated_at = Column(DateTime(timezone=True), nullable=True)
    triage_updated_by = Column(String, nullable=True)


class DetectionRun(Base):
    """One detection-pipeline cycle (scheduled or manual) — the run history.

    Lets analysts see when detection ran, what triggered it, how many
    artifacts were scanned, what it found, and whether it failed. This is
    the audit trail the dashboard's 'history' view reads from.
    """
    __tablename__ = "detection_runs"

    id = Column(Integer, primary_key=True, index=True)
    trigger = Column(String, nullable=False, default="manual")  # manual | scheduled
    status = Column(String, nullable=False, default="started")  # started | completed | failed
    host = Column(String, nullable=True)  # scope, when a single host was targeted
    rescan = Column(Integer, default=0)   # 1 = re-analyzed processed artifacts
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)
    artifacts_scanned = Column(Integer, default=0)
    detections_found = Column(Integer, default=0)
    by_severity = Column(Text, nullable=True)   # JSON-encoded counts
    by_technique = Column(Text, nullable=True)  # JSON-encoded counts


class AuditLog(Base):
    """Immutable audit trail of analyst/admin actions (Phase 3 ops hardening).

    Records who did what and when (login, run detection, triage a detection,
    update an endpoint config). Reads are admin-only; appends happen from the
    services so every state change is traceable.

    Phase 4 (F4) makes the trail tamper-evident: each row carries a SHA-256
    `record_hash` computed over (prev_hash, actor, action, detail) chained to
    the previous row's record_hash. Any modification breaks the chain, which
    GET /audit-logs/verify detects.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String, nullable=True)  # admin key label, token subject, or agent hostname
    action = Column(String, nullable=False)  # e.g. "run_detection", "triage_detection"
    detail = Column(Text, nullable=True)  # JSON-encoded context (ids, filters, counts)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    # Phase 4 (F4): hash-chain columns for tamper-evidence (nullable on legacy rows).
    prev_hash = Column(String, nullable=True)
    record_hash = Column(String, nullable=True, index=True)


class PendingCommand(Base):
    """A manual trigger queued for an agent by the dashboard (Phase 3).

    When an analyst clicks "Run collection now" on an endpoint, a row is
    inserted here; the agent's next config poll (or command poll) picks it
    up, performs the action, and marks it completed.
    """
    __tablename__ = "pending_commands"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True, nullable=False)  # target endpoint
    command = Column(String, nullable=False)               # e.g. "run_collection"
    params = Column(Text, nullable=True)                   # JSON-encoded extra params
    status = Column(String, default="pending")  # pending | picked_up | completed | failed
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    picked_up_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    result = Column(Text, nullable=True)                   # JSON-encoded result/report


class Incident(Base):
    """A correlated set of detections (Phase 4 / F2 correlation engine).

    Two grouping strategies feed incidents:
      * same rule_id across multiple hosts  -> "campaign" incident
      * multiple techniques on one host     -> "attack chain" incident
    Each incident carries an ATT&CK technique list (the chain), a severity
    derived from its members (escalated for spread), and its constituent
    detections via the IncidentDetection link table.
    """
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    signature = Column(String, unique=True, index=True, nullable=False)  # deterministic group key
    title = Column(String, nullable=False)
    severity = Column(String, nullable=True)               # info|low|medium|high|critical
    status = Column(String, default="open")  # open | acknowledged | resolved | false_positive
    host_count = Column(Integer, default=0)
    detection_count = Column(Integer, default=0)
    technique_ids = Column(Text, nullable=True)            # JSON array of ATT&CK ids (the chain)
    tactic = Column(String, nullable=True)                 # most severe member's tactic
    hosts = Column(Text, nullable=True)                    # JSON array of hostnames
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class IncidentDetection(Base):
    """Link row between an Incident and its member Detections (F2)."""
    __tablename__ = "incident_detections"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, index=True, nullable=False)
    detection_id = Column(Integer, index=True, nullable=False)
