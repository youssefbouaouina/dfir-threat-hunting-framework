"""
SQLAlchemy table models.

hosts     — one row per endpoint that has ever reported in
artifacts — one row per collected artifact (process, network conn,
            persistence entry, scheduled task, or log event)

The `processed` flag on Artifact is there for Person B: the detection
engine can query WHERE processed = 0, run YARA/Sigma/correlation against
those rows, then flip them to processed = 1 so it never re-analyzes the
same artifact twice.
"""
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

from database import Base


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
