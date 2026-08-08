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
    matched_data = Column(Text, nullable=False)         # JSON-encoded artifact data that triggered this
    detected_at = Column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String, unique=True, index=True, nullable=False)
    host_filter = Column(String, nullable=True)          # None = all hosts
    triggered_by = Column(String, nullable=False)          # "manual" | "scheduled"
    detections_count = Column(Integer, default=0)
    pdf_filename = Column(String, nullable=False)
    summary_json = Column(Text, nullable=False)             # severity/technique breakdown, for dashboard display
    generated_at = Column(DateTime(timezone=True), server_default=func.now())


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)   # friendly label, e.g. "win10-vm01"
    ip_address = Column(String, nullable=True)                        # required for "vm", auto-set for "container"
    os = Column(String, nullable=False)                                # "windows" | "linux"
    backend_type = Column(String, default="vm")                        # "vm" (SSH) | "container" (docker-managed)
    container_name = Column(String, nullable=True, unique=True)        # docker container name for container endpoints
    image = Column(String, nullable=True)                              # image reference for container endpoints
    registration_status = Column(String, default="registered")        # "registered" | "pending" | "failed"
    agent_version = Column(String, nullable=True)                     # collector version last reported via ingest
    last_heartbeat = Column(DateTime(timezone=True), nullable=True)   # last successful ingest for this endpoint
    last_ip_address = Column(String, nullable=True)                    # IP the collector reported from last time
    ssh_port = Column(Integer, default=22)
    ssh_username = Column(String, nullable=True)
    ssh_key_path = Column(String, nullable=True)                       # path inside the container, mounted read-only volume
    remote_collector_path = Column(String, nullable=True)              # where the collector lives on the endpoint
    enabled = Column(Integer, default=1)                                 # 0 = registered but excluded from auto cycles
    status = Column(String, default="unknown")                          # "online" | "offline" | "unknown"
    last_error = Column(Text, nullable=True)                             # last scan failure reason, shown on the dashboard so failures aren't silent
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
