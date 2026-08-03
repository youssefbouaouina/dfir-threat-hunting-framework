"""
Pydantic schemas — define the shape of data going in/out of the API.
ArtifactIn matches exactly what collector_agent.py's modules/common.py
wrap_artifact() produces, so a collector output JSON file can be POSTed
to /ingest as-is (it's already a JSON array of these objects).

Phase 3 additions: detection triage (DetectionTriageIn), endpoint config
updates (EndpointConfigUpdateIn), audit log read model, pending-command
models for manual "run collection now" triggers, and a metrics view.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict

TRIAGE_STATUSES = ("new", "acknowledged", "false_positive", "true_positive", "reviewed")


class ArtifactIn(BaseModel):
    host: str
    os: str
    collected_at: str
    artifact_type: str
    data: Dict[str, Any]


class ArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host: str
    os: str
    artifact_type: str
    collected_at: str
    data: Dict[str, Any]
    ingested_at: Optional[datetime] = None
    processed: int


class IngestResponse(BaseModel):
    ingested: int
    host: str
    artifact_types: List[str]
    deduplicated: int = 0
    batch_id: Optional[str] = None
    # Phase 4 (F1): when the async ingest queue is enabled, /ingest returns
    # HTTP 202 and these two fields describe the accepted (not yet persisted)
    # upload. When the queue is disabled they are left at defaults.
    accepted: bool = False
    queued: int = 0


class EndpointEnrollRequest(BaseModel):
    hostname: str
    os: str
    agent_version: Optional[str] = None


class EndpointOut(BaseModel):
    id: int
    hostname: str
    os: str
    agent_version: Optional[str] = None
    status: str
    last_seen: Optional[datetime] = None
    registered_at: Optional[datetime] = None
    config: Optional[Dict[str, Any]] = None


class EnrollResponse(EndpointOut):
    """Enrollment response — includes the one-time token issued on first enroll.

    The token is present only when this call actually issued it (first
    enrollment); re-enrollments omit it (the backend stores only its hash).
    """

    enrollment_token: Optional[str] = None


class EndpointConfigUpdateIn(BaseModel):
    """Admin-updatable agent config: which collectors run and how often."""

    collectors: Optional[List[str]] = None
    interval_seconds: Optional[int] = None  # >= 10


class EndpointConfigOut(BaseModel):
    hostname: str
    interval_seconds: int
    collectors: List[str]


class DetectionTriageIn(BaseModel):
    """Analyst decision on a detection: false positive, true positive, etc."""

    status: str
    notes: Optional[str] = None


class AuditLogOut(BaseModel):
    id: int
    actor: Optional[str] = None
    action: str
    detail: Optional[str] = None
    created_at: Optional[datetime] = None


class PendingCommandOut(BaseModel):
    id: int
    hostname: str
    command: str
    status: str
    created_at: Optional[datetime] = None


class PendingCommandResultIn(BaseModel):
    """Agent reports the outcome of a picked-up command."""

    status: str = "completed"  # completed | failed
    result: Optional[Dict[str, Any]] = None


class LoginRequest(BaseModel):
    api_key: str


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_in: int
