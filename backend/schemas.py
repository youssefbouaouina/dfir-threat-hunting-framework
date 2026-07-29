"""
Pydantic schemas — define the shape of data going in/out of the API.
ArtifactIn matches exactly what collector_agent.py's modules/common.py
wrap_artifact() produces, so a collector output JSON file can be POSTed
to /ingest as-is (it's already a JSON array of these objects).
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ArtifactIn(BaseModel):
    host: str
    os: str
    collected_at: str
    artifact_type: str
    data: Dict[str, Any]


class ArtifactOut(BaseModel):
    id: int
    host: str
    os: str
    artifact_type: str
    collected_at: str
    data: Dict[str, Any]
    ingested_at: Optional[datetime] = None
    processed: int

    class Config:
        from_attributes = True


class IngestResponse(BaseModel):
    ingested: int
    host: str
    artifact_types: List[str]
