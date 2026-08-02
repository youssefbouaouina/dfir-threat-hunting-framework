"""
Endpoint management routes — thin HTTP layer over services.endpoint_service.

Phase 2: managed endpoint inventory + agent self-enrollment. Agents POST to
/enroll on startup (agent-auth gated) and analysts/admin list the inventory
(admin-auth gated). Config polling is a GET that works for any known endpoint
(agent-auth gated) so enrolled agents can pick up their per-endpoint settings.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

import schemas
from database import get_db
from security import require_admin, require_agent
from services import endpoint_service

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@router.post("/enroll", response_model=schemas.EndpointOut, dependencies=[Depends(require_agent)])
def enroll(
    body: schemas.EndpointEnrollRequest,
    db: Session = Depends(get_db),
):
    """Agent self-registration — idempotent per hostname. Returns id + config."""
    return endpoint_service.enroll_endpoint(db, body.hostname, body.os, body.agent_version)


@router.get("", response_model=list[schemas.EndpointOut], dependencies=[Depends(require_admin)])
def list_endpoints(limit: int = 100, db: Session = Depends(get_db)):
    """Managed endpoint inventory (analyst/admin view)."""
    return endpoint_service.list_endpoints(db, limit=limit)


@router.get(
    "/config", response_model=schemas.EndpointConfigOut, dependencies=[Depends(require_agent)]
)
def endpoint_config(hostname: str, db: Session = Depends(get_db)):
    """Per-endpoint collection config, polled by agents each cycle."""
    config = endpoint_service.get_endpoint_config(db, hostname)
    return schemas.EndpointConfigOut(
        hostname=hostname,
        interval_seconds=config.get("interval_seconds", 300),
        collectors=config.get("collectors", []),
    )
