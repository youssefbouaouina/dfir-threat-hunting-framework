"""
Endpoint management routes — thin HTTP layer over services.endpoint_service.

Phase 2: managed endpoint inventory + agent self-enrollment. Agents POST to
/enroll on startup (agent-auth gated) and analysts/admin list the inventory
(admin-auth gated). Config polling is a GET that works for any known endpoint
(agent-auth gated) so enrolled agents can pick up their per-endpoint settings.

Phase 3: dashboard controls — admin edits a per-endpoint config, queues a
"run collection now" command, and the agent polls/acknowledges commands.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

import schemas
from database import get_db
from security import require_admin, require_agent
from services import endpoint_service

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@router.post(
    "/enroll",
    response_model=schemas.EnrollResponse,
    dependencies=[Depends(require_agent)],
)
def enroll(
    body: schemas.EndpointEnrollRequest,
    db: Session = Depends(get_db),
):
    """Agent self-registration — idempotent per hostname.

    Returns id + config + a one-time enrollment token (token only on the first
    enrollment for a given hostname).
    """
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


@router.put(
    "/{endpoint_id}/config",
    response_model=schemas.EndpointOut,
    dependencies=[Depends(require_admin)],
)
def update_endpoint_config(
    endpoint_id: int,
    body: schemas.EndpointConfigUpdateIn,
    db: Session = Depends(get_db),
):
    """Admin edits an endpoint's agent config (collectors / interval)."""
    try:
        result = endpoint_service.update_endpoint_config(
            db, endpoint_id, collectors=body.collectors, interval_seconds=body.interval_seconds
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return result


@router.post("/{endpoint_id}/run-collection", dependencies=[Depends(require_admin)])
def run_collection_now(endpoint_id: int, db: Session = Depends(get_db)):
    """Dashboard "Run collection now" — queues a command the agent picks up."""
    result = endpoint_service.queue_collection(db, endpoint_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return result


@router.get("/commands", dependencies=[Depends(require_agent)])
def poll_commands(hostname: str, db: Session = Depends(get_db)):
    """Agent polls for pending commands; returns them and marks them picked up."""
    return endpoint_service.poll_pending_commands(db, hostname)


@router.post("/commands/{command_id}/complete", dependencies=[Depends(require_agent)])
def complete_command(
    command_id: int,
    body: schemas.PendingCommandResultIn,
    db: Session = Depends(get_db),
):
    """Agent reports the outcome of a picked-up command."""
    result = endpoint_service.complete_command(
        db, command_id, status=body.status, result=body.result
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Command not found")
    return result
