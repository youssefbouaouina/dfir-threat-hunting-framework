"""
Endpoint management API.

Two endpoint kinds, one registry:

  - backend_type="vm"        (default, unchanged behavior): the backend holds SSH
                              connection details and reaches OUT to the endpoint for
                              liveness, on-demand scans and the automated cycle.
  - backend_type="container": the endpoint is a Docker container managed by the
                              isolated `endpoint-manager` service. Creating the
                              endpoint also creates the container; Start/Stop/Restart
                              call the manager; scans run the collector inside the
                              container via `docker exec` (no sshd / SSH keys needed).

The container path is additive — every existing VM endpoint behavior is preserved.
"""
import logging
import os
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from container_manager_client import (
    ENDPOINT_IMAGE,
    EndpointManagerError,
    container_status,
    create_endpoint_container,
    exec_collector,
    restart_container,
    start_container,
    stop_container,
)
from container_manager_client import (
    remove_container as manager_remove_container,
)
from database import get_db
from detection_routes import run_detection_job
from endpoint_orchestrator import check_liveness, run_remote_scan
from reports import generate_report

router = APIRouter()

logger = logging.getLogger("dfir.endpoints")

BACKEND_PUSH_URL = os.getenv("BACKEND_PUSH_URL", "http://192.168.50.1:8000")
# Containers live on the compose network, so they must push to the backend
# service name, not the host-reachable URL used by external VM endpoints.
CONTAINER_PUSH_URL = os.getenv("ENDPOINT_PUSH_URL", "http://backend:8000")

DOCKER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


class EndpointCreate(BaseModel):
    name: str
    ip_address: str | None = None
    os: str = "linux"
    backend_type: str = "vm"
    image: str | None = None
    container_name: str | None = None
    ssh_port: int = 22
    ssh_username: str | None = None
    ssh_key_path: str | None = None
    remote_collector_path: str | None = None
    enabled: bool = True


def _endpoint_to_dict(e: models.Endpoint) -> dict:
    return {
        "id": e.id,
        "name": e.name,
        "ip_address": e.ip_address,
        "os": e.os,
        "backend_type": e.backend_type,
        "container_name": e.container_name,
        "image": e.image,
        "registration_status": e.registration_status,
        "agent_version": e.agent_version,
        "last_heartbeat": str(e.last_heartbeat) if e.last_heartbeat else None,
        "last_ip_address": e.last_ip_address,
        "ssh_port": e.ssh_port,
        "enabled": bool(e.enabled),
        "status": e.status,
        "last_error": e.last_error,
        "last_checked_at": str(e.last_checked_at) if e.last_checked_at else None,
        "last_scan_at": str(e.last_scan_at) if e.last_scan_at else None,
    }


def _validate_container_create(payload: EndpointCreate) -> None:
    if payload.backend_type != "container":
        return
    if not DOCKER_NAME_RE.match(payload.name):
        raise HTTPException(
            status_code=422,
            detail="Container endpoint names must match [a-zA-Z0-9][a-zA-Z0-9_.-]* "
            "(used as the Docker container name).",
        )
    if not payload.container_name:
        payload.container_name = payload.name
    if payload.container_name != payload.name and not DOCKER_NAME_RE.match(payload.container_name):
        raise HTTPException(status_code=422, detail="Invalid container_name")
    if not payload.image:
        # Deployment-defined endpoint image (compose passes ENDPOINT_IMAGE).
        # Explicit per-endpoint image overrides it.
        payload.image = ENDPOINT_IMAGE


def _create_docker_container(payload: EndpointCreate) -> str:
    """Ask the endpoint-manager to create the endpoint container. Returns the name."""
    env = {"ENDPOINT_PUSH_URL": os.getenv("ENDPOINT_PUSH_URL", "http://backend:8000")}
    try:
        result = create_endpoint_container(payload.container_name, image=payload.image, env=env)
        logger.info("Container endpoint %s created via endpoint-manager", payload.name)
        return result.get("name", payload.container_name)
    except EndpointManagerError as e:
        logger.warning("Failed to create container for %s: %s", payload.name, e)
        raise HTTPException(status_code=502, detail=f"Endpoint container creation failed: {e}")


@router.post("/endpoints")
def register_endpoint(payload: EndpointCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Endpoint).filter(models.Endpoint.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Endpoint '{payload.name}' already registered")

    _validate_container_create(payload)

    registration_status = "registered"
    container_name = payload.container_name
    ip_address = payload.ip_address

    if payload.backend_type == "container":
        registration_status = "pending"
        container_name = _create_docker_container(payload)
        try:
            status = container_status(container_name)
            if status.get("ip_address"):
                ip_address = status["ip_address"]
        except EndpointManagerError:
            pass
        registration_status = "registered"

    row = models.Endpoint(
        name=payload.name,
        ip_address=ip_address,
        os=payload.os,
        backend_type=payload.backend_type,
        container_name=container_name,
        image=payload.image,
        registration_status=registration_status,
        ssh_port=payload.ssh_port,
        ssh_username=payload.ssh_username,
        ssh_key_path=payload.ssh_key_path,
        remote_collector_path=payload.remote_collector_path,
        enabled=1 if payload.enabled else 0,
        status="unknown",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _endpoint_to_dict(row)


@router.get("/endpoints")
def list_endpoints(db: Session = Depends(get_db)):
    rows = db.query(models.Endpoint).order_by(models.Endpoint.id).all()
    return [_endpoint_to_dict(e) for e in rows]


@router.get("/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return _endpoint_to_dict(row)


@router.delete("/endpoints/{endpoint_id}")
def delete_endpoint(endpoint_id: int, remove_container: bool = True, db: Session = Depends(get_db)):
    """Remove an endpoint. For container endpoints, also removes the Docker
    container by default (pass remove_container=false to keep it running)."""
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    if row.backend_type == "container" and remove_container and row.container_name:
        try:
            manager_remove_container(row.container_name)
        except EndpointManagerError as e:
            raise HTTPException(status_code=502, detail=f"Container removal failed: {e}")

    db.delete(row)
    db.commit()
    return {"deleted": endpoint_id}


@router.post("/endpoints/{endpoint_id}/check")
def check_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    """On-demand status check — container endpoints query Docker state; VM endpoints
    do a TCP liveness check of the SSH port."""
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    if row.backend_type == "container":
        try:
            state = container_status(row.container_name)
        except EndpointManagerError as e:
            row.status = "offline"
            row.last_error = f"container check failed: {e}"
            row.last_checked_at = datetime.now(UTC)
            db.commit()
            return {"id": row.id, "status": row.status, "detail": row.last_error}
        online = state.get("running", False)
        row.status = "online" if online else "offline"
        row.last_error = None if online else "container not running"
        if state.get("ip_address"):
            row.ip_address = state["ip_address"]
        row.last_checked_at = datetime.now(UTC)
        db.commit()
        return {"id": row.id, "status": row.status, "container_state": state.get("state")}

    online, latency_ms = check_liveness(row.ip_address, row.ssh_port)
    row.status = "online" if online else "offline"
    if not online:
        row.last_error = f"SSH port {row.ssh_port} unreachable"
    row.last_checked_at = datetime.now(UTC)
    db.commit()

    return {"id": row.id, "status": row.status, "latency_ms": latency_ms}


@router.post("/endpoints/{endpoint_id}/start")
def start_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    row = _require_container_endpoint(endpoint_id, db)
    try:
        start_container(row.container_name)
        row.status = "online"
        row.last_error = None
        row.last_checked_at = datetime.now(UTC)
        db.commit()
        return {"id": row.id, "name": row.name, "action": "started"}
    except EndpointManagerError as e:
        raise HTTPException(status_code=502, detail=f"Start failed: {e}")


@router.post("/endpoints/{endpoint_id}/stop")
def stop_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    row = _require_container_endpoint(endpoint_id, db)
    try:
        stop_container(row.container_name)
        row.status = "offline"
        row.last_error = None
        row.last_checked_at = datetime.now(UTC)
        db.commit()
        return {"id": row.id, "name": row.name, "action": "stopped"}
    except EndpointManagerError as e:
        raise HTTPException(status_code=502, detail=f"Stop failed: {e}")


@router.post("/endpoints/{endpoint_id}/restart")
def restart_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    row = _require_container_endpoint(endpoint_id, db)
    try:
        restart_container(row.container_name)
        row.status = "online"
        row.last_error = None
        row.last_checked_at = datetime.now(UTC)
        db.commit()
        return {"id": row.id, "name": row.name, "action": "restarted"}
    except EndpointManagerError as e:
        raise HTTPException(status_code=502, detail=f"Restart failed: {e}")


def _require_container_endpoint(endpoint_id: int, db: Session) -> models.Endpoint:
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if row.backend_type != "container":
        raise HTTPException(
            status_code=400,
            detail="start/stop/restart are only available for container endpoints "
            "(VM lifecycle is managed on the VM host and not exposed here)",
        )
    if not row.container_name:
        raise HTTPException(status_code=400, detail="Endpoint has no container_name")
    return row


@router.post("/endpoints/{endpoint_id}/run-now")
def run_endpoint_now(endpoint_id: int, db: Session = Depends(get_db)):
    """
    The dashboard's per-endpoint 'Run Now': for a container endpoint the manager
    runs the collector inside the container via docker exec; for a VM endpoint the
    orchestrator SSHes in and runs the collector. Either way the collector pushes
    its results to /ingest, then detection runs and a report scoped to this endpoint
    is generated for detections created during THIS run (since `run_started_at`).
    """
    row = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    run_started_at = datetime.now(UTC)

    if row.backend_type == "container":
        scan_result = _run_container_scan(row)
    else:
        scan_result = run_remote_scan(
            ip_address=row.ip_address,
            port=row.ssh_port,
            username=row.ssh_username,
            key_path=row.ssh_key_path,
            remote_collector_path=row.remote_collector_path,
            push_url=BACKEND_PUSH_URL,
            os_type=row.os,
        )
    if not scan_result["success"]:
        row.status = "offline"
        row.last_error = scan_result.get("error") or scan_result.get("stderr") or "Unknown failure — no error captured"
        row.last_checked_at = datetime.now(UTC)
        db.commit()
        return {"endpoint": row.name, "scan": scan_result, "detect_result": None, "report": None}

    row.status = "online"
    row.last_error = None
    row.last_checked_at = datetime.now(UTC)
    row.last_scan_at = datetime.now(UTC)
    db.commit()

    detect_result = run_detection_job(db)
    report_result = generate_report(db, host=row.name, triggered_by="manual", since=run_started_at)

    return {"endpoint": row.name, "scan": scan_result, "detect_result": detect_result, "report": report_result}


def _run_container_scan(row: models.Endpoint) -> dict:
    try:
        result = exec_collector(row.container_name, push_url=CONTAINER_PUSH_URL)
        exit_code = result.get("exit_code")
        success = result.get("success", exit_code == 0 if exit_code is not None else True)
        return {
            "success": bool(success),
            "exit_status": exit_code,
            "output": result.get("output", "")[-4000:],
            "error": None if success else result.get("error") or "collector exited non-zero",
        }
    except EndpointManagerError as e:
        return {"success": False, "error": str(e)}
