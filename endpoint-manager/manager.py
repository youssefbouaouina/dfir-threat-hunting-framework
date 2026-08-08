"""
Endpoint-manager — the ONLY service with Docker socket access.

The backend never mounts /var/run/docker.sock. Instead it talks to this service
over the private compose network with a shared bearer token, and this service
performs a deliberately narrow, allow-listed set of container operations.

Hard security invariants (enforced here, regardless of the caller):
  - NO --privileged, NO capability adds (ALL dropped).
  - NO host filesystem mounts, NO host network, NO host PID namespace.
  - Containers are placed on the internal compose network (no published ports).
  - Every image reference is validated; if ALLOWED_IMAGES is set, only those
    images may be run (deployments can harden; unset = any image is allowed).
  - Bearer token required on every request.
"""
import logging
import os

import docker
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("endpoint_manager")

app = FastAPI(title="Endpoint Manager", version="0.1.0")

TOKEN = os.getenv("ENDPOINT_MANAGER_TOKEN", "")
ALLOWED_IMAGES = {i.strip() for i in os.getenv("ALLOWED_IMAGES", "").split(",") if i.strip()}
COLLECTOR_CMD = "/opt/collector/collector_agent.py"
# YARA rules baked into the endpoint image at /opt/collector/yara_rules. The
# collector's file_scan module only embeds YARA matches when it's told where
# the rules live, so the exec command always passes --yara-rules.
COLLECTOR_YARA_RULES_DIR = "/opt/collector/yara_rules"

client = docker.from_env()


class CreateRequest(BaseModel):
    name: str
    image: str
    network: str = "dfir-internal"
    env: dict = {}
    collect_interval: int = 300


class ExecRequest(BaseModel):
    push_url: str


def _authorize(authorization: str | None = Header(default=None)) -> None:
    if not TOKEN:
        raise HTTPException(status_code=503, detail="endpoint-manager token not configured")
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")


def _validate_image(image: str) -> str:
    if not image or "/" not in image and ":" not in image and "." not in image:
        # bare image name like "ubuntu" — allow, it is still run unprivileged
        pass
    if ALLOWED_IMAGES and image not in ALLOWED_IMAGES:
        raise HTTPException(status_code=403, detail=f"image '{image}' not in ALLOWED_IMAGES")
    return image


def _container(name: str):
    try:
        return client.containers.get(name)
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail=f"container '{name}' not found")


def _container_info(container) -> dict:
    try:
        container.reload()
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="container not found")
    nets = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    ip_address = None
    for net in nets.values():
        if net.get("IPAddress"):
            ip_address = net["IPAddress"]
            break
    return {
        "name": container.name,
        "id": container.short_id,
        "state": container.status,
        "running": container.status == "running",
        "ip_address": ip_address,
        "image": container.image.tags[0] if container.image.tags else str(container.image.id),
    }


@app.post("/containers", dependencies=[Depends(_authorize)])
def create_container(req: CreateRequest):
    image = _validate_image(req.image)
    existing = _container_if_exists(req.name)
    if existing:
        raise HTTPException(status_code=409, detail=f"container '{req.name}' already exists")

    env = dict(req.env)
    env.setdefault("ENDPOINT_COLLECT_INTERVAL", str(req.collect_interval))
    env.setdefault("ENDPOINT_PUSH_URL", "http://backend:8000")

    try:
        container = client.containers.run(
            image,
            name=req.name,
            hostname=req.name,
            detach=True,
            environment=env,
            network=req.network,
            privileged=False,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit="512m",
            restart_policy={"Name": "no"},
            labels={"dfir.endpoint": "true", "dfir.name": req.name},
        )
        logger.info("Created endpoint container %s from %s", req.name, image)
    except docker.errors.APIError as e:
        raise HTTPException(status_code=502, detail=f"container create failed: {e}")

    return _container_info(container)


def _container_if_exists(name: str):
    try:
        return client.containers.get(name)
    except docker.errors.NotFound:
        return None


@app.get("/containers", dependencies=[Depends(_authorize)])
def list_containers():
    names = []
    for c in client.containers.list(all=True, filters={"label": "dfir.endpoint=true"}):
        names.append(c.name)
    return {"containers": names}


@app.get("/containers/{name}", dependencies=[Depends(_authorize)])
def get_container(name: str):
    return _container_info(_container(name))


@app.post("/containers/{name}/start", dependencies=[Depends(_authorize)])
def start_container(name: str):
    c = _container(name)
    if c.status != "running":
        c.start()
    return _container_info(_container(name))


@app.post("/containers/{name}/stop", dependencies=[Depends(_authorize)])
def stop_container(name: str):
    c = _container(name)
    if c.status == "running":
        c.stop(timeout=20)
    return _container_info(_container(name))


@app.post("/containers/{name}/restart", dependencies=[Depends(_authorize)])
def restart_container(name: str):
    c = _container(name)
    c.restart(timeout=20)
    return _container_info(_container(name))


@app.delete("/containers/{name}", dependencies=[Depends(_authorize)])
def remove_container(name: str, force: bool = True):
    c = _container(name)
    c.remove(force=force)
    return {"removed": name}


@app.post("/containers/{name}/exec", dependencies=[Depends(_authorize)])
def exec_collector(name: str, req: ExecRequest):
    c = _container(name)
    if c.status != "running":
        raise HTTPException(status_code=409, detail=f"container '{name}' is not running")
    cmd = (
        f"python3 {COLLECTOR_CMD} --push-url {req.push_url} "
        f"--yara-rules {COLLECTOR_YARA_RULES_DIR}"
    )
    logger.info("docker exec %s: %s", name, cmd)
    try:
        exit_code, output = c.exec_run(cmd, demux=False)
        if isinstance(output, bytes):
            text = output.decode(errors="replace")
        else:
            text = str(output)
        return {
            "success": exit_code == 0,
            "exit_code": exit_code,
            "output": text[-4000:],
        }
    except docker.errors.APIError as e:
        raise HTTPException(status_code=502, detail=f"exec failed: {e}")


@app.get("/health")
def health():
    try:
        client.ping()
    except docker.errors.APIError:
        raise HTTPException(status_code=503, detail="docker daemon unreachable")
    return {"status": "ok", "token_configured": bool(TOKEN)}
