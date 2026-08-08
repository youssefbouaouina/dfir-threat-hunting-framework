# Phase 5 — Endpoint Management Design

Extends the existing `Endpoint` registry. Additive only — the VM/SSH path is unchanged.

## 1. Data model (extensions to `backend/models.py`)

Existing columns stay. New nullable columns:

| Column | Type | Meaning |
|---|---|---|
| `backend_type` | String default `"vm"` | `vm` = SSH-managed (Linux or Windows), `container` = Docker-managed Linux |
| `container_name` | String nullable | Docker container name for `container` endpoints |
| `image` | String nullable | image reference for `container` endpoints |
| `registration_status` | String default `"registered"` | `registered` / `pending` / `failed` |
| `agent_version` | String nullable | collector version last seen |
| `last_heartbeat` | DateTime nullable | last successful `POST /ingest` for this endpoint's host |
| `last_ip_address` | String nullable | last IP seen from ingest (helps containers) |

`ensure_schema()` in `main.py` gains idempotent `ALTER TABLE endpoints ADD COLUMN ...`
statements for each new column (same pattern as `last_error`).

## 2. Backend APIs

New/changed (all backward compatible):

| Method | Path | Behavior |
|---|---|---|
| POST | `/endpoints` | `backend_type="vm"` → register as today. `backend_type="container"` → asks endpoint-manager to create the container, then registers. |
| GET | `/endpoints` | extended dict incl. backend_type, status, registration_status, agent_version, last_heartbeat |
| GET | `/endpoints/{id}` | single endpoint details |
| POST | `/endpoints/{id}/start` | container only → endpoint-manager start; VM → 400 |
| POST | `/endpoints/{id}/stop` | container only → endpoint-manager stop; VM → 400 |
| POST | `/endpoints/{id}/restart` | container only → endpoint-manager restart; VM → 400 |
| POST | `/endpoints/{id}/status` | container → docker state; VM → liveness check (existing) |
| POST | `/endpoints/{id}/run-now` | container → docker exec collector; VM → SSH (existing) |
| POST | `/endpoints/{id}/check` | unchanged (VM liveness); container → container running? |
| DELETE | `/endpoints/{id}` | `?remove_container=true` also removes the container |
| POST | `/ingest` | also updates matching endpoint's `last_heartbeat`, `agent_version`, `last_ip_address`, sets status `online` |

## 3. Endpoint lifecycle (container endpoints)

```
CREATE ─ POST /endpoints {backend_type:"container", name, image, config}
  → endpoint-manager.create() → container created (unprivileged) → row inserted (registration_status)
REGISTER ─ row exists; registration_status="registered"
START ─ endpoint-manager.start()
HEARTBEAT ─ collector inside container pushes /ingest on a loop → backend updates last_heartbeat
COLLECT ─ collector runs (idle loop + on-demand via exec)
SEND ─ POST /ingest to http://backend:8000
SCAN ─ POST /endpoints/{id}/run-now → endpoint-manager.exec(collector --push-url http://backend:8000)
RESULT ─ detection + report generated; dashboard shows artifacts/detections
STOP ─ endpoint-manager.stop()
RESTART ─ endpoint-manager.restart(); verify recovery via status + heartbeat
REMOVE ─ DELETE /endpoints/{id}?remove_container=true → container removed + row deleted
```

## 4. Container idle loop / heartbeat

The endpoint image runs an entrypoint that:
1. waits for the backend to be reachable (`/health`),
2. registers nothing itself (the backend creates it; the name is passed via env),
3. starts systemd services (base image) then runs the collector once at boot
   (`--push-url http://backend:8000`) and repeats on an interval (`ENDPOINT_COLLECT_INTERVAL`),
   which serves as the heartbeat (each `/ingest` refreshes `last_heartbeat`).

On-demand scans are separate `docker exec` runs (the `run-now` path), so a scan never
depends on the idle loop's timing.

## 5. Dashboard interactions

- **Add Endpoint** form: Name, Type (`container` | `vm`), OS, Image (containers), plus
  SSH fields when type=vm. Button `CREATE ENDPOINT`.
- **Endpoint list** columns: Endpoint · OS · Type · Status · Last Seen (heartbeat) · actions.
- **Actions** (container): Start, Stop, Restart, Scan, Edit, Delete.
- **Actions** (vm): Check, Scan, Edit, Delete (no unsafe VM start/stop).
- **Details view**: config, container state, last heartbeat/scan/error, agent version,
  plus a link to the endpoint's collected artifacts (`/artifacts?host=<name>`).

## 6. Collector registration / heartbeat

- Registration is **backend-initiated** (matches the existing registry + orchestration
  model). The container image does not self-register.
- Heartbeat = backend updates `endpoint.last_heartbeat` whenever `/ingest` arrives whose
  `host` matches a registered endpoint name (or `last_ip_address` matches). `agent_version`
  is parsed from a lightweight `agent_version` field the collector includes in a heartbeat
  artifact type (optional; non-breaking if absent).

## 7. Backend ↔ endpoint-manager interface

`backend/container_manager_client.py` wraps the endpoint-manager HTTP API with a shared
secret header. Operations: `create(name, image, env, network)`, `start`, `stop`,
`restart`, `status`, `exec`, `remove`, `list`. All failures map to structured errors
surfaced on the endpoint row (`last_error`) — no silent 500s.
