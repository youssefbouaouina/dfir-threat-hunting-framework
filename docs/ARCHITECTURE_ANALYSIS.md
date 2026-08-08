# Phase 1 — Architecture Analysis

**DFIR Threat Hunting Framework** — analysis of the existing system before adding
containerized endpoint management + CI/CD. No code was changed to produce this document.

## 1. Component map

| Component | Tech | Location | Runs | Status |
|---|---|---|---|---|
| Backend | FastAPI + SQLAlchemy(SQLite) + APScheduler + reportlab + paramiko | `backend/` | Docker container `dfir_backend_V5` | WORKING |
| Collector agent | Python (psutil, requests) | `collector/` | Native on endpoints (VM) | WORKING |
| Detection engine | Sigma-style YAML + YARA results + hash + IOC correlation + ATT&CK | `backend/` | Inside backend | WORKING |
| Dashboard | Jinja2 server-rendered | `backend/dashboard.py` + `templates/dashboard.html` | Served by backend | WORKING |
| Legacy `detection/` | duplicate old engine | `detection/` | not used by compose/CI | legacy |
| CI | GitHub Actions | `.github/workflows/ci-cd.yml` | GitHub hosted | present, minimal |

## 2. Data flow (as it works today)

```
Collector (native on endpoint)                    Backend (Docker)
  processes/network/persistence/                    POST /ingest
  scheduled_tasks/logs/file_scan                    └> SQLite artifacts
        │  POST /ingest (--push-url)                     │
        ▼                                                ▼
  (orchestrator SSH: run_remote_scan)  →  run_detection_job()  → SQLite detections
                                                          │
                                                          ▼
                                              generate_report() → reports/*.pdf
                                                          │
                                                          ▼
                                              Dashboard + REST API
```

- Data pushes **endpoint → backend** via `POST /ingest`.
- Control flows **backend → endpoint** via SSH (paramiko): liveness (TCP), `run-now`,
  hourly orchestration cycle.
- One SSH transport for Windows and Linux endpoints; `os_type` on the endpoint record
  switches command syntax.

## 3. Current capability matrix

| Capability | Where | Works today | Notes |
|---|---|---|---|
| Endpoint registration | `POST /endpoints` | yes | SSH-based registry, no container support |
| Endpoint list | `GET /endpoints` | yes | |
| Endpoint delete | `DELETE /endpoints/{id}` | yes | metadata only |
| Endpoint liveness | `POST /endpoints/{id}/check` + scheduler sweep | yes | TCP check of SSH port |
| Endpoint scan | `POST /endpoints/{id}/run-now` | yes | SSH in, run collector, detect, report |
| Start / Stop / Restart endpoint | — | no | nothing to control today (VMs) |
| Heartbeat | — | no | status derived from TCP liveness + last_scan_at |
| Container creation/control | — | no | **new** |
| Collect 6 artifact types | `collector/` | yes | processes, network, persistence, scheduled_tasks, logs, file_scan |
| Detection (Sigma/YARA/hash/IOC) | `backend/detection_routes.py` | yes | |
| PDF reporting | `backend/reports.py` | yes | 6 sections |
| Dashboard | `GET /dashboard` | yes | endpoints + Run Now per endpoint |
| Unit tests | — | no | CI only does lint/import/rule validation |
| Integration tests | — | no | **new** |
| Container image builds | Dockerfile (backend) | yes | pushed to Docker Hub on main |
| Security scanning | — | no | Docker Scout used ad-hoc only |
| Versioned images | Docker Hub | partial | `latest` + sha on main |

## 4. API contract inventory (must not break)

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | liveness |
| POST | `/ingest` | artifact batch |
| GET | `/artifacts` | filter host / artifact_type / limit |
| GET | `/hosts` | hosts that reported |
| POST | `/detect` | manual detection run |
| GET | `/detections` | list detections |
| GET | `/detections/summary` | dashboard aggregates |
| GET | `/scheduler/status` | scheduler state |
| POST/GET/DELETE | `/endpoints`, `/endpoints/{id}` | registry + delete |
| POST | `/endpoints/{id}/check` | liveness check |
| POST | `/endpoints/{id}/run-now` | scan + detect + report |
| POST | `/reports/generate` | generate PDF |
| POST | `/reports/run-now` | detect + report |
| GET | `/reports`, `/reports/{run_id}/download` | history / PDF |
| GET | `/dashboard` | HTML console |

## 5. Do-not-break constraints

1. VM/SSH endpoint path must keep working unchanged (Ubuntu VM + Windows VM today).
2. Detection engine, reporting, dashboard queries, scheduler jobs stay intact.
3. All new DB columns are additive/nullable with an idempotent startup migration.
4. `POST /endpoints` payload stays backward compatible (new optional fields only).
5. No new mandatory dependencies inside the hardened backend image unless required.

## 6. What this phase adds (overview)

- A generic endpoint model (`vm` | `container`).
- An isolated `endpoint-manager` service as the only component with Docker access.
- A Linux endpoint container image (systemd-based) for simulated endpoints.
- Dashboard lifecycle control for container endpoints.
- Pytest unit/integration suites and a full GitHub Actions pipeline (youssef_V2 + main).
