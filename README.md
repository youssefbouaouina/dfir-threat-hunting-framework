# dfir-threat-hunting-framework

DFIR / Threat Hunting Framework — centralized endpoint management, DFIR detection,
reporting, and free CI/CD.

Stage project — Youssef Bouaouina & Amen Ben Salah, Esprit (NEXTSTEP).

## What it does

- **Collector agent** collects 6 artifact types from endpoints: processes, network
  connections, persistence entries, scheduled tasks, logs, and file scans (hash + optional
  agent-side YARA).
- **Backend** ingests artifacts, runs the detection pipeline (Sigma-style rules, YARA
  results, known-bad hash matching, network IOC correlation, ATT&CK enrichment), generates
  PDF investigation reports, and serves a dashboard.
- **Endpoint management**: Linux test endpoints can be simulated as unprivileged containers
  and managed from the dashboard (create/start/stop/restart/scan/delete), while Linux and
  Windows VMs remain supported via SSH orchestration.

## Architecture

```
DASHBOARD
    |
BACKEND API (FastAPI)
    |                     \
endpoint-manager       SSH orchestration (paramiko)
(only Docker access)          |
    |                    VM endpoints (linux/windows)
Linux endpoint containers (backend_type="container")   (backend_type="vm")
    |                           |
    +--------> POST /ingest <---+
              |
       detection engine -> SQLite -> reports -> dashboard/API
```

Design documents live in `docs/`:
- `ARCHITECTURE_ANALYSIS.md`, `ARCHITECTURE_DECISION.md`
- `LINUX_CONTAINER_FEASIBILITY.md`, `WINDOWS_CONTAINER_FEASIBILITY.md`
- `ENDPOINT_MANAGEMENT_DESIGN.md`, `CICD_ARCHITECTURE.md`
- `TECHNICAL_REPORT.md` (internship §7 deliverable)
- `DEMO_PRESENTATION.md` (defense outline), `demo_scenario.md` (run-through),
  `RULESET_DOCUMENTATION.md` (YARA + Sigma rules)

## Prerequisites

- Docker with Compose v2 (`docker compose version`)
- Bash (macOS/Linux; Git Bash or WSL on Windows) — needed for `scripts/fetch-stix.sh`
- Python 3.12+ (only for local tooling like `backend/push_samples.py` and unit tests)

## Quick start (fresh clone)

```bash
# 1. Clone
git clone <repo-url>
cd dfir-threat-hunting-framework

# 2. Environment configuration
cp backend/.env.example backend/.env

# 3. ATT&CK/STIX data (needed for ATT&CK enrichment + attack-chain visualization)
bash scripts/fetch-stix.sh

# 4. Build and start
docker compose up --build -d

# 5. Verify
curl http://127.0.0.1:8000/health          # -> {"status":"ok"}
curl http://127.0.0.1:8000/scheduler/status # -> 3 scheduler jobs
open  http://127.0.0.1:8000/dashboard
```

## Creating endpoints

### Container endpoint (Linux, simulated, full lifecycle)

From the dashboard **Add Endpoint** form or the API:

```bash
curl -X POST http://127.0.0.1:8000/endpoints \
  -H "Content-Type: application/json" \
  -d '{
        "name": "linux-test-01",
        "os": "linux",
        "backend_type": "container",
        "image": "ghcr.io/<owner>/framework-endpoint-linux:latest"
      }'
```

The image can be omitted — the endpoint image built by this repo (the `endpoint-linux`
compose service) is used by default. The backend asks the `endpoint-manager` service to
create the container, then registers it. Start / Stop / Restart / Scan / Delete it from
the dashboard afterwards.

### VM endpoint (Linux or Windows, SSH-managed)

```bash
curl -X POST http://127.0.0.1:8000/endpoints \
  -H "Content-Type: application/json" \
  -d '{
        "name": "ns-ubuntu-server",
        "ip_address": "192.168.50.129",
        "os": "linux",
        "ssh_port": 22,
        "ssh_username": "youssef",
        "ssh_key_path": "/app/ssh_keys/dfir_orchestrator_key",
        "remote_collector_path": "/home/youssef/collector",
        "backend_type": "vm"
      }'
```

The collector runs natively on the VM. Windows VMs use `os_type="windows"` and the same SSH
transport. Full VM setup in `AUDIT_AND_SETUP_GUIDE.md`.

## Demo / evidence

A full, reproducible end-to-end run (fresh clone → endpoint → detection → report) is in
`docs/demo_scenario.md`. An attack simulation using the EICAR test file is documented there
too.

## Testing

```bash
# unit tests (backend)
cd backend && python -m pytest tests/ -q

# lint
ruff check backend endpoint-manager backend/tests

# compose validation
docker compose config -q

# integration lifecycle test (needs a running compose stack — see note below)
bash tests/integration/run_integration.sh
```

The integration test needs the compose stack up first (`docker compose up -d --build`).
CI builds and runs it on every push.

## CI/CD

`.github/workflows/ci-cd.yml` runs on pushes/PRs to `youssef_V2` and `main`:

1. Lint (ruff) + import sanity + rule validation
2. Backend unit tests (pytest)
3. Build backend + endpoint images (tagged with the git SHA)
4. Trivy security scan
5. Integration test: backend + endpoint-manager + a real Linux endpoint container
6. Publish to ghcr.io on main

Cost: **$0/month** (GitHub Actions on a public repo + ghcr.io + open-source tools).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker compose up` fails with `env file .../.env not found` | run `cp backend/.env.example backend/.env` |
| Dashboard shows raw ATT&CK names everywhere / enrichment Nones | run `bash scripts/fetch-stix.sh` and restart the backend |
| Endpoint container won't start | ensure the `endpoint-linux` image is built (`docker compose build endpoint-linux`) |
| Port 8000 busy | set another host port in a `docker-compose.override.yml`, or stop the conflicting service |