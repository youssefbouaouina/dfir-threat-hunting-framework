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
- **Endpoint management** (this phase): Linux test endpoints can be simulated as
  unprivileged containers and managed from the dashboard (create/start/stop/restart/scan/
  delete), while Linux and Windows VMs remain supported via SSH orchestration.

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
- `ARCHITECTURE_ANALYSIS.md`
- `LINUX_CONTAINER_FEASIBILITY.md`
- `WINDOWS_CONTAINER_FEASIBILITY.md`
- `ARCHITECTURE_DECISION.md`
- `ENDPOINT_MANAGEMENT_DESIGN.md`
- `CICD_ARCHITECTURE.md`

## Requirements

- Docker with Compose
- Python 3.12+ (only for local tooling like `push_samples.py`)

## Quick start

```bash
# 1. Clone and configure
git clone <repo-url>
cd dfir-threat-hunting-framework

# 2. Create backend/.env (optional keys; ABUSEIPDB is optional)
cp backend/.env.example backend/.env   # if provided, otherwise create:
# ABUSEIPDB_API_KEY=...
# DETECTION_INTERVAL_SECONDS=30

# 3. (Optional, VM endpoints only) place SSH keys
#    backend/ssh_keys/dfir_orchestrator_key  (+ .pub)

# 4. Build and start
docker compose up --build -d

# 5. Verify
curl http://127.0.0.1:8000/health          # {"status":"ok"}
curl http://127.0.0.1:8000/scheduler/status
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

The backend asks the `endpoint-manager` service to create the container, then registers
it. You can then Start / Stop / Restart / Scan / Delete it from the dashboard.

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

The collector runs natively on the VM (see `AUDIT_AND_SETUP_GUIDE.md` for full VM setup).
Windows VMs use `os_type="windows"` and the same SSH transport.

## Testing

```bash
# unit tests (backend)
cd backend && python -m pytest tests/ -q

# lint
ruff check backend collector

# integration lifecycle test (needs docker compose)
bash tests/integration/run_integration.sh
```

## CI/CD

`.github/workflows/ci-cd.yml` runs on pushes/PRs to `youssef_V2` and `main`:

1. Lint (ruff) + import sanity + rule validation
2. Backend unit tests (pytest)
3. Build backend + endpoint images (tagged with the git SHA)
4. Trivy security scan
5. Integration test: backend + endpoint-manager + a real Linux endpoint container —
   create endpoint → heartbeat → scan → ingest → detect → report → stop → start → recovery
6. Publish to ghcr.io on `main` (SHA + convenience tag)

Cost: **$0/month** (GitHub Actions on a public repo + ghcr.io + open-source tools).
