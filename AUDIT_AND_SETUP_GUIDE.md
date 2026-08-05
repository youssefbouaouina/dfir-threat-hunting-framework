# DFIR & Threat Hunting Framework — Setup, Usage & Audit Report

**Scope:** End-to-end implementation guide, architecture/usage documentation, and the
results of a full pipeline audit performed against the current deployment
(backend in Docker on the Windows host at `192.168.50.1`, collector running natively
on the Ubuntu VM `ns-ubuntu-server` at `192.168.50.129`).

Audit date: 2026-08-05.

> **Fix status (2026-08-05):** all seven bugs from §4 (BUG-1..BUG-7) have
> been applied as documented. The §5 pre-flight checklist items are now
> complete — no code changes are required before running the system.

---

## Table of Contents

1. [How the project works (architecture)](#1-architecture--how-it-works)
2. [Implementing the project from scratch](#2-implementing-from-scratch)
3. [Using the system](#3-usage-guide)
4. [Audit report](#4-audit-report)
5. [Running the system from a clean start](#5-clean-start-run-steps)
6. [Remaining issues & recommendations](#6-remaining-issues--recommendations)

---

## 1. Architecture & How It Works

### 1.1 Component map

| Component | Where it runs | Role |
|---|---|---|
| **Backend** (FastAPI + SQLAlchemy + SQLite) | Docker container `dfir-backend` | Ingest API, detection pipeline, PDF reporting, dashboard, scheduler, SSH endpoint orchestration |
| **Collector agent** | Natively on each endpoint (Windows/Linux VM) | Collects 6 artifact types, pushes them to the backend `/ingest` |
| **Detection engine** | Inside the backend container | Sigma-style rules, YARA results, known-bad hash matching, network IOC correlation |
| **Dashboard** | Served by the backend | HTML console for status, detections, endpoints, reports |

Only the backend is containerized. The collector is NOT containerized on purpose —
a container would only see its own namespace's processes, not the real host's.

### 1.2 Data flow (text diagram)

```
Ubuntu VM (ns-ubuntu-server, 192.168.50.129)
    │  collector_agent.py --push-url http://192.168.50.1:8000
    │  (processes, network, persistence, scheduled_tasks, logs, file_scan)
    │
    ▼  POST /ingest   (each artifact type = one JSON batch)
Docker Backend (192.168.50.1:8000, published from container:8000)
    │
    ▼
SQLite  (hosts, artifacts)          <-- raw collected data
    │
    ▼  run_detection_job()  (on a 30s timer, or manual POST /detect)
SQLite  detections                  <-- matched findings, enriched with ATT&CK
    │
    ▼  generate_report() (manual "Run Now" or after each orchestration cycle)
reports/  *.pdf                      <-- investigation reports (reportlab)
    │
    ▼
Dashboard (GET /dashboard) + REST API
```

### 1.3 Communication model

- **Enrollment / orchestration direction:** The backend holds a registry of known
  endpoints (SSH details) and reaches **out** to them (paramiko). This is a deliberate
  pivot from the original "self-enrolling agent" plan: manual per-endpoint triggering
  ("Run Now") and online/offline status both require the backend to reach the endpoint.
- **Data direction:** The endpoint **pushes** collected data to the backend via
  `POST /ingest`. No file copying, no `sample_data/` relay in the live path
  (`push_samples.py` is only for loading committed sample data manually).
- One SSH transport is used for both Windows and Linux endpoints (OpenSSH Server is a
  built-in Windows optional feature); `os_type` on the endpoint record controls the
  command syntax (venv `python` vs `python3`, path separators).

### 1.4 Background scheduler (APScheduler)

| Job | Interval | What it does |
|---|---|---|
| `detection_cycle` | `DETECTION_INTERVAL_SECONDS` (default 60, deployed 30) | Runs `run_detection_job()` over every unprocessed artifact; marks them `processed=1` |
| `liveness_cycle` | `LIVENESS_INTERVAL_SECONDS` (default 60) | TCP-checks each enabled endpoint's SSH port; updates online/offline status |
| `orchestration_cycle` | `ORCHESTRATION_INTERVAL_SECONDS` (default 3600) | For every enabled + online endpoint: SSH in, run the collector (which pushes its own results), then detect + report |

Status is visible at `GET /scheduler/status`.

### 1.5 Artifact schema

Every collector artifact is wrapped in the standard envelope (as intended by `SCHEMA.md`):

```json
{
  "host": "ns-ubuntu-server",
  "os": "linux",
  "collected_at": "2026-08-05T09:13:57Z",
  "artifact_type": "process | network | persistence | scheduled_task | log_event | file_scan",
  "data": { "...artifact-specific fields..." }
}
```

The `processed` flag on each stored artifact keeps detection from re-analyzing the
same row twice (`processed=0` → analyzed → `processed=1`).

### 1.6 Detection pipeline

Order of operations in `run_detection_job()` (`backend/detection_routes.py`):

1. **Sigma-style behavioral rules** — `backend/sigma_rules/*.yml`, matched against
   process/persistence/scheduled_task/network artifacts (`artifact_type` + `field`
   / `field_contains` conditions).
2. **YARA results** — file_scan artifacts already embed `yara_matches` (scanned
   agent-side); each match becomes a detection.
3. **Known-bad hash matching** — `file_scan.sha256` vs `backend/iocs/known_bad_hashes.txt`.
4. **Network IOC correlation** — remote IPs vs `backend/iocs/malicious_ips.txt`
   (offline) + best-effort live AbuseIPDB lookup (soft-fails if unconfigured/unreachable).

Every detection is persisted with ATT&CK technique enrichment
(`backend/attck_mapper.py`, local STIX dataset, soft-fails if the dataset is absent).

---

## 2. Implementing From Scratch

### 2.1 Backend (Docker)

Prerequisites on the host: Docker with Docker Compose, Python 3.12+ (only needed for
the optional local tooling like `push_samples.py`).

1. Clone the repository:
   ```bash
   git clone <repo-url> dfir-threat-hunting-framework
   cd dfir-threat-hunting-framework
   ```

2. Create `backend/.env` (used by `docker-compose.yml` via `env_file`):
   ```bash
   ABUSEIPDB_API_KEY=<your-abuseipdb-key>
   DETECTION_INTERVAL_SECONDS=30
   ```
   (Only `ABUSEIPDB_API_KEY` and `DETECTION_INTERVAL_SECONDS` are consumed today.
   `LIVENESS_INTERVAL_SECONDS`, `ORCHESTRATION_INTERVAL_SECONDS` and
   `BACKEND_PUSH_URL` have defaults in `backend/scheduler.py` / `backend/endpoints.py`.)

3. Place the SSH private key that will log into endpoints:
   ```
   backend/ssh_keys/dfir_orchestrator_key      (private key, keep permissions tight)
   backend/ssh_keys/dfir_orchestrator_key.pub
   ```
   The compose file bind-mounts `./backend/ssh_keys` read-only to `/app/ssh_keys` in the
   container, so endpoint records reference paths like `/app/ssh_keys/dfir_orchestrator_key`.

4. Build and start:
   ```bash
   docker compose up --build -d
   ```

5. Verify:
   ```bash
   curl http://127.0.0.1:8000/health        # -> {"status":"ok"}
   curl http://127.0.0.1:8000/scheduler/status
   open http://127.0.0.1:8000/docs          # interactive API docs
   open http://127.0.0.1:8000/dashboard     # investigation console
   ```

Notes:
- SQLite DB lives in the named volume `dfir-data` (`/app/data/dfir.db`), reports in
  `dfir-reports` (`/app/reports`) — both survive `docker compose down`.
- On first run the tables are auto-created (`create_all`). **There is no automatic
  migration** for later model changes (see BUG-6 in the audit) — if you change a model,
  you must either recreate the volume or apply the ALTER manually.
- The published port `8000` must be reachable from your endpoint's subnet on the host
  (firewall rule for inbound 8000).

### 2.2 Collector on an endpoint (Ubuntu VM)

On the endpoint (user `youssef` in this deployment):

```bash
# 1. Get the collector code onto the endpoint
mkdir -p ~/collector
# copy the collector/ folder from the repo (scp/rsync) to ~/collector

# 2. Create a venv and install dependencies
cd ~/collector
python3 -m venv venv
venv/bin/pip install -r requirements.txt
# requirements.txt must contain psutil, requests (and pywin32 on Windows)

# 3. Install the backend's SSH public key for password-less login
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "<content of dfir_orchestrator_key.pub>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Smoke-test collection locally (should print per-module record counts and write files
under `./output/<date>_<hostname>/`):

```bash
cd ~/collector && venv/bin/python3 collector_agent.py --only processes,network
```

> **Elevation:** run as root/sudo (or Administrator on Windows) for full visibility of
> processes/connections/logs owned by other users. As a non-root user some sources are
> skipped or error — see BUG-1/BUG-3 in the audit.

### 2.3 Enroll the endpoint

Register the endpoint with the backend:

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
        "enabled": true
      }'
```

- `name` should match the collector's hostname (`socket.gethostname()`) so report
  host-filtering lines up with detection records (see observation in §4.8).
- `remote_collector_path` is where `collector_agent.py` + `venv/` live on the endpoint.
  The orchestrator runs `cd <path> && <path>/venv/bin/python3 collector_agent.py --push-url <BACKEND_PUSH_URL>`.

Verify the endpoint appears:

```bash
curl http://127.0.0.1:8000/endpoints
```

The liveness sweep (every 60s) will mark it online if SSH port 22 is reachable.

### 2.4 Network prerequisites summary

| Path | Requirement |
|---|---|
| VM → backend host `192.168.50.1:8000` | VM can reach host IP; host firewall allows inbound 8000 |
| Host/backend → VM `192.168.50.129:22` | SSH server running; `authorized_keys` has the orchestrator key; key permissions valid |
| Backend → AbuseIPDB (optional) | Outbound HTTPS + valid `ABUSEIPDB_API_KEY` for the live IOC layer |

---

## 3. Usage Guide

### 3.1 API endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness check (used by the Docker healthcheck) |
| POST | `/ingest` | Accepts a JSON array of artifacts (one collector output file) |
| GET | `/artifacts?host=&artifact_type=&limit=` | Query stored artifacts |
| GET | `/hosts` | List hosts that have ever reported in |
| POST | `/detect` | Manually run the detection pipeline on unprocessed artifacts |
| GET | `/detections?host=&severity=&limit=` | List persisted detections |
| GET | `/detections/summary` | Aggregates for the dashboard |
| GET | `/scheduler/status` | Scheduler state + next run times |
| POST | `/endpoints` | Register an endpoint |
| GET | `/endpoints` | List registered endpoints |
| DELETE | `/endpoints/{id}` | Remove an endpoint |
| POST | `/endpoints/{id}/check` | On-demand liveness check |
| POST | `/endpoints/{id}/run-now` | SSH in, run collector, detect, generate per-endpoint report |
| POST | `/reports/generate?host=` | Generate a PDF report from current detections |
| POST | `/reports/run-now` | Run detection, then generate a report (dashboard "Run Investigation Now") |
| GET | `/reports` | Report history |
| GET | `/reports/{report_id}/download` | Download a report PDF |
| GET | `/dashboard` | HTML console |

### 3.2 Dashboard

Open `http://<host>:8000/dashboard`. It shows:
- Endpoints monitored / artifacts collected / total detections / reports on record.
- Severity signal bar (critical/high/medium/low/unknown).
- ATT&CK technique coverage.
- Registered endpoints with status badges (online/offline/unknown) and per-endpoint **Run Now**.
- Recent detections and report history with **Download PDF** links.
- A global **Run Investigation Now** button (POST `/reports/run-now`).

### 3.3 Loading committed sample data

To replay the bundled sample data into the backend (useful for demos without a live VM):

```bash
# from backend/
python push_samples.py ../sample_data/2026-07-29_win10-vm01 --url http://127.0.0.1:8000
python push_samples.py ../sample_data/2026-07-29_ns-ubuntu-server --url http://127.0.0.1:8000
```

Then run detection and generate a report:

```bash
curl -X POST http://127.0.0.1:8000/detect
curl -X POST "http://127.0.0.1:8000/reports/run-now"
```

### 3.4 Manual end-to-end run against a live endpoint

1. Ensure backend is up: `curl http://127.0.0.1:8000/health`
2. Trigger a scan + detect + report for one endpoint:
   ```bash
   curl -X POST http://127.0.0.1:8000/endpoints/1/run-now
   ```
3. Confirm ingested artifacts:
   ```bash
   curl "http://127.0.0.1:8000/artifacts?host=ns-ubuntu-server&limit=500"
   curl "http://127.0.0.1:8000/detections"
   ```
4. Refresh `/dashboard` and download the new report.

### 3.5 Collector CLI

```bash
python collector_agent.py                                  # collect everything
python collector_agent.py --only processes,network         # subset
python collector_agent.py --output /tmp/dfir_out           # custom output dir
python collector_agent.py --push-url http://192.168.50.1:8000   # collect + push live
python collector_agent.py --yara-rules /path/to/rules      # enable agent-side YARA
```

Output is written to `./output/<YYYY-MM-DD>_<hostname>/*.json`.

---

## 4. Audit Report

**Method:** Inspected all source/config/Docker files; examined container state, logs,
the SQLite volume, and the endpoint over SSH; executed the collector modules directly on
the VM and drove the backend APIs/logs to verify behavior. No fixes were applied during
the audit; recommended fixes are documented below and left unapplied per the owner's
decision.

### Verification performed (evidence summary)

| Test | Result |
|---|---|
| Docker container state | `dfir-backend` **exited (137)** — force-stopped, not OOM (`OOMKilled: false`) |
| Container health/logs | `/health` 200; `/ingest` 200 (multiple); `/dashboard` 200 after 08:14; scheduler jobs running |
| DB volume contents | 2 hosts, 2,290 artifacts, 2 detections, 6 reports, 1 endpoint (`ns-ubuntu-server`, 192.168.50.129, user `youssef`) |
| Host network | Host IP is `192.168.50.1` → matches `BACKEND_PUSH_URL` default `http://192.168.50.1:8000` |
| VM reachability | TCP 22 open; SSH auth with `dfir_orchestrator_key` succeeds |
| VM collector install | Present at `/home/youssef/collector`, venv Python 3.14.4, `requests` installed ad-hoc, `yara` **not** installed |
| VM → backend push | **Works** — 1434 artifacts ingested 2026-08-05 09:13:58 (processes+network); file_scan/log_event pushed 08:17 |
| Individual collector modules (live, non-root) | `processes` ~0.1s/222 records, `network` ~0.0s/11 records, `persistence` **PermissionError**, `scheduled_tasks` **PermissionError**, `logs` **hangs in ausearch** (RC=124 after 20s) |
| SSH timeout enforcement | `exec_command(timeout=8)` + `recv_exit_status()` blocked the full 60s → timeout **not enforced** |

---

### BUG-1 — CRITICAL: Collector hangs forever in `ausearch`

- **Component:** `collector/modules/logs.py` `_collect_linux_logs()` (ausearch call, ~line 99).
- **Severity:** CRITICAL — prevents the collector from ever finishing a full run, which
  stalls automated and manual scans and causes data loss for every module after `logs`.
- **Evidence:** As non-root `youssef`, `ausearch -k exec_tracking -ts recent` blocks
  indefinitely (`timeout 20` → RC=124). `/var/log/audit/audit.log` exists but is not
  readable by non-root; instead of failing fast, `ausearch` waits on the audit pipe. The
  09:13 orchestration cycle pushed only processes+network, then stalled at the logs stage
  for the rest of the hour (container log shows no orchestration completion/failure line).
- **Root cause:** `subprocess.check_output([...])` has no timeout, and the orchestrator's
  SSH timeout is not enforced on top (see BUG-2), so the hang propagates indefinitely.
- **Recommended minimal fix:**
  ```python
  try:
      output = subprocess.check_output(
          ["ausearch", "-k", "exec_tracking", "-ts", "recent"],
          text=True, stderr=subprocess.DEVNULL, timeout=5,
      )
      if output.strip():
          data = {"source": "auditd", "key": "exec_tracking", "raw": output[-4000:]}
          records.append(wrap_artifact("log_event", data))
  except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
      pass
  ```

### BUG-2 — CRITICAL: Orchestrator SSH timeout is not enforced

- **Component:** `backend/endpoint_orchestrator.py` `run_remote_scan()` (`stdout.channel.recv_exit_status()`).
- **Severity:** CRITICAL — a slow/hung collector (BUG-1) hangs the orchestration cycle
  and the per-endpoint `run-now` request forever; `SCAN_TIMEOUT_SECONDS` never fires.
- **Evidence:** Direct test against the VM: `c.exec_command("sleep 60; echo DONE", timeout=8)`
  then `stdout.channel.recv_exit_status()` returned 0 only after **60.1s** — the timeout
  was ignored. The 09:13 orchestration run produced no "scan failed" log, consistent with
  the thread being stuck.
- **Root cause:** `recv_exit_status()` waits on the channel event and does not honor the
  `exec_command` timeout the way `stdout.read()` does.
- **Recommended minimal fix:** poll `exit_status_ready()` against a deadline instead:
  ```python
  deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
  while not stdout.channel.exit_status_ready():
      if time.monotonic() > deadline:
          raise TimeoutError("scan exceeded SCAN_TIMEOUT_SECONDS")
      time.sleep(0.5)
  exit_status = stdout.channel.recv_exit_status()
  ```
  (Optionally raise `SCAN_TIMEOUT_SECONDS` from 120 to ~300 for hash-heavy scans.)

### BUG-3 — HIGH: Collector crashes on persistence & scheduled_tasks as non-root

- **Component:** `collector/modules/persistence.py` `_linux_cron_entries()` (~line 130);
  `collector/modules/scheduled_tasks.py` `_collect_linux_timers()` (~line 76).
- **Severity:** HIGH — two of the six artifact types are never collected in live runs
  under the deployed user.
- **Evidence:** Live tracebacks on the VM:
  `PermissionError: [Errno 13] Permission denied: '/var/spool/cron/crontabs'`
  (the dir is `drwx-wx--T root crontab`). DB confirms **zero live persistence /
  scheduled_task** artifacts for `ns-ubuntu-server` (only 07-29 sample data exists).
- **Root cause:** `os.listdir('/var/spool/cron/crontabs')` requires root to read.
- **Recommended minimal fix:** guard the listing in both modules:
  ```python
  try:
      crontabs = os.listdir(spool_dir)
  except (IOError, PermissionError):
      crontabs = []
  for user in crontabs:
      ...
  ```

### BUG-4 — HIGH: `generate_report()` called with unsupported `since` keyword

- **Component:** `backend/endpoints.py` `run_endpoint_now()` (line ~161) calling
  `backend/reports.py` `generate_report()` (signature has no `since`).
- **Severity:** HIGH — `POST /endpoints/{id}/run-now` raises `TypeError` → HTTP 500 the
  moment a scan succeeds, after detection has already run. Masked during the audit only
  because every live scan failed earlier for other reasons.
- **Evidence:** Running image `endpoints.py` calls
  `generate_report(db, host=row.name, triggered_by="manual", since=run_started_at)`;
  `/app/reports.py` in the same image has no `since` parameter.
- **Root cause:** Work-in-progress change passed a keyword the callee doesn't accept.
- **Recommended minimal fix:** add `since` support to `generate_report` so the report is
  scoped to detections created during this run (as the call-site docstring intends):
  ```python
  def generate_report(db, host=None, triggered_by="manual", since=None):
      query = db.query(models.Detection)
      if host:
          query = query.filter(models.Detection.host == host)
      if since is not None:
          if since.tzinfo is not None:
              since = since.astimezone(UTC).replace(tzinfo=None)
          query = query.filter(models.Detection.detected_at >= since)
      ...
  ```

### BUG-5 — HIGH: `collector/requirements.txt` missing `requests`

- **Component:** `collector/requirements.txt` vs `collector/collector_agent.py` (imports `requests`).
- **Severity:** HIGH — a clean deploy from the repo fails immediately at
  `import requests`; the collector never runs.
- **Evidence:** The endpoint's recorded `last_error` in the DB is literally
  `ModuleNotFoundError: No module named 'requests'`. The VM's copy was patched ad-hoc
  (its local `requirements.txt` gained `requests>=2.31.0`), but the repo file still lacks it.
- **Root cause:** dependency drift between the agent code and its declared requirements.
- **Recommended minimal fix:** add one line to `collector/requirements.txt`:
  ```
  requests>=2.31.0
  ```

### BUG-6 — MEDIUM/HIGH: No schema migration → dashboard 500 + data loss on model changes

- **Component:** `backend/models.py` + `backend/main.py` (`Base.metadata.create_all`).
- **Severity:** HIGH when it triggers (breaks `/dashboard` and the scheduler's endpoint
  queries), but only when the model changes against an existing SQLite file.
- **Evidence:** After `endpoints.last_error` was added to the model, the still-existing
  volume DB lacked the column → repeated
  `GET /dashboard → 500: sqlite3.OperationalError: no such column: endpoints.last_error`.
  The deployment only recovered by recreating the volume DB (prior history lost).
- **Root cause:** `create_all` only creates missing *tables*, never missing *columns*;
  there is no migration step.
- **Recommended minimal fix:** idempotent startup check after `create_all` in `main.py`:
  ```python
  from sqlalchemy import inspect, text
  def ensure_schema():
      insp = inspect(engine)
      if "endpoints" in insp.get_table_names():
          cols = {c["name"] for c in insp.get_columns("endpoints")}
          if "last_error" not in cols:
              with engine.begin() as conn:
                  conn.execute(text("ALTER TABLE endpoints ADD COLUMN last_error TEXT"))
  ensure_schema()
  ```

### BUG-7 — LOW (security): Live API keys committed to git

- **Component:** `detection/.env.txt` (tracked) contains real `ABUSEIPDB_API_KEY`,
  `OTX_API_KEY`, `URLhaus_API_KEY`.
- **Severity:** LOW for functionality; security concern.
- **Root cause:** legacy folder tracked with secrets.
- **Recommended remediation (not yet applied):** `git rm --cached detection/.env.txt`,
  add to `.gitignore`, and rotate the exposed keys.

### 4.8 Working components & observations (not bugs)

- `/health`, `/ingest`, `/artifacts`, `/hosts`, `/detect`, `/detections`, `/reports/*`,
  report PDF download, `/dashboard` (after BUG-6 workaround), healthcheck and all three
  scheduler jobs functioned correctly.
- VM→backend push works; ingestion and detection on pushed data works
  (09:14 cycle scanned 237 artifacts).
- `file_scan` on the live endpoint hashes files but **YARA never fires** because
  `yara` is not in the collector dependencies and rules are not shipped to endpoints.
  This is arguably by design (hash + result-embedding still works); flagging as a gap
  only if agent-side YARA is expected.
- Report host-filtering uses `endpoint.name`, while detections store the collector's
  hostname. Works today because both are `ns-ubuntu-server`; fragile if names ever diverge.
- `collector/output/2026-07-31_DESKTOP-68VLDRS` and the `detection/` folder are stale
  legacy artifacts unused by compose/CI; `backend/reports (1).py` is a stray copy.

---

## 5. Clean-Start Run Steps

From an empty state, in order:

1. **Backend up:**
   ```bash
   cd dfir-threat-hunting-framework
   # ensure backend/.env and backend/ssh_keys/dfir_orchestrator_key exist
   docker compose up --build -d
   curl http://127.0.0.1:8000/health        # expect {"status":"ok"}
   ```
2. **Collector on the endpoint:**
   ```bash
   # on the VM
   mkdir -p ~/collector && cd ~/collector
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt   # psutil + requests (+ pywin32 on Windows)
   # install backend public key into ~/.ssh/authorized_keys
   venv/bin/python3 collector_agent.py --only processes,network   # smoke test
   ```
3. **Enroll the endpoint:**
   ```bash
   curl -X POST http://127.0.0.1:8000/endpoints -H "Content-Type: application/json" \
     -d '{"name":"ns-ubuntu-server","ip_address":"192.168.50.129","os":"linux",
          "ssh_username":"youssef","ssh_key_path":"/app/ssh_keys/dfir_orchestrator_key",
          "remote_collector_path":"/home/youssef/collector"}'
   ```
4. **Wait ~60s** for the liveness sweep to mark it online (`GET /endpoints`).
5. **End-to-end run:**
   ```bash
   curl -X POST http://127.0.0.1:8000/endpoints/1/run-now
   curl "http://127.0.0.1:8000/detections"
   curl "http://127.0.0.1:8000/reports"
   ```
6. **Dashboard:** open `http://127.0.0.1:8000/dashboard`, download a report PDF,
   or use the per-endpoint "Run Now" button.

**IMPORTANT pre-flight checklist (fixes from §4 must be applied first):**
- [ ] `collector/requirements.txt` includes `requests` (BUG-5).
- [ ] `logs.py` ausearch call has a timeout (BUG-1).
- [ ] `persistence.py` / `scheduled_tasks.py` guard the cron spool dir (BUG-3).
- [ ] `endpoint_orchestrator.py` enforces `SCAN_TIMEOUT_SECONDS` (BUG-2).
- [ ] `reports.py` accepts `since` (BUG-4).
- [ ] startup schema check for `endpoints.last_error` (BUG-6).

---

## 6. Remaining Issues & Recommendations

| # | Issue | Impact | Recommendation |
|---|---|---|---|
| 1 | BUG-1..6 unapplied | Pipeline incomplete / hangs / 500s | Apply the documented minimal fixes (each is 1-15 lines) |
| 2 | No migrations | Future model changes break existing DBs | Add the startup schema check; adopt a tiny migration pattern |
| 3 | Non-root collector | Missing persistence/scheduled_task data; ausearch hangs | Run collector as root/sudo, or apply BUG-1/BUG-3 guards |
| 4 | Committed secrets | Key exposure | Remove `detection/.env.txt` from git + rotate keys |
| 5 | Agent YARA off | file_scan detects hashes only on live endpoints | If desired, add `yara-python` to collector deps and ship rules |
| 6 | Endpoint name vs hostname coupling | Report scoping fragile | Keep `endpoint.name` == collector hostname, or filter reports by hostname explicitly |
