# DFIR Threat Hunting Framework — Complete Setup & Run Guide

**Audience:** a brand-new user on a Windows laptop with **VMware Workstation**,
running two lab VMs — an **Ubuntu Server** VM and a **Windows 10** VM — exactly
like the environment this project was developed in.

This guide takes you from "nothing installed" to a running lab:
backend + dashboard on your Windows host, and the collector agent collecting
from both VMs and pushing data in — then using the dashboard to trigger
collections manually, run detection, and triage the results.

---

## 0. Architecture at a glance

```
┌────────────────────────────── Windows host ──────────────────────────────┐
│                                                                          │
│  Backend (FastAPI, port 8000)                                            │
│   ├─ POST /ingest          ← agents push collected artifacts here        │
│   ├─ /dashboard            ← analyst web UI (your browser)               │
│   ├─ /detect, /detection-runs, /detections, /metrics, /audit-logs       │
│   └─ SQLite DB (backend/dfir.db) + bundled ATT&CK STIX dataset           │
│                                                                          │
└───────────────▲───────────────────────────────▲──────────────────────────┘
                │ http://<host-ip>:8000          │ http://<host-ip>:8000
┌───────────────┴──────────────────┐   ┌────────┴─────────────────────────┐
│  Ubuntu Server VM (VMware)        │   │  Windows 10 VM (VMware)          │
│  collector_agent --daemon         │   │  collector_agent --daemon         │
│  collects processes/network/      │   │  collects processes/network/      │
│  persistence/scheduled_tasks/     │   │  persistence/scheduled_tasks/     │
│  logs + file_scan → pushes JSON   │   │  logs + file_scan → pushes JSON   │
└───────────────────────────────────┘   └──────────────────────────────────┘
```

**What runs where**

| Component | Where | Purpose |
|---|---|---|
| Backend API + dashboard | Windows host | Stores artifacts, runs detection, serves the web UI |
| Collector agent | Ubuntu Server VM | Gathers artifacts on Linux and pushes them |
| Collector agent | Windows 10 VM | Gathers artifacts on Windows and pushes them |

> You could equally run the backend inside the Ubuntu VM instead of the host —
> everything still works. Hosting it on the Windows host is the simplest path
> because that's where your repo checkout and browser already are.

---

## 1. Prerequisites

- **Windows laptop** with administrator access.
- **Python 3.10–3.12** installed on the host (3.12 recommended). Check:
  ```cmd
  python --version
  ```
  If missing, install from https://www.python.org/downloads/ — **tick
  "Add python.exe to PATH"** during install.
- **VMware Workstation** (Pro or Player) with two already-created VMs:
  - **Ubuntu Server** VM (e.g. 22.04/24.04, SSH or console access, `sudo`).
  - **Windows 10** VM (with your collector's target apps installed).
- The project source on the host. Either:
  - `git clone <your-repo-url>` (recommended), or
  - copy the project folder onto the host.
- VMs and host must be on a network where they can reach each other.
  VMware **NAT** works out of the box (VMs can reach the host via its LAN IP).

---

## 2. Part 1 — Set up the backend on your Windows host

All backend commands run from a **Command Prompt or PowerShell** in the project
folder.

### 2.1 Create a virtual environment and install dependencies

```cmd
cd dfir-threat-hunting-frameworkV3
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` includes everything the backend needs: FastAPI, uvicorn,
SQLAlchemy, Alembic (migrations), the Sigma-style matcher's YAML lib,
`mitreattack-python` (ATT&CK enrichment) and `psycopg2-binary` (optional
Postgres).

> `yara-python` is also pulled in — it's only needed by the collector's
> `file_scan` module, but installing it here doesn't hurt.

### 2.2 (Optional) Configure `.env`

The backend runs **open by default** (auth off) so you can start right away.
To make auth opt-in later, copy the template and fill in values:

```cmd
copy .env.example .env
```

Defaults that matter:
- `AUTH_ENABLED=false` — open lab mode.
- `ADMIN_API_KEY`, `AUTH_SECRET`, `AGENT_API_KEYS` — only used when auth is on.
- `DETECTION_INTERVAL_SECONDS=30` — scheduler auto-runs detection every 30 s.
- `DATABASE_URL=sqlite:///./dfir.db` — SQLite by default (Postgres optional).

### 2.3 Start the backend

```cmd
venv\Scripts\activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

- `--host 0.0.0.0` is **required** so your two VMs can reach it — not just
  localhost.
- Run it from the `backend\` folder (the SQLite DB path `./dfir.db` and the
  static dashboard are resolved relative to it).
- On startup the app automatically applies Alembic migrations
  (`migrate_to_head()`), so your DB is always at the current schema.
- The ATT&CK STIX dataset is already bundled in the repo at
  `dfir-refs\cti\enterprise-attack\enterprise-attack.json` — enrichment works
  with zero extra setup.

### 2.4 Verify the backend

Open a browser on the host:

- **`http://127.0.0.1:8000/health`** → `{"status":"ok", ...}` (liveness).
- **`http://127.0.0.1:8000/dashboard`** → the analyst dashboard.
- **`http://127.0.0.1:8000/docs`** → interactive API docs (try endpoints here).

Or from the command line:

```cmd
curl http://127.0.0.1:8000/health
```

---

## 3. Part 2 — Open the backend to your VMs (Windows Firewall)

When you first ran `uvicorn`, Windows may have shown a firewall prompt for
Python. If you clicked Cancel, the VMs won't be able to reach port 8000.

1. Find your host's LAN IPv4 address:
   ```cmd
   ipconfig
   ```
   Look for the IPv4 of your active adapter, e.g. `192.168.1.50` (or the
   VMware `192.168.84.1` NAT adapter).

2. Add an inbound firewall rule for port 8000 (elevated PowerShell/CMD):
   ```cmd
   netsh advfirewall firewall add rule name="DFIR Backend 8000" dir=in action=allow protocol=TCP localport=8000
   ```

3. Confirm from a VM that the host is reachable (do this from the Ubuntu VM):
   ```bash
   curl http://192.168.1.50:8000/health
   ```
   Replace `192.168.1.50` with your host IP. A `{"status":"ok"}` means the VMs
   can reach the backend.

> **VMware NAT tip:** with default NAT, VMs use the host's **real LAN IP**
> (from `ipconfig`) to reach the host. If that doesn't work, also try the
> VMware NAT gateway address of the host (`192.168.<vmnet8>.1`), or switch the
> VM adapter to **Bridged** so VMs sit on your real LAN.

---

## 4. Part 3 — Load demo data (optional, recommended first)

Before wiring up live agents, prove the whole pipeline with the bundled sample
folders. They're pre-collected artifact sets for a Windows 10 VM and an Ubuntu
Server VM (`sample_data\2026-07-29_win10-vm01\`, `..._ns-ubuntu-server\`).

With the backend running and a second terminal in `backend\`:

```cmd
venv\Scripts\activate
python push_samples.py ..\sample_data\2026-07-29_win10-vm01
python push_samples.py ..\sample_data\2026-07-29_ns-ubuntu-server
```

Each `*.json` file is POSTed to `/ingest` (idempotent via `batch_id`). Then in
the dashboard (Overview view) you should see hosts, artifacts, and detection
counts. You can also run detection manually and watch the History view populate.

---

## 5. Part 4 — Install & run the collector on the **Ubuntu Server VM**

Open a shell in the Ubuntu VM (console or SSH). Install prerequisites and copy
the project's `collector/` folder onto the VM (e.g. via shared folder, scp, or
a fresh `git clone`).

### 5.1 Install Python and the agent

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

cd collector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` installs `psutil` and `requests` (Linux) — no `pywin32`.

> **YARA (optional):** `file_scan` only scans executables with YARA when you
> point it at a rules folder and `yara-python` is installed. Without it, the
> module still records SHA-256 hashes of executables, which the backend matches
> against known-bad hashes. To enable it:
> ```bash
> pip install yara-python
> ```

### 5.2 Run the collector against the backend

Enroll the VM with the backend, then push everything it collects:

```bash
cd collector
source venv/bin/activate

# One-shot: collect locally and write to ./output/<date>_<hostname>/
python collector_agent.py

# Push a collected run to the backend manually (batch is idempotent):
#   (the --daemon mode below does this automatically)
```

**Enroll + continuous daemon** (recommended — collects and pushes every 60 s):

```bash
python collector_agent.py \
  --api-url http://192.168.1.50:8000 \
  --enroll --daemon --interval 60
```

- `--api-url` → your host IP + port 8000.
- `--enroll` → registers this hostname with the backend (idempotent).
- `--daemon --interval 60` → loop forever: collect → push → sleep 60 s.
- Pass `--yara-rules ../backend/yara_rules` if you want YARA file scanning.
- Run with `sudo` for full visibility of other users' processes/connections.

**Verify:** in the dashboard's **Endpoints** view the Ubuntu VM now appears
(online), and the **Artifacts** view fills with its `processes`, `network`,
`persistence`, `scheduled_tasks`, `logs`, `file_scan` artifacts.

---

## 6. Part 5 — Install & run the collector on the **Windows 10 VM**

Open an **elevated** (Administrator) Command Prompt / PowerShell in the
Windows 10 VM and copy the project's `collector/` folder onto it.

### 6.1 Install Python and the agent

```cmd
python --version
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

On Windows this also installs `pywin32`. Run its post-install step **once**
(elevated):

```cmd
python venv\Scripts\pywin32_postinstall.py -install
```

> **YARA (optional):** `pip install yara-python` to enable YARA file scanning
> via `--yara-rules`.

### 6.2 Run the collector against the backend

**One-shot local collection** (no backend):
```cmd
python collector_agent.py
```

**Enroll + continuous daemon** (recommended):
```cmd
python collector_agent.py --api-url http://192.168.1.50:8000 --enroll --daemon --interval 60
```

Run it **elevated** (Administrator) — otherwise some processes/connections owned
by other users are skipped.

**Verify:** the Windows 10 VM shows up under **Endpoints**, and its artifacts
start appearing in the dashboard.

---

## 7. Part 6 — Use the dashboard end-to-end

Open **`http://127.0.0.1:8000/dashboard`** on the host.

Views (left sidebar):

| View | What you can do |
|---|---|
| **Overview** | Summary cards: artifacts, detections, endpoints, hosts + latest runs |
| **Endpoints** | See both VMs (status / last-seen / OS / interval). **Add endpoint**, **Edit config**, and **Run collection now** buttons |
| **Detections** | Filter by host/severity/technique; **triage** each detection (new → acknowledged → false/true positive → reviewed) with notes |
| **History** | Detection run history — trigger, status, scope, rescan, timing, counts |
| **Artifacts** | Explore raw collected artifacts |
| **Audit** | Admin action audit trail (enrolls, config edits, run detection, triage, login) |

### 7.1 "Run collection now" (manual trigger)

1. Open **Endpoints**.
2. Pick a VM and click **Run collection now**.
3. The backend queues a `run_collection` pending command; the agent picks it up
   on its next poll (within `--interval`), collects, pushes, and reports back.
4. Watch **Audit** for the `queue_collection` + `complete_command` entries.

### 7.2 "Run detection now" (manual trigger)

1. Open **Detections** (or Overview) and click **Run detection now**.
   - Optional **host** scope (run only for one VM).
   - Optional **rescan** (re-analyze already-processed artifacts).
2. The result summary shows `run_id`, artifacts scanned, detections found.
3. The run appears in **History**, and any new detections appear in
   **Detections** with `triage_status: new`.

> The scheduler also auto-runs detection every `DETECTION_INTERVAL_SECONDS`
> (default 30 s) on unprocessed artifacts — you'll see those as
> `trigger: scheduled` runs.

### 7.3 Triage a detection

In **Detections**, pick a row → set status (acknowledged / false positive /
true positive / reviewed) and add a note. The change is saved and written to
the audit log.

### 7.4 Ops views

- **`http://127.0.0.1:8000/metrics`** — Prometheus-format metrics
  (artifacts_total, detections_open, endpoints_total, pending_commands, ...).
- **`http://127.0.0.1:8000/audit-logs`** — the same audit trail as the
  dashboard's Audit view, as JSON.
- **`http://127.0.0.1:8000/health`** — liveness + metric summary.

---

## 8. Optional — enable authentication

By default everything is open (fine for an isolated lab). To require keys:

1. In `backend\.env`:
   ```ini
   AUTH_ENABLED=true
   ADMIN_API_KEY=<your-admin-api-key>
   AUTH_SECRET=<a-long-random-string-for-signing-tokens>
   AGENT_API_KEYS=<agent-key-ubuntu>,<agent-key-win10>
   ```
2. Restart the backend.
3. Agents present their per-endpoint key:
   ```bash
   python collector_agent.py --api-url http://192.168.1.50:8000 \
     --api-key <agent-key-ubuntu> --enroll --daemon --interval 60
   ```
4. The dashboard logs in with the **admin key** (`POST /auth/login` → bearer
   token). Admin-only routes (`/endpoints`, `/metrics`, `/audit-logs`) then
   enforce the key/token.

---

## 9. Optional — Docker + Postgres (containers)

For a production-like stack on the host (requires Docker Desktop + WSL2):

```cmd
docker compose up --build
```

- Starts **Postgres 16** + the **backend** (auto-migrates at startup).
- Backend reachable at `http://127.0.0.1:8000` (or the host LAN IP for VMs).
- The **collector agent is intentionally not containerized** — it stays a
  lightweight native agent on each VM.

---

## 10. Common problems & fixes

| Symptom | Fix |
|---|---|
| VMs can't reach the backend | Host firewall blocks 8000 → add the rule (Part 2). Use the host's LAN IP, not `127.0.0.1`. On NAT try the VMware host IP (`ipconfig`), or switch VM to Bridged. |
| `uvicorn main:app` says module not found | Run from the `backend\` folder with the venv active. |
| Agent enroll fails | Confirm `--api-url http://<host-ip>:8000` (not `127.0.0.1` on the VM) and that `/health` returns `ok` from the VM. |
| No `file_scan` artifacts | YARA not installed and/or no `--yara-rules` — hashes still work; install `yara-python` + pass `--yara-rules ../backend/yara_rules` for YARA matches. |
| Windows collector skips data | Not running elevated — reopen as Administrator. |
| Duplicate/pending commands never run | Agent interval is long (default 300 s) — reduce with `--interval 60`. |
| Dashboard shows 0 endpoints | Agents haven't enrolled yet, or auth is on but `--api-key` not passed. |
| DB in a weird state | The app runs migrations on every startup — restart it. SQLite lives at `backend\dfir.db`; back it up before experiments. |
| Port 8000 already in use | Pick another port: `uvicorn main:app --host 0.0.0.0 --port 8001` and point agents/dashboard at it. |

---

## 11. Quick reference — main endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness + metrics summary |
| GET | `/dashboard` | Analyst dashboard (web UI) |
| GET | `/docs` | Interactive API docs |
| POST | `/ingest` | Push a batch of artifacts (`?batch_id=` for idempotency) |
| GET | `/artifacts` | Query artifacts (`host`, `artifact_type`, `limit`) |
| GET | `/hosts` | List hosts that reported in |
| POST | `/detect` | Run detection (`?host=`, `?rescan=1`) |
| GET | `/detection-runs` | Detection run history |
| GET | `/detections` | Query detections (incl. triage fields) |
| PATCH | `/detections/{id}` | Triage a detection |
| GET | `/detections/summary` | Aggregated counts (incl. `by_triage`) |
| POST | `/endpoints/enroll` | Agent self-enrollment |
| GET | `/endpoints` | List enrolled endpoints (admin) |
| PUT | `/endpoints/{id}/config` | Edit an endpoint's agent config (admin) |
| POST | `/endpoints/{id}/run-collection` | Queue "run collection now" (admin) |
| GET | `/endpoints/commands` | Agent polls pending commands |
| POST | `/endpoints/commands/{id}/complete` | Agent reports command outcome |
| GET | `/metrics` | Prometheus metrics (admin) |
| GET | `/audit-logs` | Admin action audit trail (admin) |

---

That's the whole lab. From here you can:
- Let the daemons run for a while, then check **History** + **Audit**.
- Plant a "malicious" process/reg key/task in a VM, wait a detection cycle, and
  triage the result in the dashboard.
- Re-scan old artifacts with `rescan=1` after adding new rules.
