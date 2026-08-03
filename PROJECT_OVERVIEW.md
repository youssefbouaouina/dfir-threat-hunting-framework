# DFIR Threat Hunting Framework — Project Overview

> **Purpose of this document:** persistent development context. It documents the system **as it currently exists** (including known problems), so future work can navigate the codebase and avoid the traps it already contains. It is a living reference — update it whenever the architecture, schema, endpoints, or dependencies change.

Stage: Youssef Bouaouina & Amen Ben Salah — ESPRIT, NEXTSTEP.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Folder Structure](#2-folder-structure)
3. [Data Schema](#3-data-schema)
4. [Modules](#4-modules)
5. [API Endpoints](#5-api-endpoints)
6. [Classes](#6-classes)
7. [Dependencies](#7-dependencies)
8. [Execution Flow](#8-execution-flow)
9. [Rulesets](#9-rulesets)
10. [Known Issues & Gotchas](#10-known-issues--gotchas)

---

## 1. Project Overview

A three-tier, offline-first **DFIR (Digital Forensics & Incident Response) threat hunting framework**. The pipeline is:

**Collect → Ship → Store → Detect → Query**

- **Collector** (`collector/`) — a cross-platform agent that runs **on the endpoint** (Windows VM / Linux server). It snapshots processes, network connections, persistence mechanisms, scheduled tasks, log events, and hashes/YARA-scans executables locally. Output is a folder of JSON files, one per artifact type.
- **Backend** (`backend/`) — a FastAPI service with two halves:
  - *Ingest API:* receives artifact JSON, validates the envelope, and stores it (SQLite by default; Postgres via `DATABASE_URL`). Ingestion is idempotent when a `batch_id` is supplied.
  - *Detection engine:* periodically (scheduler) or on-demand (`POST /detect`) sweeps unprocessed artifacts through four detection layers (Sigma-style behavioral rules, embedded YARA matches, known-bad hash matching, network IOC correlation), enriches findings with MITRE ATT&CK technique metadata from a local STIX dataset, persists them, and exposes them for querying.
- **SQLite/Postgres** (`backend/dfir.db` by default) — managed by **Alembic migrations** (see `backend/migrations/`): tables `hosts`, `artifacts`, `detections`, plus new `endpoints`, `detection_runs`, `incidents` + `incident_detections` (F2), `pending_commands` and new artifact columns `analyzed_at`, `source_run_id`, `agent_batch_id`; `endpoints.team` + `audit_logs` hash-chain columns (F4).

Detection is **deliberately decoupled from ingest**: ingest just stores; a background scheduler (APScheduler, every 30 s by default) picks up whatever is unprocessed. This mirrors real EDR/SIEM backend design and keeps ingest fast.

Current state: the pipeline is proven end-to-end on real VM data. The local `dfir.db` contains the demo VM data (2,742 artifacts from 2 hosts — `DESKTOP-A5E108P` Windows 10, `ns-ubuntu-server` Ubuntu — and 4 detections) and is **untracked** (regenerate via migrations + `push_samples.py`). Agents can now **enroll** (`POST /endpoints/enroll`), poll a **config** (`GET /endpoints/config`), and **auto-push** collected data with idempotent batches (`collector/agent_client.py`, `collector_agent.py --daemon`). Phase 4 added async ingest via an optional Redis queue + worker, incident correlation, retention/archival, and RBAC with team scoping.

---

## 2. Folder Structure

```
dfir-threat-hunting-frameworkV3/
├── README.md                    # 2 lines; effectively empty (no setup/usage docs)
├── PROJECT_OVERVIEW.md          # this file
├── .gitignore                   # standard Python; ignores venv/, __pycache__, dfir-refs/* (except enterprise-attack.json)
│
├── backend/                     # FastAPI ingest + detection API (canonical backend)
│   ├── main.py                  # FastAPI app, ingest/query endpoints, scheduler lifecycle
│   ├── models.py                # SQLAlchemy ORM models: Host, Artifact, Detection, Endpoint, DetectionRun, Incident, IncidentDetection, AuditLog, PendingCommand
│   ├── schemas.py               # Pydantic request/response models
│   ├── database.py              # SQLite engine, session factory, get_db dependency
│   ├── detection_routes.py      # detection pipeline + /detect /detections endpoints (+ triage PATCH)
│   ├── endpoint_routes.py       # /endpoints/enroll, /endpoints, /endpoints/config (+ config PUT, run-collection, commands)
│   ├── incident_routes.py       # /incidents (list/summary/detail/recompute/triage) — Phase 4 F2
│   ├── retention_routes.py      # /retention (status/run) — Phase 4 F3
│   ├── ingest_queue.py          # Redis async ingest queue (enqueue/dequeue) — Phase 4 F1
│   ├── scheduler.py             # APScheduler background job (periodic detection + offline_sweep/intel_refresh/retention_sweep)
│   ├── sigma_matcher.py         # custom Sigma-style rule loader + evaluator
│   ├── hash_checker.py          # known-bad hash matching (iocs/known_bad_hashes.txt)
│   ├── ioc_correlation.py       # network IOC matching (local blocklist + AbuseIPDB + URLhaus/OTX/Feodo)
│   ├── attck_mapper.py          # MITRE ATT&CK enrichment from dfir-refs STIX dataset
│   ├── logging_config.py        # structured JSON logging (LOG_FORMAT=json)
│   ├── push_samples.py          # CLI: push sample_data/ folders into /ingest
│   ├── ingest_service.py        # ingest_artifacts() incl. batch_id idempotency + dedup
│   ├── services/
│   │   ├── endpoint_service.py  # enroll_endpoint, list_endpoints (team-filtered), get_endpoint_config, update_endpoint_config, queue_collection, poll_pending_commands, complete_command, mark_offline_stale
│   │   ├── detection_service.py # run_detection_job, list_detections, triage_detection, detections_summary, list_detection_runs
│   │   ├── correlation_service.py # recompute_incidents, list_incidents, incidents_summary, get_incident, triage_incident — Phase 4 F2
│   │   ├── retention_service.py # run_retention (JSONL archival + optional OpenSearch sink), retention_status — Phase 4 F3
│   │   ├── audit_service.py     # log_action (hash-chained), list_audit_logs, verify_audit_chain
│   │   ├── metrics_service.py   # Prometheus /metrics text + /health payload
│   │   ├── ingest_service.py    # artifact ingest (batch idempotency + dedup)
│   │   └── query_service.py     # artifact/host queries + scoped_hosts (team scoping, F4)
│   ├── workers/                 # Phase 4 F1
│   │   └── ingest_worker.py     # drains the Redis queue → ingest_service
│   ├── static/                  # Phase 3 analyst dashboard (served at /dashboard)
│   │   ├── index.html           # single-page app shell
│   │   ├── style.css            # dashboard styling
│   │   └── app.js               # overview/endpoints/detections/runs/artifacts/audit views
│   ├── alembic.ini              # Alembic config (sqlite default; DATABASE_URL overrides)
│   ├── migrations/              # Alembic env + versions/
│   │   ├── versions/4823f807fcd2_initial_schema_endpoints_artifacts_.py
│   │   ├── versions/ca41c1ba0e02_phase3_triage_lifecycle_audit_logs_.py
│   │   ├── versions/e19d4f2a7c10_phase4_correlation_engine_incidents_.py
│   │   └── versions/4a1f2c9d3b70_phase4_rbac_endpoint_team_audit_.py
│   ├── Dockerfile               # multi-stage, python:3.12-slim, non-root, healthcheck
│   ├── docker-entrypoint.sh     # alembic upgrade head, then exec "$@"
│   ├── tests/                   # pytest suite (115 tests incl. test_phase2.py, test_phase3.py, test_phase4.py, test_retention.py, test_rbac.py)
│   ├── requirements.txt         # UTF-8, top-level deps incl. alembic + psycopg2-binary
│   ├── requirements-dev.txt     # pytest + ruff + test deps
│   ├── README.md                # setup/run notes for the backend
│   ├── .env.example             # placeholder secrets (real keys removed from repo)
│   ├── dfir.db                  # ⚠ committed SQLite database (runtime data)
│   ├── iocs/                    # threat intel data files
│   │   ├── known_bad_hashes.txt # <sha256> <description> lines
│   │   └── malicious_ips.txt    # <ip> <description> lines
│   ├── sigma_rules/             # behavioral detection rules (YAML)
│   │   ├── rule001_*.yml … rule015_*.yml   # 15 canonical rules
│   │   ├── RULES_INDEX.md       # excellent human-readable rule index
│   │   └── .gitkeep
│   └── yara_rules/              # YARA rules
│       ├── curated_ruleset.yar  # 6 rules used by the collector agent (referenced by index)
│       └── .gitkeep
│
├── collector/                   # endpoint-side agent
│   ├── collector_agent.py       # CLI entrypoint, orchestrates modules
│   ├── agent_client.py          # enroll, get_endpoint_config, push_folder, daemon_loop, poll_pending_commands, complete_command
│   ├── requirements.txt         # psutil, pywin32 (Windows only), requests
│   ├── pyproject.toml           # ruff config for collector conventions
│   ├── README.md                # setup/run notes
│   ├── tests/                   # pytest suite (conftest.py + test_agent_client.py)
│   ├── modules/
│   │   ├── __init__.py          # empty
│   │   ├── common.py            # schema wrapper + JSON writer (shared)
│   │   ├── processes.py         # running processes (psutil)
│   │   ├── network.py           # active network connections (psutil)
│   │   ├── persistence.py       # Run keys/services (Win) / cron, rc.local, systemd (Linux)
│   │   ├── scheduled_tasks.py   # schtasks (Win) / systemd timers + cron (Linux)
│   │   ├── logs.py              # Sysmon (Win) / journalctl + auditd (Linux)
│   │   ├── file_scan.py         # SHA-256 + optional YARA scan of executables
│   │   └── .gitkeep
│
├── dfir-refs/                   # reference datasets (mostly gitignored)
│   └── cti/enterprise-attack/enterprise-attack.json  # MITRE ATT&CK STIX 2.1 dataset (committed; rest ignored)
│
├── docker-compose.yml           # dev stack: Postgres 16 + backend
├── .dockerignore
├── .github/
│   └── workflows/
│       └── ci.yml               # lint+test+gitleaks; GHCR build+push+smoke on v* tags
│
├── sample_data/                 # collected artifact folders (manually copied from VMs)
│   ├── 2026-07-29_win10-vm01/   # Windows VM: processes/network/persistence/scheduled_tasks/logs .json
│   └── 2026-07-29_ns-ubuntu-server/  # Ubuntu server: same 5 files
```

**Conventions across the codebase:**

- Every collector module is cross-platform with **lazy platform imports** (`winreg`, `pywin32`) so modules can be imported on either OS.
- Detection layers are **offline-first / fail-soft**: missing network, keys, or datasets degrade gracefully instead of crashing `/detect`.
- All detection results are **persisted** (`detections` table) and scanned artifacts are marked `processed=1` so re-runs don't duplicate work.
- Heavy use of `__main__` blocks for quick manual smoke testing (not a real test suite).

---

## 3. Data Schema

### 3.1 Artifact envelope (wire + storage format)

Every artifact is a JSON object with this standard shape (defined in `collector/modules/common.py::wrap_artifact` and `backend/schemas.py::ArtifactIn`):

```json
{
  "host": "DESKTOP-A5E108P",        // string — endpoint hostname
  "os": "windows",                  // string — "windows" | "linux" (else platform.system().lower())
  "collected_at": "2026-07-29T05:44:47Z",  // string — ISO8601 UTC
  "artifact_type": "process",       // string — see table below
  "data": { /* artifact-specific fields, see below */ }
}
```

| `artifact_type` | Collector module | `data` fields |
|---|---|---|
| `process` | processes.py | `pid`, `ppid`, `name`, `exe`, `cmdline` (joined string), `username`, `create_time` |
| `network` | network.py | `fd`, `family`, `type`, `local_address` (`"ip:port"` or null), `remote_address` (`"ip:port"` or null), `status`, `pid` |
| `persistence` | persistence.py | Win: `type` (`registry_run_key`\|`service`), `hive`, `key_path`, `value_name`, `value_data`; service: `name`, `display_name`, `status` (STOPPED/RUNNING/…). Linux: `type` (`cron`\|`rc.local`\|`systemd_service`), `source`/`path`, `entry`/`content`/`unit`, `state`, `user` |
| `scheduled_task` | scheduled_tasks.py | Win: `task_name`, `status`, `next_run_time`, `task_to_run`, `run_as_user`, `schedule`. Linux: `type` (`systemd_timer`\|`cron`), `raw`/`unit`/`entry`, `user` |
| `log_event` | logs.py | Win: `event_id`, `time_generated`, `source_name`, `event_category`, `string_inserts`. Linux: `message`, `unit`, `pid`, `priority`, `timestamp_us`, or auditd: `source`, `key`, `raw` |
| `file_scan` | file_scan.py | `path`, `sha256`, `size_bytes`, `yara_matches` (`[{rule, tags, meta}]`) |

### 3.2 Database (`backend/dfir.db` by default; Postgres via `DATABASE_URL`)

Schema is **managed by Alembic migrations** (`backend/migrations/`). On app import, `backend/main.py::migrate_to_head()` runs `alembic upgrade head` — it replaces the old `Base.metadata.create_all`. The initial migration is **idempotent**: for a Phase-1 SQLite DB that already has `artifacts`/`hosts`/`detections` from `create_all`, it adds the new columns/tables in place and preserves existing rows (verified against the committed `dfir.db`).

**`hosts`** — one row per endpoint that has ever reported in (kept for backwards compatibility; new enrollments go to `endpoints`).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | indexed |
| `hostname` | String, unique, not null | indexed |
| `os` | String, not null | refreshed on every ingest |
| `last_seen` | DateTime(tz) | `server_default=func.now()`, `onupdate=func.now()` |

**`artifacts`** — one row per collected artifact.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | indexed |
| `host` | String, not null | indexed — **denormalized string, no FK** |
| `os` | String, not null | |
| `artifact_type` | String, not null | indexed |
| `collected_at` | String, not null | ISO8601 string as produced by collector (**stored as string, not datetime**) |
| `data` | Text, not null | JSON-encoded artifact-specific fields |
| `ingested_at` | DateTime(tz) | `server_default=func.now()` |
| `processed` | Integer | `0` = not yet analyzed, `1` = analyzed (terminal — see Known Issues #10) |
| `analyzed_at` | DateTime(tz) | nullable — set when a detection run marks the artifact `processed=1` (added by migration) |
| `source_run_id` | Integer | nullable — FK to `detection_runs.id` of the run that analyzed it |
| `agent_batch_id` | String | nullable — idempotency key; repeat pushes of the same `(host, batch_id)` are deduplicated by ingest |

**`endpoints`** — one row per enrolled endpoint (added in Phase 2).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | indexed |
| `hostname` | String, unique, not null | enrollment is idempotent per hostname |
| `os` | String, nullable | |
| `agent_version` | String, nullable | |
| `status` | String, default `online` | `online` / `offline` |
| `last_seen` | DateTime(tz) | refreshed on enroll/config poll |
| `enrollment_token_hash` | String, nullable | SHA-256 of the one-time enrollment token |
| `config_json` | Text, nullable | per-endpoint agent config (default: collectors + `interval_seconds: 300`) |
| `registered_at` | DateTime(tz) | `server_default=func.now()` |
| `team` | String, default `"default"` | team scope for RBAC (Phase 4 F4; DB-nullable for SQLite, service defaults it) |

**`detection_runs`** — one row per detection cycle (run history; written by `run_detection_job` since Phase 3).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | indexed |
| `trigger` | String | `scheduled` / `manual` |
| `status` | String | `started` / `completed` / `failed` |
| `host` | String, nullable | scope — set when a single host was targeted |
| `rescan` | Integer | `1` when processed artifacts were re-analyzed |
| `started_at` | DateTime(tz) | `server_default=func.now()` |
| `finished_at` | DateTime(tz) | nullable |
| `artifacts_scanned` | Integer | default 0 |
| `detections_found` | Integer | default 0 |
| `by_severity` | Text | JSON |
| `by_technique` | Text | JSON |

**`detections`** — one row per detection produced by the pipeline.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | indexed |
| `host` | String, not null | indexed |
| `rule_id` | String, not null | indexed — e.g. `rule-001`, `yara-<RuleName>`, `hash-match`, `ioc-local-blocklist`, `ioc-abuseipdb` |
| `rule_title` | String, not null | |
| `technique_id` | String, nullable | e.g. `T1059.001`; indexed |
| `technique_name` | String, nullable | enriched from STIX |
| `tactic` | String, nullable | first kill-chain phase from STIX |
| `artifact_type` | String, not null | |
| `severity` | String, nullable | `low`/`medium`/`high`/`critical`/`unknown` |
| `matched_data` | Text, not null | JSON-encoded artifact `data` that triggered the rule |
| `detected_at` | DateTime(tz) | `server_default=func.now()` |
| `triage_status` | String | default `new`; `new`/`acknowledged`/`false_positive`/`true_positive`/`reviewed` (Phase 3) |
| `triage_notes` | Text, nullable | analyst notes (Phase 3) |
| `triage_updated_at` | DateTime(tz) | nullable (Phase 3) |
| `triage_updated_by` | String | nullable (Phase 3) |

**`audit_logs`** — admin/analyst action trail (added Phase 3; hash chain Phase 4 F4).

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | indexed |
| `actor` | String, nullable | admin key label, token subject, or agent hostname |
| `action` | String, not null | whitelisted action name (see §4.2 `audit_service`) |
| `detail` | Text, nullable | JSON-encoded context (host, run_id, before/after, etc.) |
| `created_at` | DateTime(tz) | `server_default=func.now()`, indexed |
| `prev_hash` | String, nullable | previous row's `record_hash` (chain link, F4) |
| `record_hash` | String, nullable | SHA-256 over `(prev_hash, actor, action, detail_json)`, indexed (F4) |

**`pending_commands`** — agent command queue (added Phase 3; powers "Run collection now").

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | indexed |
| `hostname` | String, not null | target endpoint, indexed |
| `command` | String, not null | currently `run_collection` |
| `params` | Text, nullable | command-specific options (JSON) |
| `status` | String | `pending` → `picked_up` → `completed` / `failed` |
| `created_at` | DateTime(tz) | `server_default=func.now()`, indexed |
| `picked_up_at` | DateTime(tz) | nullable |
| `completed_at` | DateTime(tz) | nullable |
| `result` | Text, nullable | agent-reported outcome |

### 3.3 IOC file formats

**`iocs/known_bad_hashes.txt`** — `known_bad_hashes.txt`:
```
<sha256> [whitespace] [#] optional description
# lines starting with # are comments
```
Currently contains only the EICAR test hash (`275a021b…`) for pipeline validation.

**`iocs/malicious_ips.txt`** — `malicious_ips.txt`:
```
<ip> [whitespace] [#] optional description
# lines starting with # are comments
```
Currently contains only `203.0.113.66` (RFC 5737 TEST-NET range, safe for validation).

---

## 4. Modules

### 4.1 Collector

**`collector/collector_agent.py`** — CLI entrypoint. Orchestrates modules, resolves executable paths from process/persistence records, and writes output to `output/<YYYY-MM-DD>_<hostname>/`.

- `CORE_COLLECTORS` — dict of collector name → `(filename, callable)`.
- `_extract_exe_paths(process_records, persistence_records) -> set` — gathers `exe` paths from process artifacts and a best-effort first-token path parse of registry Run key `value_data`.
- `run_collection(output_dir, only, yara_rules_dir) -> str` — runs `processes` + `persistence` first (file_scan depends on their output), then `network`, `scheduled_tasks`, `logs`, then `file_scan`. Each module is wrapped in try/except; a failure records `[]` (for processes/persistence) or is skipped, never aborting the run. Returns the run directory (used as the idempotent `batch_id` when pushing).
- CLI flags: `--output`, `--only processes,network`, `--yara-rules <dir>`, plus Phase 2 `--api-url`, `--api-key`, `--enroll`, `--daemon`, `--interval <seconds>` (env fallbacks `DFIR_API_URL`, `DFIR_API_KEY`, `COLLECT_INTERVAL_SECONDS`).

**`collector/agent_client.py`** — HTTP client for the agent-to-backend interface (Phase 2, extended Phase 3).
- `make_batch_id() -> str` — unique id per run (timestamp + hostname + random suffix; avoids same-second collisions).
- `enroll(api_url, hostname, os, agent_version, api_key=None) -> dict` — `POST /endpoints/enroll`; returns endpoint + config + enrollment token.
- `get_endpoint_config(api_url, hostname, api_key=None) -> dict` — `GET /endpoints/config?hostname=`; returns interval + collectors.
- `push_folder(folder, api_url, api_key=None, batch_id=None) -> dict` — for each `*.json` artifact file in `folder`, `POST /ingest?batch_id=<id>`; aggregates `{ingested, deduplicated}`; returns `{}` on connection error (fail-soft).
- `poll_pending_commands(api_url, hostname, api_key=None) -> dict` — `GET /endpoints/commands`; returns `{"command": {...}}` or `{"command": None}`; returns `{"command": None}` on connection error (fail-soft).
- `complete_command(api_url, command_id, summary, api_key=None) -> dict` — `POST /endpoints/commands/{id}/complete`; reports the outcome of a manually-triggered collection.
- `daemon_loop(...)` — collect → push → **poll pending commands → run manual collection if one is pending** → sleep(interval) forever; used by `--daemon`.

**`collector/modules/common.py`** — shared helpers.
- `get_hostname() -> str` — `socket.gethostname()`.
- `get_os() -> str` — `platform.system().lower()`, normalized to `"windows"`/`"linux"` (else raw value).
- `now_iso() -> str` — UTC `YYYY-MM-DDTHH:MM:SSZ`.
- `wrap_artifact(artifact_type, data) -> dict` — builds the standard envelope.
- `write_json(filepath, records) -> None` — mkdirs + writes with `indent=2, default=str`.

**`collector/modules/processes.py`**
- `collect_processes() -> list` — `psutil.process_iter(["pid","ppid","name","exe","cmdline","username","create_time"])`; skips `NoSuchProcess`/`AccessDenied`/`ZombieProcess`.

**`collector/modules/network.py`**
- `collect_network() -> list` — `psutil.net_connections(kind="inet")`; formats addresses as `"ip:port"`. On `AccessDenied`, warns to re-run elevated/root. Linux needs root for full visibility.

**`collector/modules/persistence.py`**
- `collect_persistence() -> list` — dispatches to Windows/Linux implementation by `platform.system()`.
- `_collect_windows_persistence()` — reads 4 Run/RunOnce keys (HKLM + HKCU) via `winreg`, then enumerates installed services via pywin32 `win32service` with a `STATE_MAP` (1=STOPPED … 7=PAUSED).
- `_collect_linux_persistence()` — cron entries (`/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`), `/etc/rc.local` content, and enabled systemd units (`systemctl list-unit-files --state=enabled`).

**`collector/modules/scheduled_tasks.py`**
- `collect_scheduled_tasks() -> list` — dispatches Windows/Linux.
- `_collect_windows_tasks()` — `schtasks /query /fo CSV /v` parsed with `csv.DictReader`, skipping re-emitted header rows.
- `_collect_linux_timers()` — `systemctl list-timers --all` raw lines + per-user cron spools.

**`collector/modules/logs.py`**
- `collect_logs(max_events=200) -> list` — dispatches Windows/Linux.
- `_collect_windows_sysmon_logs()` — Sysmon Operational log via `win32evtlog`, backwards/sequential read, masks severity bits off `EventID`, capped by `max_events`.
- `_collect_linux_logs()` — `journalctl -o json -n <max>` parsed line-by-line + `ausearch -k exec_tracking -ts recent` (raw tail, last 4000 chars).

**`collector/modules/file_scan.py`**
- `_sha256_of_file(filepath, chunk_size=65536) -> str` — streaming SHA-256.
- `_load_yara_rules(rules_dir)` — compiles all `.yar`/`.yara` files; returns `None` if `yara` import missing or dir absent.
- `collect_file_scans(exe_paths, yara_rules_dir=None, max_file_mb=50) -> list` — hashes each path (skips missing, >50 MB, or unreadable files), optionally YARA-scans, and returns `file_scan` artifacts with embedded `yara_matches`.

> **Design rationale (documented in the module):** file scanning happens **on the endpoint**, not the backend — raw files are never shipped over the network; only the hash + YARA results are reported as ordinary artifacts.

### 4.2 Backend

**`backend/main.py`** — FastAPI app (`title="DFIR Ingest & Detection API"`, `version="0.5.0"`).
- Module import runs `migrate_to_head()` → `alembic upgrade head` (replaces the old `create_all`).
- `lifespan(app)` context manager — calls `start_scheduler()` on startup, `stop_scheduler()` on shutdown.
- Includes the detection router, the endpoint router, the incident router (F2), and the retention router (F3).
- Optional auth layer (`AUTH_ENABLED=true`): agent-key gate on `/ingest` + `/endpoints/*`, admin-key gate on the rest; Phase 4 added human roles (`admin`/`analyst`/`viewer`) via `/auth/login` + `require_role`, with team scoping for list/summary endpoints.
- Structured logging via `logging_config.configure_logging()` (env `LOG_FORMAT=json` for JSON output, `LOG_LEVEL` to change level).
- Phase 3 additions: static `/dashboard` mount, `GET /metrics`, `GET /audit-logs`, `/health` now returns the metrics payload.
- Phase 4 additions: `/ingest` 202 async path when `INGEST_QUEUE_URL` set, `/incidents/*`, `/retention/*`, `GET /audit-logs/verify`, `/auth/login`.
- Endpoints: `/ingest`, `/artifacts`, `/hosts`, `/health`, `/scheduler/status`, `/metrics`, `/audit-logs`, `/audit-logs/verify`, `/dashboard`, `/endpoints/*`, `/incidents/*`, `/retention/*` (see [§5](#5-api-endpoints)).

**`backend/ingest_service.py`**
- `ingest_artifacts(db, artifacts, batch_id=None) -> dict` — validates, upserts the `Host` row, inserts `Artifact` rows, and (when `batch_id` given) skips rows already ingested for that `(host, batch_id)`. Returns `{ingested, deduplicated, host, artifact_types, batch_id}`.

**`backend/services/endpoint_service.py`**
- `enroll_endpoint(db, hostname, os=None, agent_version=None) -> (endpoint, token)` — idempotent per hostname; generates a `secrets.token_urlsafe(32)` enrollment token (stored hashed, returned once on first enroll) and the default agent config (`interval_seconds: 300` + collector list). Writes an `endpoint_enroll` audit entry.
- `list_endpoints(db, limit=None, team=None)` — all endpoint rows, optionally team-filtered (F4).
- `get_endpoint_config(db, hostname)` — per-endpoint config, falling back to defaults; acts as a heartbeat (`_touch_endpoint` restores `online`).
- `update_endpoint_config(db, endpoint_id, interval_seconds=None, collectors=None)` — merges fields into the stored config (interval floored at 10s), touches `last_seen`, returns the full endpoint dict; records an `endpoint_config_update` audit entry.
- `queue_collection(db, endpoint_id)` — creates a `run_collection` `pending_commands` row and an audit entry; returns the command id.
- `poll_pending_commands(db, endpoint_id)` — returns one unclaimed pending command and flips it `pending → picked_up` (first-call-wins, so a command runs once).
- `complete_command(db, command_id, summary)` — marks a picked-up command `completed` with a result summary.
- `mark_offline_stale(db)` — flips endpoints stale past `OFFLINE_STALE_AFTER_SECONDS` to `offline` (run by the scheduler's `offline_sweep` job).

**`backend/services/detection_service.py`** — extracted from `detection_routes.py` (Phase 3) so routes stay thin.
- `run_detection_job(db, host=None, rescan=False, trigger="manual") -> dict` — the shared pipeline (sigma + embedded YARA + hash check + IOC correlation), honoring an optional `host` scope filter and a `rescan` flag to re-analyze processed artifacts; writes a `DetectionRun` row (the run history) and a `run_detection` audit row. After persisting detections it recomputes incidents (Phase 4 F2).
- `_persist_detection(db, d)` — enriches via `enrich_technique` and inserts a `Detection` row with `triage_status="new"`.
- `list_detections(db, ...)` / `triage_detection(db, detection_id, status, notes)` — triage update (validates status against `TRIAGE_STATUSES`, raises `ValueError` on bad input) / `detections_summary(db, hosts=None)` (adds `by_triage`; hosts-scoped) / `list_detection_runs(db, status, limit, hosts=None)`.

**`backend/services/correlation_service.py`** — Phase 4 F2, correlation engine.
- `recompute_incidents(db, actor)` — idempotent, signature-keyed rebuild of `incidents` (same-rule campaigns across hosts; ≥2-technique ATT&CK chains per host; severity escalation); preserves triage; cleans up stale incidents.
- `list_incidents(db, status=None, severity=None, hosts=None)` / `incidents_summary(db)` / `get_incident(db, id)` / `triage_incident(db, id, status, notes, actor)`.

**`backend/services/retention_service.py`** — Phase 4 F3, retention/archival.
- `run_retention(db)` — deletes rows older than `RETENTION_*_DAYS` per table into monthly JSONL archives under `RETENTION_ARCHIVE_DIR` (+ optional OpenSearch bulk sink, fail-soft); idempotent batch deletes; cleans up orphaned incident links.
- `retention_status(db)` — per-table window + archive dir info.

**`backend/services/audit_service.py`** — Phase 3 (hash chain added F4).
- `KNOWN_ACTIONS` — whitelist: `endpoint_enroll`, `endpoint_config_update`, `queue_collection`, `run_detection`, `triage_detection`, `complete_command`, `login`, `recompute_incidents`, `triage_incident`, `retention_run`.
- `log_action(db, action, username=None, detail=None)` — inserts an `AuditLog` row (unknown actions are dropped with a warning); computes `record_hash` chained over `(prev_hash, actor, action, detail_json)` (SHA-256).
- `list_audit_logs(db, action=None, limit=50)` — recent audit entries.
- `verify_audit_chain(db)` — returns `{valid, checked, broken_at}`; skips legacy rows with NULL `record_hash`.

**`backend/services/metrics_service.py`** — Phase 3.
- `metrics_text(db) -> str` — Prometheus `# HELP`/`# TYPE` text: `dfir_artifacts_total`, `dfir_artifacts_unprocessed`, `dfir_detections_total`, `dfir_detections_open`, `dfir_endpoints_total`, `dfir_endpoints_online`, `dfir_detection_runs_total`, `dfir_pending_commands`, `dfir_hosts_total`.
- `health_payload(db) -> dict` — `{status, version, scheduler, metrics}` used by `/health`.

**`backend/models.py`** — SQLAlchemy models `Host`, `Artifact`, `Detection`, `DetectionRun`, `Endpoint` (incl. `team`, F4), `Incident` + `IncidentDetection` (F2), `AuditLog` (incl. `prev_hash`/`record_hash` chain, F4), `PendingCommand` (see [§6](#6-classes) and [§3.2](#32-sqlite-database-backenddfirdb)).

**`backend/schemas.py`** — Pydantic models `ArtifactIn`, `ArtifactOut`, `IngestResponse`, `EndpointOut` (incl. `team`), `EnrollResponse`, `IncidentOut`, `IncidentTriageIn`, `LoginResponse` (incl. `role`/`team`), `RetentionStatusOut` (see [§6](#6-classes)).

**`backend/database.py`**
- `DATABASE_URL = "sqlite:///./dfir.db"` (relative to CWD — run uvicorn from `backend/`).
- `engine` — SQLAlchemy engine with `check_same_thread=False` (required for SQLite under FastAPI's threaded request handling).
- `SessionLocal` — `sessionmaker(autocommit=False, autoflush=False)`.
- `Base` — `declarative_base()`.
- `get_db()` — FastAPI dependency; yields a session and always closes it.

**`backend/detection_routes.py`** — the detection HTTP surface (pipeline lives in `services/detection_service.py`).
- `_row_to_artifact_dict(row) -> dict` — converts an `Artifact` ORM row back to the wire dict (`data` JSON-decoded).
- Endpoints: `POST /detect` (host scope + rescan), `GET /detection-runs` (history), `GET /detections`, `PATCH /detections/{id}` (triage), `GET /detections/summary` (see [§5](#5-api-endpoints)).

**`backend/sigma_matcher.py`** — a lightweight, transparent Sigma-*inspired* matcher (deliberately not a real pySigma backend; the docstring explains this and notes pySigma can be swapped in later).
- Rule file format: YAML with `title`, `id`, `artifact_type`, `technique_id`, `severity`, `condition`.
- `load_rules(rules_dir) -> list` — loads every `.yml`/`.yaml` file via `yaml.safe_load`, **validates structure and deduplicates by rule `id`** (first file wins, later duplicates are skipped with a warning).
- `_matches_condition(data, condition) -> bool` — supports three operators:
  - `field: value` → exact match
  - `field: [v1, v2]` → value must be one of the list
  - `field_contains: [s1, s2]` → string field must contain ≥1 substring (case-insensitive)
- `evaluate(rules, artifacts) -> list` — for each rule, for each artifact of matching `artifact_type`, if `_matches_condition` returns True, emit a detection dict.

**`backend/hash_checker.py`**
- `DEFAULT_HASH_LIST` — `iocs/known_bad_hashes.txt` relative to this file.
- `_cache` — module-level dict keyed by path (load once per process).
- `load_known_bad_hashes(path) -> dict` — parses `sha256 → description`.
- `check_file_scan_artifacts(artifacts, hash_list_path) -> list` — for `file_scan` artifacts whose `data.sha256` (lowercased) is in the list, emits a detection (`rule_id="hash-match"`, `technique_id="T1204"`, severity `critical`).

**`backend/ioc_correlation.py`**
- `ABUSEIPDB_API_KEY` / `OTX_API_KEY` — from env via `load_dotenv()`.
- `_extract_ip("1.2.3.4:4444") -> "1.2.3.4"` — `rsplit(":", 1)`.
- `load_local_blocklist(path) -> dict` — parses `ip → description`.
- `_is_private_or_local(ip) -> bool` — `ipaddress` checks (`is_private`/`is_loopback`/`is_link_local`); unparseable → `True`.
- `check_abuseipdb(ip) -> dict` / `check_urlhaus(domain)` / `check_otx(ip)` — best-effort live lookups (5 s timeout; return `{}`/empty on no key or any request failure). `refresh_feodo_blocklist()` writes `iocs/feodo_ips.txt` (scheduled by `intel_refresh`).
- `correlate_network_artifacts(artifacts) -> list` — Layer 1: local blocklist + Feodo list (checked regardless of private status; skips live lookup on match). Layer 2: live AbuseIPDB/URLhaus/OTX, skipping private/loopback addresses; results memoized in module-level `_ip_cache`. Emits `ioc-local-blocklist` (severity high) or `ioc-abuseipdb` (high if score ≥ 75 else medium), both `technique_id="T1071"`.

**`backend/attck_mapper.py`**
- `DEFAULT_STIX_PATH` — resolved relative to the **repo root** (`Path(__file__).resolve().parents[2] / "dfir-refs/cti/enterprise-attack/enterprise-attack.json`), which is **bundled in this repo** (Phase 3). Env `STIX_PATH` overrides.
- `_cache` — module-level dict keyed by path.
- `_get_attack_data(stix_path)` — lazily imports `mitreattack.stix20.MitreAttackData` (so the module can be imported before the dataset is set up).
- `enrich_technique(technique_id, stix_path) -> dict` — returns `{technique_id, name, tactic, description[:300]}`. **Fails soft**: any exception or missing technique returns a dict with `None` fields and, on error, an `error` key.

**`backend/scheduler.py`**
- `DETECTION_INTERVAL_SECONDS` — env `DETECTION_INTERVAL_SECONDS`, default `30`.
- `scheduler` — module-level `BackgroundScheduler()` (thread-based, chosen over `AsyncIOScheduler` because DB work is synchronous SQLAlchemy).
- `_scheduled_detection_run()` — opens its own `SessionLocal()` session (cannot reuse a request-scoped one), calls `run_detection_job`, logs if artifacts scanned > 0, catches/logs exceptions so a failed cycle never crashes the scheduler or app, closes the session.
- `start_scheduler()` — idempotent; adds job `detection_cycle` with `max_instances=1` + `coalesce=True` (no concurrent/overlapping runs), then starts.
- `stop_scheduler()` — idempotent shutdown.
- `get_status() -> dict` — `{running, interval_seconds, next_run_time}`.

**`backend/push_samples.py`** — CLI utility.
- `push_folder(folder_path, api_url) -> None` — for each `*.json` file in the folder, loads it (must be an artifact array) and POSTs to `{api_url}/ingest`; handles connection errors and non-200 responses; skips empty files.
- CLI: `python push_samples.py <folder> [--url http://127.0.0.1:8000]`.

**`backend/yara_engine.py`** — **REMOVED (Phase 3 cleanup).** Was dead code (never imported by `main.py` or `detection_routes.py`; the pipeline consumes YARA results embedded by the collector in `file_scan` artifacts). Its `__main__` wrote `yara_rules/test_eicar.yar`, which was also removed.

### 4.3 `detection/` directory — **REMOVED (Phase 3 cleanup)**

A **stale, partial copy** of `backend/`'s detection code existed here: `detection_routes.py` was an older version (pipeline inline in `POST /detect`, no `run_detection_job` extraction), it could not run standalone (imports `database`/`models` that did not exist), its modules were byte-identical copies of `backend/`'s, and `detection/.env.txt` contained **additional committed API keys** (OTX, URLhaus). **Deleted in Phase 3** along with the other vestigial items (see §4.4). All active detection development lives in `backend/`.

---

## 5. API Endpoints

Base URL: `http://127.0.0.1:8000` (auto-generated interactive docs at `/docs`).

### 5.1 Endpoint summary

| Method | Path | Auth | Summary |
|---|---|---|---|
| GET | `/health` | none | Liveness check (now includes metrics payload) |
| GET | `/metrics` | admin | Prometheus-format metrics text |
| GET | `/audit-logs` | admin | Audit trail of admin/analyst actions |
| POST | `/ingest` | none* | Store a batch of artifacts (idempotent with `?batch_id=`) |
| GET | `/artifacts` | none* | Query stored artifacts (filterable) |
| GET | `/hosts` | none* | List all known hosts |
| GET | `/scheduler/status` | none | Scheduler running state |
| POST | `/detect` | none | Manually trigger the detection pipeline (`?host=` scope, `?rescan=1`) |
| GET | `/detection-runs` | none | Detection run history (`?status=`, `?limit=`) |
| GET | `/detections` | none | Query detections (filterable; includes triage fields) |
| GET | `/detections/summary` | none | Aggregated detection counts (incl. `by_triage`) |
| PATCH | `/detections/{id}` | none* | Update detection triage status + analyst notes |
| POST | `/endpoints/enroll` | agent key* | Enroll an endpoint (idempotent per hostname) |
| GET | `/endpoints` | admin key* | List enrolled endpoints |
| GET | `/endpoints/config?hostname=` | agent key* | Poll per-endpoint agent config |
| PUT | `/endpoints/{id}/config` | admin key* | Update endpoint config (interval_seconds ≥ 10) |
| POST | `/endpoints/{id}/run-collection` | admin key* | Enqueue a `run_collection` pending command |
| GET | `/endpoints/commands` | agent key* | Agent polls pending commands (manual collection triggers) |
| POST | `/endpoints/commands/{id}/complete` | agent key* | Agent reports a command's completion summary |
| GET | `/incidents` | none* | List correlated incidents (filterable, team-scoped) |
| GET | `/incidents/summary` | none* | Incident count summary |
| GET | `/incidents/{id}` | admin* | Incident detail (linked detections) |
| POST | `/incidents/recompute` | admin/analyst* | Manually rebuild incidents from current detections |
| PATCH | `/incidents/{id}` | admin/analyst* | Triage an incident (status + notes) |
| GET | `/retention/status` | admin* | Retention policy + archive status |
| POST | `/retention/run` | admin* | Run a retention sweep now (audited) |
| GET | `/audit-logs/verify` | admin* | Verify the audit hash chain integrity |
| POST | `/auth/login` | none | Exchange a human API key for an HMAC token (returns `role` + `team`) |
| GET | `/dashboard` | none | Analyst dashboard SPA (static mount) |

> \* **Authentication is optional and opt-in** (`AUTH_ENABLED=true` in env; default off for lab/demo use). When enabled: `POST /ingest` and agent-facing `/endpoints/*` routes require the agent API key (`X-API-Key`), and admin routes require the admin key. Phase 4 added human roles (`admin`/`analyst`/`viewer`) via `/auth/login` with `key@team` env keys; non-admin list/summary endpoints are scoped to the user's team. See [Known Issues #7](#10-known-issues--gotchas).

### 5.2 Endpoint details

**GET `/health`** — Liveness + readiness check.
- Response: `{status, version, scheduler: {...}, metrics: {...}}` (metrics summary via `metrics_service.health_payload`; `status: "ok"`).

**GET `/metrics`** — Prometheus-format metrics text (admin-facing). Exposes `dfir_artifacts_total`, `dfir_artifacts_unprocessed`, `dfir_detections_total`, `dfir_detections_open`, `dfir_endpoints_total`, `dfir_endpoints_online`, `dfir_detection_runs_total`, `dfir_pending_commands`, `dfir_hosts_total`.

**GET `/audit-logs`** — Audit trail of admin/analyst actions (admin-facing). Query params: `action` (optional filter, from the whitelist), `limit` (default 50, max 1000). Returns `[{id, actor, action, detail, created_at, prev_hash, record_hash}]`. Actions are recorded by `audit_service.log_action` (whitelist: `endpoint_enroll`, `endpoint_config_update`, `queue_collection`, `run_detection`, `triage_detection`, `complete_command`, `login`, `recompute_incidents`, `triage_incident`, `retention_run`). Each entry carries a `record_hash` chained over `(prev_hash, actor, action, detail)` (SHA-256).

**GET `/audit-logs/verify`** — Verifies the tamper-evident audit chain. Returns `{valid, checked, broken_at}`; legacy rows with NULL `record_hash` are skipped (chain validated from the first hashed row onward).

**POST `/ingest`** — Stores a JSON array of artifacts (the exact content of one collector output file). Request body is `List[ArtifactIn]`.
- Query param `batch_id` (optional): if provided, repeat pushes of the same `(host, batch_id)` are deduplicated — second push returns `{ingested: 0, deduplicated: 1}` and inserts nothing.
- Behavior: rejects an empty list (400). Upserts a `Host` row for `artifacts[0].host` (updates `os` if changed). Inserts one `Artifact` row per element with `data` JSON-encoded. Commits once.
- Response `200`: `{"ingested": <n>, "deduplicated": <n>, "batch_id": <id>, "host": <hostname>, "artifact_types": [...]}`
- Errors: `400` empty list; Pydantic `422` on schema violation.

**POST `/endpoints/enroll`** — Enroll an endpoint (agent-facing).
- Body: `{hostname, os?, agent_version?}`. Creates (or returns) an `Endpoint` row keyed by unique hostname (idempotent — re-enrolling returns the same endpoint).
- Response `200`: `{id, hostname, enrollment_token, config: {...}, status}` — `enrollment_token` is returned **once** (only on first enroll); the stored value is a hash, so a lost token requires re-enrollment.

**GET `/endpoints`** — List enrolled endpoints (admin-facing).
- Response `200`: `List[{id, hostname, os, agent_version, status, last_seen, registered_at}]`.

**GET `/endpoints/config?hostname=`** — Poll per-endpoint agent config (agent-facing).
- Response `200`: `{hostname, interval_seconds, collectors: [...]}` — defaults applied for unknown hostnames.

**GET `/artifacts`** — Query stored artifacts.
- Query params: `host` (optional), `artifact_type` (optional), `limit` (default 50, max 500).
- Ordering: `id` descending (newest first).
- Response `200`: `List[ArtifactOut]` — `{id, host, os, artifact_type, collected_at, data, ingested_at, processed}`.

**GET `/hosts`** — List all known hosts.
- Response `200`: `[{id, hostname, os, last_seen}]`.

**GET `/scheduler/status`** — Scheduler state.
- Response `200`: `{running, interval_seconds, next_run_time}`.

**POST `/detect`** — Manually trigger the full detection pipeline (same code path as the scheduler). Uses the request-scoped DB session.
- Query params: `host` (optional — restrict to artifacts of a single host), `rescan` (default false — when true, re-analyze already-processed artifacts).
- Writes a `run_detection` audit entry (with `run_id`) and a `DetectionRun` history row.
- Response `200`: `{run_id, artifacts_scanned, detections_found, by_severity: {...}, by_technique: {...}}`

**GET `/detection-runs`** — Detection run history (feeds the dashboard's "Detection history" view).
- Query params: `status` (optional — `started` | `completed` | `failed`), `limit` (default 50, capped at 500).
- Ordering: `id` descending.
- Response `200`: array of `{id, trigger, status, host, rescan, started_at, finished_at, artifacts_scanned, detections_found, by_severity, by_technique}`.

**GET `/detections`** — Query detections.
- Query params: `host` (optional), `severity` (optional), `limit` (default 100, capped at 500).
- Ordering: `id` descending.
- Response `200`: array of `{id, host, rule_id, rule_title, technique_id, technique_name, tactic, artifact_type, severity, matched_data, detected_at, triage_status, triage_notes, triage_updated_at, triage_updated_by}`.

**PATCH `/detections/{id}`** — Update a detection's triage state (Phase 3). Body: `{triage_status: "acknowledged" | "false_positive" | "true_positive" | "reviewed", notes?: str}`. Records `triage_detection` in the audit log.
- Response `200`: updated detection (full fields incl. triage).
- Errors: `404` unknown detection id; `400` invalid `triage_status`.

**GET `/detections/summary`** — Aggregated counts across all stored detections (feeds the ATT&CK-coverage "dashboard" view).
- Response `200`: `{total_detections, by_technique: {...}, by_severity: {...}, by_host: {...}, by_triage: {...}}`

**PUT `/endpoints/{id}/config`** — Update a single endpoint's agent config (admin-facing, Phase 3).
- Body: `{interval_seconds?: int (min 10), collectors?: [...]}`; merges into the stored config and bumps `last_seen`.
- Response `200`: full endpoint record `{id, hostname, os, agent_version, status, last_seen, registered_at, config: {...}}`.
- Errors: `404` unknown endpoint; `400` `interval_seconds < 10`.

**POST `/endpoints/{id}/run-collection`** — Enqueue a manual "run collection now" command for an endpoint (admin-facing, Phase 3). Creates a `pending_commands` row (`command=run_collection`) that the agent picks up on its next `/endpoints/commands` poll. Records a `queue_collection` audit entry.
- Response `200`: `{command_id, status: "pending"}`.
- Errors: `404` unknown endpoint.

**GET `/endpoints/commands?hostname=`** — Agent polls for pending commands (agent-facing, Phase 3). Returns **all unclaimed** pending commands for the endpoint and flips them `pending → picked_up` (first-call-wins, so a command is only executed once).
- Response `200`: `[{id, hostname, command, status, created_at}]` (empty array when nothing is pending).

**POST `/endpoints/commands/{id}/complete`** — Agent reports a command's outcome (agent-facing, Phase 3). Body: `{status?: "completed"|"failed", result?: object}`. Sets `completed_at` + `result`.
- Response `200`: `{command_id, status}`.
- Errors: `404` unknown command id.

**GET `/incidents`** — List correlated incidents (Phase 4 F2). Query params: `status`, `severity`, `limit`. Team-scoped via `current_user` when auth is on. Response: array of `IncidentOut`.
- **GET `/incidents/summary`** — `{total, by_severity, by_status}`.
- **GET `/incidents/{id}`** — Incident detail incl. linked detections (admin). `404` if unknown.
- **POST `/incidents/recompute`** — Rebuild incidents from current detections (admin/analyst, audited as `recompute_incidents`). Idempotent; preserves triage.
- **PATCH `/incidents/{id}`** — Triage an incident (admin/analyst, audited as `triage_incident`). Body: `{triage_status, notes?}`.

**GET `/retention/status`** — Retention policy + archive info (admin, Phase 4 F3): per-table windows, last run, archive dir.
- **POST `/retention/run`** — Run a retention sweep now (admin, audited as `retention_run`). Off by default; no-op when no `RETENTION_*_DAYS` set.

**POST `/auth/login`** — Exchange a human API key for a short-lived HMAC token (Phase 4 F4). Body: `{api_key}`. Response `200`: `{token, role, team}`. `role` ∈ `admin`|`analyst`|`viewer`; `team` from the `key@team` env mapping (or `admin` team `null`).

**GET `/dashboard`** — Analyst dashboard SPA (Phase 3). Serves `backend/static/` (`index.html`, `style.css`, `app.js`) as a static mount.

---

## 6. Classes

| Class | Module | Type | Purpose |
|---|---|---|---|
| `Host` | `backend/models.py` | SQLAlchemy model | Table `hosts` — one row per reporting endpoint (legacy) |
| `Endpoint` | `backend/models.py` | SQLAlchemy model | Table `endpoints` — one row per enrolled endpoint (incl. `team`, F4) |
| `Artifact` | `backend/models.py` | SQLAlchemy model | Table `artifacts` — one row per collected artifact |
| `DetectionRun` | `backend/models.py` | SQLAlchemy model | Table `detection_runs` — one row per detection cycle (history) |
| `Detection` | `backend/models.py` | SQLAlchemy model | Table `detections` — one row per detection result (+ triage fields) |
| `Incident` / `IncidentDetection` | `backend/models.py` | SQLAlchemy model | Tables `incidents` + `incident_detections` — correlated detections (F2) |
| `AuditLog` | `backend/models.py` | SQLAlchemy model | Table `audit_logs` — admin/analyst action trail (+ `prev_hash`/`record_hash` chain, F4) |
| `PendingCommand` | `backend/models.py` | SQLAlchemy model | Table `pending_commands` — agent command queue (manual collection triggers) |
| `ArtifactIn` | `backend/schemas.py` | Pydantic | Request model for `/ingest` items; matches collector `wrap_artifact` output |
| `ArtifactOut` | `backend/schemas.py` | Pydantic | Response model for `/artifacts`; `Config.from_attributes = True` (ORM compatible) |
| `IngestResponse` | `backend/schemas.py` | Pydantic | Response model for `POST /ingest` (incl. `deduplicated`, `batch_id`) |
| `EndpointEnrollRequest` / `EndpointOut` / `EndpointConfigOut` / `EndpointConfigUpdateIn` / `EnrollResponse` | `backend/schemas.py` | Pydantic | Request/response models for `/endpoints/*` |
| `DetectionTriageIn` / `AuditLogOut` / `PendingCommandOut` / `PendingCommandResultIn` | `backend/schemas.py` | Pydantic | Phase 3 request/response models (triage, audit, command queue) |
| `IncidentOut` / `IncidentTriageIn` / `LoginResponse` / `RetentionStatusOut` | `backend/schemas.py` | Pydantic | Phase 4 models (incidents, login role/team, retention) |

**`Host`** — columns: `id` (int PK, indexed), `hostname` (str, unique, not null, indexed), `os` (str, not null), `last_seen` (DateTime tz, `server_default=func.now()`, `onupdate=func.now()`).

**`Endpoint`** — columns: `id` (int PK, indexed), `hostname` (str, unique, not null, indexed), `os` (str, nullable), `agent_version` (str, nullable), `status` (str, default `online`), `last_seen` (DateTime tz, server_default now), `enrollment_token_hash` (str, nullable), `config_json` (Text, nullable), `registered_at` (DateTime tz, server_default now), `team` (str, default `"default"`, indexed — Phase 4 F4).

**`Artifact`** — columns: `id` (int PK, indexed), `host` (str, not null, indexed), `os` (str, not null), `artifact_type` (str, not null, indexed), `collected_at` (str, not null), `data` (Text, not null — JSON-encoded), `ingested_at` (DateTime tz, server_default now), `processed` (int, default 0), `analyzed_at` (DateTime tz, nullable), `source_run_id` (int, nullable), `agent_batch_id` (str, nullable).

**`DetectionRun`** — columns: `id` (int PK, indexed), `trigger` (str — `manual` | `scheduled`), `status` (str — `started` | `completed` | `failed`), `host` (str, nullable — scope when a single host was targeted), `rescan` (int, default 0), `started_at` (DateTime tz, server_default now), `finished_at` (DateTime tz, nullable), `artifacts_scanned` (int, default 0), `detections_found` (int, default 0), `by_severity` (Text — JSON), `by_technique` (Text — JSON). One row per detection cycle; written by `run_detection_job` (Phase 3).

**`Detection`** — columns: `id` (int PK, indexed), `host` (str, not null, indexed), `rule_id` (str, not null, indexed), `rule_title` (str, not null), `technique_id` (str, nullable, indexed), `technique_name` (str, nullable), `tactic` (str, nullable), `artifact_type` (str, not null), `severity` (str, nullable), `matched_data` (Text, not null — JSON-encoded), `detected_at` (DateTime tz, server_default now), **Phase 3 triage**: `triage_status` (str, default `new`), `triage_notes` (Text, nullable), `triage_updated_at` (DateTime tz, nullable), `triage_updated_by` (str, nullable).

**`Incident`** — columns: `id` (int PK, indexed), `signature` (str, not null, unique — idempotent recompute key), `title` (str), `severity` (str), `status` (str, default `open`), `hosts_json` (Text), `techniques_json` (Text), `detection_count` (int), `first_detected_at` / `last_detected_at` (DateTime tz), triage fields (F4). **`IncidentDetection`** — join table `(incident_id FK cascade, detection_id FK cascade)`.

**`AuditLog`** — columns: `id` (int PK), `actor` (str, nullable), `action` (str, not null, indexed), `detail` (Text, nullable), `created_at` (DateTime tz, server_default now, indexed), `prev_hash` (str, nullable), `record_hash` (str, nullable, indexed — SHA-256 chain over `(prev_hash, actor, action, detail_json)`, Phase 4 F4).

**`PendingCommand`** — columns: `id` (int PK), `hostname` (str, not null, indexed), `command` (str, not null — e.g. `run_collection`), `params` (Text, nullable), `status` (str, default `pending`), `created_at` (DateTime tz, server_default now, indexed), `picked_up_at` (DateTime tz, nullable), `completed_at` (DateTime tz, nullable), `result` (Text, nullable).

**`ArtifactIn`** — fields: `host: str`, `os: str`, `collected_at: str`, `artifact_type: str`, `data: Dict[str, Any]`.

**`ArtifactOut`** — fields: `id: int`, `host`, `os`, `artifact_type`, `collected_at`, `data: Dict[str, Any]`, `ingested_at: Optional[datetime]`, `processed: int`, `analyzed_at: Optional[datetime]`, `source_run_id: Optional[int]`, `agent_batch_id: Optional[str]`.

**`IngestResponse`** — fields: `ingested: int`, `deduplicated: int = 0`, `batch_id: Optional[str]`, `host: str`, `artifact_types: List[str]`.

> The collector has no classes — it is function-based.

---

## 7. Dependencies

### 7.1 Backend (`backend/requirements.txt`)

Now a clean UTF-8 file of top-level packages (see the **Known Issues #4** history note; it was previously a UTF-16 `pip freeze` dump and is now installable on Linux):

| Package | Version | Used by |
|---|---|---|
| fastapi | >=0.110 | main.py, detection_routes.py, endpoint_routes.py |
| uvicorn | >=0.30 | ASGI server (run command) |
| sqlalchemy | >=2.0 | database.py, models.py |
| alembic | >=1.12 | migrations (added Phase 2) |
| psycopg2-binary | >=2.9 | Postgres driver (added Phase 2) |
| pydantic | >=2 | schemas.py |
| APScheduler | >=3.10 | scheduler.py |
| PyYAML | >=6 | sigma_matcher.py |
| requests | >=2.31 | ioc_correlation.py, push_samples.py |
| python-dotenv | >=1 | ioc_correlation.py (`load_dotenv`) |
| python-multipart | >=0.0.9 | (FastAPI form support) |
| yara-python | >=4.5 | used by the collector's `file_scan.py` (installed in the backend image so both sides can share the rules tree); the pipeline consumes YARA results embedded in `file_scan` artifacts, no in-process scanning |
| mitreattack-python | >=3.0 | `backend/attck_mapper.py` (lazy import) |

**`requirements-dev.txt`** — pytest + ruff (+ psycopg2-binary for Postgres tests).

**External, not pip-installable:**
- MITRE ATT&CK STIX dataset (`enterprise-attack.json`) — **bundled in this repo** at `dfir-refs/cti/enterprise-attack/enterprise-attack.json` (Phase 3). `attck_mapper.py` resolves it relative to the repo root by default (`STIX_PATH` env overrides). See Known Issues #8.

### 7.2 Collector (`collector/requirements.txt`)

| Package | Constraint | Notes |
|---|---|---|
| psutil | >=5.9.0 | processes, network modules |
| requests | >=2.31 | agent_client.py (enroll/push/config) |
| pywin32 | >=306, `sys_platform == 'win32'` | persistence (win32service), logs (win32evtlog) on Windows; requires `pywin32_postinstall.py -install` once |

`yara` (yara-python) is **optional** for the collector — `file_scan.py` imports it in a try/except; without it, hashing still works but YARA scanning is skipped.

### 7.3 Runtime environment
- Python 3.12 / 3.14 (both seen in committed venvs; backend venv is 3.14, detection venv is 3.12).
- SQLite (bundled with Python via sqlalchemy).
- Windows: Sysmon recommended for `log_event` collection; Linux: `systemctl`, `journalctl`, `ausearch` (auditd with an `exec_tracking` key).

---

## 8. Execution Flow

### 8.1 Flow A — Collection (on the endpoint)

```
collector_agent.py
  ├─ get_hostname(); run_dir = output/<YYYY-MM-DD>_<hostname>/
  ├─ processes()  ─┐
  ├─ persistence()─┴─ collect into memory (needed by file_scan)
  ├─ network(), scheduled_tasks(), logs()
  └─ file_scan(exe_paths derived from processes + persistence)
        each module → list of wrapped artifacts
        each list → write_json → output/<run_dir>/<type>.json
```

### 8.2 Flow B — Ship + Ingest

```
[agent] collector_agent.py --enroll --api-url http://<host>:8000 --api-key <key>
  └─ POST /endpoints/enroll {hostname, os, agent_version}  → receives config + enrollment_token
[agent] collector_agent.py --daemon --api-url ... [--enroll]
  └─ every COLLECT_INTERVAL_SECONDS (default 300, from config):
       run_collection() → output/<YYYY-MM-DD>_<hostname>/   (run_dir = batch_id)
       push_folder(run_dir) → POST /ingest?batch_id=<run_dir> per JSON file
         main.py::ingest_artifacts
           ├─ validate with Pydantic ArtifactIn (envelope only; data is free-form)
           ├─ skip rows already ingested for (host, batch_id)  → deduplicated
           ├─ upsert Host row (create or refresh os)
           ├─ insert Artifact row per element (data → JSON text, processed=0)
           └─ commit → response {ingested, deduplicated, batch_id, host, artifact_types}
[offline replay] python backend/push_samples.py sample_data/<date>_<hostname> [--url ...] [--batch-id ...]
```

The agent's `agent_client.py` (`enroll`, `get_endpoint_config`, `push_folder`, `daemon_loop`) fails soft on connection/HTTP errors so a missing backend never aborts a collection run.

### 8.3 Flow C — Detection

Two identical triggers, one shared function `run_detection_job(db)`:
- **Automatic:** `scheduler.py` every `DETECTION_INTERVAL_SECONDS` (default 30 s) via `BackgroundScheduler` (`max_instances=1`, `coalesce=True`). Job opens its own session; failures are logged, never fatal.
- **Manual:** `POST /detect` (uses the request-scoped session).

```
run_detection_job(db)
  1. SELECT artifacts WHERE processed = 0
  2. Sigma-style rules       ← sigma_matcher.evaluate(load_rules(sigma_rules/), artifacts)
  3. Embedded YARA matches   ← file_scan artifacts' data["yara_matches"]
  4. Known-bad hashes        ← hash_checker.check_file_scan_artifacts()
  5. Network IOC             ← ioc_correlation.correlate_network_artifacts()
     (local blocklist first, then AbuseIPDB live lookup for non-private IPs)
  6. for each detection: _persist_detection() → enrich via attck_mapper.enrich_technique()
  7. write DetectionRun history row + run_detection audit entry
  8. mark all scanned artifacts processed = 1
  9. commit (atomic) → return {run_id, artifacts_scanned, detections_found, by_severity, by_technique}
```

Note: sigma rules are **reloaded from disk on every detection run** (no caching). `hash_checker` and `attck_mapper` cache their loaded data; `ioc_correlation` caches live IP lookups per process (never cleared).

### 8.4 Flow D — Query / Reporting

```
GET /detections            → filtered detection rows (host, severity, limit) incl. triage fields
GET /detections/summary    → by_technique / by_severity / by_host / by_triage counts
GET /detection-runs        → run history (status, limit)
GET /audit-logs            → admin action audit trail (action, limit)
GET /metrics               → Prometheus-format metrics text
GET /artifacts             → stored artifacts (host, artifact_type, limit)
GET /hosts                 → known endpoints
GET /scheduler/status      → scheduler state
```

### 8.5 App lifecycle

```
uvicorn main:app (from backend/)
  ├─ import: migrate_to_head() → alembic upgrade head (idempotent; adds new tables/columns to legacy DBs)
  ├─ startup (lifespan): start_scheduler()
  └─ shutdown: stop_scheduler()

docker compose up   # containerized equivalent:
  ├─ db (postgres:16-alpine, healthcheck)
  └─ backend (python:3.12-slim, non-root)
       entrypoint: alembic upgrade head → uvicorn
       DATABASE_URL=postgresql+psycopg2://dfir:dfir@db:5432/dfir
```

---

## 9. Rulesets

### 9.1 Sigma-style rules (`backend/sigma_rules/`, evaluated by `sigma_matcher.py`)

Authoring format:
```yaml
title: Human-readable rule name
id: rule-XXX            # string, matched per artifact (see duplicate-ID caveat below)
artifact_type: process  # which artifact_type the rule applies to
technique_id: T1059.001 # MITRE ATT&CK technique
severity: high          # low | medium | high | critical
condition:
  field: value                  # exact match
  field: [v1, v2]               # value must be one of the list
  field_contains: [s1, s2]      # field (string, case-insensitive) contains ≥1 substring
```

Canonical rules (`rule001_*.yml` … `rule015_*.yml`), per `RULES_INDEX.md`:

| ID | Title (short) | Technique | Artifact type | Severity |
|---|---|---|---|---|
| rule-001 | Suspicious PowerShell EncodedCommand | T1059.001 | process | high |
| rule-002 | Cron entry referencing script outside standard paths | T1053.003 | persistence | medium |
| rule-003 | Registry Run key pointing to Temp folder | T1547.001 | persistence | high |
| rule-004 | Windows service with suspicious binary path | T1543.003 | persistence | high |
| rule-005 | Scheduled task invoking a script interpreter | T1053.005 | scheduled_task | medium |
| rule-006 | PsExec-style remote service execution indicator | T1569.002 | scheduled_task | high |
| rule-007 | WMIC process creation | T1047 | process | medium |
| rule-008 | System/account discovery commands | T1082 | process | low |
| rule-009 | Network configuration discovery | T1016 | process | low |
| rule-010 | Established connection to common malware/C2 port | T1571 | network | high |
| rule-011 | Ingress tool transfer (download & execute) | T1105 | process | high |
| rule-012 | Shadow copy/backup deletion | T1490 | process | critical |
| rule-013 | rc.local boot script persistence | T1037.004 | persistence | low |
| rule-014 | Security tooling service stopped/disabled | T1562.001 | persistence | medium |
| rule-015 | Reverse shell one-liner pattern | T1059.004 | process | critical |

✅ **Duplicate/legacy rule files** (`suspicious_powershell.yml` + `test_encoded_ps.yml`, `suspicious_cron.yml`, `suspicious_run_key_temp.yml`) were **deleted in Phase 3** — only the canonical `ruleNNN_*.yml` files remain, and `load_rules` deduplicates by rule `id` as a safety net.

### 9.2 YARA rules (`backend/yara_rules/curated_ruleset.yar`)

Used **by the collector agent** (`file_scan.py`) on the endpoint, not by the backend. Each rule sets `technique_id` in `meta`, which the backend reads when converting `yara_matches` into detections.

| Rule | Indicator class | Technique |
|---|---|---|
| EICAR_Test_String | Pipeline validation string | N/A (test) |
| Suspicious_Base64_PowerShell_Loader | Base64/reflective PowerShell loader strings | T1059.001 |
| Possible_Credential_Dumping_Tool | Mimikatz-style strings (sekurlsa, gentilkiwi, lsadump, wdigest) | T1003 |
| Suspicious_Webshell_Indicators | PHP/ASP webshell patterns | T1505.003 |
| Suspicious_Ingress_Tool_Transfer | Download-and-execute command patterns | T1105 |
| Suspicious_Shadow_Copy_Deletion | Recovery-inhibiting commands | T1490 |

✅ `backend/yara_rules/test_eicar.yar` (legacy EICAR-only test rule) was **deleted in Phase 3** — it was never part of the curated set.

### 9.3 Documented scope limitations (from `RULES_INDEX.md` — keep in mind for future work)
- Severity is heuristic; low-severity discovery rules are meant to correlate, not stand alone.
- Process-injection / in-memory-only techniques (e.g. T1055) are out of scope (collector reads metadata, not memory).
- Port-based C2 detection (rule-010) is a weak signal alone; complemented by the IOC correlation layer.

---

## 10. Known Issues & Gotchas

Facts about the current state that future development must account for.

1. ~~**Committed secrets.**~~ **RESOLVED in Phase 1** — `backend/.env.txt` / `detection/.env.txt` were removed from the repo; `.env.example` with placeholders added. (If any key was ever pushed publicly, still rotate it — see Phase 1 exit criteria.)
2. **`detection/` is a broken stale copy.** It lacks `database.py`/`models.py`/`schemas.py`, its `detection_routes.py` predates the `run_detection_job` refactor, and it cannot run. Do not develop there; prefer `backend/`. (Repeated rule files under both trees must stay in sync if both are kept.) **Still present** — scheduled for removal but awaiting explicit approval.
3. ~~**Zero automated tests.**~~ **RESOLVED in Phases 1–4** — pytest suite in `backend/tests/` (115 tests) and `collector/tests/` (10 tests) covers sigma matcher, hash checker, IOC correlation (mocked), detection service, API, security/RBAC, Phase 2 (enroll/config/dedup/analyzed_at), Phase 3 (triage, dashboard mount, metrics, audit log, run-collection queue), Phase 4 (async queue, correlation/incidents, retention, team scoping, audit chain), and agent client.
4. ~~**`backend/requirements.txt` is UTF-16** and missing deps.~~ **RESOLVED in Phase 1** — now a clean UTF-8 top-level file; `alembic` + `psycopg2-binary` added in Phase 2.
5. ~~**Duplicate sigma rule IDs** cause duplicate detections.~~ **RESOLVED in Phase 1** — rule validation + dedup at `load_rules` (deterministic filename sort, skips invalid rules).
6. ~~**Runtime data committed.**~~ **RESOLVED (M7)** — `backend/dfir.db` was a tracked SQLite DB (2,742 artifacts, hostnames). It is now `git rm --cached` (untracked, gitignored) but remains on disk for local demo use; regenerate via migrations + `push_samples.py`. `collector/output/` removed in Phase 3.
7. **Auth is opt-in and off by default.** `AUTH_ENABLED=true` (env) enables the key-gated agent/admin endpoints, but the default lab/demo profile runs open. Keep it on a trusted lab network; CI smoke tests run with auth on for `/endpoints`.
8. **ATT&CK enrichment uses the in-repo STIX dataset** at `dfir-refs/cti/enterprise-attack/enterprise-attack.json` (bundled in Phase 3; ~47 MB). If missing, `enrich_technique` silently returns `None` fields / error dicts.
9. ~~**Ingest has no idempotency.**~~ **RESOLVED in Phase 2** — `?batch_id=` deduplicates repeat `(host, batch_id)` pushes.
10. **`processed=1` is terminal by default** — artifacts are not re-analyzed when new rules are added. **Partially resolved in Phase 3**: `POST /detect?rescan=true` re-analyzes processed artifacts on demand; the scheduler still only scans unprocessed artifacts.
11. **Vestigial code — REMOVED (Phase 3):** `backend/yara_engine.py` (dead code) and its `__main__`-written `test_eicar.yar`; the `detection/` stale copy tree (incl. committed API keys in `detection/.env.txt`); `db/` empty placeholder; `docs/mitre_mapping.json`, `SCHEMA.md`, `sample_data/README.md` empty placeholders; duplicate `suspicious_*.yml`/`test_encoded_ps.yml` sigma rules (canonical `ruleNNN_*.yml` kept); committed `collector/output/` runtime data. **All deleted in Phase 3.**
12. **Small perf/robustness notes:** sigma rules reloaded from disk every detection run; `ioc_correlation._ip_cache` never expires (unbounded growth); live IOC lookups (AbuseIPDB/URLhaus/OTX) and the Feodo refresh are implemented and fail-soft (M2); `collected_at` is stored as a string (no time-window queries); `host` is denormalized (no FK).
13. ~~**`attck_mapper.DEFAULT_STIX_PATH` is CWD-relative.**~~ **RESOLVED in Phase 3** — now repo-root-relative and the dataset is bundled in-repo (`dfir-refs/cti/enterprise-attack/enterprise-attack.json`).
14. **Scheduler + `--reload`:** with uvicorn `--reload` the lifespan runs in the reloader process too; a duplicate scheduler can start. Prefer running without `--reload` for the scheduled path, or verify behavior if this matters.
15. ~~**`detection_runs` history is not yet populated.**~~ **RESOLVED in Phase 3** — `run_detection_job` writes a `DetectionRun` row per cycle (scheduled or manual), so run history feeds the dashboard's "Detection history" view.

---

*End of document. Keep this file updated when the architecture, schema, endpoints, dependencies, or rules change.*
