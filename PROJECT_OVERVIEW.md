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
  - *Ingest API:* receives artifact JSON, validates the envelope, and stores it in SQLite.
  - *Detection engine:* periodically (scheduler) or on-demand (`POST /detect`) sweeps unprocessed artifacts through four detection layers (Sigma-style behavioral rules, embedded YARA matches, known-bad hash matching, network IOC correlation), enriches findings with MITRE ATT&CK technique metadata from a local STIX dataset, persists them, and exposes them for querying.
- **SQLite** (`backend/dfir.db`) — three tables: `hosts`, `artifacts`, `detections`.

Detection is **deliberately decoupled from ingest**: ingest just stores; a background scheduler (APScheduler, every 30 s by default) picks up whatever is unprocessed. This mirrors real EDR/SIEM backend design and keeps ingest fast.

Current state: the pipeline is proven end-to-end on real VM data. The committed `dfir.db` contains 2,742 artifacts from 2 hosts (`DESKTOP-A5E108P` Windows 10, `ns-ubuntu-server` Ubuntu) and 4 detections.

---

## 2. Folder Structure

```
dfir-threat-hunting-frameworkV3/
├── README.md                    # 2 lines; effectively empty (no setup/usage docs)
├── SCHEMA.md                    # EMPTY — referenced by collector docs but never filled in
├── PROJECT_OVERVIEW.md          # this file
├── .gitignore                   # standard Python; ignores venv/, __pycache__, *.db is NOT ignored
│
├── backend/                     # FastAPI ingest + detection API (canonical backend)
│   ├── main.py                  # FastAPI app, ingest/query endpoints, scheduler lifecycle
│   ├── models.py                # SQLAlchemy ORM models: Host, Artifact, Detection
│   ├── schemas.py               # Pydantic request/response models
│   ├── database.py              # SQLite engine, session factory, get_db dependency
│   ├── detection_routes.py      # detection pipeline + /detect /detections endpoints
│   ├── scheduler.py             # APScheduler background job (periodic detection)
│   ├── sigma_matcher.py         # custom Sigma-style rule loader + evaluator
│   ├── hash_checker.py          # known-bad hash matching (iocs/known_bad_hashes.txt)
│   ├── ioc_correlation.py       # network IOC matching (local blocklist + AbuseIPDB)
│   ├── attck_mapper.py          # MITRE ATT&CK enrichment from local STIX dataset
│   ├── push_samples.py          # CLI: push sample_data/ folders into /ingest
│   ├── yara_engine.py           # DEAD CODE — unused by the app (see Known Issues)
│   ├── requirements.txt         # UTF-16 pip-freeze dump; MISSING deps (see Known Issues)
│   ├── README.md                # setup/run notes for the backend
│   ├── .env.txt                 # ⚠ committed API keys (AbuseIPDB) — rotate!
│   ├── dfir.db                  # ⚠ committed SQLite database (runtime data)
│   ├── db/                      # empty (.gitkeep) — placeholder, unused
│   ├── iocs/                    # threat intel data files
│   │   ├── known_bad_hashes.txt # <sha256> <description> lines
│   │   └── malicious_ips.txt    # <ip> <description> lines
│   ├── sigma_rules/             # behavioral detection rules (YAML)
│   │   ├── rule001_*.yml … rule015_*.yml   # 15 canonical rules
│   │   ├── suspicious_*.yml, test_encoded_ps.yml  # duplicate/legacy rules (see Known Issues)
│   │   ├── RULES_INDEX.md       # excellent human-readable rule index
│   │   └── .gitkeep
│   ├── yara_rules/              # YARA rules
│   │   ├── curated_ruleset.yar  # 6 rules used by the collector agent (referenced by index)
│   │   ├── test_eicar.yar       # legacy test rule (unused by pipeline)
│   │   └── .gitkeep
│   └── venv/                    # committed Python venv (gitignored)
│
├── collector/                   # endpoint-side agent
│   ├── collector_agent.py       # CLI entrypoint, orchestrates modules
│   ├── requirements.txt         # psutil, pywin32 (Windows only)
│   ├── README.md                # setup/run notes
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
│   └── output/                  # ⚠ committed collection output (runtime data)
│       └── 2026-07-31_DESKTOP-68VLDRS/   # one folder per collection run
│           ├── processes.json, network.json, persistence.json,
│           ├── scheduled_tasks.json, logs.json, file_scan.json
│
├── detection/                   # ⚠ BROKEN STALE COPY of backend/ detection code
│   ├── attck_mapper.py          # identical copy of backend's
│   ├── detection_routes.py      # OLDER version — no run_detection_job refactor
│   ├── hash_checker.py          # identical copy
│   ├── ioc_correlation.py       # identical copy
│   ├── sigma_matcher.py         # identical copy
│   ├── yara_engine.py           # identical copy
│   ├── requirements.txt         # DIFFERENT — includes yara-python + mitreattack-python
│   ├── .env.txt                 # ⚠ committed API keys (AbuseIPDB, OTX, URLhaus) — rotate!
│   ├── iocs/                    # copies of the two IOC files
│   ├── sigma_rules/             # copies of the sigma rules
│   └── yara_rules/              # copies of the yara rules
│   └── (no database.py, models.py, schemas.py — cannot run standalone)
│
├── sample_data/                 # collected artifact folders (manually copied from VMs)
│   ├── README.md                # EMPTY
│   ├── 2026-07-29_win10-vm01/   # Windows VM: processes/network/persistence/scheduled_tasks/logs .json
│   └── 2026-07-29_ns-ubuntu-server/  # Ubuntu server: same 5 files
│
└── docs/
    └── mitre_mapping.json       # EMPTY placeholder (intended ATT&CK mapping table)
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

### 3.2 SQLite database (`backend/dfir.db`)

Created on first run by `models.Base.metadata.create_all(bind=engine)` in `backend/main.py`.

**`hosts`** — one row per endpoint that has ever reported in.

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
- `run_collection(output_dir, only, yara_rules_dir) -> str` — runs `processes` + `persistence` first (file_scan depends on their output), then `network`, `scheduled_tasks`, `logs`, then `file_scan`. Each module is wrapped in try/except; a failure records `[]` (for processes/persistence) or is skipped, never aborting the run.
- CLI flags: `--output`, `--only processes,network`, `--yara-rules <dir>`.

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

**`backend/main.py`** — FastAPI app (`title="DFIR Ingest & Detection API"`, `version="0.3.0"`).
- Module import creates all DB tables.
- `lifespan(app)` context manager — calls `start_scheduler()` on startup, `stop_scheduler()` on shutdown.
- Includes the detection router.
- Endpoints: `/ingest`, `/artifacts`, `/hosts`, `/health`, `/scheduler/status` (see [§5](#5-api-endpoints)).

**`backend/models.py`** — SQLAlchemy models `Host`, `Artifact`, `Detection` (see [§6](#6-classes) and [§3.2](#32-sqlite-database-backenddfirdb)).

**`backend/schemas.py`** — Pydantic models `ArtifactIn`, `ArtifactOut`, `IngestResponse` (see [§6](#6-classes)).

**`backend/database.py`**
- `DATABASE_URL = "sqlite:///./dfir.db"` (relative to CWD — run uvicorn from `backend/`).
- `engine` — SQLAlchemy engine with `check_same_thread=False` (required for SQLite under FastAPI's threaded request handling).
- `SessionLocal` — `sessionmaker(autocommit=False, autoflush=False)`.
- `Base` — `declarative_base()`.
- `get_db()` — FastAPI dependency; yields a session and always closes it.

**`backend/detection_routes.py`** — the detection pipeline.
- `_row_to_artifact_dict(row) -> dict` — converts an `Artifact` ORM row back to the wire dict (`data` JSON-decoded).
- `_persist_detection(db, d) -> models.Detection` — enriches via `enrich_technique` (if `technique_id` present) and inserts a `Detection` row.
- `run_detection_job(db) -> dict` — the actual pipeline, extracted as a plain function so it runs identically from `POST /detect` and the scheduler:
  1. Select `processed == 0` artifacts.
  2. **Sigma-style behavioral rules** — `sigma_matcher.load_rules(SIGMA_RULES_DIR)` + `evaluate_sigma(rules, artifacts)`.
  3. **Embedded YARA results** — for `file_scan` artifacts, each entry in `data["yara_matches"]` becomes a detection (`rule_id="yara-<rule>"`, severity high).
  4. **Known-bad hash matching** — `hash_checker.check_file_scan_artifacts(artifacts)`.
  5. **Network IOC correlation** — `ioc_correlation.correlate_network_artifacts(artifacts)`.
  6. Persist all detections, mark all scanned artifacts `processed=1`, commit.
  7. Return `{artifacts_scanned, detections_found, by_severity, by_technique}`.
- `_count_by(detections, field) -> dict` — helper counting detections grouped by a field (`unknown` fallback).
- Endpoints: `POST /detect`, `GET /detections`, `GET /detections/summary` (see [§5](#5-api-endpoints)).

**`backend/sigma_matcher.py`** — a lightweight, transparent Sigma-*inspired* matcher (deliberately not a real pySigma backend; the docstring explains this and notes pySigma can be swapped in later).
- Rule file format: YAML with `title`, `id`, `artifact_type`, `technique_id`, `severity`, `condition`.
- `load_rules(rules_dir) -> list` — loads every `.yml`/`.yaml` file via `yaml.safe_load`; **no validation and no duplicate-ID dedup**.
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
- `ABUSEIPDB_API_KEY` — from env via `load_dotenv()`.
- `_extract_ip("1.2.3.4:4444") -> "1.2.3.4"` — `rsplit(":", 1)`.
- `load_local_blocklist(path) -> dict` — parses `ip → description`.
- `_is_private_or_local(ip) -> bool` — `ipaddress` checks (`is_private`/`is_loopback`/`is_link_local`); unparseable → `True`.
- `check_abuseipdb(ip) -> dict` — best-effort live lookup (5 s timeout, confidence ≥ 50 flagged); returns `{}` if no key or any request failure.
- `correlate_network_artifacts(artifacts) -> list` — Layer 1: local blocklist (checked regardless of private status; skips live lookup on match). Layer 2: live AbuseIPDB, skipping private/loopback addresses; results memoized in module-level `_ip_cache`. Emits `ioc-local-blocklist` (severity high) or `ioc-abuseipdb` (high if score ≥ 75 else medium), both `technique_id="T1071"`.

**`backend/attck_mapper.py`**
- `DEFAULT_STIX_PATH` — `os.path.join("..", "..", "dfir-refs", "cti", "enterprise-attack", "enterprise-attack.json")` — **CWD-relative and outside this repo** (expects the `mitre/cti` repo cloned as `dev/dfir-refs/cti`).
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

**`backend/yara_engine.py`** — **DEAD CODE.** Not imported by `main.py` or `detection_routes.py`; the pipeline consumes YARA results that the collector embeds in `file_scan` artifacts instead. Contains `load_rules`, `scan_file`, `scan_bytes` (thin `yara-python` wrappers). Its `__main__` writes `yara_rules/test_eicar.yar`.

### 4.3 `detection/` directory

A **stale, partial copy** of `backend/`'s detection code:
- `detection_routes.py` is an **older version** — it contains the detection pipeline inline inside `POST /detect` (no `run_detection_job` extraction), so it cannot be called by a scheduler.
- It **cannot run standalone**: it imports `database` and `models`, which do not exist in `detection/`.
- The other modules (`attck_mapper.py`, `hash_checker.py`, `ioc_correlation.py`, `sigma_matcher.py`, `yara_engine.py`) are byte-identical to `backend/`.
- `detection/requirements.txt` **differs** from backend's — it includes `yara-python` and `mitreattack-python`, which backend's requirements lack.
- `detection/.env.txt` contains **additional** API keys (OTX, URLhaus) not present in backend's.

> Treat `detection/` as legacy. All active development should happen in `backend/`. It is documented here as-is for context.

---

## 5. API Endpoints

Base URL: `http://127.0.0.1:8000` (auto-generated interactive docs at `/docs`).

### 5.1 Endpoint summary

| Method | Path | Auth | Summary |
|---|---|---|---|
| GET | `/health` | none | Liveness check |
| POST | `/ingest` | none | Store a batch of artifacts |
| GET | `/artifacts` | none | Query stored artifacts (filterable) |
| GET | `/hosts` | none | List all known hosts |
| GET | `/scheduler/status` | none | Scheduler running state |
| POST | `/detect` | none | Manually trigger the detection pipeline |
| GET | `/detections` | none | Query detections (filterable) |
| GET | `/detections/summary` | none | Aggregated detection counts |

> **No authentication/authorization on any endpoint.** Do not expose beyond a trusted lab network (see Known Issues #7).

### 5.2 Endpoint details

**GET `/health`** — Liveness check.
- Response: `{"status": "ok"}`

**POST `/ingest`** — Stores a JSON array of artifacts (the exact content of one collector output file). Request body is `List[ArtifactIn]`.
- Behavior: rejects an empty list (400). Upserts a `Host` row for `artifacts[0].host` (updates `os` if changed). Inserts one `Artifact` row per element with `data` JSON-encoded. Commits once.
- Response `200`: `{"ingested": <n>, "host": <hostname>, "artifact_types": [...]}`
- Errors: `400` empty list; Pydantic `422` on schema violation.
- **No idempotency** — re-posting duplicates rows.

**GET `/artifacts`** — Query stored artifacts.
- Query params: `host` (optional), `artifact_type` (optional), `limit` (default 50, max 500).
- Ordering: `id` descending (newest first).
- Response `200`: `List[ArtifactOut]` — `{id, host, os, artifact_type, collected_at, data, ingested_at, processed}`.

**GET `/hosts`** — List all known hosts.
- Response `200`: `[{id, hostname, os, last_seen}]`.

**GET `/scheduler/status`** — Scheduler state.
- Response `200`: `{running, interval_seconds, next_run_time}`.

**POST `/detect`** — Manually trigger the full detection pipeline (same code path as the scheduler). Uses the request-scoped DB session.
- Response `200`: `{artifacts_scanned, detections_found, by_severity: {...}, by_technique: {...}}`

**GET `/detections`** — Query detections.
- Query params: `host` (optional), `severity` (optional), `limit` (default 100, capped at 500).
- Ordering: `id` descending.
- Response `200`: array of `{id, host, rule_id, rule_title, technique_id, technique_name, tactic, artifact_type, severity, matched_data, detected_at}`.

**GET `/detections/summary`** — Aggregated counts across all stored detections (feeds the ATT&CK-coverage "dashboard" view).
- Response `200`: `{total_detections, by_technique: {...}, by_severity: {...}, by_host: {...}}`

---

## 6. Classes

| Class | Module | Type | Purpose |
|---|---|---|---|
| `Host` | `backend/models.py` | SQLAlchemy model | Table `hosts` — one row per reporting endpoint |
| `Artifact` | `backend/models.py` | SQLAlchemy model | Table `artifacts` — one row per collected artifact |
| `Detection` | `backend/models.py` | SQLAlchemy model | Table `detections` — one row per detection result |
| `ArtifactIn` | `backend/schemas.py` | Pydantic | Request model for `/ingest` items; matches collector `wrap_artifact` output |
| `ArtifactOut` | `backend/schemas.py` | Pydantic | Response model for `/artifacts`; `Config.from_attributes = True` (ORM compatible) |
| `IngestResponse` | `backend/schemas.py` | Pydantic | Response model for `POST /ingest` |

**`Host`** — columns: `id` (int PK, indexed), `hostname` (str, unique, not null, indexed), `os` (str, not null), `last_seen` (DateTime tz, `server_default=func.now()`, `onupdate=func.now()`).

**`Artifact`** — columns: `id` (int PK, indexed), `host` (str, not null, indexed), `os` (str, not null), `artifact_type` (str, not null, indexed), `collected_at` (str, not null), `data` (Text, not null — JSON-encoded), `ingested_at` (DateTime tz, server_default now), `processed` (int, default 0).

**`Detection`** — columns: `id` (int PK, indexed), `host` (str, not null, indexed), `rule_id` (str, not null, indexed), `rule_title` (str, not null), `technique_id` (str, nullable, indexed), `technique_name` (str, nullable), `tactic` (str, nullable), `artifact_type` (str, not null), `severity` (str, nullable), `matched_data` (Text, not null — JSON-encoded), `detected_at` (DateTime tz, server_default now).

**`ArtifactIn`** — fields: `host: str`, `os: str`, `collected_at: str`, `artifact_type: str`, `data: Dict[str, Any]`.

**`ArtifactOut`** — fields: `id: int`, `host`, `os`, `artifact_type`, `collected_at`, `data: Dict[str, Any]`, `ingested_at: Optional[datetime]`, `processed: int`.

**`IngestResponse`** — fields: `ingested: int`, `host: str`, `artifact_types: List[str]`.

> The collector has no classes — it is function-based.

---

## 7. Dependencies

### 7.1 Backend (`backend/requirements.txt`)

⚠ The file is **UTF-16 encoded** (PowerShell `pip freeze`) — `pip install -r requirements.txt` fails on Linux. It is a full frozen dump, and it is **missing** `yara-python` and `mitreattack-python` (both imported by backend code). Content (pinned versions):

| Package | Version | Used by |
|---|---|---|
| fastapi | 0.141.1 | main.py, detection_routes.py |
| uvicorn | 0.52.0 | ASGI server (run command) |
| sqlalchemy | 2.0.51 | database.py, models.py |
| pydantic / pydantic-core | 2.13.4 / 2.46.4 | schemas.py |
| APScheduler | 3.11.3 | scheduler.py |
| PyYAML | 6.0.3 | sigma_matcher.py |
| requests | 2.34.2 | ioc_correlation.py, push_samples.py |
| python-dotenv | 1.2.2 | ioc_correlation.py (`load_dotenv`) |
| (transitives) annotated-doc, annotated-types, anyio, certifi, charset-normalizer, click, colorama, greenlet, h11, httptools, idna, starlette, typing-inspection, typing_extensions, tzdata, tzlocal, urllib3, watchfiles, websockets | | pulled in by the above |

**Missing from backend requirements (present in `detection/requirements.txt`):**
- `yara-python>=4.5.0` — required by `backend/yara_engine.py` (dead code) and the collector's `file_scan.py`.
- `mitreattack-python>=3.0.0` — required by `backend/attck_mapper.py` (lazy import).

**External, not pip-installable:**
- MITRE ATT&CK STIX dataset (`enterprise-attack.json`) — must be cloned (e.g. `git clone https://github.com/mitre/cti`) to `../../(CWD)/dfir-refs/cti/enterprise-attack/enterprise-attack.json` relative to where the backend runs. **Not bundled in this repo** (see Known Issues #8).

### 7.2 Collector (`collector/requirements.txt`)

| Package | Constraint | Notes |
|---|---|---|
| psutil | >=5.9.0 | processes, network modules |
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
[manually] copy collector output folder → sample_data/<date>_<hostname>/
[manually] python backend/push_samples.py sample_data/<date>_<hostname>
  └─ POST {/ingest} with each JSON file's artifact array
       main.py::ingest_artifacts
         ├─ validate with Pydantic ArtifactIn (envelope only; data is free-form)
         ├─ upsert Host row (create or refresh os)
         ├─ insert Artifact row per element (data → JSON text, processed=0)
         └─ commit → response {ingested, host, artifact_types}
```

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
  7. mark all scanned artifacts processed = 1
  8. commit (atomic) → return {artifacts_scanned, detections_found, by_severity, by_technique}
```

Note: sigma rules are **reloaded from disk on every detection run** (no caching). `hash_checker` and `attck_mapper` cache their loaded data; `ioc_correlation` caches live IP lookups per process (never cleared).

### 8.4 Flow D — Query / Reporting

```
GET /detections            → filtered detection rows (host, severity, limit)
GET /detections/summary    → by_technique / by_severity / by_host counts
GET /artifacts             → stored artifacts (host, artifact_type, limit)
GET /hosts                 → known endpoints
GET /scheduler/status      → scheduler state
```

### 8.5 App lifecycle

```
uvicorn main:app (from backend/)
  ├─ import: create_all tables (no-op if present)
  ├─ startup (lifespan): start_scheduler()
  └─ shutdown: stop_scheduler()
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

⚠ **Duplicate/legacy rule files** also live in the folder: `suspicious_powershell.yml` + `test_encoded_ps.yml` (duplicate rule-001), `suspicious_cron.yml` (duplicate rule-002), `suspicious_run_key_temp.yml` (duplicate rule-003). `load_rules` loads **all** of them with no dedup → matching artifacts produce duplicate detections with the same `rule_id`. (Confirmed in committed DB: 4 detections, all `rule-005`, from 4 matching scheduled tasks.)

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

`backend/yara_rules/test_eicar.yar` is a legacy duplicate (only EICAR) — not part of the curated set.

### 9.3 Documented scope limitations (from `RULES_INDEX.md` — keep in mind for future work)
- Severity is heuristic; low-severity discovery rules are meant to correlate, not stand alone.
- Process-injection / in-memory-only techniques (e.g. T1055) are out of scope (collector reads metadata, not memory).
- Port-based C2 detection (rule-010) is a weak signal alone; complemented by the IOC correlation layer.

---

## 10. Known Issues & Gotchas

Facts about the current state that future development must account for.

1. **Committed secrets.** `backend/.env.txt` (AbuseIPDB key) and `detection/.env.txt` (AbuseIPDB + OTX + URLhaus keys) are committed to git. **Rotate these keys and remove the files**; replace with a `.env.example`.
2. **`detection/` is a broken stale copy.** It lacks `database.py`/`models.py`/`schemas.py`, its `detection_routes.py` predates the `run_detection_job` refactor, and it cannot run. Do not develop there; prefer `backend/`. (Repeated rule files under both trees must stay in sync if both are kept.)
3. **Zero automated tests.** Only `__main__` smoke blocks in each module. The 4-engine pipeline, ingest, and DB writes have no regression coverage.
4. **`backend/requirements.txt` is UTF-16** and missing `yara-python` + `mitreattack-python`. `pip install -r` fails on Linux; install missing deps manually or fix the file.
5. **Duplicate sigma rule IDs** cause duplicate detections (see §9.1).
6. **Runtime data committed.** `backend/dfir.db` (2,742 artifacts, hostnames) and `collector/output/` are in git. `dfir.db` is **not** gitignored.
7. **No auth on any API endpoint** and README suggests binding `0.0.0.0`. Keep it on a trusted lab network.
8. **ATT&CK enrichment depends on an external STIX dataset** (`../../dfir-refs/cti/…` relative to CWD) that is not in the repo; if missing, `enrich_technique` silently returns `None` fields / error dicts.
9. **Ingest has no idempotency** — re-posting duplicates artifact rows.
10. **`processed=1` is terminal** — there is no rescan path; artifacts never re-analyzed when new rules are added.
11. **Vestigial code:** `backend/yara_engine.py` (and its `__main__`-written `test_eicar.yar`) is unused by the app; `db/` is an unused empty placeholder; `docs/mitre_mapping.json`, `SCHEMA.md`, and `sample_data/README.md` are empty placeholders.
12. **Small perf/robustness notes:** sigma rules reloaded from disk every detection run; `ioc_correlation._ip_cache` never expires (unbounded growth); `ioc_correlation` advertises URLhaus/Feodo but only implements AbuseIPDB (OTX/URLhaus keys unused); `collected_at` is stored as a string (no time-window queries); `host` is denormalized (no FK); the committed `.env.txt` is named `.env.txt` so `load_dotenv()` in `ioc_correlation.py` will **not** pick it up — the API key currently comes from real env vars.
13. **`attck_mapper.DEFAULT_STIX_PATH` is CWD-relative** — running uvicorn from `backend/` resolves to `dev/dfir-refs/cti/…`; running from the repo root resolves elsewhere. Depends on where the process is launched.
14. **Scheduler + `--reload`:** with uvicorn `--reload` the lifespan runs in the reloader process too; a duplicate scheduler can start. Prefer running without `--reload` for the scheduled path, or verify behavior if this matters.

---

*End of document. Keep this file updated when the architecture, schema, endpoints, dependencies, or rules change.*
