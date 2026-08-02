# Phase 3 — Dashboard, Endpoint Management, and Manual Trigger Controls

> **Status:** ✅ DONE — implemented, tested, and committed on the `youssef` branch.
> This document records exactly what was delivered in Phase 3, how to use it,
> and what changed vs. the end of Phase 2.

Companion docs: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) (system as it exists),
[ROADMAP.md](ROADMAP.md) (Phase 3 section with per-item checkboxes).

---

## 1. What was delivered

### 1.1 Analyst dashboard (web app)

A lightweight, dependency-free SPA lives in `backend/static/` and is served by the
backend itself at **`GET /dashboard`** (a `StaticFiles(html=True)` mount in
`main.py`). No build step, no extra npm toolchain — it ships inside the existing
backend container image.

Views (sidebar):
- **Overview** — summary cards (artifacts, detections, endpoints, hosts) + latest
  detection runs.
- **Endpoints** — inventory list with status/last-seen/OS/agent version/interval;
  "Add endpoint" enroll form; per-endpoint **Run collection now** and **Edit config**
  buttons.
- **Detections** — filterable table (host, severity, technique) with an inline
  **triage dropdown** (new / acknowledged / false positive / true positive / reviewed)
  + analyst notes.
- **History** — detection run history (`GET /detection-runs`): trigger, status,
  host scope, rescan flag, timing, counts.
- **Artifacts** — explorer over stored artifacts.
- **Audit** — the admin action audit trail (`GET /audit-logs`).

Auth: the SPA logs in through `POST /auth/login` (Phase 1 JWT flow) and sends the
bearer token; admin/agent-gated routes use the same `require_admin` /
`require_agent` dependencies as the rest of the API.

### 1.2 Endpoint management

- **`PUT /endpoints/{id}/config`** (admin) — edit a single endpoint's agent config
  (`interval_seconds` with a 10-second floor, `collectors` list). Returns the full
  endpoint record. Audit entry: `endpoint_config_update`.
- **`POST /endpoints/{id}/run-collection`** (admin) — "Run collection now". Creates
  a `pending_commands` row (`command=run_collection`) that the agent picks up on its
  next poll. Audit entry: `queue_collection`.
- **`GET /endpoints/commands?hostname=`** (agent) — the agent polls for pending
  commands. All unclaimed commands are returned and flipped `pending → picked_up`
  (first-call-wins, so a command is executed exactly once).
- **`POST /endpoints/commands/{id}/complete`** (agent) — the agent reports the
  outcome (`status: completed|failed` + optional `result`).
- Enroll ("Add endpoint") was already present; it now also writes an
  `endpoint_enroll` audit entry.

### 1.3 Manual detection triggers + history

- **`POST /detect`** gained **`?host=`** (scope to a single host's artifacts) and
  **`?rescan=1`** (re-analyze already-processed artifacts) query params.
- **`GET /detection-runs`** (admin) — run history. `run_detection_job` now writes a
  `DetectionRun` row for **every** cycle (scheduled or manual), so the scheduler no
  longer runs "silently". Each run is also recorded in the audit log
  (`run_detection`, with `run_id` in the detail).
- **`GET /detections/summary`** now includes `by_triage` in addition to the existing
  `by_technique` / `by_severity` / `by_host`.

### 1.4 Detection triage lifecycle

`detections` gained four columns (migration `ca41c1ba0e02`):

| Column | Type | Notes |
|---|---|---|
| `triage_status` | String | default `new`; `new` → `acknowledged` → `false_positive`/`true_positive` → `reviewed` |
| `triage_notes` | Text | analyst notes |
| `triage_updated_at` | DateTime | when triaged |
| `triage_updated_by` | String | acting user (when auth is on) |

`PATCH /detections/{id}` (admin) accepts `{triage_status, notes?}`; invalid statuses
→ `400`, unknown id → `404`. Every change is audit-logged (`triage_detection`).

### 1.5 Ops hardening

- **Structured logging** — new stdlib-only `backend/logging_config.py`. Set
  `LOG_FORMAT=json` for single-line JSON records (ts/level/logger/message + optional
  `task_id`, `endpoint`, `host`, `status` extras); default remains human-readable.
- **`GET /metrics`** (admin) — Prometheus-format text for: `dfir_artifacts_total`,
  `dfir_artifacts_unprocessed`, `dfir_detections_total`, `dfir_detections_open`,
  `dfir_endpoints_total`, `dfir_endpoints_online`, `dfir_detection_runs_total`,
  `dfir_pending_commands`, `dfir_hosts_total`.
- **Audit trail** — new `audit_logs` table + `services/audit_service.py`
  (`log_action` with a `KNOWN_ACTIONS` whitelist; `list_audit_logs`). Exposed at
  **`GET /audit-logs`** (admin; `?action=` filter, `limit` max 1000). Actions
  recorded: `endpoint_enroll`, `endpoint_config_update`, `queue_collection`,
  `run_detection`, `triage_detection`, `complete_command`, `login`.
- **`/health`** now returns a richer payload: `{status, version, scheduler, metrics}`.

### 1.6 ATT&CK enrichment from the bundled STIX dataset

`backend/attck_mapper.py` no longer relies on a CWD-relative external clone. The
MITRE ATT&CK STIX 2.1 dataset is **bundled in the repo** at
`dfir-refs/cti/enterprise-attack/enterprise-attack.json` (~47 MB) and resolved
relative to the repo root. `STIX_PATH` env still overrides. Verified enrichment:
`T1059.001 → PowerShell (execution)`, `T1003 → OS Credential Dumping (credential-access)`.

### 1.7 Cleanup of useless / stale artifacts

The Phase-3 commit **removes**:
- `detection/` — broken stale copy of `backend/` (predates `run_detection_job`, can't
  run standalone, contained **committed API keys** in `detection/.env.txt`).
- `backend/yara_engine.py` — dead code (never imported); its `__main__`-written
  `test_eicar.yar` too.
- Empty placeholders: `db/`, `docs/mitre_mapping.json`, `SCHEMA.md`,
  `sample_data/README.md`.
- Duplicate sigma rules (`suspicious_cron.yml`, `suspicious_powershell.yml`,
  `suspicious_run_key_temp.yml`, `test_encoded_ps.yml`) — canonical `ruleNNN_*.yml`
  retained; `load_rules` dedupes by rule id as a safety net.
- Committed runtime data under `collector/output/`.

### 1.8 Collector agent (Phase 3 additions)

- `agent_client.poll_pending_commands()` — `GET /endpoints/commands`, fail-soft
  (connection error → no command, never crashes the loop).
- `agent_client.complete_command()` — reports collection outcome.
- `daemon_loop` now checks for pending commands each cycle and runs the manual
  collection if one is queued.

---

## 2. Schema & migration

Migration: `backend/migrations/versions/ca41c1ba0e02_phase3_triage_lifecycle_audit_logs_.py`

- Creates `audit_logs` and `pending_commands`.
- Adds the four triage columns to `detections` (PRAGMA-gated on SQLite so it is
  **idempotent** on both fresh and already-migrated DBs; `triage_status`
  `server_default='new'`).

Verified:
- Fresh DB: `'' → 4823f807fcd2 → ca41c1ba0e02` → tables `artifacts, audit_logs,
  detection_runs, detections, endpoints, hosts, pending_commands`, version
  `ca41c1ba0e02`.
- Legacy committed `dfir.db`: idempotent re-run after a half-applied attempt;
  2,743 artifacts / 4 detections / 3 hosts all preserved.

---

## 3. New / changed files

| File | Change |
|---|---|
| `backend/models.py` | `Detection` triage columns; `AuditLog`; `PendingCommand` |
| `backend/schemas.py` | `ConfigDict`; `DetectionTriageIn`, `EndpointConfigUpdateIn`, `AuditLogOut`, `PendingCommandOut`, `PendingCommandResultIn`, `TRIAGE_STATUSES` |
| `backend/services/detection_service.py` | pipeline moved here; host scope + rescan; run-history rows; triage |
| `backend/services/endpoint_service.py` | config update, run-collection queue, command poll/complete, audit entries |
| `backend/services/audit_service.py` | **new** — audit log |
| `backend/services/metrics_service.py` | **new** — Prometheus metrics + health payload |
| `backend/detection_routes.py` | triage `PATCH`, `GET /detection-runs`, scope/rescan on `POST /detect` |
| `backend/endpoint_routes.py` | `PUT /{id}/config`, `POST /{id}/run-collection`, `GET /commands`, `POST /commands/{id}/complete` |
| `backend/main.py` | v0.5.0; `/dashboard` static mount; `/metrics`; `/audit-logs`; richer `/health`; `configure_logging()` |
| `backend/logging_config.py` | **new** — structured JSON logging |
| `backend/attck_mapper.py` | repo-root STIX path (`dfir-refs/…/enterprise-attack.json`) |
| `backend/static/index.html` + `style.css` + `app.js` | **new** — dashboard SPA |
| `backend/migrations/versions/ca41c1ba0e02_*.py` | **new** — Phase 3 migration |
| `backend/tests/test_phase3.py` | **new** — 9 tests |
| `backend/tests/test_api.py` | updated `/health` assertion (metrics payload) |
| `collector/agent_client.py` | command poll + complete; daemon loop runs manual collections |
| `collector/collector_agent.py` | help text no longer references removed `../detection/` tree |
| `collector/tests/test_agent_client.py` | +3 tests (poll returns list, fail-soft, complete) |
| `dfir-refs/cti/enterprise-attack/enterprise-attack.json` | **new** — bundled ATT&CK STIX dataset (rest of `dfir-refs/` gitignored) |
| `.gitignore` | ignore `dfir-refs/*` except the committed `enterprise-attack.json` |
| `ROADMAP.md` / `PROJECT_OVERVIEW.md` | Phase 3 status + full system doc update |

---

## 4. How to run / use it

```bash
# backend (from repo root)
PYTHONPATH=backend python3 -m uvicorn main:app --app-dir backend --port 8000
# → open http://127.0.0.1:8000/dashboard

# agent with manual-trigger support (any shell on the endpoint)
python3 collector_agent.py --enroll --api-url http://<backend>:8000 \
    --api-key <agent_key> --daemon --interval 60
```

Dashboard workflow (proves the Phase 3 exit criteria — no CLI/curl needed):
1. **Add endpoint** in the Endpoints view → the returned config keys the agent.
2. Start the agent (`--daemon`) → it enrolls and starts pushing artifacts.
3. Click **Run collection now** → agent picks up the `run_collection` command next
   poll and reports back (`pending → picked_up → completed`).
4. Click **Run detection now** (with optional host scope / rescan) → result shown
   inline; the run appears in **History** and the audit trail.
5. Triage any new detection via the dropdown + notes.

---

## 5. Tests

- `backend/tests/test_phase3.py` (9 tests): triage lifecycle, invalid-status `400`,
  missing-detection `404`, summary `by_triage`, endpoint config edit + run-collection
  queue → poll → complete → config picked up, interval `< 10` → `400`, `/metrics`
  text, audit log recorded, `/dashboard` served.
- `collector/tests/` (7 total): + poll returns list, fail-soft poll, complete_command.
- Full suite: **backend 53 passed**, **collector 7 passed**, `ruff` clean on both trees.

---

## 6. Known follow-ups (deferred, not part of Phase 3)

- Agent packaging (`Dockerfile.agent` / one-file bundle) — Phase 2 leftover.
- `ioc_correlation` still advertises OTX/URLhaus but only implements AbuseIPDB;
  `_ip_cache` never expires.
- Scheduler + uvicorn `--reload` can double-start the scheduler (prefer no `--reload`).
- `collected_at` stored as a string (no time-window queries); `host` denormalized.
