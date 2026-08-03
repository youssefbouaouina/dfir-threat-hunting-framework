# Module Index

Backend code lives in `backend/`, collector in `collector/`. Per AI_RULES: thin endpoints → services → models. Import direction is `main.py` → routes → services → models/database.

## Backend — entry / infra

### `backend/main.py`
- **Purpose:** FastAPI app; wires routers, static dashboard, auth deps, migrations, scheduler lifecycle.
- **Responsibilities:** `migrate_to_head()` (Alembic upgrade at import); `lifespan` start/stop scheduler; define app-level routes (`/health`, `/metrics`, `/audit-logs`, `/ingest`, `/artifacts`, `/hosts`, `/auth/login`, `/scheduler/status`); mount `/dashboard`.
- **Dependencies:** `database`, `detection_routes`, `endpoint_routes`, `security`, `scheduler`, `logging_config`, `services.{audit,ingest,metrics,query}_service`.
- **Inputs:** HTTP requests. **Outputs:** JSON responses; Prometheus text.
- **Key functions:** `migrate_to_head()`, `lifespan(app)`, `health()`, `metrics()`, `ingest_artifacts()`.
- **Status:** Current (v0.5.0). **Future:** add correlation/notifications routes.

### `backend/database.py`
- **Purpose:** engine + session factory + Base.
- **Responsibilities:** `DATABASE_URL` (default `sqlite:///./dfir.db`); `create_engine(check_same_thread=False)`; `SessionLocal`; `get_db()` FastAPI dependency.
- **Dependencies:** sqlalchemy. **Inputs/Outputs:** n/a.
- **Status:** Current. **Future:** pooling config for Postgres scale.

### `backend/models.py`
- **Purpose:** SQLAlchemy ORM models.
- **Classes:** `Endpoint` (endpoints, managed inventory), `Host` (legacy passive hosts), `Artifact` (artifacts), `Detection` (detections + triage cols), `DetectionRun` (run history), `AuditLog` (audit trail), `PendingCommand` (manual-trigger queue).
- **Key fields:** Artifact: `processed`, `analyzed_at`, `source_run_id`, `agent_batch_id`. Detection: `technique_id/name`, `tactic`, `severity`, `triage_status/notes/updated_at/updated_by`. PendingCommand: `status` (pending|picked_up|completed|failed).
- **Dependencies:** `database.Base`. **Status:** Current. **Future:** `incidents`/`incident_detections` (Phase 4).

### `backend/schemas.py`
- **Purpose:** Pydantic v2 I/O models.
- **Classes:** `ArtifactIn/Out`, `IngestResponse`, `EndpointEnrollRequest`, `EndpointOut`, `EndpointConfigUpdateIn`, `EndpointConfigOut`, `DetectionTriageIn`, `AuditLogOut`, `PendingCommandOut`, `PendingCommandResultIn`, `LoginRequest/Response`.
- **Notes:** `TRIAGE_STATUSES` constant duplicated here and in `detection_service.py` (keep in sync).
- **Status:** Current.

### `backend/security.py`
- **Purpose:** opt-in auth + rate limiting.
- **Responsibilities:** env config (`AUTH_ENABLED`, `ADMIN_API_KEY`, `AUTH_SECRET`, `TOKEN_TTL_SECONDS`, `AGENT_API_KEYS`); stdlib HMAC-signed tokens (`issue_token`, `_verify_token`); FastAPI deps `require_agent`, `require_admin`; `authenticate_login`; sliding-window `rate_limit` (in-memory).
- **Key facts:** All deps no-op when `AUTH_ENABLED=false`. Admin key `change-me-admin-key` default.
- **Status:** Current. **Future:** token refresh/revocation; real key store.

### `backend/scheduler.py`
- **Purpose:** background detection cadence.
- **Responsibilities:** APScheduler `BackgroundScheduler`; `_scheduled_detection_run()` opens its own session, calls `run_detection_job(trigger="scheduled")`; `start/stop/get_status`.
- **Key facts:** `DETECTION_INTERVAL_SECONDS` (default 30); `max_instances=1`, `coalesce=True`.
- **Status:** Current. **Future:** queue-based worker in Phase 4.

### `backend/logging_config.py`
- **Purpose:** structured logging.
- **Responsibilities:** `JsonFormatter` (stdlib-only; fields ts/level/logger/message + extras task_id/endpoint/host/status + exception); `configure_logging()` keyed on `LOG_FORMAT` (plain|json) and `LOG_LEVEL`.
- **Status:** Current.

## Backend — routes (thin)

### `backend/detection_routes.py`
- **Routes:** `POST /detect` (host/rescan), `GET /detection-runs`, `GET /detections`, `GET /detections/summary`, `PATCH /detections/{id}` (triage).
- **Auth:** all `Depends(require_admin)`.
- **Dependencies:** `services.detection_service`.
- **Status:** Current. **Future:** correlation endpoints.

### `backend/endpoint_routes.py`
- **Routes (prefix `/endpoints`):** `POST /enroll` (agent), `GET ""` (admin list), `GET /config` (agent poll), `PUT /{id}/config` (admin), `POST /{id}/run-collection` (admin queue), `GET /commands` (agent poll), `POST /commands/{id}/complete` (agent report).
- **Auth:** enroll/config/commands = `require_agent`; list/update/run = `require_admin`.
- **Dependencies:** `services.endpoint_service`.
- **Status:** Current.

## Backend — services (business logic)

### `backend/services/ingest_service.py`
- **Purpose:** persist artifact batches.
- **Functions:** `ingest_artifacts(db, artifacts, batch_id)` — dedupe by `(host, batch_id)`, upsert `Host`, store artifacts with `processed=0`, return `IngestResponse`. Raises `ValueError` on empty batch (→400).
- **Status:** Current.

### `backend/services/query_service.py`
- **Purpose:** read queries.
- **Functions:** `list_artifacts(...)` (filters host/artifact_type/time/processed/limit), `list_hosts()`.
- **Status:** Current.

### `backend/services/detection_service.py`
- **Purpose:** the detection pipeline — single source of truth.
- **Key functions:** `run_detection_job(db, host=None, rescan=False, trigger="manual")` → writes `DetectionRun`, runs 4 engines, persists detections + enrichment, marks artifacts processed, audits; `_persist_detection(db, d)`; `list_detections(...)`; `triage_detection(db, id, status, notes, actor)`; `list_detection_runs(...)`; `detections_summary(db)` (by technique/severity/host/triage).
- **Engines used:** `sigma_matcher.evaluate`, embedded YARA matches in `file_scan` data, `hash_checker.check_file_scan_artifacts`, `ioc_correlation.correlate_network_artifacts`.
- **Constants:** `SIGMA_RULES_DIR`, `TRIAGE_STATUSES`.
- **Notes:** Run row committed first so failure still records a failed run; `db.rollback()` on error keeps run visible.
- **Status:** Current. **Future:** correlation engine hook.

### `backend/services/endpoint_service.py`
- **Purpose:** endpoint inventory + commands.
- **Functions:** `enroll_endpoint` (idempotent; generates+hashes token), `update_endpoint_config` (interval min 10), `queue_collection` (insert `run_collection` PendingCommand), `poll_pending_commands` (pending→picked_up, first-call-wins), `complete_command`, `list_endpoints`, `get_endpoint_config`.
- **Notes:** enrollment token is stored hashed but **not returned to the agent** (vestigial). `DEFAULT_CONFIG` = 6 collectors, 300s.
- **Status:** Current. **Future:** heartbeat/offline detection, key issuance.

### `backend/services/audit_service.py`
- **Purpose:** immutable action trail.
- **Functions:** `log_action(db, action, actor, detail)` — whitelisted actions else `custom:` prefix; `list_audit_logs(db, limit, action)`.
- **Whitelist:** login, run_detection, triage_detection, update_endpoint_config, queue_collection, endpoint_enroll.
- **Status:** Current.

### `backend/services/metrics_service.py`
- **Purpose:** Prometheus-style operational gauges (no library).
- **Functions:** `metrics_text(db)` → 9 gauges (`dfir_artifacts_total`, `_unprocessed`, `dfir_detections_total`, `_open`, `dfir_endpoints_total`, `_online`, `dfir_detection_runs_total`, `dfir_pending_commands`, `dfir_hosts_total`); `health_payload(db)` → live counts for dashboard.
- **Status:** Current. **Future:** histograms, per-rule counts.

## Backend — detection engines

### `backend/sigma_matcher.py`
- **Purpose:** lightweight Sigma-inspired matcher (no pySigma).
- **Functions:** `load_rules(rules_dir)` — validates required keys (`id,title,artifact_type,condition`), dedups by id, deterministic filename sort, skips invalid with warning; `evaluate(rules, artifacts)` — condition operators: exact, in-list, `field_contains`.
- **Rule format:** YAML, e.g. `condition: {cmdline_contains: ["-enc"]}`.
- **Status:** Current. **Future:** pySigma backend swap (Phase 5).

### `backend/hash_checker.py`
- **Purpose:** known-bad hash matching (offline).
- **Functions:** `load_known_bad_hashes(path)` (cached), `check_file_scan_artifacts(artifacts, path)` → detection `rule_id="hash-match"`, severity `critical`, technique `T1204`.
- **Data:** `backend/iocs/known_bad_hashes.txt`.
- **Status:** Current.

### `backend/ioc_correlation.py`
- **Purpose:** network IOC correlation, two layers.
- **Functions:** `load_local_blocklist`, `_extract_ip` (host:port → host), `_is_private_or_local`, `check_abuseipdb(ip)` (best-effort, soft-fail, threshold 50/75), `correlate_network_artifacts(artifacts)`.
- **Rules:** local blocklist → `ioc-local-blocklist` (T1071, high); AbuseIPDB → `ioc-abuseipdb` (T1071, high≥75 else medium). IP cache in-process.
- **Data:** `backend/iocs/malicious_ips.txt`; key `ABUSEIPDB_API_KEY`.
- **Status:** Local layer complete; live layer implemented, OTX/URLhaus/Feodo not implemented.

### `backend/attck_mapper.py`
- **Purpose:** MITRE ATT&CK enrichment from local STIX.
- **Functions:** `_get_attack_data` (lazy mitreattack import, cached), `enrich_technique(technique_id, stix_path=DEFAULT_STIX_PATH)` → name/tactic/description(300 chars); fail-soft.
- **Key fact:** `DEFAULT_STIX_PATH` = `<repo>/dfir-refs/cti/enterprise-attack/enterprise-attack.json` (in-repo since Phase 3); override `STIX_PATH`.
- **Status:** Current.

## Backend — tooling / misc

### `backend/push_samples.py`
- **Purpose:** replay collected JSON folders into `/ingest` (offline demo tool).
- **Functions:** `push_folder(folder, api_url)`.
- **Status:** Current (maintenance mode; superseded for live endpoints by agent daemon).

### `backend/migrations/versions/4823f807fcd2_initial_schema_endpoints_artifacts_.py`
- **Purpose:** Phase 2 initial schema (endpoints, artifacts, detections, detection_runs, hosts); idempotent on legacy `create_all` DBs (has_table guards).
- **Status:** Applied.

### `backend/migrations/versions/ca41c1ba0e02_phase3_triage_lifecycle_audit_logs_.py`
- **Purpose:** Phase 3: `audit_logs` + `pending_commands` tables; PRAGMA-gated add of triage columns to `detections` (`triage_status` server_default `'new'`).
- **Status:** Applied (verified on committed `dfir.db`; 2743 artifacts preserved).

### `backend/static/{index.html, app.js, style.css}`
- **Purpose:** analyst dashboard SPA served at `/dashboard`.
- **Views:** overview (health cards + manual run-detect + summary), endpoints (list, run-collection, edit-config, add-endpoint), detections (filters + triage dropdown), runs (history), artifacts (filters), audit.
- **Auth:** token in localStorage from `POST /auth/login`; 401 → auto-logout.
- **Status:** Current. **Future:** host-criticality, incidents view.

### `backend/Dockerfile`, `backend/docker-entrypoint.sh`, `docker-compose.yml`, `.dockerignore`
- **Purpose:** containerization. Multi-stage non-root build; entrypoint runs `alembic upgrade head` then uvicorn (2 workers); compose = postgres:16-alpine + backend. Agent intentionally not containerized.
- **Status:** Current.

### `backend/alembic.ini`, `backend/pyproject.toml`
- Alembic config; ruff (line-length 100, E/F/W/I/UP/B, ignore B008) + pytest (`testpaths=["tests"]`).
- **Status:** Current.

### `backend/sigma_rules/rule001..rule015_*.yml`
- Canonical Sigma-style rules (deduped; legacy duplicates deleted). `RULES_INDEX.md` documents scope/limitations.
- **Status:** Current.

### `backend/yara_rules/curated_ruleset.yar`
- YARA ruleset run by the **collector** at file-scan time (results embedded in artifacts).
- **Status:** Current.

### `backend/iocs/{known_bad_hashes.txt, malicious_ips.txt}`
- Local offline IOC lists (format: `<value><ws># description`).
- **Status:** Current (needs real feed refresh — maintenance task).

## Collector

### `collector/collector_agent.py`
- **Purpose:** CLI orchestrator (v3). One-shot or `--daemon`.
- **Functions:** `_extract_exe_paths(process, persistence)` → candidate exe paths; `run_collection(output_dir, only, yara_rules_dir)` → runs collectors, writes per-type JSON, file_scan after processes/persistence.
- **Args:** `--output`, `--only`, `--yara-rules`, `--api-url`, `--api-key`, `--enroll`, `--daemon`, `--interval`.
- **Status:** Current.

### `collector/agent_client.py`
- **Purpose:** agent↔backend HTTP client; all calls fail-soft.
- **Functions:** `_post_json`, `get_endpoint_config`, `poll_pending_commands` (returns + backend marks picked_up), `complete_command`, `enroll`, `push_folder` (batch_id = folder name), `daemon_loop` (collect+push cadence + command poll), `make_batch_id`.
- **Status:** Current. Daemon honors backend `collectors` subset + `interval_seconds` (H2).

### `collector/modules/common.py`
- **Purpose:** shared helpers. `get_hostname`, `get_os`, `now_iso`, `wrap_artifact` (envelope builder — single source of truth), `write_json`.
- **Status:** Current.

### `collector/modules/processes.py`
- `collect_processes()` — OS process snapshot (psutil). **Status:** Current.

### `collector/modules/network.py`
- `collect_network()` — active connections incl. `remote_address`, `status`. **Status:** Current.

### `collector/modules/persistence.py`
- `collect_persistence()` — registry Run keys (Windows) / cron, rc.local, systemd services (Linux). **Status:** Current.

### `collector/modules/scheduled_tasks.py`
- `collect_scheduled_tasks()` — Windows tasks / Linux timers. **Status:** Current.

### `collector/modules/logs.py`
- `collect_logs(max_events=200)` — Windows Sysmon / Linux syslog. **Status:** Current.

### `collector/modules/file_scan.py`
- `collect_file_scans(exe_paths, yara_rules_dir, max_file_mb=50)` — sha256 + optional YARA scan (embedded `yara_matches`). Lazy yara import. **Status:** Current.

## Repo root / infra

- **`dfir-refs/cti/enterprise-attack/enterprise-attack.json`** — committed STIX dataset (48 MB); rest of `dfir-refs/` (atomic-red-team, sigma, rules) gitignored via whitelist.
- **`.github/workflows/ci.yml`** — lint+test+gitleaks on push/PR to main; GHCR build+push+smoke on `v*` tags.
- **`backend/dfir.db`** — tracked legacy SQLite DB (2743 artifacts, 4 detections, 3 hosts at checkpoint; migrated to `ca41c1ba0e02`).
- **`SETUP_GUIDE.md`** — 435-line new-user setup/run guide (Windows host + 2 VMs). Written but **uncommitted**.
- **`PROJECT_SUMMARY.md`** — STALE (Phase 1 only).
