# Module Index

Backend code lives in `backend/`, collector in `collector/`. Per AI_RULES: thin endpoints → services → models. Import direction is `main.py` → routes → services → models/database.

## Backend — entry / infra

### `backend/main.py`
- **Purpose:** FastAPI app; wires routers, static dashboard, auth deps, migrations, scheduler lifecycle.
- **Responsibilities:** `migrate_to_head()` (Alembic upgrade at import); `lifespan` start/stop scheduler; define app-level routes (`/health`, `/metrics`, `/audit-logs`, `/audit-logs/verify`, `/ingest`, `/artifacts`, `/hosts`, `/auth/login`, `/scheduler/status`, `/retention/*`); mount `/dashboard`; register `sigma_router`, `ioc_router`, `taxii_router`, `stats_router` (F6–F8).
- **Dependencies:** `database`, `detection_routes`, `endpoint_routes`, `incident_routes`, `retention_routes`, `sigma_routes`, `ioc_routes`, `taxii_routes`, `stats_routes`, `security`, `scheduler`, `logging_config`, `services.{audit,ingest,metrics,query}_service`.
- **Inputs:** HTTP requests. **Outputs:** JSON responses; Prometheus text.
- **Key functions:** `migrate_to_head()`, `lifespan(app)`, `health()`, `metrics()`, `ingest_artifacts()`.
- **Status:** Current (v0.5.0). **Future:** notifications fully wired into dashboard (F5 landed: service + hooks + env).

### `backend/database.py`
- **Purpose:** engine + session factory + Base.
- **Responsibilities:** `DATABASE_URL` (default `sqlite:///./dfir.db`); `create_engine(check_same_thread=False)`; `SessionLocal`; `get_db()` FastAPI dependency.
- **Dependencies:** sqlalchemy. **Inputs/Outputs:** n/a.
- **Status:** Current (F8). **Future:** pooling config for Postgres scale — done (env-driven `DB_POOL_ENABLED/SIZE/MAX_OVERFLOW/RECYCLE/PRE_PING`, Postgres-only).

### `backend/models.py`
- **Purpose:** SQLAlchemy ORM models.
- **Classes:** `Endpoint` (endpoints + team, managed inventory), `Host` (legacy passive hosts), `Artifact` (artifacts), `Detection` (detections + triage cols), `DetectionRun` (run history), `Incident` + `IncidentDetection` (correlated incidents, F2), `AuditLog` (audit trail + `prev_hash`/`record_hash` hash chain, F4), `PendingCommand` (manual-trigger queue), `Ioc` (feed-derived indicators, F7; unique `(value, ioc_type, source)`), `StatsSnapshot` (materialized stats cache, F8; unique `metric`).
- **Key fields:** Artifact: `processed`, `analyzed_at`, `source_run_id`, `agent_batch_id`. Detection: `technique_id/name`, `tactic`, `severity`, `triage_status/notes/updated_at/updated_by`. Endpoint: `team` (String, default `"default"`, indexed). Incident: `signature` (idempotent recompute key), `status`, `severity`, `critical_hosts`. AuditLog: `prev_hash`, `record_hash` (SHA-256 chain). PendingCommand: `status` (pending|picked_up|completed|failed). Ioc: `value`, `ioc_type` (ip|domain|url|file_hash), `source`, `first_seen/last_seen`. StatsSnapshot: `metric`, `value` (JSON), `computed_at`.
- **Dependencies:** `database.Base`. **Status:** Current.

### `backend/schemas.py`
- **Purpose:** Pydantic v2 I/O models.
- **Classes:** `ArtifactIn/Out`, `IngestResponse`, `EndpointEnrollRequest`, `EndpointOut` (incl. `team`), `EndpointConfigUpdateIn`, `EndpointConfigOut`, `EnrollResponse`, `DetectionTriageIn`, `AuditLogOut`, `PendingCommandOut`, `PendingCommandResultIn`, `LoginRequest/Response` (incl. `role`/`team`), `IncidentOut`, `IncidentTriageIn`, `RetentionStatusOut`.
- **Notes:** `TRIAGE_STATUSES` constant duplicated here and in `detection_service.py` (keep in sync).
- **Status:** Current.

### `backend/security.py`
- **Purpose:** opt-in auth + RBAC + rate limiting.
- **Responsibilities:** env config (`AUTH_ENABLED`, `ADMIN_API_KEY`, `ANALYST_API_KEYS`/`VIEWER_API_KEYS` in `key@team` form, `AUTH_SECRET`, `TOKEN_TTL_SECONDS`, `AGENT_API_KEYS`, `RATE_LIMIT_ENABLED`); roles `ROLE_ADMIN`/`ROLE_ANALYST`/`ROLE_VIEWER`; stdlib HMAC-signed tokens (`issue_token` embeds `role`+`team`, `_verify_token`, `_decode_token`); FastAPI deps `require_agent`, `require_admin`, `current_user` (returns `{role, team, subject}`), `require_role(*roles)` factory; `authenticate_login` (returns `{role, team}`); sliding-window `rate_limit` (in-memory).
- **Key facts:** All deps no-op when `AUTH_ENABLED=false` (open-lab demo mode). Admin key `change-me-admin-key` default (startup refuses placeholders when auth on). Startup rejects empty `AGENT_API_KEYS` when auth enabled.
- **Status:** Current. **Future:** token refresh/revocation; real key store.

### `backend/scheduler.py`
- **Purpose:** background detection cadence.
- **Responsibilities:** APScheduler `BackgroundScheduler`; `_scheduled_detection_run()` opens its own session, calls `run_detection_job(trigger="scheduled")`; `start/stop/get_status`.
- **Key facts:** `DETECTION_INTERVAL_SECONDS` (default 30); `max_instances=1`, `coalesce=True`. Phase 3+ added `offline_sweep` (M6), `intel_refresh` (M2), and `retention_sweep` (F3) jobs; Phase 5 (F7/F8) added `_scheduled_intel_refresh` (own session → `intel_service.refresh_all_feeds`) and `_scheduled_stats_compute` (`STATS_INTERVAL_SECONDS`, default 60).
- **Status:** Current. **Future:** queue-based worker in Phase 4 — done (`workers/detection_worker.py`, F5).

### `backend/logging_config.py`
- **Purpose:** structured logging.
- **Responsibilities:** `JsonFormatter` (stdlib-only; fields ts/level/logger/message + extras task_id/endpoint/host/status + exception); `configure_logging()` keyed on `LOG_FORMAT` (plain|json) and `LOG_LEVEL`.
- **Status:** Current.

## Backend — routes (thin)

### `backend/detection_routes.py`
- **Routes:** `POST /detect` (host/rescan), `GET /detection-runs`, `GET /detections`, `GET /detections/summary`, `PATCH /detections/{id}` (triage).
- **Auth:** admin/analyst list+summary; triage requires `require_role("admin","analyst")`; scoped by team via `current_user` → `_scope_hosts`.
- **Dependencies:** `services.detection_service`, `services.query_service.scoped_hosts`, `security`.
- **Status:** Current.

### `backend/endpoint_routes.py`
- **Routes (prefix `/endpoints`):** `POST /enroll` (agent), `GET ""` (admin list), `GET /config` (agent poll), `PUT /{id}/config` (admin), `POST /{id}/run-collection` (admin queue), `GET /commands` (agent poll), `POST /commands/{id}/complete` (agent report).
- **Auth:** enroll/config/commands = `require_agent`; list/update/run = `require_admin`; list also scoped by team via `current_user`.
- **Dependencies:** `services.endpoint_service`.
- **Status:** Current.

### `backend/incident_routes.py`
- **Routes (prefix `/incidents`):** `GET ""` (list, scoped), `GET /summary`, `GET /{id}`, `POST /recompute`, `PATCH /{id}` (triage).
- **Auth:** list/summary scoped by team; recompute + triage require `require_role("admin","analyst")` and pass `actor` (audited).
- **Dependencies:** `services.correlation_service`, `security`.
- **Status:** Current (F2).

### `backend/retention_routes.py`
- **Routes (prefix `/retention`):** `GET /status`, `POST /run` (audited, admin).
- **Dependencies:** `services.retention_service`, `services.audit_service`.
- **Status:** Current (F3).

### `backend/sigma_routes.py`
- **Routes (prefix `/sigma`):** `GET /status` (rules loaded per source), `GET /rules` (listing), `POST /refresh` (admin, audited) — re-imports SigmaHQ into `sigma_rules/native/sigmahq/` (local dir or shallow git clone).
- **Dependencies:** `services.sigma_service`, `security`.
- **Status:** Current (F6).

### `backend/ioc_routes.py`
- **Routes (prefix `/iocs`):** `GET ""` (list, filter + cursor page), `GET /status` (per-feed last refresh + circuit-breaker states), `POST /refresh` (admin, audited), `POST /breakers/reset` (admin, audited), `GET /export/stix` (STIX 2.1 bundle).
- **Dependencies:** `services.intel_service`, `security`, `services.audit_service`.
- **Status:** Current (F7/F8).

### `backend/taxii_routes.py`
- **Routes (prefix `/taxii`):** `GET /` (discovery), `GET /api/` (root), `GET /api/collections`, `GET /api/collections/{id}/objects` — minimal read-only TAXII 2.1 server over the IOC store.
- **Dependencies:** `services.intel_service` (taxii envelopes).
- **Status:** Current (F7).

### `backend/stats_routes.py`
- **Routes (prefix `/stats`):** `GET /summary` (cached values for detection_summary/health_counts/ioc_counts), `POST /recompute` (admin, audited).
- **Dependencies:** `services.stats_service`, `security`, `services.audit_service`.
- **Status:** Current (F8).

## Backend — services (business logic)

### `backend/services/ingest_service.py`
- **Purpose:** persist artifact batches.
- **Functions:** `ingest_artifacts(db, artifacts, batch_id)` — dedupe by `(host, batch_id)`, upsert `Host`, store artifacts with `processed=0`, return `IngestResponse`. Raises `ValueError` on empty batch (→400).
- **Status:** Current.

### `backend/services/query_service.py`
- **Purpose:** read queries.
- **Functions:** `list_artifacts(...)` (filters host/artifact_type/time/processed/limit + `hosts` team allow-list), `list_hosts()`, `scoped_hosts(db, team)` → list of hostnames for a team, or `None` when no team (unscoped).
- **Status:** Current.

### `backend/services/detection_service.py`
- **Purpose:** the detection pipeline — single source of truth.
- **Key functions:** `run_detection_job(db, host=None, rescan=False, trigger="manual")` → writes `DetectionRun`, runs 5 engines, persists detections + enrichment, marks artifacts processed, audits, then recomputes incidents (F2); `_persist_detection(db, d)`; `list_detections(...)` (hosts-scoped); `triage_detection(db, id, status, notes, actor)`; `list_detection_runs(...)` (hosts-scoped); `detections_summary(db, hosts=None)` (by technique/severity/host/triage, GROUP BY).
- **Engines used:** `sigma_matcher.evaluate` (legacy) + `sigma_engine` pySigma backend (F6), embedded YARA matches in `file_scan` data, `hash_checker.check_file_scan_artifacts`, `ioc_correlation.correlate_network_artifacts`.
- **Constants:** `SIGMA_RULES_DIR`, `TRIAGE_STATUSES`.
- **Notes:** Run row committed first so failure still records a failed run; `db.rollback()` on error keeps run visible.
- **Status:** Current.

### `backend/services/endpoint_service.py`
- **Purpose:** endpoint inventory + commands.
- **Functions:** `enroll_endpoint` (idempotent; generates+hashes token, returns `enrollment_token` once on first enroll), `update_endpoint_config` (interval min 10), `queue_collection` (insert `run_collection` PendingCommand), `poll_pending_commands` (pending→picked_up, first-call-wins), `complete_command`, `list_endpoints(db, limit, team)` (team-filtered), `get_endpoint_config`, `mark_offline_stale`, `_touch_endpoint` (heartbeat restore).
- **Notes:** Enrollment token returned once (H1). Heartbeat/offline via config poll + `offline_sweep` (M6). `DEFAULT_CONFIG` = 6 collectors, 300s.
- **Status:** Current.

### `backend/services/audit_service.py`
- **Purpose:** immutable action trail.
- **Functions:** `log_action(db, action, actor, detail)` — whitelisted actions else `custom:` prefix; computes `record_hash` chained over `(prev_hash, actor, action, detail_json)` (SHA-256, F4); `list_audit_logs(db, limit, action)`; `verify_audit_chain(db)` → `{valid, checked, broken_at}` (skips legacy NULL-hash rows).
- **Whitelist:** login, run_detection, triage_detection, update_endpoint_config, queue_collection, endpoint_enroll, complete_command, recompute_incidents, triage_incident, retention_run, sigma_refresh, ioc_refresh, ioc_breaker_reset, stats_recompute.
- **Status:** Current (F4 hash chain).

### `backend/services/metrics_service.py`
- **Purpose:** Prometheus-style operational gauges (no library).
- **Functions:** `metrics_text(db)` → 9 gauges (`dfir_artifacts_total`, `_unprocessed`, `dfir_detections_total`, `_open`, `dfir_endpoints_total`, `_online`, `dfir_detection_runs_total`, `dfir_pending_commands`, `dfir_hosts_total`); `health_payload(db)` → live counts for dashboard.
- **Status:** Current. **Future:** histograms, per-rule counts.

### `backend/services/correlation_service.py`
- **Purpose:** correlation engine (F2) — groups detections into incidents.
- **Functions:** `recompute_incidents(db, actor)` — idempotent, signature-keyed (`rule+technique+host set+window`); preserves triage on recompute; stale cleanup; `list_incidents(db, status, severity, hosts)` (hosts-scoped via `IncidentDetection→Detection.host`), `incidents_summary(db)`, `get_incident(db, id)`, `triage_incident(db, id, status, notes, actor)`.
- **Logic:** campaigns = same rule on ≥2 hosts; chains = ≥2 techniques on one host (ATT&CK sequence); severity escalation.
- **Status:** Current (F2).

### `backend/services/retention_service.py`
- **Purpose:** storage retention/archival (F3).
- **Functions:** `run_retention(db)` — ages out rows per `RETENTION_*_DAYS` (artifacts/detections/detection_runs/audit_logs) into monthly JSONL under `RETENTION_ARCHIVE_DIR`, optional OpenSearch bulk sink (`OPENSEARCH_URL`, fail-soft, `_id={table}-{row_id}`), batch delete (idempotent, per-batch commits), incident-link cleanup; `retention_status(db)`.
- **Notes:** off by default (no `RETENTION_*_DAYS` set). Known B9: crash between JSONL append and DB delete can duplicate an archive line (harmless).
- **Status:** Current (F3).

### `backend/services/intel_service.py`
- **Purpose:** IOC feed automation + STIX/TAXII export (F7).
- **Functions:** `refresh_all_feeds(db)` — per-feed fetchers (Feodo `_parse_feodo_ips`, URLhaus CSV via `csv.DictReader`, MalwareBazaar `get_recent` API, OTX pulses keyless-or-skipped), each behind its own circuit breaker, idempotent upsert into `Ioc`, fail-soft per feed (one dead feed never aborts the batch); `list_iocs(...)` (type/source/value filter, cursor page), `ioc_status(db)` (per-feed last refresh + breaker states), `lookup_ioc`, `export_stix_bundle(db)` (STIX 2.1 indicators, hand-rolled — no stix2 dep), `taxii_*` envelope builders; `get_breaker_status()/reset_breaker(name)`.
- **Env:** `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `INTEL_REFRESH_INTERVAL_SECONDS`; breaker knobs `IOC_FEED_FAILURE_THRESHOLD` (3), `IOC_FEED_RESET_TIMEOUT_SECONDS` (300).
- **Status:** Current (F7).

### `backend/services/circuit_breaker.py`
- **Purpose:** per-feed fault isolation (F8).
- **Classes:** `CircuitBreaker(name, failure_threshold, reset_timeout_seconds)` — states closed/open/half_open, thread-safe (Lock); `CircuitOpenError`; `call()/record_success/record_failure`.
- **Status:** Current (F8).

### `backend/services/stats_service.py`
- **Purpose:** materialized stats (F8, portable stand-in for a Postgres matview).
- **Functions:** `compute_all(db)` — recomputes `detection_summary`, `health_counts`, `ioc_counts` into `StatsSnapshot`; `get_snapshot(db)` / `snapshot_status(db)`; fail-soft.
- **Status:** Current (F8).

## Backend — queue / workers (F1)

### `backend/ingest_queue.py`
- **Purpose:** async ingest queue bridge (F1).
- **Functions:** `enqueue_artifacts(...)` / `dequeue_artifacts()` via Redis (`INGEST_QUEUE_URL`); fail-soft when Redis is unavailable (caller falls back to sync ingest).
- **Status:** Current (F1).

### `backend/workers/ingest_worker.py`
- **Purpose:** drains the Redis ingest queue → `ingest_service.ingest_artifacts` (preserves `batch_id` idempotency).
- **Status:** Current (F1).

## Backend — detection engines

### `backend/sigma_matcher.py`
- **Purpose:** lightweight Sigma-inspired matcher (no pySigma).
- **Functions:** `load_rules(rules_dir)` — validates required keys (`id,title,artifact_type,condition`), dedups by id, deterministic filename sort, skips invalid with warning; `evaluate(rules, artifacts)` — condition operators: exact, in-list, `field_contains`.
- **Rule format:** YAML, e.g. `condition: {cmdline_contains: ["-enc"]}`.
- **Status:** Current (legacy). **Future:** pySigma backend swap (Phase 5) — done; see `sigma_engine` below (both engines run).

### `backend/sigma_engine.py`
- **Purpose:** real pySigma backend (F6).
- **Functions:** `pysigma_backend()` — `pySigmaBackend` with `FIELD_MAP` (Sigma field → collector schema per artifact_type) + `LOGSRC_TO_ARTIFACT` (logsource → artifact_type); `parse_rules(...)`/`load_rules(...)`; `evaluate(rules, artifacts)` — walks the typed condition tree (parsed once, cached) honoring `1 of`/`all of` selectors, `NOT` filters, and modifiers (`|re`, `|cidr`, `|gte`, `|contains`, case-insensitive `SigmaString` regex).
- **Rule format:** native Sigma YAML under `sigma_rules/native/` + SigmaHQ import under `sigma_rules/native/sigmahq/`.
- **Status:** Current (F6).

### `backend/services/sigma_service.py`
- **Purpose:** SigmaHQ update pipeline (F6).
- **Functions:** `refresh_sigma_rules(db, actor)` — imports rules from a local `SIGMA_RULES_DIR` or shallow-clones the SigmaHQ repo into `sigma_rules/native/sigmahq/` (filter `logsource` mapping, dedup by rule id); `sigma_status(db)` → per-source counts + last refresh; `list_rules(db)`.
- **Env:** `SIGMA_RULES_DIR`, `SIGMAHQ_REPO_URL`.
- **Status:** Current (F6).

### `backend/hash_checker.py`
- **Purpose:** known-bad hash matching (offline).
- **Functions:** `load_known_bad_hashes(path)` (cached), `check_file_scan_artifacts(artifacts, path)` → detection `rule_id="hash-match"`, severity `critical`, technique `T1204`.
- **Data:** `backend/iocs/known_bad_hashes.txt`.
- **Status:** Current.

### `backend/ioc_correlation.py`
- **Purpose:** network IOC correlation, two layers.
- **Functions:** `load_local_blocklist`, `_extract_ip` (host:port → host), `_is_private_or_local`, `check_abuseipdb(ip)` (best-effort, soft-fail, threshold 50/75), `check_urlhaus(domain)`, `check_otx(ip)` (M2), `refresh_feodo_blocklist()` → writes `iocs/feodo_ips.txt` (superseded by `intel_service` for scheduled refresh, F7), `correlate_network_artifacts(artifacts)`.
- **Rules:** local blocklist → `ioc-local-blocklist` (T1071, high); AbuseIPDB → `ioc-abuseipdb` (T1071, high≥75 else medium); URLhaus/OTX/Feodo merged. IP cache in-process.
- **Data:** `backend/iocs/malicious_ips.txt` + `iocs/feodo_ips.txt`; keys `ABUSEIPDB_API_KEY`, `OTX_API_KEY`.
- **Status:** Local layer complete; live layer (AbuseIPDB/URLhaus/OTX + Feodo refresh) implemented (M2), all fail-soft. F7 adds a DB-backed `Ioc` store + scheduled `refresh_all_feeds` (keeps the txt files in sync).

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
- **Status:** Applied.

### `backend/migrations/versions/e19d4f2a7c10_phase4_correlation_engine_incidents_.py`
- **Purpose:** Phase 4 F2: `incidents` + `incident_detections` tables (`signature` idempotency key, severity/host indexes, FK cascade).
- **Status:** Applied.

### `backend/migrations/versions/4a1f2c9d3b70_phase4_rbac_endpoint_team_audit_.py`
- **Purpose:** Phase 4 F4: `endpoints.team` column (indexed) + `audit_logs.prev_hash`/`record_hash` (hash chain). Idempotent per-column `ALTER`; `team` stays DB-nullable (SQLite can't ALTER nullability; service layer defaults it). Down from `e19d4f2a7c10`.
- **Status:** Applied.

### `backend/migrations/versions/5f0a1c2d9b73_phase4_notifications_criticality.py`
- **Purpose:** Phase 4 F5: `endpoints.criticality` column (low/standard/important/critical).
- **Status:** Applied.

### `backend/migrations/versions/6f7a1b2c3d4e_phase5_ioc_feed_automation.py`
- **Purpose:** Phase 5 F7: `iocs` table (`value`, `ioc_type`, `source`, `first_seen`/`last_seen`, unique `(value, ioc_type, source)`).
- **Status:** Applied (head `7a8b1c2d3e4f`).

### `backend/migrations/versions/7a8b1c2d3e4f_phase5_perf_composite_indexes_stats.py`
- **Purpose:** Phase 5 F8: composite indexes on hot query paths (artifacts `processed+ingested_at`, detections `host+detected_at`, detections `rule_id+detected_at`, audit_logs `action+created_at`, incidents `status+updated_at`) + `stats_snapshots` table. Idempotent.
- **Status:** Applied (current head).

### `backend/static/{index.html, app.js, style.css}`
- **Purpose:** analyst dashboard SPA served at `/dashboard`.
- **Views:** overview (health cards + manual run-detect + summary), endpoints (list, run-collection, edit-config, add-endpoint), detections (filters + triage dropdown), runs (history), artifacts (filters), audit.
- **Auth:** token in localStorage from `POST /auth/login`; 401 → auto-logout. Overview auto-refreshes every 15s (D3); scheduler status box (D4).
- **Status:** Current. **Future:** incidents/notifications/IOC/STIX views (APIs exist — F2/F5/F7 — UI pending).

### `backend/Dockerfile`, `backend/docker-entrypoint.sh`, `docker-compose.yml`, `.dockerignore`
- **Purpose:** containerization. Multi-stage non-root build; entrypoint runs `alembic upgrade head` then uvicorn (2 workers); compose = postgres:16-alpine + backend. Agent intentionally not containerized.
- **Status:** Current.

### `backend/alembic.ini`, `backend/pyproject.toml`
- Alembic config; ruff (line-length 100, E/F/W/I/UP/B, ignore B008) + pytest (`testpaths=["tests"]`).
- **Status:** Current.

### `backend/sigma_rules/rule001..rule015_*.yml`
- Canonical Sigma-style rules (deduped; legacy duplicates deleted). `RULES_INDEX.md` documents scope/limitations.
- **Status:** Current.

### `backend/sigma_rules/native/`
- 6 native pySigma rules (F6) — real Sigma YAML with `logsource` + `detection` blocks, evaluated by `sigma_engine.py`. SigmaHQ imports land in `sigma_rules/native/sigmahq/` (gitignored).

### `backend/yara_rules/curated_ruleset.yar`
- YARA ruleset run by the **collector** at file-scan time (results embedded in artifacts).
- **Status:** Current.

### `backend/iocs/{known_bad_hashes.txt, malicious_ips.txt}`
- Local offline IOC lists (format: `<value><ws># description`).
- **Status:** Current. Feodo blocklist refreshed automatically by `intel_service` (F7); curated lists remain manual.

### `k8s/` (repo root)
- **Purpose:** Phase 5 F8 HA manifests for a Postgres deployment. Files: `namespace.yaml`, `configmap.yaml`, `secret.example.yaml` (template — real secrets via sealed/k8s), `backend-deployment.yaml` (3 replicas, probes, resource limits), `backend-hpa.yaml` (3–10 replicas, CPU+memory), `backend-service.yaml`, `backend-pdb.yaml` (minAvailable 2), `ingest-worker-deployment.yaml`, `postgres.yaml` (StatefulSet).
- **Image:** `ghcr.io/youssefbouaouina/dfir-threat-hunting-framework:latest`. **Status:** Current (F8).

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
- **`.github/workflows/ci.yml`** — lint+mypy+pytest+pip-audit+gitleaks on push/PR; GHCR build+push+smoke on `v*` tags; containerized `agent-e2e` job (F1 exercises async queue loop).
- **`backend/dfir.db`** — untracked local SQLite DB (migrated to `4a1f2c9d3b70`; regenerable via migrations + `push_samples.py`).
- **`SETUP_GUIDE.md`** — 435-line new-user setup/run guide (Windows host + 2 VMs). Committed (H3).
- **`PROJECT_SUMMARY.md`** — refreshed for Phases 1–3 + F1–F4 (see summary update).
- **Tests:** `backend/tests/test_rbac.py` (F4, 14), `test_retention.py` (F3, 9), `test_phase4.py` (F1/F2, 9), `test_sigma_engine.py` (F6, 16), `test_intel_service.py` (F7, 17), `test_f8.py` (F8, 13); backend total 179, collector 10.
