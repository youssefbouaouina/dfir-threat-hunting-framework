# Execution Flow

Complete end-to-end flow from backend startup through collection, ingest, detection, and reporting. Two parallel producers (scheduled auto-detection and manual dashboard triggers) share one pipeline entry point.

## Stage 0 — Backend startup

1. `backend/main.py` imported → `configure_logging()` (root logger; `LOG_FORMAT=plain|json`).
2. `_BACKEND_DIR` added to `sys.path` (so `import schemas/models/...` resolve when run from elsewhere).
3. `migrate_to_head()` runs at **import time**: builds Alembic `Config` from `backend/alembic.ini`, overrides `sqlalchemy.url` from `DATABASE_URL` if set, `command.upgrade(..., "head")`. Result: `dfir.db` (or Postgres) is at revision `ca41c1ba0e02` before the app serves traffic. **This is why there is no `Base.metadata.create_all` anywhere.**
4. FastAPI app created (v0.5.0), detection + endpoint routers included, `/dashboard` static mounted if `backend/static/` exists.
5. `lifespan` runs on startup: `start_scheduler()` → APScheduler `BackgroundScheduler` adds `detection_cycle` job every `DETECTION_INTERVAL_SECONDS` (default 30; `max_instances=1`, `coalesce=True`). On shutdown: `stop_scheduler()`.

## Stage 1 — Collection (agent side)

Two modes (`collector/collector_agent.py`):

- **One-shot:** `python collector_agent.py [--only X,Y] [--output DIR] [--yara-rules ...]`
- **Automated:** `python collector_agent.py --api-url <url> [--api-key <k>] --enroll [--daemon --interval N]`

Collection order in `run_collection()`:
1. `processes` + `persistence` first (their exe paths feed file_scan).
2. `network`, `scheduled_tasks`, `logs`.
3. `file_scan` last — `_extract_exe_paths()` gathers executable paths from process + persistence records, hashes each (`_sha256_of_file`), optionally runs YARA (`curated_ruleset.yar`) and embeds `yara_matches` in the artifact data.

Every record is wrapped by `common.wrap_artifact()`: `{host, os, collected_at (ISO UTC), artifact_type, data}` and written to `output/<YYYY-MM-DD>_<hostname>/<type>.json`.

## Stage 2 — Enroll + push (agent → backend)

- `enroll()` → `POST /endpoints/enroll` (agent-auth) → `endpoint_service.enroll_endpoint()` → idempotent upsert by hostname, status=online, last_seen=now; returns `{id, hostname, os, agent_version, status, last_seen, config}`.
- `push_folder()` → for each `*.json` in the run dir → `POST /ingest?batch_id=<run-dir-name>` (one batch per run dir). `batch_id` makes re-push a no-op.
- `daemon_loop()`: loop { poll `GET /endpoints/commands?hostname=...` → run any `run_collection` command + `complete_command()` → `run_collection()` → `push_folder()` } then sleep `max(interval, 10)`.
- **Config poll:** `get_endpoint_config()` → `GET /endpoints/config?hostname=...` (agent-auth) returns `interval_seconds` + `collectors`. Note: collector list currently informational only — the agent does not filter its collectors from it.

## Stage 3 — Ingest (backend)

`POST /ingest` (`main.py`) → `ingest_service.ingest_artifacts(db, artifacts, batch_id)`:
1. Empty batch → `ValueError` → HTTP 400.
2. If `batch_id` present: check for existing `Artifact` with same `(host, agent_batch_id)` → if found, return `IngestResponse(ingested=0, deduplicated=1)` (no DB writes).
3. Upsert `Host` row (hostname/os; `last_seen` auto-update).
4. Insert each artifact (`processed=0`, `agent_batch_id=batch_id`).
5. Commit → `IngestResponse(ingested=N, artifact_types=[...], deduplicated=0)`.

Artifacts now sit unprocessed in `artifacts` table.

## Stage 4 — Detection (scheduler or manual POST)

Entry point (shared): `detection_service.run_detection_job(db, host=None, rescan=False, trigger="manual"|"scheduled")`.

1. **Record run:** insert `DetectionRun(trigger, host, rescan, status="started")`, commit immediately (survives later rollback).
2. **Select artifacts:** `Artifact` rows filtered by `host` (if given) and `processed == 0` (unless `rescan=True`).
3. **Run engines** against the selected artifacts (order):
   1. **Sigma:** `load_sigma_rules(SIGMA_RULES_DIR)` (validates + dedups by id) → `evaluate()` → detections for artifacts whose `artifact_type` matches the rule and whose `data` satisfies the condition.
   2. **Embedded YARA:** for `file_scan` artifacts, each `yara_matches[].rule` becomes a detection `yara-<rule>` with `severity="high"` (hardcoded), technique from rule meta.
   3. **Hash:** `hash_checker.check_file_scan_artifacts()` → `rule_id="hash-match"`, severity `critical`, technique `T1204`.
   4. **Network IOC:** `ioc_correlation.correlate_network_artifacts()` → local blocklist (`ioc-local-blocklist`, T1071) and best-effort AbuseIPDB (`ioc-abuseipdb`, T1071).
4. **Persist detections:** each via `_persist_detection()` → `Detection` row (`triage_status="new"`, `technique_name/tactic` filled by `attck_mapper.enrich_technique` — fail-soft).
5. **Mark processed:** all scanned artifacts → `processed=1`, `analyzed_at=now`, `source_run_id=run.id`.
6. **Finalize run:** `artifacts_scanned`, `detections_found`, `by_severity` (JSON), `by_technique` (JSON), `status="completed"`, `finished_at`; commit.
7. **Audit:** `log_action("run_detection", actor=trigger, detail={run_id, trigger, host, rescan, counts})`.
8. **Error path:** `except` → `db.rollback()` → set run `status="failed"` + `finished_at` → re-raise. Scheduler catches and logs; API surfaces as 500.

Returns `{artifacts_scanned, detections_found, by_severity, by_technique}`.

## Stage 5 — Query / reporting / triage

- **Dashboard (overview):** `GET /health` (live counts via `health_payload`) + `GET /detections/summary` (by technique/severity/host/triage).
- **Endpoints view:** `GET /endpoints`; actions: `POST /endpoints/{id}/run-collection` (queues PendingCommand), `PUT /endpoints/{id}/config`, `POST /endpoints/enroll` (add endpoint).
- **Detections view:** `GET /detections?host=&severity=`; triage via `PATCH /detections/{id}` → `triage_detection()` → updates row + `log_action("triage_detection")`.
- **Runs view:** `GET /detection-runs?status=`.
- **Artifacts view:** `GET /artifacts?host=&artifact_type=&processed=&limit=`.
- **Audit view:** `GET /audit-logs?action=&limit=`.
- **Ops:** `GET /metrics` (Prometheus text, 9 gauges); `GET /scheduler/status` (admin).

## Data flow summary

```
collector modules → wrap_artifact → JSON files
      → push_folder(POST /ingest, batch_id)
          → artifacts(processed=0)
              → run_detection_job (scheduler@30s OR POST /detect)
                  → Detection rows + DetectionRun row + audit_logs row
                      → artifacts(processed=1, analyzed_at, source_run_id)
                          → dashboard views / metrics
```

## Lifecycle notes / gotchas

- Scheduler and `POST /detect` can run near-simultaneously; both write to the same tables. Scheduler is single-instance (`max_instances=1`), but manual POST is **not** gated — at demo scale SQLite locking is the practical guard.
- `db.commit()` of the DetectionRun happens before any analysis; a failure still yields a visible `failed` run (by design).
- `/ingest` has no request-size cap when auth is off (rate limit only active when `AUTH_ENABLED=true`).
- The dashboard does not auto-refresh (no polling except on view switch / refresh buttons).
