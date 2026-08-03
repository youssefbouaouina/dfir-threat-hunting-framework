# Engineering Checkpoint — DFIR Threat Hunting Framework

> Generated: 2026-08-03. Branch: `youssef`. Head commit: `af77469` (`phase 3 completed:Dashboard, EndpointManagement, and Manual Trigger Controls`).
>
> **Session update (2026-08-03, continuation):** Baseline re-validated on Windows (Python 3.12, deps in `%TEMP%\dfir_venv`): backend 53 tests pass, collector 7 pass, ruff clean on both, DB at head migration `ca41c1ba0e02`. **Critical finding: the entire `.ai/` directory (all AI memory files) is untracked in git** — never committed. This session commits it as the top priority. Leaked keys still on disk in `detection/.env.txt` + `backend/.env.txt` (gitignored).
>
> **Phase 2 validation (same session):** Auth path verified live end-to-end with `AUTH_ENABLED=true` (login → token, admin 401s, agent-key 401s, enroll+config work). `.ai/` committed (docs commit). Full analysis in `.ai/CURRENT_ANALYSIS.md`. Remaining priorities: C1 (delete/rotate keys), H1 (return enrollment token), H2 (honor collectors config), H3 (commit SETUP_GUIDE + fix PROJECT_SUMMARY), H4 (ingest size limit + split rate-limit flag), then M1–M7.
>
> **Phase 3 (same session):** completion roadmap created in `.ai/COMPLETION_ROADMAP.md` — A (critical), B (high), C (medium), D (low), F (future Phases 4–5), each with files/deps/risk/validation. Execution order locked: A1 → B1(H3) → B2(H1) → B3(H2) → B4(H4) → C1(M1) → C5(M5) → …
>
> **Phase 4 progress (same session):** C1 ✅ (leaked `detection/.env.txt` + `backend/.env.txt` deleted, user-approved; rotate keys on provider dashboards). B1/H3 ✅ (`SETUP_GUIDE.md` committed + `PROJECT_SUMMARY.md` refreshed, commit `b2094f0`). B2/H1 ✅ (enrollment token returned once on first enroll, commit `6113fc6`; backend now 55 tests). B3/H2 ✅ (agent daemon honors backend `collectors` + `interval_seconds`, commit `96a5d04`; collector 9 tests). B4/H4 ✅ (`/ingest` body cap → 413 middleware, `RATE_LIMIT_ENABLED` decoupled from auth, commits `c25ee12` + `50e8a34`; backend 60 tests). A2 ✅ (startup rejects placeholder secrets when auth enabled, commit `50e8a34`). **Phases A + B of the roadmap complete.**
>
> **Phase C progress (same session, M-series):** M1 ✅ YARA severity from rule meta (commit `520750c`, backend 61). M5 ✅ stale docs fixed + README rewritten (commit `1f72448`). M6 ✅ heartbeat/offline detection (`_touch_endpoint` + `mark_offline_stale` + `offline_sweep` job, commit `200e639`, backend 64). M3 ✅ SQL GROUP BY aggregation for summary/metrics (commit `77abbd2`, backend 65). M4 ✅ `before_id` cursor pagination on /artifacts /detections /detection-runs (commit `17bb884`, backend 67). M2 ✅ URLhaus/OTX live lookups + Feodo blocklist refresh into `iocs/feodo_ips.txt` + `intel_refresh` scheduler job (commit `917006b`, backend 73). M7 ✅ `git rm --cached backend/dfir.db` (file stays on disk, now gitignored; commit `8879160`).
>
> **Phase D progress (same session, D-series / Low):** D1/L1 ✅ mypy gradual typing + pip-audit CI hard gates (commit `af5b401`; backend 73 tests, ruff + mypy clean). D2/L2 ✅ `Dockerfile.agent` + CI `agent-e2e` job (build images, enroll + one-shot collect, verify `/artifacts`); also fixed backend Dockerfile entrypoint chmod order and a real `push_folder` data-loss bug (folder-level batch id collapsed runs to the first file) — commit `132b873`, validated locally with Docker (16 artifacts ingested). D3+D4/L3+L4 ✅ dashboard scheduler status box (`#scheduler-box` via `/scheduler/status`) + 15s overview auto-refresh (commit `9ae3c33`). **Phases A–D of the roadmap complete.**
>
> **F-series progress (same session, Phases 4–5):** F1 ✅ async Redis ingest queue (commit `5afca4d`): `backend/ingest_queue.py` fail-soft enqueue/dequeue; `/ingest` returns 202 + `accepted=true,queued=N` when `INGEST_QUEUE_URL` set (sync 200 default); `workers/ingest_worker.py` drains via the same `ingest_service.ingest_artifacts` (batch_id idempotency preserved); docker-compose redis + worker services; CI `agent-e2e` now exercises the full async loop. 9 backend + 1 collector tests. F2 ✅ correlation engine (commit `46310fb`): `Incident` + `IncidentDetection` models (migration `e19d4f2a7c10`), `services/correlation_service.py` (campaigns = same rule ≥2 hosts; chains = ≥2 techniques one host; severity escalation; idempotent signature-keyed `recompute_incidents` preserving triage), `/incidents` router (list/summary/detail/recompute/PATCH), `run_detection_job` recomputes after every run. 10 tests. (Also fixed a leftover: `app.include_router(incident_router)` wiring commit `b260b55`.) F3 ✅ retention/archival (commit `ccf62a8`): `services/retention_service.py` ages out rows per `RETENTION_*_DAYS` into monthly JSONL under `RETENTION_ARCHIVE_DIR` + optional OpenSearch sink (`OPENSEARCH_URL`, fail-soft) + batch delete; `retention_sweep` scheduler job; `GET /retention/status` + `POST /retention/run` (audited). 9 tests. F4 ✅ RBAC/team scoping + immutable audit (commit `c503503`): roles `admin`/`analyst`/`viewer` (`ADMIN_API_KEY` + `ANALYST_API_KEYS`/`VIEWER_API_KEYS` in `key@team` form), `issue_token`/`current_user`/`require_role` in `security.py`; `Endpoint.team` (migration `4a1f2c9d3b70`) + `scoped_hosts` applied across artifacts/detections/runs/summary/incidents/endpoints (empty team host list now hides everything); audit SHA-256 hash chain (`prev_hash`/`record_hash`) + `verify_audit_chain` + `GET /audit-logs/verify`. 14 tests. **Backend now 115 tests, ruff + mypy clean (46 files). F5 (notifications) is next.**

## Project name
DFIR Threat Hunting Framework (repo: `dfir-threat-hunting-frameworkV3`, remote: `youssefbouaouina/dfir-threat-hunting-framework` — private).

## Current purpose
A lightweight, offline-first DFIR threat-hunting platform: lightweight collector agents run on endpoints and ship artifact batches to a FastAPI backend, which stores them and runs a multi-engine detection pipeline (Sigma-style behavioral rules, embedded YARA results, known-bad hash matching, network IOC correlation) with MITRE ATT&CK enrichment. An analyst dashboard (`/dashboard`) provides endpoint management, manual collection/detection triggers, detection run history, triage, audit log, and metrics. Built as a capstone ("stage ... esprit in NEXTSTEP", README).

## Current maturity
- Phases 1–3 of the 5-phase roadmap **implemented and committed on `youssef`**; roadmap Phases A + B (critical/high hardening), C (medium), D (low), and F1–F4 (Phase 4: async queue, correlation, retention, RBAC/audit) are **complete**. F5–F8 (notifications, pySigma, IOC feeds, k8s/HA) remain.
- 115 backend pytest tests + 10 collector pytest tests; ruff clean; mypy clean (gradual); CI (GitHub Actions) gates lint+mypy+pytest+pip-audit+gitleaks, plus a containerized agent→backend e2e job.
- Opt-in auth (disabled by default = open-lab demo mode), SQLite default (Postgres ready), containerized backend + agent + compose stack, GHCR build/push on `v*` tags. Enabling auth now refuses placeholder secrets; `/ingest` enforces a 10 MB body cap; rate limiting works independent of auth.
- No production deployment, no notifications, no pySigma (Phases 4–5).

## Repository version
- Backend API version: `0.5.0` (FastAPI `app` version).- Collector agent version string: `3.0` (passed at enroll).
- No unified repo-level version/tag yet. CI tags images `v*` from git tags.

## Major technologies
- **Backend:** Python 3.12, FastAPI, Uvicorn, SQLAlchemy 2.x, Alembic, Pydantic 2, APScheduler, PyYAML, requests, python-dotenv, yara-python (indirect), mitreattack-python (STIX enrichment), psycopg2-binary (Postgres).
- **Collector:** Python, psutil, requests, pywin32 (Windows-only).
- **DB:** SQLite default (`backend/dfir.db`); PostgreSQL 16 via `DATABASE_URL` + `docker-compose.yml`.
- **Ops:** Prometheus-style text metrics (hand-rolled, no library), structured JSON logging (stdlib only), GitHub Actions CI/CD (`ci.yml`), Docker multi-stage build, gitleaks secret scan.
- **Frontend:** vanilla JS/HTML/CSS SPA (no build step) served statically.
- **Threat data:** in-repo MITRE ATT&CK STIX dataset (`dfir-refs/cti/enterprise-attack/enterprise-attack.json`, ~48 MB, the only committed part of `dfir-refs/`).

## Current architecture
```
Endpoints (agents)  --enroll/config/commands + ingest (idempotent batch_id)-->  FastAPI backend
  collector_agent.py  (--daemon loops collect+push, polls pending commands)      |_ /health /metrics /audit-logs
  modules/*.py        (processes, network, persistence, scheduled_tasks,         |_ /dashboard (static SPA)
  agent_client.py     logs, file_scan w/ embedded yara_matches)                   |_ /ingest /artifacts /hosts
                                                                                  |_ /endpoints/* /endpoints/commands
                                                                                  |_ /detect /detections /detections/{id}
                                                                                  |_ /detection-runs /auth/login
                                                                                  |_ SQLite/Postgres (Alembic migrations)
                                                                                  |_ APScheduler background detection loop
```
- Backend single process; detection runs in-thread (scheduler) or in-request (`POST /detect`). No worker queue.
- Agent is intentionally a native process per endpoint (not containerized).

## Current execution flow (high level)
1. **Startup:** `migrate_to_head()` applies Alembic migrations → FastAPI app mounts routers + `/dashboard` static → `lifespan` starts the APScheduler detection loop.
2. **Collect:** agent runs collectors → wrapped artifacts (`{host, os, collected_at, artifact_type, data}`) → JSON files per type → `push_folder` POSTs to `/ingest?batch_id=<run>`.
3. **Ingest:** dedupe by `(host, batch_id)` → store artifacts (processed=0) → upsert `Host` row.
4. **Detect:** scheduler (`POST /detect` equivalent) calls `run_detection_job()` → loads sigma rules, evaluates sigma + embedded YARA + hash + network IOC → persists `Detection` rows with ATT&CK enrichment → marks artifacts processed=1/analyzed_at/source_run_id → writes a `DetectionRun` row + audit log.
5. **Query/report:** dashboard reads `/health`, `/detections/summary`, `/detections`, `/detection-runs`, `/artifacts`, `/audit-logs`; analysts triage via `PATCH /detections/{id}`.

## Current modules
Full index in `.ai/MODULE_INDEX.md`. Backend: `main.py`, `database.py`, `models.py`, `schemas.py`, `security.py`, `scheduler.py`, `logging_config.py`, `detection_routes.py`, `endpoint_routes.py`, `sigma_matcher.py`, `hash_checker.py`, `ioc_correlation.py`, `attck_mapper.py`, `push_samples.py`, `services/{ingest,query,detection,endpoint,audit,metrics}_service.py`, `migrations/versions/{4823f807fcd2, ca41c1ba0e02}`, `static/{index.html,app.js,style.css}`, `iocs/*`, `sigma_rules/rule0NN_*.yml`, `yara_rules/curated_ruleset.yar`.
Collector: `collector_agent.py`, `agent_client.py`, `modules/{common,processes,network,persistence,scheduled_tasks,logs,file_scan}.py`.

## Completed features
- **Phase 1:** removed committed secrets from index; installable UTF-8 `requirements.txt` + `requirements-dev.txt`; services-layer refactor; sigma rule validation + dedup; detection run history; `/detect` host scope + rescan; artifact time/processed filters; opt-in JWT/API-key auth + rate limiting; 53-test suite + ruff; gitleaks in CI.
- **Phase 2:** backend `Dockerfile` (multi-stage, non-root, healthcheck, migration entrypoint) + `docker-compose.yml` (Postgres 16) + `.dockerignore`; Alembic migrations (idempotent on legacy DBs); agent automation (`--enroll`, `--daemon`, push-to-API, idempotent `batch_id`); `ci.yml` lint+test+gitleaks + GHCR build/push/smoke on tags.
- **Phase 3:** `/dashboard` static SPA (overview/endpoints/detections/runs/artifacts/audit); endpoint management (`PUT /endpoints/{id}/config`, add-endpoint enroll); manual triggers (`run-collection` via `pending_commands`, `POST /detect?host=&rescan=`, `GET /detection-runs`); detection triage lifecycle (new→acknowledged→fp/tp/reviewed + notes); ops hardening (JSON logging `LOG_FORMAT=json`, `/metrics`, `/audit-logs`); ATT&CK enrichment from in-repo STIX; repo cleanup (removed `detection/`, dead code, duplicate rules, empty placeholders).

## Partially completed features
- **Auth end-to-end:** implemented, unit-tested, verified live (login → token, 401s) and hardened — placeholder secrets now refuse startup, rate limiting is decoupled from auth. Agent-key path (`--api-key`, `AGENT_API_KEYS`) not re-exercised this session; admin JWT path was smoke-tested earlier.
- **Per-endpoint config `collectors`:** stored and served by backend, and now honored by the agent daemon (B3/H2). `--only` also applies in one-shot CLI mode.
- **Enrollment token:** generated + stored hashed, and now returned once to the agent on first enroll (B2/H1).
- **Threat intel:** AbuseIPDB + URLhaus + OTX live lookups implemented (all fail-soft); Feodo blocklist auto-refreshed into `iocs/feodo_ips.txt` (M2). Keys rotate on provider dashboards (user action pending).

## Not started features
- Phase 4: notifications webhook/email/Slack/Teams (F5).
- Phase 5: pySigma backend, SigmaHQ update pipeline, IOC feed automation, STIX/TAXII export, k8s/HA, pagination/matview performance work (F6–F8).
- Agent packaging as a CI artifact; collector cross-platform packaging (PyInstaller etc.).

## Current strengths
- Single detection entry point `run_detection_job()` shared by scheduler + API (no drift).
- Thin endpoints / services layer with DI (`Depends(get_db)`), unit-tested.
- Offline-first design: local hash list + local IP blocklist + in-repo STIX; live feeds fail soft.
- Idempotent ingest (`batch_id`) and first-call-wins command polling.
- Everything configurable via env; no secrets in repo (`.env.example` + gitleaks).
- Strong docstring habit; rule validation/dedup prevents duplicate detections.

## Current weaknesses
- Auth not re-verified end-to-end after the agent-key changes; default creds (`change-me-admin-key`) are placeholders (refused on startup only when auth enabled).
- No correlation/incidents, no real intel feeds, no retention/pagination for scale.
- YARA only runs at collection time on the agent (no backend re-scan); embedded results only.
- Scheduler is in-process (single point of failure; no distributed workers).

## Current blockers
- None blocking. Pushing to the private remote requires a GitHub PAT (no embedded credential in repo config).

## Current technical debt
- `security.py` token uses stdlib HMAC (fine) but no JWT library; no token revocation/refresh.
- `_hits` rate-limit state is in-memory (lost on restart), keyed on X-Forwarded-For (untrusted unless proxied).
- `models.py` legacy `Host` table kept for backwards compat (dead-ish duplication with `Endpoint`).
- `AuditLog` hash chain rows created before F4 migration have NULL `prev_hash`/`record_hash` (legacy rows skipped by `verify_audit_chain`).
- Metrics/health do repeated full-table counts (SQLite) — fine at demo scale, not at scale.
- YARA embedded-match detection still hardcodes severity on some paths. *(M1 covers meta severity)*
- `docker-compose.yml` doesn't yet include the agent service (intentionally native per endpoint; the containerized agent exists for CI e2e).

## Current risks
- Default `AUTH_ENABLED=false` + placeholder admin key means a deployed-open instance is unprotected.
- Real leaked keys on disk (`detection/.env.txt`) — rotation pending; gitleaks only scans git history.
- 48 MB STIX JSON is committed; repo size growth on every resync.
- Single-process scheduler + SQLite means no HA; concurrent `/detect` and scheduler cycles could race (mitigated by `max_instances=1` but manual POST is not gated).

## Recent architectural changes
- Phase D (commits `af5b401`, `132b873`, `9ae3c33`): mypy gradual typing + pip-audit CI gates; `Dockerfile.agent` + CI agent→backend e2e job; `push_folder` per-file batch ids (fixes silent multi-file data loss); backend Dockerfile entrypoint chmod ordering fix; dashboard scheduler status box + 15s overview auto-refresh; `backend/dfir.db` untracked (M7, `8879160`).
- Phase 3 (commit `af77469`): added `audit_logs` + `pending_commands` tables and triage columns (migration `ca41c1ba0e02`); added `services/{audit,metrics}_service.py`; `/dashboard` static mount; `/metrics` + `/audit-logs` endpoints; structured JSON logging; triage lifecycle; in-repo STIX path; removed `detection/` tree, `yara_engine.py`, dead files.
- Phase 2 (commit `37144db`): Alembic migrations replaced `create_all`; `Endpoint` model replaced passive host tracking; agent daemon/enroll/batch-id; Docker/compose/CI.
- Phase 1: services layer extraction (`72acd89`), rule hygiene (`0873d43`), run history (`98fc6b4`), test net (`578d34d`).
