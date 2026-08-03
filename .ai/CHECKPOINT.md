# Engineering Checkpoint — DFIR Threat Hunting Framework

> Generated: 2026-08-03. Branch: `youssef`. Head commit: `af77469` (`phase 3 completed:Dashboard, EndpointManagement, and Manual Trigger Controls`).
>
> **Session update (2026-08-03, continuation):** Baseline re-validated on Windows (Python 3.12, deps in `%TEMP%\dfir_venv`): backend 53 tests pass, collector 7 pass, ruff clean on both, DB at head migration `ca41c1ba0e02`. **Critical finding: the entire `.ai/` directory (all AI memory files) is untracked in git** — never committed. This session commits it as the top priority. Leaked keys still on disk in `detection/.env.txt` + `backend/.env.txt` (gitignored).
>
> **Phase 2 validation (same session):** Auth path verified live end-to-end with `AUTH_ENABLED=true` (login → token, admin 401s, agent-key 401s, enroll+config work). `.ai/` committed (docs commit). Full analysis in `.ai/CURRENT_ANALYSIS.md`. Remaining priorities: C1 (delete/rotate keys), H1 (return enrollment token), H2 (honor collectors config), H3 (commit SETUP_GUIDE + fix PROJECT_SUMMARY), H4 (ingest size limit + split rate-limit flag), then M1–M7.

## Project name
DFIR Threat Hunting Framework (repo: `dfir-threat-hunting-frameworkV3`, remote: `youssefbouaouina/dfir-threat-hunting-framework` — private).

## Current purpose
A lightweight, offline-first DFIR threat-hunting platform: lightweight collector agents run on endpoints and ship artifact batches to a FastAPI backend, which stores them and runs a multi-engine detection pipeline (Sigma-style behavioral rules, embedded YARA results, known-bad hash matching, network IOC correlation) with MITRE ATT&CK enrichment. An analyst dashboard (`/dashboard`) provides endpoint management, manual collection/detection triggers, detection run history, triage, audit log, and metrics. Built as a capstone ("stage ... esprit in NEXTSTEP", README).

## Current maturity
- Phases 1–3 of the 5-phase roadmap **implemented and committed on `youssef`**.
- 53 backend pytest tests + 7 collector pytest tests; ruff clean; CI (GitHub Actions) gates lint+test+gitleaks.
- Opt-in auth (disabled by default = open-lab demo mode), SQLite default (Postgres ready), containerized backend + compose stack, GHCR build/push on `v*` tags.
- No production deployment, no queueing, no incident correlation (Phases 4–5).

## Repository version
- Backend API version: `0.5.0` (FastAPI `app` version).
- Collector agent version string: `3.0` (passed at enroll).
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
- **Auth end-to-end:** implemented and unit-tested but opt-in (`AUTH_ENABLED=false` default). Agent-key path (`--api-key`, `AGENT_API_KEYS`) not exercised in this session; only the admin JWT path was smoke-tested.
- **Per-endpoint config `collectors`:** stored and served by backend, but the agent ignores it (agent always runs its fixed collector set; `--only` only applies in one-shot CLI mode).
- **Enrollment token:** generated + stored hashed, but never returned to the agent (vestigial).
- **Threat intel:** only AbuseIPDB live lookup implemented (soft-fail); OTX/URLhaus/Feodo are env keys only, no code.
- **Run-history/rescan:** delivered (`detection_runs` row per cycle, `rescan=true`); `Dockerfile.agent` still outstanding.

## Not started features
- Phase 4: async ingest queue (Redis/RabbitMQ), correlation engine (incidents), storage retention, RBAC, notifications.
- Phase 5: pySigma backend, SigmaHQ update pipeline, IOC feed automation, STIX/TAXII export, k8s/HA, pagination/matview performance work.
- Agent packaging as a CI artifact; collector cross-platform packaging (PyInstaller etc.).

## Current strengths
- Single detection entry point `run_detection_job()` shared by scheduler + API (no drift).
- Thin endpoints / services layer with DI (`Depends(get_db)`), unit-tested.
- Offline-first design: local hash list + local IP blocklist + in-repo STIX; live feeds fail soft.
- Idempotent ingest (`batch_id`) and first-call-wins command polling.
- Everything configurable via env; no secrets in repo (`.env.example` + gitleaks).
- Strong docstring habit; rule validation/dedup prevents duplicate detections.

## Current weaknesses
- Docs drift: `PROJECT_SUMMARY.md` stale (Phase 1 only); `README.md` is a 1-line stub; some docstrings reference deleted files (`SCHEMA.md`, `detection/`).
- Auth not verified end-to-end; default creds (`change-me-admin-key`) are placeholders.
- No correlation/incidents, no real intel feeds, no retention/pagination for scale.
- YARA only runs at collection time on the agent (no backend re-scan); embedded results only.
- Scheduler is in-process (single point of failure; no distributed workers).

## Current blockers
- None blocking. `SETUP_GUIDE.md` (new-user setup/run guide) is written but **uncommitted** (`?? SETUP_GUIDE.md`) — pending commit+push.
- Pushing to the private remote requires a GitHub PAT (no embedded credential in repo config).

## Current technical debt
- `detection/.env.txt` with real leaked API keys still on disk under gitignored `detection/` dir — needs deletion/rotation.
- `security.py` token uses stdlib HMAC (fine) but no JWT library; no token revocation/refresh.
- `_hits` rate-limit state is in-memory (lost on restart), keyed on X-Forwarded-For (untrusted unless proxied).
- `models.py` legacy `Host` table kept for backwards compat (dead-ish duplication with `Endpoint`).
- Metrics/health do repeated full-table counts (SQLite) — fine at demo scale, not at scale.
- YARA embedded-match detection hardcodes `severity="high"` regardless of rule meta.

## Current risks
- Default `AUTH_ENABLED=false` + placeholder admin key means a deployed-open instance is unprotected.
- Real leaked keys on disk (`detection/.env.txt`) — rotation pending; gitleaks only scans git history.
- 48 MB STIX JSON is committed; repo size growth on every resync.
- Single-process scheduler + SQLite means no HA; concurrent `/detect` and scheduler cycles could race (mitigated by `max_instances=1` but manual POST is not gated).
- `dfir.db` is a tracked binary artifact — merges will conflict frequently.

## Recent architectural changes
- Phase 3 (commit `af77469`): added `audit_logs` + `pending_commands` tables and triage columns (migration `ca41c1ba0e02`); added `services/{audit,metrics}_service.py`; `/dashboard` static mount; `/metrics` + `/audit-logs` endpoints; structured JSON logging; triage lifecycle; in-repo STIX path; removed `detection/` tree, `yara_engine.py`, dead files.
- Phase 2 (commit `37144db`): Alembic migrations replaced `create_all`; `Endpoint` model replaced passive host tracking; agent daemon/enroll/batch-id; Docker/compose/CI.
- Phase 1: services layer extraction (`72acd89`), rule hygiene (`0873d43`), run history (`98fc6b4`), test net (`578d34d`).
