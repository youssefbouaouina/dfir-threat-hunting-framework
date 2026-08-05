# Roadmap Status vs Implementation

Source: `ROADMAP.md` (the authoritative 5-phase plan). Phases 1–3 are done; Phases 4–5 are proposals.

## Status summary

| Phase | Theme | Status | Completion estimate |
|---|---|---|---|---|
| 1 | Harden & Stabilize (security + testability) | ✅ DONE (committed on `youssef`) | ~95% |
| 2 | Containers, Postgres, CI/CD, agent automation | ✅ DONE (committed on `youssef`) | ~90% |
| 3 | Dashboard, endpoint mgmt, manual triggers | ✅ DONE (committed `af77469`) | ~95% |
| 4 | Scale, correlation, enterprise features | ✅ DONE (F1–F5) | ~95% |
| 5 | Advanced detection, intel automation, HA | ✅ DONE (F6–F8, this session) | ~90% |

**Overall roadmap completion: ≈ 95%** (all 5 phases implemented). The per-task completion roadmap (`.ai/COMPLETION_ROADMAP.md`) Phases A–D and the full F-series are complete: **F1 (async queue), F2 (correlation), F3 (retention), F4 (RBAC/team scoping + immutable audit), F5 (notifications + host criticality), F6 (pySigma backend + SigmaHQ update pipeline), F7 (IOC feed automation + STIX/TAXII export), F8 (k8s/HA, autoscaling, circuit breakers, pooling, matviews) are all done.** Remaining polish items: user-side provider key rotation and long-running production soak (e.g. HPA behavior under load).

## Phase 1 — Harden & Stabilize

**Completed milestones:**
- Secrets removed from index; `.env.example` added; `.env`/`.env.txt` in `.gitignore`; gitleaks in CI.
- `requirements.txt` rewritten (UTF-8, top-level, ranged) + `requirements-dev.txt`.
- Dead/broken code retired (detection/ tree, `yara_engine.py`, empty placeholders) — done in Phase 3 cleanup.
- Rule hygiene: duplicate sigma rules deleted; `load_rules` validates + dedups by id.
- AuthN/AuthZ: opt-in JWT (admin) + per-endpoint API keys (agents) + rate limiting (active only when auth enabled).
- Test net: 53 backend + 7 collector tests; ruff config committed.

**Remaining (~5%):** `mypy` (gradual typing) not adopted; `pip-audit` dependency-vulnerability step not in CI; `POST /ingest` request-size limit not enforced; live verification of the agent-key auth path pending.

> **Update (2026-08-03 continuation):** the agent-key + admin-token + rate-limit auth paths were **verified end-to-end** via a live `AUTH_ENABLED=true` smoke (see `.ai/CURRENT_ANALYSIS.md`). `POST /ingest` size limit still pending (H4).

## Phase 2 — Containers, Postgres, CI/CD

**Completed milestones:**
- `backend/Dockerfile` (multi-stage, non-root, healthcheck, migration entrypoint), `docker-compose.yml` (backend + Postgres 16), `.dockerignore`.
- `Dockerfile.agent` (containerized agent, non-root, yara-python) — used by the CI e2e job (commit `132b873`).
- Alembic migrations (initial schema `4823f807fcd2` idempotent on legacy DBs; `DATABASE_URL`-driven).
- Agent automation: `--enroll`, `--daemon`, push-to-API, idempotent `batch_id` (per-file after the push_folder fix).
- `ci.yml`: lint + mypy + pytest + pip-audit + gitleaks on push/PR; agent→backend containerized e2e job; GHCR build+push+smoke on `v*` tags.
- Scheduler records a `detection_runs` row per cycle (delivered/verified in Phase 3).

**Remaining (~5%):** no version tag/release has been cut yet (build job untested end-to-end on a real tag).

## Phase 3 — Dashboard, Endpoint Management, Manual Triggers

**Completed milestones (all checkboxes `[x]` in ROADMAP):**
- `/dashboard` vanilla-JS SPA (overview/endpoints/detections/runs/artifacts/audit).
- Endpoint management: enroll/add-endpoint, status/health list, `PUT /endpoints/{id}/config` (interval min 10s).
- Manual triggers: run-collection-now (pending_commands queue), `POST /detect?host=&rescan=`, `GET /detection-runs`.
- Detection triage lifecycle (`new → acknowledged → false_positive|true_positive|reviewed` + notes; migration `ca41c1ba0e02`).
- Ops hardening: JSON logging, `/metrics` (9 gauges), `/audit-logs`.
- ATT&CK enrichment now uses in-repo STIX; repo cleanup done.

**Remaining (~5%):** `detections/summary` is computed by loading all detections into memory (fine now, needs aggregation at scale); no host criticality field; agent heartbeat/offline detection is last-seen-based only.

> **Update (2026-08-03 continuation, D-series / Low):** `mypy` gradual typing + `pip-audit` dependency audit are now CI hard gates (commit `af5b401`). `Dockerfile.agent` + a containerized agent→backend e2e CI job landed (commit `132b873`), validated locally with Docker. Dashboard got a `/scheduler/status` box + 15s overview auto-refresh (commit `9ae3c33`). `backend/dfir.db` is untracked again (M7, `8879160`). **Phase D of the completion roadmap is done; only F1–F8 (Phases 4–5) remain.**

## Phase 4 — Scale, Correlation, Enterprise

**F1 done (commit `5afca4d`):** async ingest queue via Redis (`backend/ingest_queue.py` fail-soft enqueue/dequeue; `/ingest` → 202 + `accepted=true,queued=N` when `INGEST_QUEUE_URL` set, sync 200 default; `workers/ingest_worker.py` drains via `ingest_service.ingest_artifacts`, batch_id idempotency preserved; docker-compose redis + worker; CI `agent-e2e` exercises the full async loop). 9 backend + 1 collector tests.

**F2 done (commit `46310fb`):** correlation engine — `Incident` + `IncidentDetection` models (migration `e19d4f2a7c10`), `services/correlation_service.py` (campaigns = same rule ≥2 hosts, chains = ≥2 techniques one host, severity escalation, idempotent signature-keyed `recompute_incidents` preserving triage, stale cleanup), `/incidents` routes (list/summary/detail/recompute/PATCH). `run_detection_job` recomputes after each run. 10 tests. Router wiring leftover fixed in `b260b55`.

**F3 done (commit `ccf62a8`):** storage retention — `services/retention_service.py` ages out rows per `RETENTION_*_DAYS` (artifacts/detections/detection_runs/audit_logs) into monthly JSONL archives under `RETENTION_ARCHIVE_DIR` + optional OpenSearch sink (`OPENSEARCH_URL`, fail-soft) + batch delete (idempotent, per-batch commits); `retention_sweep` scheduler job; `GET /retention/status` + `POST /retention/run` (audited). Off by default. 9 tests.

**F4 done (commit `c503503`):** RBAC/team scoping + tamper-evident audit — roles `admin`/`analyst`/`viewer` (`ADMIN_API_KEY` + `ANALYST_API_KEYS`/`VIEWER_API_KEYS` env in `key@team` form), `issue_token`/`current_user`/`require_role` in `security.py`; team scoping via `Endpoint.team` (migration `4a1f2c9d3b70`) + `scoped_hosts` helper applied to artifacts/detections/runs/summary/incidents/endpoints (empty team host list now correctly hides everything); immutable audit via SHA-256 hash chain `prev_hash`/`record_hash` in `audit_service.log_action` + `verify_audit_chain` + `GET /audit-logs/verify` (legacy NULL-hash rows skipped). 14 tests. Validation: 115 backend + 10 collector tests, ruff clean, mypy clean.

**F5 done (2026-08-04 session):** notifications — `services/notification_service.py` (webhook + SMTP email, `NOTIFY_*` env, fail-soft), fired from `run_detection_job` (severity threshold) and `mark_offline_stale` (endpoint offline); **host criticality** severity factor — `Endpoint.criticality` (`low`/`standard`/`important`/`critical`, migration `5f0a1c2d9b73`) amplified into correlation severity scoring (`important` → +1, `critical` → +2 rank bump, capped); **queue-driven detection worker** (`workers/detection_worker.py`) so detection can run as a containerized consumer alongside the scheduler; `POST /endpoints/scan-all` (audited) + per-endpoint report `GET /endpoints/{id}/report` (artifacts/detections/incidents/run-history aggregates); dashboard rewritten as a **brutalist technical report** (incidents + per-endpoint report views, scan-all, criticality badges); collector enroll helpers `scripts/enroll_agent.sh`/`.ps1`. 18 tests → backend **133 passed**, collector **10 passed**, ruff + mypy clean. Docker build + compose stack re-verified.

**F6–F8 done (2026-08-04 continuation, Phase 5):** see the three entries below. Backend suite grew to **179 passed**; ruff + mypy clean; two new Alembic migrations (`6f7a1b2c3d4e` iocs, `7a8b1c2d3e4f` composite indexes + stats_snapshots) verified to apply from a clean DB.

## Phase 5 — Advanced Detection, Intel Automation, HA

**F6 done — pySigma backend + SigmaHQ update pipeline:** `backend/sigma_engine.py` is a real pySigma backend walking the typed condition tree (`1 of`/`all of` selectors, NOT filters, `|re`/`|cidr`/`|gte` modifiers, case-insensitive `SigmaString` regex). `FIELD_MAP` maps Sigma field names to collector schema per artifact_type; `LOGSRC_TO_ARTIFACT` maps logsource categories. 6 committed native rules under `sigma_rules/native/`; `run_detection_job` now runs both the legacy matcher and the pySigma engine. `services/sigma_service.py` imports SigmaHQ rules (local dir or shallow git clone) into `sigma_rules/native/sigmahq/` with filter/dedup-by-id; `GET /sigma/{status,rules}` + `POST /sigma/refresh` (admin, audited). `pysigma>=1.5.0` in requirements. 15 engine/service tests + integration test.

**F7 done — IOC feed automation + STIX/TAXII export:** `Ioc` model + migration `6f7a1b2c3d4e` (unique `(value, ioc_type, source)`). `services/intel_service.py` ingests Feodo (also keeps `iocs/feodo_ips.txt` for the offline layer), URLhaus CSV, MalwareBazaar `get_recent`, and OTX pulses (keyless feeds need no creds; OTX without key is skipped) — idempotent upsert, fail-soft per feed, refresh on the scheduler (`intel_refresh`) and `POST /iocs/refresh` (admin, audited). `GET /iocs` (filterable, cursor-paged), `GET /iocs/status`, and `GET /iocs/export/stix` emit a STIX 2.1 bundle (`spec_version=2.1`, indicator patterns per type). Minimal **TAXII 2.1** read-only server in `taxii_routes.py` (`/taxii/` discovery, `/taxii/api/` root, collections, collection objects). 17 tests.

**F8 done — k8s/HA, autoscaling, circuit breakers, pooling, matviews:** `services/circuit_breaker.py` (closed/open/half-open, per-feed, trip threshold + timeout via `IOC_FEED_*` env, state surfaced in `/iocs/status`, manual reset `POST /iocs/breakers/reset`). DB connection-pool tuning in `database.py` (`DB_POOL_SIZE/MAX_OVERFLOW/RECYCLE/PRE_PING`, Postgres-only). Composite-index migration `7a8b1c2d3e4f` (artifacts/detections/audit_logs/incidents hot paths). Materialized stats: `StatsSnapshot` model + `services/stats_service.py` precomputes detection_summary/health_counts/ioc_counts on a `stats_compute` scheduler job, served by `GET /stats/summary` + `POST /stats/recompute` (admin, audited) — the portable stand-in for a Postgres matview. `k8s/` manifests: namespace, ConfigMap, Secret template, backend Deployment (3 replicas, probes, resources), HPA (CPU+memory, 3–10), Service, PodDisruptionBudget, ingest-worker Deployment, Postgres StatefulSet. 13 tests (incl. k8s YAML validity).

## Cross-cutting work

- Documentation updated through Phase 3 + D-series (ROADMAP, PROJECT_OVERVIEW, PHASE3, SETUP_GUIDE, README rewritten in M5).
- `SETUP_GUIDE.md` committed (H3).
- End-to-end CI test using a containerized agent — present (`agent-e2e` job, commit `132b873`).

## Deliverables-per-phase gaps (exit-criteria check)

- **Phase 1 exit criteria:** installable requirements ✓; pytest green ✓; mypy clean ✓; pip-audit clean ✓; no secrets in repo ✓ (gitleaks scans git history; `detection/.env.txt` deleted, key rotation still user action); agent+admin endpoints require auth — ⚠️ only when `AUTH_ENABLED=true` (default false); duplicate rules gone ✓.
- **Phase 2 exit criteria:** `docker compose up` runs stack ✓; migrations apply cleanly ✓; images build+deploy via CI on tag — ⚠️ not exercised on a real tag; agent enroll + auto-push ✓ (e2e-verified in CI job); run history row per cycle ✓; manual `/detect` rescan + host scope ✓.
- **Phase 3 exit criteria:** analyst can enroll endpoint from dashboard, trigger collection+detection, see history, triage — ✓ (all dashboard-exercised in smoke tests).
