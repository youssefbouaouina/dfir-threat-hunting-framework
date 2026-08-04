# DFIR Threat Hunting Framework — Enterprise Roadmap

> **Status:** Plan with Phases 1–3 **implemented and committed on the `youssef` branch**. Phase 1 (security hardening, test net, CI scaffolding), Phase 2 (containers, Postgres-ready migrations, CI/CD delivery pipeline, agent automation), Phase 3 (dashboard, endpoint management, manual triggers, detection triage, ops hardening), and Phase 4 F1–F5 (async ingest queue, correlation engine, retention/archival, RBAC/team scoping + immutable audit, notifications + host criticality) are done. Phase 5 has partial groundwork (queue-driven detection worker). This roadmap is the architectural blueprint for evolving the framework into an enterprise-grade, containerized, CI/CD-driven DFIR platform with automated collection/detection, self-service endpoint enrollment from a dashboard, detection run history, and manual trigger controls.

Companion doc: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) — documents the system as it exists today, including all known issues this roadmap fixes.

---

## Guiding Principles

1. **Security first.** Secrets, auth, and least-privilege are Phase 1, non-negotiable, before any feature growth.
2. **Highest impact first.** Each phase ships independently and is usable on its own; ordering = impact × risk reduction ÷ effort.
3. **Everything automated.** Collection, detection, testing, building, and deployment should require zero manual steps once configured.
4. **Backwards-compatible, incremental.** The existing `backend/` FastAPI app is the kernel — we evolve it, not rewrite it. The broken `detection/` tree was **removed in Phase 3**; the shared `run_detection_job()` is the single pipeline entry point.
5. **Containers for the backend** (the user-visible platform); the **collector stays a lightweight native agent** on endpoints (agents in containers on every endpoint are operationally heavy) — but agent packaging becomes a first-class CI artifact.
6. **Configuration-as-code + infrastructure-as-code.** Env-driven config, Alembic migrations, Docker Compose for dev, tagged CI/CD releases.

---

## Target Architecture (end state after Phase 5)

```
┌────────────┐  enroll + heartbeat + config poll   ┌──────────────────────────────────────┐
│ Endpoints  │────────────────────────────────────►│  API Gateway / Reverse Proxy (TLS)    │
│ (agents)   │◄─── collect config, yara/sigma pkgs │     ├─ /auth (login, tokens)          │
└────────────┘                                    │     ├─ /ingest (agent, auth, idempotent)│
        │                                          │     ├─ /endpoints (CRUD, enrollment)   │
        └─────────── artifacts (JSON) ──────────────►  ├─ /detect (manual trigger)         │
                                                     ├─ /detections + /runs (history)      │
                                                    └───► FastAPI workers (containerized)  │
                                                          ├─ API containers                 │
                                                          ├─ detection worker (queue-driven)│
                                                          ├─ scheduler (cron)               │
                                                          └─ Postgres (SQLAlchemy/Alembic)  │
                                   Dashboard (web) ────────►  add endpoints, trigger        │
                                                          collection/detection, view history│
                                                                                            │
   CI/CD (GitHub Actions): lint → test → build images → publish (GHCR) → deploy (compose/k8s)
```

---

## Phase 1 — Harden & Stabilize (Security + Testability)

**Goal:** eliminate the known critical risks and make the codebase safely buildable/testable. Highest impact per effort: fixes committed secrets, makes `requirements.txt` actually installable, and adds the first real test net + CI gates.

### Work items

- **Secrets & hygiene**
  - Rotate and invalidate all leaked keys in `backend/.env.txt` and `detection/.env.txt` (AbuseIPDB, OTX, URLhaus).
  - Delete those files from the repo (and `git rm --cached`); add `.env.example` with placeholder values; enforce `.env` in `.gitignore`.
  - Add a leaked-secret scan step to CI (e.g. `gitleaks`).
- **Dependency/install correctness**
  - Rewrite `backend/requirements.txt` as UTF-8, top-level packages only, unpinned-or-ranged; add missing `yara-python` and `mitreattack-python`.
  - Split into `requirements-dev.txt` (pytest, ruff, mypy, gitleaks).
- **Retire dead/broken code** (✅ done in Phase 3 cleanup)
  - Remove the non-functional `detection/` duplicate tree (its detection_routes.py predates `run_detection_job`).
  - Remove dead `backend/yara_engine.py` + legacy `test_eicar.yar`; remove unused `db/`, empty `docs/mitre_mapping.json`, empty `SCHEMA.md`/`sample_data/README.md` (or fill them).
- **Rule hygiene** (✅ done in Phase 3 cleanup)
  - Delete duplicate sigma rule files (`suspicious_*.yml`, `test_encoded_ps.yml`); add rule validation + duplicate-ID detection at `load_rules`.
- **AuthN/AuthZ (API layer)**
  - API-key auth for all agent-facing endpoints (`/ingest`, agent config, heartbeat) — per-endpoint keys, not one global key.
  - Admin/analyst auth (JWT) for `/detect`, `/detections`, `/hosts`, dashboard-backed endpoints.
  - Rate limiting + request size limits on `/ingest`.
- **Test net + lint**
  - `pytest` suite: sigma matcher fixtures, hash checker, IOC correlation (mocked live feed), ingest round-trip, full `POST /detect` integration against a temp DB.
  - `ruff` + `mypy` (gradual typing), configs committed.
- **CI/CD scaffolding**
  - GitHub Actions: `lint + test` on every PR/merge to `main`; `gitleaks` secret scan; dependency vulnerability check (e.g. `pip-audit`).

**Exit criteria:** `pip install -r requirements.txt` works on Linux; `pytest` green in CI; no secrets in repo; agent and admin endpoints require auth; duplicate rules gone.

---

## Phase 2 — Containers, Postgres, and a Real CI/CD Delivery Pipeline

> **Status: ✅ DONE** (committed on `youssef`). Delivered: backend `Dockerfile` (multi-stage, non-root, healthcheck, migration entrypoint) + `docker-compose.yml` (backend + Postgres 16) + `.dockerignore`; Alembic migrations (initial schema incl. `endpoints`, `detection_runs`, new artifact columns; idempotent for Phase-1 SQLite DBs, `DATABASE_URL`-driven for Postgres); agent automation (`--daemon`, push to API, enrollment, idempotent `batch_id`); GitHub Actions `ci.yml` (lint+test+gitleaks on push/PR, GHCR build+push+smoke on `v*` tags). See `backend/tests/test_phase2.py` + `collector/tests/`. Outstanding items from the original list (`/detect` scope/rescan, `detection_runs` row per cycle) were delivered in Phase 3. Not yet done: `Dockerfile.agent`.

**Goal:** the backend becomes a containerized, deployable service with migrations and an automated build/deploy pipeline; agents begin reporting on a schedule automatically.

### Work items

- **Containerization (backend)**
  - `backend/Dockerfile` — multi-stage, non-root user, slim base, healthcheck (`/health`), entrypoint runs migrations then uvicorn (workers).
  - `docker-compose.yml` (dev): backend + Postgres; optional collector as a containerized test agent for CI e2e.
  - `Dockerfile.agent` (optional) to run the collector inside a container for CI/pipeline validation of collection logic.
- **Database: SQLite → PostgreSQL**
  - Add `sqlalchemy-utils`/psycopg2 (or `asyncpg`); `DATABASE_URL` from env (default remains SQLite for dev/tests).
  - Introduce **Alembic** migrations; model `Base.metadata.create_all` in `main.py` becomes migration-managed.
  - Schema upgrades enabled by migration:
    - `endpoints` table (replaces `hosts`): `id, hostname, os, agent_version, status (online|offline), last_seen, enrollment_token_hash, config_json, registered_at`.
    - `detection_runs` table (**history**): `id, started_at, finished_at, trigger (scheduled|manual|api), artifacts_scanned, detections_found, by_severity JSON, by_technique JSON`.
    - `artifacts`: add `source_run_id`, `agent_batch_id` for idempotency; change `processed` lifecycle → add `analyzed_at` (keeps history, enables rescan).
  - Backfill/migration of existing `dfir.db` data (one-time script).
- **CI/CD full delivery pipeline**
  - GitHub Actions: lint → test → **build & push images to GHCR** (tagged `sha-<x>` + semantic version) → deploy to a compose environment (or k8s manifests in Phase 5) → smoke test (`/health`, migrate, `/detect`).
  - Release flow: PR → merge to `main` → tag → versioned release + image.
- **Agent automation (collection)**
  - `collector_agent.py` gains: `--daemon` mode (loop with `COLLECT_INTERVAL`), direct **push to API** with `--api-url` + `--api-key`, and an `enroll` flow (register with backend, receive endpoint id/token).
  - Idempotent upload: each batch carries `agent_batch_id`; ingest dedupes.
  - Remove the manual `sample_data/` copy step for live endpoints (keep `push_samples.py` as a replay/offline tool).
- **Scheduler hardening**
  - Scheduler uses the same `run_detection_job` (already shared) and records a `detection_runs` row per cycle.
  - Add `POST /detect` run options: `scope` (host filter), `rescan` flag (re-analyze already-processed artifacts).

**Exit criteria:** `docker compose up` runs the full stack; DB migrations apply cleanly; images build and deploy via CI on tag; an agent can enroll and auto-push on a schedule; every detection cycle logs a history row; manual `/detect` supports rescan + host scope.

---

## Phase 3 — Dashboard, Endpoint Management, and Manual Trigger Controls

> **Status: ✅ DONE** (this session; commit + push on `youssef`). Delivered: `backend/static/` dashboard served at `/dashboard` (overview/endpoints/detections/history/artifacts/audit views); endpoint management (`PUT /endpoints/{id}/config`, add-endpoint enroll); manual triggers (run collection now via `pending_commands` queue, run detection with host scope + rescan, `GET /detection-runs` history); detection triage lifecycle (new → acknowledged → false_positive/true_positive/reviewed + analyst notes); ops hardening (structured JSON logging, `/metrics`, `/audit-logs` audit trail); ATT&CK enrichment now uses the in-repo `dfir-refs/cti/enterprise-attack` STIX dataset; repo cleanup (removed `detection/`, dead code, empty placeholders, duplicate rules). Tests: `backend/tests/test_phase3.py` (9) + collector command-poll tests (3).

**Goal:** a web dashboard where an analyst can add endpoints in one click, see their health, trigger collection/detection on demand, and browse detection history — the user-facing "self-service" surface.

### Work items

- **Dashboard (web app)**
  - [x] Lightweight vanilla-JS SPA (`backend/static/`) served by the backend at `/dashboard` — no build step, ships in the container image.
  - [x] Auth via the Phase 1 JWT flow; admin actions (`/endpoints`, `/metrics`, `/audit-logs`) gated behind the existing `admin` role.
- **Endpoint management**
  - [x] **"Add endpoint"**: admin fills host/OS → `POST /endpoints` returns the agent's collection config.
  - [x] Endpoint list: status (online/offline/last seen), OS, agent version, artifact counts, config `interval_seconds` (editable via `PUT /endpoints/{id}/config`, min 10s).
  - [x] Agent config editing: per-endpoint collector interval; agents poll `/endpoints/commands` each cycle.
- **Manual triggers & history (dashboard controls)**
  - [x] Button: **Run collection now** → `POST /endpoints/{id}/run-collection` enqueues a `run_collection` pending command the agent picks up next poll.
  - [x] Button: **Run detection now** → `POST /detect?host=&rescan=1` with host scope/rescan options; result shown inline.
  - [x] Views: **Detection history** (recent runs with timing/counts), **Detections** table (filter host/severity/technique + triage), **ATT&CK coverage** (`/detections/summary` incl. `by_triage`), **Artifacts explorer**.
- **Detection result lifecycle**
  - [x] Detection triage states: `new → acknowledged → false_positive | true_positive | reviewed`, with analyst notes (`triage_status`, `triage_notes`, `triage_updated_at`, `triage_updated_by`; migration `ca41c1ba0e02`).
- **Operations hardening**
  - [x] Structured JSON logging (env `LOG_FORMAT=json`, stdlib-only `logging_config.py`); `/metrics` (Prometheus) for artifacts/detections/endpoints/runs/pending commands; `/audit-logs` endpoint for admin actions (audit table + `audit_service`).

**Exit criteria:** an analyst can enroll a new endpoint entirely from the dashboard, trigger collection + detection manually, see run history, and triage detections. No CLI/curl needed for daily operations. ✅

---

## Phase 4 — Scale, Correlation, and Enterprise Features

> **Status: F1–F5 done** (committed on `youssef`). **F1 (async ingest queue, `5afca4d`):** Redis/RabbitMQ-style queue (`backend/ingest_queue.py`) + `workers/ingest_worker.py`; `/ingest` returns 202 when `INGEST_QUEUE_URL` set. **F2 (correlation engine, `46310fb`):** `Incident` + `IncidentDetection` models + `services/correlation_service.py` (same-rule campaigns across hosts, ATT&CK chains per host, severity escalation, idempotent recompute); `/incidents` routes; recomputed after every detection run. **F3 (retention, `ccf62a8`):** `services/retention_service.py` — per-table windows, monthly JSONL archives, optional OpenSearch sink, `/retention/status` + `/retention/run`. **F4 (RBAC + audit, `c503503`):** `admin`/`analyst`/`viewer` roles + `Endpoint.team` scoping + SHA-256 audit hash chain + `/audit-logs/verify`. **F5 (notifications + criticality, this session):** `services/notification_service.py` (webhook + SMTP email, `NOTIFY_*` env, fail-soft) fired on detection severity threshold + endpoint offline; `Endpoint.criticality` (`low`/`standard`/`important`/`critical`, migration `5f0a1c2d9b73`) amplified into correlation severity; `workers/detection_worker.py` queue-driven detection consumer; `POST /endpoints/scan-all` + per-endpoint report `GET /endpoints/{id}/report`; dashboard rewritten as a brutalist technical report with incidents + per-endpoint report views. Tests: `backend/tests/test_phase4_f5.py` (18) → backend **133**, collector **10**, ruff + mypy clean; docker build + compose verified.

**Goal:** handle many endpoints and higher volume without degrading, and turn raw detections into correlated incidents.

### Work items

- **Async ingest pipeline**
  - [x] Backend produces artifact batches to a message queue (**Redis/RabbitMQ**); workers (containerized) consume → validate → write Postgres. Ingest API returns immediately (accepted). *(F1)*
  - [x] Detection worker consumes unprocessed artifacts via queue or a scheduled sweep; scheduler stays as the cadence source. *(detection worker, this session)*
- **Correlation engine**
  - [x] Group detections by host + time window into **incidents** (new `incidents` + `incident_detections` tables). *(F2)*
  - [x] Same-rule-across-hosts aggregation (scans wider than one box); ATT&CK chain reconstruction per host (tactic sequence). *(F2)*
  - [x] Severity scoring combining rule severity × host criticality × IOC confidence. *(F2 + host criticality factor this session)*
- **Storage & retention**
  - [x] Retention/purging policies per artifact type; archival exports (JSONL) for compliance. *(F3)*
  - [ ] Optional OpenSearch/Elasticsearch sink for high-volume `log_event` search; Postgres remains the system of record. *(F3 landed OpenSearch bulk sink; dedicated search UX pending)*
- **RBAC & audit**
  - [x] Team/org scoping, granular roles (endpoint admin, incident handler, read-only). *(F4)*
  - [x] Immutable audit trail of all admin/analyst actions. *(F4)*
- **Notifications**
  - [x] Alerting hooks: webhook, email, Slack/Teams on high/critical detections or endpoint offline > threshold. *(F5 — webhook + email; Slack/Teams adapters are payload-format swaps on the same webhook)*

**Exit criteria:** 100s of endpoints ingest without blocking the API; detections auto-correlate into incidents with ATT&CK chains; alerts fire on configured channels; retention works. **✅ delivered (F1–F5).**

---

## Phase 5 — Advanced Detection, Threat Intel Automation & HA

> **Status: partial groundwork done.** `workers/detection_worker.py` (queue-driven detection consumer) landed in the F5 session, giving the platform a containerized detection path beyond the in-process scheduler. Remaining: pySigma, SigmaHQ update pipeline, IOC feed automation, HA/perf work — all below.

**Goal:** production-grade detection content and resilience.

### Work items

- **pySigma integration**
  - Replace the custom matcher's evaluation core with a real **pySigma backend** (keeping the current rule format via a conversion layer, or migrating rules to SigmaHQ schema).
  - **Sigma rule update pipeline** in CI: pull SigmaHQ repo on a schedule → validate → build a packaged rule bundle agents/backend consume.
- **Threat intel automation**
  - Scheduled jobs to refresh IOC feeds (MalwareBazaar, Feodo, URLhaus, OTX) → write to `iocs/` (versioned) or DB tables.
  - Complete the IOC correlation layer: implement URLhaus/Feodo (currently stubbed), STIX/TAXII export of detections/indicators.
- **HA & operations**
  - Kubernetes (or managed container platform) deployment: multiple API replicas, Postgres HA + backups/restore, queue HA.
  - Autoscaling workers; circuit breakers for external intel lookups; graceful shutdown.
- **Performance**
  - Pagination/indexing review, materialized views for summary endpoints, connection pooling tuning.

**Exit criteria:** detection content is updated automatically from SigmaHQ; IOC feeds refresh automatically; the platform is horizontally scalable and survives node loss.

---

## Cross-cutting work (all phases)

- **Documentation:** update `PROJECT_OVERVIEW.md` and `ROADMAP.md` as each phase lands; architecture diagrams; runbooks (deploy, enroll endpoint, backup/restore).
- **Testing:** unit + integration tests per phase; end-to-end test in CI using a containerized agent against the stack.
- **Config as code:** all infra (compose → k8s manifests) versioned in-repo; env-driven secrets via a vault/CI secret store, never files.

---

## Prioritization rationale (impact first)

| Phase | Theme | Why this order |
|---|---|---|
| 1 | Harden & stabilize | Leaked keys + no tests + uninstallable requirements are active risks that block everything else. Cheap to fix, huge risk reduction. |
| 2 | Containers + DB + CI/CD + agent automation | Enables automated collection/detection and reproducible deploys; the delivery pipeline everything later depends on. |
| 3 | Dashboard + endpoint mgmt + manual triggers | Delivers the user-facing self-service (add endpoints, manual triggers, history) on the Phase 1–2 foundation. |
| 4 | Scale + correlation + enterprise | Queue-based ingest and incident correlation are the real "enterprise-grade" leap; needs many endpoints first. **F1–F5 delivered.** |
| 5 | Advanced detection + intel + HA | Polish and resilience; build after the platform is stable and populated. *(detection worker groundwork done)* |

---

## Suggested first sprint (Phase 1 kickoff)

1. Rotate/revoke leaked API keys; delete `.env.txt` files; add `.env.example` + gitleaks CI step. *(day 1)*
2. Fix `requirements.txt` (UTF-8, top-level, add yara-python/mitreattack) + add `requirements-dev.txt`. *(day 1)*
3. Add pytest suite (sigma, hash, IOC mocked, ingest round-trip, /detect integration). *(days 2–4)*
4. GitHub Actions: lint + test + gitleaks + pip-audit. *(day 5)*
5. Remove `detection/` tree, dead code, duplicate rules; add rule validation. *(day 5–6)*

---

*This is a plan only. No code was modified. Phase ownership and exact tooling choices (RabbitMQ vs Redis, React vs server-rendered, compose vs k8s timing) are decisions to lock before each phase starts.*
