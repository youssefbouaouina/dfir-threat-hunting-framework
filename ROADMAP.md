# DFIR Threat Hunting Framework — Enterprise Roadmap

> **Status:** Proposed plan only. No code changes have been made. This roadmap is the architectural blueprint for evolving the current demo-stage framework (collect → ship → store → detect → query) into an enterprise-grade, containerized, CI/CD-driven DFIR platform with automated collection/detection, self-service endpoint enrollment from a dashboard, detection run history, and manual trigger controls.

Companion doc: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) — documents the system as it exists today, including all known issues this roadmap fixes.

---

## Guiding Principles

1. **Security first.** Secrets, auth, and least-privilege are Phase 1, non-negotiable, before any feature growth.
2. **Highest impact first.** Each phase ships independently and is usable on its own; ordering = impact × risk reduction ÷ effort.
3. **Everything automated.** Collection, detection, testing, building, and deployment should require zero manual steps once configured.
4. **Backwards-compatible, incremental.** The existing `backend/` FastAPI app is the kernel — we evolve it, not rewrite it. Remove the broken `detection/` tree, keep the shared `run_detection_job()` as the single pipeline entry point.
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
- **Retire dead/broken code**
  - Remove the non-functional `detection/` duplicate tree (its detection_routes.py predates `run_detection_job`).
  - Remove dead `backend/yara_engine.py` + legacy `test_eicar.yar`; remove unused `db/`, empty `docs/mitre_mapping.json`, empty `SCHEMA.md`/`sample_data/README.md` (or fill them).
- **Rule hygiene**
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

**Goal:** a web dashboard where an analyst can add endpoints in one click, see their health, trigger collection/detection on demand, and browse detection history — the user-facing "self-service" surface.

### Work items

- **Dashboard (web app)**
  - New `dashboard/` SPA (e.g. React/Vite or a lightweight server-rendered app), served by the backend (static mount) in the container image.
  - Auth via the Phase 1 JWT flow; roles: `admin`, `analyst`, `viewer`.
- **Endpoint management**
  - **"Add endpoint" wizard**: admin clicks Add → backend generates a one-time enrollment token + a ready-to-run agent command (downloadable config `agent-config.json` / install snippet).
  - Endpoint cards/list: status (online/offline/last seen), OS, agent version, artifact counts, pending/unprocessed artifacts.
  - Agent config editing: per-endpoint collector modules, interval, yara rules dir; agents poll `/endpoints/<id>/config` on each cycle.
- **Manual triggers & history (dashboard controls)**
  - Button: **Run collection now** → sends a signal to the endpoint (agent polls `pending_commands`) or directly triggers agent if reachable.
  - Button: **Run detection now** → `POST /detect` with scope/rescan options; result shown inline.
  - Views: **Detection history** (`detection_runs` list with timing/counts), **Detections** table (filter host/severity/technique), **ATT&CK coverage** (existing `/detections/summary`), **Artifacts explorer**.
- **Detection result lifecycle**
  - Detection triage states: `new → acknowledged → false_positive | true_positive | reviewed`, with analyst notes (new columns/migration).
- **Operations hardening**
  - Structured JSON logging; `/metrics` (Prometheus) for API, queue, scheduler; audit log endpoint for admin actions.

**Exit criteria:** an analyst can enroll a new endpoint entirely from the dashboard, trigger collection + detection manually, see run history, and triage detections. No CLI/curl needed for daily operations.

---

## Phase 4 — Scale, Correlation, and Enterprise Features

**Goal:** handle many endpoints and higher volume without degrading, and turn raw detections into correlated incidents.

### Work items

- **Async ingest pipeline**
  - Backend produces artifact batches to a message queue (**Redis/RabbitMQ**); workers (containerized) consume → validate → write Postgres. Ingest API returns immediately (accepted).
  - Detection worker consumes unprocessed artifacts via queue or a scheduled sweep; scheduler stays as the cadence source.
- **Correlation engine**
  - Group detections by host + time window into **incidents** (new `incidents` + `incident_detections` tables).
  - Same-rule-across-hosts aggregation (scans wider than one box); ATT&CK chain reconstruction per host (tactic sequence).
  - Severity scoring combining rule severity × host criticality × IOC confidence.
- **Storage & retention**
  - Retention/purging policies per artifact type; archival exports (JSONL) for compliance.
  - Optional OpenSearch/Elasticsearch sink for high-volume `log_event` search; Postgres remains the system of record.
- **RBAC & audit**
  - Team/org scoping, granular roles (endpoint admin, incident handler, read-only).
  - Immutable audit trail of all admin/analyst actions.
- **Notifications**
  - Alerting hooks: webhook, email, Slack/Teams on high/critical detections or endpoint offline > threshold.

**Exit criteria:** 100s of endpoints ingest without blocking the API; detections auto-correlate into incidents with ATT&CK chains; alerts fire on configured channels; retention works.

---

## Phase 5 — Advanced Detection, Threat Intel Automation & HA

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
| 4 | Scale + correlation + enterprise | Queue-based ingest and incident correlation are the real "enterprise-grade" leap; needs many endpoints first. |
| 5 | Advanced detection + intel + HA | Polish and resilience; build after the platform is stable and populated. |

---

## Suggested first sprint (Phase 1 kickoff)

1. Rotate/revoke leaked API keys; delete `.env.txt` files; add `.env.example` + gitleaks CI step. *(day 1)*
2. Fix `requirements.txt` (UTF-8, top-level, add yara-python/mitreattack) + add `requirements-dev.txt`. *(day 1)*
3. Add pytest suite (sigma, hash, IOC mocked, ingest round-trip, /detect integration). *(days 2–4)*
4. GitHub Actions: lint + test + gitleaks + pip-audit. *(day 5)*
5. Remove `detection/` tree, dead code, duplicate rules; add rule validation. *(day 5–6)*

---

*This is a plan only. No code was modified. Phase ownership and exact tooling choices (RabbitMQ vs Redis, React vs server-rendered, compose vs k8s timing) are decisions to lock before each phase starts.*
