# DFIR Threat Hunting Framework — Project Summary & Showcase Guide

> **Audience:** anyone visiting this repository (collaborators, reviewers, or an evaluation committee).
> **Purpose:** one document that tells the full story — where the project started, everything we changed, what it achieves now, what is still left to reach our goals, and a complete step-by-step guide to set it up and showcase it.
> **Branch:** all of our Phase 1–3 work lives on the **`youssef`** branch. It is not merged into `main`.
> **Quick start:** for the full Windows-host + two-VM walkthrough see **[SETUP_GUIDE.md](SETUP_GUIDE.md)** (the "showcase guide" this summary used to carry inline — moved to its own document in Phase 3).

**Authors:** Youssef Bouaouina & Amen Ben Salah — ESPRIT, NEXTSTEP.

Companion documents:
- [SETUP_GUIDE.md](SETUP_GUIDE.md) — step-by-step setup + run guide (Windows host + VMware lab).
- [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) — technical reference of the system as it exists (schema, modules, endpoints, rules).
- [ROADMAP.md](ROADMAP.md) — the multi-phase plan to enterprise-grade.
- [AI_RULES.md](AI_RULES.md) — binding rules for any future modification.
- [CONTRIBUTING.md](CONTRIBUTING.md) — development conventions.

---

## Table of Contents

1. [The Short Story](#1-the-short-story)
2. [Original State — Where We Started](#2-original-state--where-we-started)
3. [Changes Made Until Now (in detail)](#3-changes-made-until-now-in-detail)
4. [What We Have Achieved](#4-what-we-have-achieved)
5. [What Is Still Needed to Complete Our Goals](#5-what-is-still-needed-to-complete-our-goals)
6. [Showcase Guide — Setup & Usage (step by step)](#6-showcase-guide--setup--usage-step-by-step)
7. [Troubleshooting](#7-troubleshooting)
8. [Appendix — Branch & Commit History](#8-appendix--branch--commit-history)

---

## 1. The Short Story

We built an **offline-first DFIR (Digital Forensics & Incident Response) threat hunting framework** with the pipeline:

```
Collect → Ship → Store → Detect → Query
```

- A **collector agent** runs on endpoints (Windows / Linux), snapshots processes, network connections, persistence mechanisms, scheduled tasks, log events, and hashes/YARA-scans executables.
- A **FastAPI backend** ingests those artifacts into SQLite and runs a **4-layer detection pipeline** (Sigma-style behavioral rules, embedded YARA results, known-bad hash matching, network IOC correlation), enriches findings with **MITRE ATT&CK** technique metadata, and exposes everything via a REST API.
- A **background scheduler** re-runs detection automatically; detection **run history** is recorded.

When we received the project it was a working demo that had never been hardened: **committed secrets, an uninstallable UTF-16 `requirements.txt`, zero automated tests, a broken duplicate code tree, duplicate detection rules, and no authentication.** Since then, on the `youssef` branch, we delivered **Phases 1–3 of the roadmap**:

- **Phase 1 (security + testability):** opt-in auth + rate limiting, installable dependency set, services-layer refactor, rule deduplication/validation, detection run history, host-scoped + rescan detection, artifact time/processed filters, and a **53-test pytest suite with ruff lint clean**.
- **Phase 2 (containers + CI/CD + agent automation):** multi-stage non-root `Dockerfile` + `docker-compose.yml` (Postgres 16), **Alembic migrations** replacing `create_all`, agent `--enroll`/`--daemon`/idempotent batch uploads, and a GitHub Actions pipeline (lint + test + gitleaks; GHCR build/push/smoke on version tags).
- **Phase 3 (dashboard + endpoint mgmt + manual triggers):** analyst **dashboard** at `/dashboard` (overview/endpoints/detections/runs/artifacts/audit), endpoint management (`PUT /endpoints/{id}/config`, add-endpoint enroll), manual triggers (run-collection-now command queue, `POST /detect` with host scope/rescan, run history), **detection triage lifecycle** (new → acknowledged → false/true positive → reviewed + notes), ops hardening (structured JSON logging, `/metrics`, `/audit-logs`), and ATT&CK enrichment from the **in-repo STIX dataset**.

Today the framework is a self-service platform: an analyst can enroll endpoints from the dashboard, trigger collection/detection on demand, browse history, and triage detections — all without CLI/curl.

---

## 2. Original State — Where We Started

This is the state of the repository at the baseline (`main` branch, commit `976db96`, and the inherited working tree committed in `1bef00a`).

### 2.1 What existed and worked

A complete end-to-end demo pipeline, proven against real VM data (`backend/dfir.db` contained 2,742 artifacts from 2 hosts — a Windows 10 VM and an Ubuntu server):

- **Collector** (`collector/`): a cross-platform agent (`collector_agent.py`) with modules for processes, network, persistence, scheduled tasks, logs, and file scanning (`collector/modules/`). File scanning happened on the endpoint — only hashes + YARA results were shipped, never raw files.
- **Backend** (`backend/`): a FastAPI app with `main.py`, `models.py`, `schemas.py`, `database.py` (SQLite). Endpoints: `/health`, `/ingest`, `/artifacts`, `/hosts`. This was a pure **ingest API** — no detection engine in the backend yet.
- **Detection** (`detection/`): a *separate, second copy* of detection code (`attck_mapper.py`, `detection_routes.py`, `hash_checker.py`, `ioc_correlation.py`, `sigma_matcher.py`, `yara_engine.py`) — see the problems below.
- **Rules & intel**: 15 Sigma-style rules (`backend/sigma_rules/rule001…rule015_*.yml`) plus duplicate/legacy rule files; 6 curated YARA rules (`backend/yara_rules/curated_ruleset.yar`); IOC files (`iocs/known_bad_hashes.txt`, `iocs/malicious_ips.txt`).
- **Sample data** (`sample_data/`): two collected folders from the Windows VM and Ubuntu server, used to replay into the API via `push_samples.py`.

### 2.2 The problems we inherited (the "why" of Phase 1)

These were documented in the original `PROJECT_OVERVIEW.md` "Known Issues" section:

| # | Problem | Impact |
|---|---|---|
| 1 | **Committed secrets** — real API keys in `backend/.env.txt` and `detection/.env.txt` (AbuseIPDB, OTX, URLhaus) | Keys exposed in git history |
| 2 | **`detection/` was a broken stale copy** — no `database.py`/`models.py`/`schemas.py`; its `detection_routes.py` predated the pipeline refactor; it could not run | Duplicated, drifting code |
| 3 | **Zero automated tests** — only `__main__` smoke blocks | No regression safety net |
| 4 | **`backend/requirements.txt` was UTF-16** (PowerShell `pip freeze`) and **missing `yara-python` + `mitreattack-python`** | `pip install -r` failed on Linux; installs were broken |
| 5 | **Duplicate Sigma rule IDs** (4 legacy files duplicating rule-001/002/003) | Duplicate detections from the same rule |
| 6 | **Runtime data committed** — `backend/dfir.db` not gitignored; `collector/output/` in the tree | Repo bloat + data leaks |
| 7 | **No authentication** on any endpoint; README suggested binding `0.0.0.0` | Unsafe beyond a trusted lab |
| 8 | **ATT&CK enrichment depended on an external STIX dataset** (`../../dfir-refs/cti/…`) not in the repo | Fails soft (silently returns `None`) if missing |
| 9 | **Ingest had no idempotency** | Re-posting duplicated rows |
| 10 | **`processed=1` was terminal** — no rescan path | New rules could never re-analyze old artifacts |
| 11 | **Vestigial code** — `yara_engine.py`, `db/`, empty `SCHEMA.md`, empty `docs/mitre_mapping.json` | Confusion, dead weight |
| 12 | Various **perf/robustness notes** (rules reloaded from disk every run, unbounded IP cache, time stored as string, denormalized `host`, `load_dotenv()` not picking up `.env.txt`) | Technical debt |

Also on `main`: a 2-line `README.md`, an empty `SCHEMA.md`, and `PROJECT_OVERVIEW.md` itself — which accurately documented all the problems above. The project had **no branches** besides `main` (the `dashboard/attack-mapping-and-reports` branch already existed on the remote).

---

## 3. Changes Made Until Now (in detail)

All of the following is committed on the **`youssef`** branch. Each change was smoke-tested before its commit.

### 3.1 Git & repository hygiene

- Created and worked exclusively on the **`youssef`** branch (never merged into `main`).
- Set local git identity: `youssefbouaouina <youssef.bouaouina@esprit.tn>`.
- **Pushed `youssef` to GitHub** (`origin`) so the branch is visible to collaborators: `https://github.com/youssefbouaouina/dfir-threat-hunting-framework/tree/youssef`.
- `.gitignore` now ignores `.env.txt`, `*.db`, and `*.db-journal`.

### 3.2 Documentation & governance

- Added `PROJECT_OVERVIEW.md` (living technical reference), `ROADMAP.md` (5-phase enterprise plan), `AI_RULES.md` (binding modification rules), and `CONTRIBUTING.md` (development conventions).

### 3.3 Dependencies & installability (commit `3ab5125`)

- Rewrote `backend/requirements.txt` as a **UTF-8, top-level, ranged** file that actually installs on Linux, and added the previously-missing `yara-python>=4.5.0` and `mitreattack-python>=3.0.0`.
- Added `backend/requirements-dev.txt` (`pytest`, `ruff`, `httpx`, includes `-r requirements.txt`).
- Added `backend/.env.example` with placeholder values for auth, rate limiting, scheduler, and intel keys, and wired `load_dotenv()` so a real `.env` is honored.
- Removed `backend/.env.txt` (committed secrets) from the index.

### 3.4 Security — opt-in auth & rate limiting (commit `1bef00a`)

- New `backend/security.py`:
  - **Auth is opt-in** — `AUTH_ENABLED=false` by default, preserving the open-lab demo behavior. When enabled, missing/invalid credentials return `401`.
  - **Agent auth**: long-lived per-endpoint API keys (`AGENT_API_KEYS`, comma-separated in env) required for `/ingest` via `Authorization: Bearer <key>`.
  - **Admin/analyst auth**: the admin key (`ADMIN_API_KEY`) or a short-lived **HMAC-signed token** (issued by `POST /auth/login`, TTL from `TOKEN_TTL_SECONDS`, default 1800 s) required for `/artifacts`, `/hosts`, `/scheduler/status`, `/detect`, `/detections`, `/detections/summary`.
  - **Rate limiting**: sliding-window per client (active only when auth is enabled) returning `429` over limit.
  - No secrets are ever logged; stdlib-only token signing (`base64`/`hmac`/`hashlib`).

### 3.5 Services-layer refactor — thin endpoints (commit `72acd89`)

Introduced `backend/services/` with DI-friendly, unit-testable business logic, per AI_RULES (thin endpoints, services for logic):

- `services/ingest_service.py` — `ingest_artifacts(db, artifacts)` (host upsert + artifact insert, `ValueError` on empty batch).
- `services/query_service.py` — `list_artifacts(...)` and `list_hosts(db)`.
- `services/detection_service.py` — the full detection pipeline as `run_detection_job(db, host, rescan, trigger)`, shared by **both** the scheduler and `POST /detect` so the two trigger paths can never drift. Also `list_detections`, `list_detection_runs`, `detections_summary`.
- `backend/main.py` and `backend/detection_routes.py` are now thin HTTP layers.
- Endpoint upgrades delivered in the same commit:
  - `POST /detect` now accepts **`host`** (scope to one host) and **`rescan`** (re-analyze already-processed artifacts).
  - `GET /artifacts` now accepts **`collected_since` / `collected_until` / `processed`** filters.
  - `GET /hosts` returns newest-`last_seen` first.
- `backend/database.py` honors a **`DATABASE_URL`** env override (default remains SQLite — no migration yet).

### 3.6 Sigma rule hygiene (commit `0873d43`)

- `sigma_matcher.load_rules()` now **validates** rule files (required keys, parseable YAML, mapping document) and **dedupes by `id`** — invalid/duplicate files are skipped with a warning instead of crashing a run or double-firing.
- Removed the fragile `"-e "` token from `rule001_powershell_encoded.yml` (it was causing a false positive against `nc -e` one-liners). Only the 15 canonical rules load; the 4 legacy duplicate files are skipped with a warning.

### 3.7 Detection run history (commit `98fc6b4`)

- New `DetectionRun` model / `detection_runs` table: `trigger` (`manual` | `scheduled`), `status` (`started` | `completed` | `failed`), `host`, `rescan`, `started_at`/`finished_at`, `artifacts_scanned`, `detections_found`, `by_severity` and `by_technique` (JSON).
- Every pipeline invocation records a run — **including failed cycles** (rolled back but visible), so a broken run is never silent.
- `GET /detection-runs` exposes the history (filterable by status, limit).
- The scheduler passes `trigger="scheduled"`; `POST /detect` passes `trigger="manual"`.

### 3.8 Automated tests & lint (commit `578d34d`)

- Added `backend/pyproject.toml` with **ruff** config (line-length 100, rule set E/F/W/I/UP/B, `B008` ignored for FastAPI `Depends` idiom) and pytest config (`testpaths=["tests"]`).
- Added a **38-test pytest suite** in `backend/tests/`:
  - `test_sigma_matcher.py` — rule loading validation/dedup (incl. the duplicate-id + `nc -e` regression), condition operators (contains / exact / list / artifact-type gating).
  - `test_hash_checker.py` — known-bad hash parsing and matching (EICAR → critical detection).
  - `test_ioc_correlation.py` — IP extraction, local blocklist hits, live-feed severity thresholds (mocked), private-address skip.
  - `test_detection_service.py` — full pipeline against a temp DB: persist + history, no-rescan dedup, rescan, host scope, failed-run recording.
  - `test_security.py` — token issue/verify/tamper/expiry, admin & agent dependency auth, login, rate-limit blocking.
  - `test_api.py` — TestClient integration: health, ingest round-trip, empty-ingest 400, `/detect` end-to-end, rescan, host scope, run history, artifact filters.
  - `tests/conftest.py` — isolated per-test SQLite DBs via `dependency_overrides`; the app's default engine pointed at a session-wide temp DB (never touches the real `dfir.db`).
- Ran `ruff check` across the backend and fixed all findings (import sorting, line length, unused imports, mode args). **`ruff` is clean; all 38 tests pass.**

### 3.9 Not yet changed (deliberately, awaiting approval)

Per AI_RULES §14 (ask before deleting files), these deletion candidates have been **identified but not removed** — they still exist in the tree and are NOT part of the current commit set:

- `detection/` — the broken stale duplicate tree.
- `backend/yara_engine.py` — dead code (the pipeline consumes YARA results embedded by the collector instead).
- `backend/db/` (empty placeholder), empty `docs/mitre_mapping.json`, empty `SCHEMA.md`, empty `sample_data/README.md`.
- Duplicate/legacy sigma rule files (`suspicious_*.yml`, `test_encoded_ps.yml`) — now skipped at load, but still on disk.

---

## 4. What We Have Achieved

### 4.1 Against the Phase 1–3 exit criteria

| Phase | Exit criterion | Status |
|---|---|---|
| P1 | `pip install -r requirements.txt` works on Linux | ✅ UTF-8 top-level requirements + `requirements-dev.txt` |
| P1 | `pytest` green | ✅ 53 backend + 7 collector tests, all passing |
| P1 | No secrets in repo | ✅ `.env.txt` removed from index; `.env.example` + `.gitignore` + gitleaks in CI |
| P1 | Agent & admin endpoints require auth | ✅ Opt-in auth (`AUTH_ENABLED`), agent keys + admin tokens + rate limiting |
| P1 | Duplicate rules gone | ✅ Validation + dedup at `load_rules` |
| P2 | `docker compose up` runs the stack | ✅ backend + Postgres 16 |
| P2 | DB migrations apply cleanly | ✅ Alembic; committed `dfir.db` verified at head `ca41c1ba0e02` |
| P2 | Images build + deploy via CI on tag | ⚠️ workflow present; not yet exercised on a real tag |
| P2 | Agent enrolls + auto-pushes on schedule | ✅ `--enroll --daemon` + idempotent `batch_id` |
| P2 | Every detection cycle logs a history row | ✅ `detection_runs` row per cycle (incl. failures) |
| P2 | Manual `/detect` supports rescan + host scope | ✅ |
| P3 | Analyst enrolls endpoint from dashboard | ✅ Add-endpoint + run-collection-now + edit-config |
| P3 | Trigger collection + detection manually | ✅ `pending_commands` queue + `POST /detect` |
| P3 | See run history and triage detections | ✅ Runs view + triage lifecycle + audit trail |

### 4.2 Delivered capabilities (current state)

- **Full collect → ship → store → detect → query pipeline**, proven on real Windows/Ubuntu VM data.
- **4 detection layers**: Sigma-style behavioral rules (15 rules), embedded YARA results (6 rules), known-bad hash matching, network IOC correlation (local blocklist + best-effort AbuseIPDB live feed).
- **MITRE ATT&CK enrichment** from the **bundled in-repo STIX dataset** (`dfir-refs/cti/enterprise-attack/enterprise-attack.json`) — works offline.
- **Analyst dashboard** (`/dashboard`): overview health cards, endpoint management, manual run triggers, detection history, artifact explorer, audit trail.
- **Detection triage lifecycle** with analyst notes, fully audited.
- **Endpoint management**: self-enrollment, per-endpoint config (`PUT /endpoints/{id}/config`), manual "run collection now" command queue.
- **Ops hardening**: structured JSON logging (`LOG_FORMAT=json`), Prometheus-style `/metrics`, immutable `/audit-logs`.
- **Containerized backend** (non-root, healthcheck, auto-migrate entrypoint) + `docker-compose.yml` (Postgres 16) + GitHub Actions CI/CD (lint/test/gitleaks; GHCR build/push/smoke on tags).
- **Background scheduler** (APScheduler, configurable interval) + manual `POST /detect`.
- **Host-scoped & rescan detection** — DFIR triage scoping and re-analysis after rule updates.
- **Detection run history** — every cycle recorded (trigger, status, timing, counts), including failures.
- **Filterable queries** — artifacts (host / type / time window / processed state), detections (host / severity), run history (status).
- **Opt-in production-grade auth** — agent API keys, admin HMAC tokens, rate limiting; verified end-to-end.
- **Clean architecture** — thin endpoints, services layer with DI, no duplicated logic, lint-clean, typed, documented.
- **60 automated tests** (53 backend + 7 collector) covering the matcher, hash checker, IOC correlation, security, detection service, endpoint mgmt, and the full HTTP API.

### 4.3 Quality attributes achieved

- **Security**: secrets removed from index; auth/rate-limit implemented behind a flag; no secrets logged.
- **Maintainability**: services layer, docstrings everywhere, typing, logging, ruff-clean, single source of truth for the pipeline (`run_detection_job`).
- **Correctness**: rule validation + dedup; regression tests for the `nc -e` false positive; failed runs are visible in history.
- **Offline-first / fail-soft**: every detection layer degrades gracefully (missing feeds/keys/datasets never crash `/detect`).

---

## 5. What Is Still Needed to Complete Our Goals

The **ROADMAP.md** target is an enterprise-grade, containerized, CI/CD-driven platform. **Phases 1–3 are done**; the following remain:

### Phase 4 — Scale, correlation, enterprise features *(next)*
- **Async ingest** via a message queue (Redis/RabbitMQ) + containerized workers — `/ingest` returns 202, no API blocking.
- **Correlation engine**: group detections into `incidents` (new `incidents` + `incident_detections` tables), same-rule-across-hosts aggregation, ATT&CK chain reconstruction, severity scoring.
- **Storage & retention**: retention/purging policies per artifact type, JSONL archival, optional OpenSearch sink.
- **RBAC & audit**: team/org scoping, granular roles, immutable audit trail.
- **Notifications**: webhook/email/Slack/Teams on high/critical detections or endpoint offline > threshold.

### Phase 5 — Advanced detection, intel automation, HA
- Real **pySigma** backend + **SigmaHQ rule update pipeline** in CI (keeping the current rule format via a conversion layer).
- **IOC feed automation** (MalwareBazaar/Feodo/URLhaus/OTX) into `iocs/` + STIX/TAXII export; complete the IOC correlation live layer (OTX/URLhaus/Feodo are currently env-keys-only).
- **HA & performance**: Kubernetes/multi-replica, Postgres HA + backups, connection pooling, pagination/matview review.

### Immediate low-effort follow-ups (from the engineering backlog)
1. Rotate/revoke the API keys that were previously committed (best practice — the `.env.txt` files were deleted from disk in the continuation session).
2. Backend-side YARA re-scan of stored files (needs file storage; currently hashes only).
3. Enforce `/ingest` request-size limit + make rate limiting independent of auth.
4. Return the enrollment token to the agent on first enroll; honor per-endpoint `collectors` config in the agent daemon.

---

## 6. Showcase Guide — Setup & Usage (step by step)

> **The full, tested walkthrough moved to [SETUP_GUIDE.md](SETUP_GUIDE.md)** — written for the project's real target environment (Windows laptop + VMware + two VMs: Ubuntu Server + Windows 10). It covers backend setup, firewall, loading demo data, enrolling both VMs, dashboard use, auth, and Docker/Postgres.

The abbreviated Linux quick-start below remains accurate for a single-machine demo (Python 3.10+).

### 6.1 What you will show

1. A **live API** (`/health`, `/docs`) receiving artifact data.
2. The **collection agent** producing real artifacts on an endpoint.
3. The **4-layer detection pipeline** firing on injected/sample malicious artifacts.
4. **MITRE ATT&CK-enriched detections** and a **run-history** view.

### 6.2 Prerequisites

- Python 3.10+ with `pip` (or a venv). On Windows you would use `py -m venv`; this guide uses Linux commands.
- A copy of the repo: `git clone https://github.com/youssefbouaouina/dfir-threat-hunting-framework.git` and `git checkout youssef`.
- (Optional) Internet access for the AbuseIPDB live-feed layer and for `mitreattack-python` ATT&CK enrichment.

### 6.3 Backend setup

```bash
cd dfir-threat-hunting-frameworkV3/backend

# (recommended) isolated environment
python3 -m venv .venv && source .venv/bin/activate

# install dependencies
pip install -r requirements.txt

# optional: create a local env file (auth stays OFF for the demo)
cp .env.example .env
```

> If your environment cannot create venvs (like some sandboxes), you can install into a target directory instead:
> `pip install --target /tmp/pydeps -r requirements.txt` and run everything with `PYTHONPATH=/tmp/pydeps`.

### 6.4 Run the backend

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

- Interactive API docs: **http://127.0.0.1:8000/docs**
- Liveness check: `curl http://127.0.0.1:8000/health` → `{"status":"ok"}`
- The **scheduler starts automatically** (every 30 s by default; change with `DETECTION_INTERVAL_SECONDS`).

### 6.5 Load data

**Option A — replay bundled sample data (no endpoint needed):**

```bash
python push_samples.py ../sample_data/2026-07-29_win10-vm01
python push_samples.py ../sample_data/2026-07-29_ns-ubuntu-server
```

**Option B — run the collector on a real endpoint (Windows or Linux):**

```bash
cd ../collector
pip install -r requirements.txt      # on Windows also: pywin32_postinstall.py -install
python collector_agent.py            # run elevated / sudo for full visibility
```

This writes `collector/output/<date>_<hostname>/<artifact_type>.json`. Copy that folder into `sample_data/` (or point `push_samples.py` at it directly) and push it as above.

**Option C — inject a malicious artifact for a guaranteed detection:**

```bash
curl -X POST http://127.0.0.1:8000/ingest \
  -H "Content-Type: application/json" \
  -d '[{"host":"demo-host","os":"linux","collected_at":"2026-01-01T00:00:00Z",\
       "artifact_type":"process",\
       "data":{"name":"powershell.exe","cmdline":"powershell.exe -enc SQBFAFgA"}}]'
```

This triggers **rule-001 (Suspicious PowerShell EncodedCommand, T1059.001, high)**.

### 6.6 Run detection

- **Automatic:** the scheduler already runs it every 30 s.
- **Manual:** `POST /detect` — scope to a host with `?host=desk-01`, or force a re-analysis with `?rescan=true`:

```bash
curl -X POST http://127.0.0.1:8000/detect
```

Response example:

```json
{"artifacts_scanned": 2742, "detections_found": 4,
 "by_severity": {"medium": 4}, "by_technique": {"T1053.005": 4}}
```

### 6.7 View results

```bash
curl http://127.0.0.1:8000/detections                    # all detections
curl "http://127.0.0.1:8000/detections?severity=high"    # filtered by severity
curl http://127.0.0.1:8000/detections/summary            # ATT&CK coverage counts
curl http://127.0.0.1:8000/detection-runs                # run history (trigger/status/counts)
curl http://127.0.0.1:8000/artifacts?limit=5             # stored artifacts
curl http://127.0.0.1:8000/hosts                         # known endpoints
curl http://127.0.0.1:8000/scheduler/status              # scheduler state
```

### 6.8 Enable authentication (the "security" highlight)

To demonstrate the opt-in auth during a showcase:

```bash
export AUTH_ENABLED=true
export ADMIN_API_KEY=demo-admin-key
export AGENT_API_KEYS=demo-agent-key-1
uvicorn main:app --host 0.0.0.0 --port 8000
```

Now:
- `GET /hosts` without a token → **401**.
- Login for an analyst token: `curl -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" -d '{"api_key":"demo-admin-key"}'` → `{"token":"<jwt-like signed token>", ...}`.
- `curl http://127.0.0.1:8000/hosts -H "Authorization: Bearer <token>"` → **200**.
- Ingesting requires an agent key: `curl -X POST http://127.0.0.1:8000/ingest -H "Authorization: Bearer demo-agent-key-1" -H "Content-Type: application/json" -d '[...]'`.

### 6.9 Run the test suite (the "quality" highlight)

```bash
cd ../backend
pip install -r requirements-dev.txt
pytest -v            # 53 tests, all green
ruff check .         # lint clean
```

> The suite uses isolated temp SQLite databases; it never touches your real `dfir.db`. The collector has its own 7-test suite (`cd ../collector && pytest`).

### 6.10 Suggested showcase script (10 minutes)

| Minute | Action | What the audience sees |
|---|---|---|
| 0:00 | Backend up, `/docs` open | Real REST API, auto docs |
| 0:30 | Push `sample_data` (Option A) | Artifacts land (`/artifacts`) |
| 1:00 | `POST /detect` | Pipeline runs, counts returned |
| 1:30 | Show `/detections` + `/detections/summary` | ATT&CK-enriched detections, coverage |
| 2:00 | Inject the PowerShell artifact (Option C) | A **high** detection appears for rule-001 |
| 2:30 | `GET /detection-runs` | Run history with trigger/status/counts |
| 3:00 | Open `/dashboard` — add endpoint, run collection/detection, triage | The Phase 3 self-service surface |
| 3:30 | Enable auth (6.8) | 401 without token, login flow, token works |
| 4:00 | `pytest -v` | 53 tests green |
| 4:30 | Open-ended Q&A | Deep dive into rules, collector, roadmap |

---

## 7. Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| `pip install -r requirements.txt` fails | You are on the old UTF-16 file — `git checkout youssef` (the fix is on our branch). |
| `mitreattack-python` / ATT&CK names missing in detections | `attck_mapper` needs the STIX dataset (`enterprise-attack.json`). It fails soft — install the `mitre/cti` repo, or accept `None` fields. This is documented. |
| `/detect` returns 401 after enabling auth | You need `ADMIN_API_KEY` or a login token; agent keys only work on `/ingest`. |
| No detections after pushing samples | Most sample VMs are "clean". Inject a malicious artifact (Option C) or add a matching rule. |
| Duplicate detections with the same `rule_id` | Legacy duplicate rule files — on `youssef` they are **skipped at load** with a warning; only the 15 canonical rules run. |
| `nc -e` one-liner doesn't fire rule-001 anymore | Intentional: we removed the fragile `"-e "` token to kill that false positive. |
| Scheduler appears twice under `uvicorn --reload` | Known: the reloader process also runs the lifespan. Prefer running without `--reload`. |
| Warnings about `schemas.py` Pydantic `Config` | Pydantic v2 deprecation; cosmetic, slated for a follow-up. |

---

## 8. Appendix — Branch & Commit History

### 8.1 Branch layout

- **`main`** — the original demo state (untouched by Phase 1).
- **`youssef`** ← **our work** — Phases 1–3 (pushed to GitHub).
- `dashboard/attack-mapping-and-reports` — pre-existing on the remote (not ours).

### 8.2 Commits on `youssef` (oldest → newest)

| Hash | Message | Content |
|---|---|---|
| `1bef00a` | chore: checkpoint youssef branch — inherited uncommitted working tree + docs + Phase 1 auth baseline | Baseline checkpoint: docs (`PROJECT_OVERVIEW`, `ROADMAP`, `AI_RULES`, `CONTRIBUTING`), `.env.example`, `security.py`, protected endpoints, `create_all` wiring |
| `3ab5125` | fix: restore installable requirements.txt (UTF-8, top-level) + requirements-dev.txt | Dependency fixes |
| `72acd89` | refactor: extract services layer; add /detect host scope + rescan, /artifacts filters | Services (`ingest/query/detection`), thin endpoints, filters, `DATABASE_URL` support |
| `0873d43` | fix: validate + dedupe sigma rules at load; drop fragile '-e ' token from rule-001 | Rule hygiene |
| `98fc6b4` | feat: detection run history (detection_runs) + GET /detection-runs | Run history model + endpoint |
| `578d34d` | test: pytest suite (38 tests) + ruff config; lint fixes across backend | Phase 1 test suite + lint |
| `3d4d153` | docs: add PROJECT_SUMMARY.md — original state, changes, achievements, remaining work, and showcase guide | Phase 1 summary document |
| `37144db` | phase 2 Containers, Postgres, and a RealCI/CD Delivery Pipeline | Dockerfile + compose + `.dockerignore`, Alembic migrations (initial `4823f807fcd2`), agent enroll/daemon/batch-id, `ci.yml` (lint/test/gitleaks + GHCR build/push/smoke), collector tests (7) |
| `af77469` | phase 3 completed:Dashboard, EndpointManagement, and Manual Trigger Controls | `/dashboard` static SPA, endpoint config PUT + run-collection + command queue, triage lifecycle + migration `ca41c1ba0e02`, `/metrics` + `/audit-logs`, JSON logging, in-repo STIX, repo cleanup (removed `detection/`, dead code) |
| `…` | continuation session (2026-08-03) | `.ai/` AI memory committed + Phase 2/3 validation (see `.ai/SESSION_HISTORY.md`) |

> The **complete Phase 1–3 summary**, the detailed technical reference, and the plan for the remaining phases live in [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) and [ROADMAP.md](ROADMAP.md). The full setup/run walkthrough is [SETUP_GUIDE.md](SETUP_GUIDE.md).

---

*End of summary. Keep this file updated as the project progresses.*
