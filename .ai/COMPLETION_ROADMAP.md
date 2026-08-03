# Completion Roadmap — DFIR Threat Hunting Framework

> Generated: 2026-08-03 continuation session. Based on `.ai/CURRENT_ANALYSIS.md`, `.ai/NEXT_STEPS.md`, and `ROADMAP.md`. Every task lists files affected, dependencies, difficulty, risk, expected result, and validation method. Order follows impact-first: **Critical → High → Medium → Low → Future** (Phases 4–5).

## Prioritization criteria (applied to every task)

1. Critical functionality (does the core loop break / is there a live credential risk?)
2. Stability (correctness of existing features)
3. Security (credential leaks, open-instance protection)
4. Maintainability (doc drift, duplicated logic)
5. Performance (scale behavior)
6. User experience (dashboard truthfulness, live UX)
7. Advanced capabilities (Phase 4–5)

---

## Phase A — Critical (security / blocking)

### A1. Delete + rotate leaked API keys (`detection/.env.txt`, `backend/.env.txt`)
- **Why:** real AbuseIPDB/OTX/URLhaus keys sit on disk under gitignored dirs; they were previously committed so they are compromised (KNOWN_ISSUES S1).
- **Files:** `detection/.env.txt`, `backend/.env.txt` (delete); provider dashboards (rotate, manual by user).
- **Deps:** user approval (AI_RULES §14) + user performs key rotation.
- **Difficulty:** trivial. **Risk:** none (files are gitignored; deletion does not touch git history).
- **Result:** no live credentials on disk; only `.env.example` placeholders remain.
- **Validation:** `Test-Path` both files → false; `git status` shows no tracked change.

### A2. Reject startup with default secrets when auth is enabled — ✅ DONE (commit `50e8a34`)
- **Why:** `AUTH_ENABLED=true` + default `change-me-*` secrets silently deploys an unprotected instance (S2).
- **Files:** `backend/security.py`; possibly `.env.example` comment.
- **Deps:** none. **Difficulty:** trivial. **Risk:** none.
- **Result:** app refuses to start when `AUTH_ENABLED=true` and `ADMIN_API_KEY`/`AUTH_SECRET` are defaults or empty (also rejects empty `AGENT_API_KEYS`). Raises at import instead of log-warning.
- **Validation:** 2 unit tests reload the module with placeholder vs strong config and restore a working module afterwards; backend 60 tests pass; ruff clean.

---

## Phase B — High (correctness / required)

### B1 (H3). Commit `SETUP_GUIDE.md` + refresh `PROJECT_SUMMARY.md`
- **Why:** new-user guide is complete but untracked; `PROJECT_SUMMARY.md` describes Phase 1 only and misleads reviewers (D1).
- **Files:** `SETUP_GUIDE.md` (add), `PROJECT_SUMMARY.md` (rewrite Phases 2–3), commit.
- **Deps:** none. **Difficulty:** trivial–medium (docs). **Risk:** none.
- **Result:** repo self-documents Phases 1–3; guide lands in git.
- **Validation:** `git status` clean after commit; doc review.

### B2 (H1). Return the enrollment token to the agent (or remove it)
- **Why:** `enroll_endpoint` hashes a token it never returns — vestigial/misleading (B1). Real per-endpoint credential issuance.
- **Files:** `backend/services/endpoint_service.py`, `backend/schemas.py` (`EndpointOut` + new `EnrollResponse`), `backend/endpoint_routes.py`, `collector/agent_client.py` (enroll), `backend/tests/test_phase2.py` or `test_api.py`.
- **Deps:** none (decide: return token once on first enroll). **Difficulty:** small. **Risk:** low (response shape change — call out in commit; dashboard unaffected since it enrolls via same endpoint).
- **Result:** first-time enroll returns `enrollment_token`; subsequent re-enrolls omit it (idempotent).
- **Validation:** pytest for enroll-twice behavior; manual curl shows token only on first call.

### B3 (H2). Honor per-endpoint `collectors` config on the agent — ✅ DONE (commit `96a5d04`)
- **Why:** dashboard "edit config" is currently a lie — agent ignores the `collectors` list (B2).
- **Files:** `collector/agent_client.py` (`daemon_loop`, `get_endpoint_config`), `collector/collector_agent.py` (`run_collection`/CLI plumbing to pass `only`), `collector/tests/test_agent_client.py`.
- **Deps:** none. **Difficulty:** small–medium. **Risk:** low (agent-side behavior only; fail-soft if config empty).
- **Result:** daemon uses backend-provided `collectors` subset instead of the fixed full set.
- **Validation:** collector unit test simulating config response → asserts `run_collection` called with the subset.

### B4 (H4). Enforce `/ingest` request-size limit + make rate limiting independent of auth — ✅ DONE (commit `c25ee12`)
- **Why:** open-lab instance is trivially floodable; no body cap (S3).
- **Files:** `backend/main.py` (middleware or per-route size check), `backend/security.py` (split `RATE_LIMIT_ENABLED`), `backend/.env.example`, `backend/tests/test_security.py`.
- **Deps:** none. **Difficulty:** small. **Risk:** low (new 413 on oversized body; rate-limit flag defaults to auth state to preserve behavior).
- **Result:** requests > cap (default 10 MB) → 413 via `enforce_ingest_size` middleware; `RATE_LIMIT_ENABLED` works without auth (defaults to the `AUTH_ENABLED` value).
- **Validation:** pytest 413 + rate-limit-on-without-auth + rate-limit-off-when-disabled tests (3 new, backend 58 at that commit); ruff clean.

---

## Phase C — Medium (quality / scale)

### C1 (M1). YARA severity from rule meta instead of hardcoded `high` — ✅ DONE (commit `520750c`)
- **Files:** `backend/services/detection_service.py`, `backend/tests/test_detection_service.py` (+ a rule with meta.severity fixture).
- **Deps:** none. **Difficulty:** small. **Risk:** low.
- **Result:** `severity = meta.get("severity") or meta.get("level") or "high"`.
- **Validation:** pytest asserting severity per rule meta (3 cases: severity, level, bare-rule default). Backend 61 tests.

### C2 (M2). Real live-IOC coverage (OTX/URLhaus/Feodo) + scheduled feed refresh — ✅ DONE (commit `917006b`)
- **Why:** env keys are dead config; roadmap Phase 5 wants automated feeds into `iocs/`.
- **Files:** `backend/ioc_correlation.py`, `backend/requirements.txt` (no new dep needed — requests), `backend/services/` new `intel_service.py` or extend `ioc_correlation`, `backend/.env.example`, tests.
- **Deps:** none; reuse `check_abuseipdb` pattern. **Difficulty:** medium. **Risk:** medium (new network calls must fail soft).
- **Result:** URLhaus (keyless) + OTX live checks; `refresh_feodo_blocklist()` writes `iocs/feodo_ips.txt`; scheduler `intel_refresh` job every `INTEL_REFRESH_INTERVAL_SECONDS` (default 12h); correlation merges curated + feodo lists.
- **Validation:** 6 new mocked tests (URLhaus/OTX hits, checker order, feodo write + fail-soft, merge). Backend 73 tests.

### C3 (M3). Aggregate queries for metrics/summary (drop full-table scans) — ✅ DONE (commit `77abbd2`)
- **Files:** `backend/services/metrics_service.py`, `backend/services/detection_service.py::detections_summary`, tests.
- **Deps:** none. **Difficulty:** small (SQLAlchemy `func.count`/`group_by`). **Risk:** low.
- **Result:** `/health`, `/metrics`, `/detections/summary` use SQL aggregation (no full-table Python loads).
- **Validation:** pytest counts match; dashboard summary still renders. 1 new test. Backend 65 tests.

### C4 (M4). Pagination + cursor for list endpoints — ✅ DONE (commit `17bb884`)
- **Files:** `backend/main.py` (`/artifacts`), `backend/services/query_service.py`, `backend/services/detection_service.py`, `backend/detection_routes.py` (`/detections`, `/detection-runs`), tests.
- **Deps:** C3. **Difficulty:** medium. **Risk:** low (additive `before_id` cursor; `limit` kept; response shape unchanged).
- **Result:** stable cursor pagination (`id < before_id`); no page drift.
- **Validation:** pytest walking pages of /artifacts + /detections. Backend 67 tests.

### C5 (M5). Fix stale doc references (AI_RULES, docstrings, README) — ✅ DONE (commit `1f72448`)
- **Files:** `AI_RULES.md` (service names, removed files), `README.md` (rewrite stub), `collector/modules/common.py`, `collector/collector_agent.py`, `PROJECT_OVERVIEW.md` §7.1, `backend/schemas.py` docstring.
- **Deps:** none. **Difficulty:** trivial. **Risk:** none.
- **Result:** docs reference only existing files/services; README useful.
- **Validation:** grep for removed paths (`detection/`, `yara_engine.py`, `services/detection.py`, `SCHEMA.md`) → no stale hits in active docs; `.ai/MODULE_INDEX.md` refreshed.

### C6 (M6). Heartbeat/offline detection for endpoints — ✅ DONE (commit `200e639`)
- **Files:** `backend/services/endpoint_service.py` (`_touch_endpoint`, `mark_offline_stale`), `backend/scheduler.py` (`offline_sweep` job), `.env.example` (`OFFLINE_SWEEP_INTERVAL_SECONDS`, `OFFLINE_STALE_AFTER_SECONDS`), tests.
- **Deps:** none. **Difficulty:** medium. **Risk:** low (read-only sweep; status flip only).
- **Result:** config poll refreshes `last_seen` + restores `online`; endpoints stale > `OFFLINE_STALE_AFTER_SECONDS` (default 900s) → `offline`.
- **Validation:** 3 new tests (heartbeat, sweep flips stale, poll restores offline). Backend 64 tests.

### C7 (M7). Stop tracking `backend/dfir.db` (user decision)
- **Why:** binary tracked artifact → merge conflicts + bloat (W4).
- **Files:** `backend/dfir.db` (`git rm --cached`), `.gitignore` (`backend/dfir.db`), docs.
- **Deps:** user decision (it's demo data). **Difficulty:** small. **Risk:** medium (removes committed demo DB; document how to regenerate).
- **Result:** `.db` untracked; demo data obtainable via `push_samples.py` + sample_data.
- **Validation:** `git status` clean; fresh DB boots via migrations.

---

## Phase D — Low (polish)

### D1 (L1). `mypy` gradual typing + `pip-audit` in CI
- **Files:** `.github/workflows/ci.yml`, `backend/pyproject.toml`, `requirements-dev.txt`.
- **Deps:** none. **Difficulty:** medium. **Risk:** low (CI-only; keep ruff gates).
- **Result:** type + dependency-vulnerability gates in CI.

### D2 (L2). `Dockerfile.agent` + containerized e2e test in CI
- **Files:** `Dockerfile.agent`, `docker-compose.yml`, `.github/workflows/ci.yml`.
- **Deps:** none. **Difficulty:** medium. **Risk:** low–medium (agent on Linux container has limited collectors; scope to process/network).
- **Result:** CI exercises agent→backend loop.

### D3 (L3). Dashboard auto-refresh / websocket
- **Files:** `backend/static/app.js` (+ maybe SSE endpoint).
- **Deps:** none. **Difficulty:** small. **Risk:** low.
- **Result:** live counts without manual refresh.

### D4 (L4). `/scheduler/status` in dashboard
- **Files:** `backend/static/app.js`, `backend/static/index.html`.
- **Deps:** none. **Difficulty:** trivial. **Risk:** none.

---

## Phase E — Future (Phases 4–5, from ROADMAP.md)

| ID | Task | Files | Difficulty | Risk | Exit criterion |
|---|---|---|---|---|---|
| F1 | Async ingest queue (Redis/RabbitMQ) + workers | new `workers/`, `docker-compose.yml`, `main.py` | high | high | `/ingest` returns 202; workers persist |
| F2 | Correlation engine: `incidents` + `incident_detections` | `models.py`, new migration, `services/correlation_service.py` | high | high | detections group into incidents with ATT&CK chains |
| F3 | Retention/archival (JSONL) + OpenSearch sink | `services/retention_service.py`, config | medium | medium | retention policy enforced |
| F4 | RBAC/team scoping + immutable audit | `security.py`, `models.py`, migration | high | high | roles enforced |
| F5 | Notifications (webhook/email/Slack) | `services/notify_service.py` | medium | medium | alerts on high/critical + offline |
| F6 | pySigma backend + SigmaHQ update pipeline | `sigma_matcher.py`, `ci.yml` | high | high | real Sigma backend; CI rule refresh |
| F7 | IOC feed automation + STIX/TAXII export | `services/intel_service.py`, export routes | medium | medium | feeds refresh automatically |
| F8 | k8s/HA, autoscaling, circuit breakers, pooling, matviews | infra + perf | high | high | horizontally scalable |

---

## Suggested execution order (within this continuation effort)

```
A1 ✅ (user-approved, delete+rotate) → B1 (H3) ✅ → B2 (H1) ✅ → B3 (H2) ✅ → B4 (H4) ✅ → A2 ✅
→ C1 (M1) ✅ → C5 (M5) ✅ → C6 (M6) ✅ → C3 (M3) ✅ → C4 (M4) ✅ → C2 (M2) ✅
→ C7 (M7, user decision) → D1–D4 → F1–F8
```

- Phase A + B complete; Phase C complete except **C7/M7** (stop tracking `backend/dfir.db` — needs user decision).
- Keep every commit green: `pytest` + `ruff` per task.
- Update `.ai/*` memory files after every completed task (Phase 5 refresh).
