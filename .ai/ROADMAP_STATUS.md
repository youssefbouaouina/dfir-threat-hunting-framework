# Roadmap Status vs Implementation

Source: `ROADMAP.md` (the authoritative 5-phase plan). Phases 1–3 are done; Phases 4–5 are proposals.

## Status summary

| Phase | Theme | Status | Completion estimate |
|---|---|---|---|
| 1 | Harden & Stabilize (security + testability) | ✅ DONE (committed on `youssef`) | ~95% |
| 2 | Containers, Postgres, CI/CD, agent automation | ✅ DONE (committed on `youssef`) | ~90% |
| 3 | Dashboard, endpoint mgmt, manual triggers | ✅ DONE (committed `af77469`) | ~95% |
| 4 | Scale, correlation, enterprise features | Not started (proposal) | ~5% |
| 5 | Advanced detection, intel automation, HA | Not started (proposal) | ~0% |

**Overall roadmap completion: ≈ 50%** (3 of 5 phases done; Phases 4–5 are the bulk of remaining effort).

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
- Alembic migrations (initial schema `4823f807fcd2` idempotent on legacy DBs; `DATABASE_URL`-driven).
- Agent automation: `--enroll`, `--daemon`, push-to-API, idempotent `batch_id`.
- `ci.yml`: lint + test + gitleaks on push/PR; GHCR build+push+smoke on `v*` tags.
- Scheduler records a `detection_runs` row per cycle (delivered/verified in Phase 3).

**Remaining (~10%):**
- `Dockerfile.agent` (containerized agent for CI/e2e) — not done.
- No version tag/release has been cut yet (build job untested end-to-end on a real tag).

## Phase 3 — Dashboard, Endpoint Management, Manual Triggers

**Completed milestones (all checkboxes `[x]` in ROADMAP):**
- `/dashboard` vanilla-JS SPA (overview/endpoints/detections/runs/artifacts/audit).
- Endpoint management: enroll/add-endpoint, status/health list, `PUT /endpoints/{id}/config` (interval min 10s).
- Manual triggers: run-collection-now (pending_commands queue), `POST /detect?host=&rescan=`, `GET /detection-runs`.
- Detection triage lifecycle (`new → acknowledged → false_positive|true_positive|reviewed` + notes; migration `ca41c1ba0e02`).
- Ops hardening: JSON logging, `/metrics` (9 gauges), `/audit-logs`.
- ATT&CK enrichment now uses in-repo STIX; repo cleanup done.

**Remaining (~5%):** `detections/summary` is computed by loading all detections into memory (fine now, needs aggregation at scale); no host criticality field; agent heartbeat/offline detection is last-seen-based only.

## Phase 4 — Scale, Correlation, Enterprise

**Not started.** Work items: async ingest queue (Redis/RabbitMQ) + containerized workers; correlation engine (`incidents` + `incident_detections` tables, same-rule-across-hosts, ATT&CK chain, severity scoring); storage retention/archival; RBAC/team scoping; notifications (webhook/email/Slack). **Estimate: 5%** (design only).

## Phase 5 — Advanced Detection, Intel Automation, HA

**Not started.** Work items: pySigma backend; SigmaHQ rule update pipeline; IOC feed automation (MalwareBazaar/Feodo/URLhaus/OTX) + STIX/TAXII export; k8s/HA, autoscaling, circuit breakers; performance (pagination, matviews, pooling). **Estimate: 0%.**

## Cross-cutting work

- Documentation updated through Phase 3 (ROADMAP, PROJECT_OVERVIEW, PHASE3). **PROJECT_SUMMARY.md is stale** (Phase 1 only) — needs a Phase 2–3 update.
- `SETUP_GUIDE.md` (setup/run guide) written but **not committed**.
- End-to-end CI test using a containerized agent — not present.

## Deliverables-per-phase gaps (exit-criteria check)

- **Phase 1 exit criteria:** installable requirements ✓; pytest green ✓; no secrets in repo ✓ (gitleaks scans git history; `detection/.env.txt` still on disk, gitignored); agent+admin endpoints require auth — ⚠️ only when `AUTH_ENABLED=true` (default false); duplicate rules gone ✓.
- **Phase 2 exit criteria:** `docker compose up` runs stack ✓; migrations apply cleanly ✓; images build+deploy via CI on tag — ⚠️ not exercised on a real tag; agent enroll + auto-push ✓; run history row per cycle ✓; manual `/detect` rescan + host scope ✓.
- **Phase 3 exit criteria:** analyst can enroll endpoint from dashboard, trigger collection+detection, see history, triage — ✓ (all dashboard-exercised in smoke tests).
