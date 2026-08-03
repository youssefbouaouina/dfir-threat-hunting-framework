# Session History

Accomplishments, decisions, and lessons across the work on the `youssef` branch, summarized for context recovery.

## Continuation session (2026-08-03) — Phases 1–3 (restore, validate, roadmap)

### Context recovery
- Re-read all `.ai/*` memory files + `PROJECT_OVERVIEW.md`, `ROADMAP.md`, `AI_RULES.md`, `PROJECT_SUMMARY.md`, `SETUP_GUIDE.md`, `README.md`.
- Established the baseline: head `af77469`, Phases 1–3 done, 53 backend + 7 collector tests, ruff clean, DB at migration `ca41c1ba0e02`.

### Environment
- This box is **Windows (win32)**, Python 3.12.10 system-wide. The handover's `/tmp/opencode/pydeps` path is from a Linux dev box — **not applicable here**.
- Built a working venv at `%TEMP%\dfir_venv` and installed `backend/requirements.txt` + `requirements-dev.txt` + `collector/requirements.txt` (all installed cleanly; includes mitreattack-python 6.1, yara-python 4.5.4, ruff 0.16).
- Baseline runs: backend pytest = **53 passed**, collector pytest = **7 passed**, `ruff check .` clean in both trees, `alembic current` = `ca41c1ba0e02 (head)`.

### Critical discoveries
1. **`.ai/` is entirely untracked.** `git ls-files .ai` returns nothing — the whole AI knowledge base existed only on disk. This session commits it (Phase 1 checkpoint commit).
2. `SETUP_GUIDE.md` untracked (known H3 item).
3. `backend/.venv` and `backend/venv` are broken/non-functional on this machine (Linux-style + stale Python 3.14 pointer); not used.
4. `detection/.env.txt` (3 leaked keys) + `backend/.env.txt` (1 key) still on disk, gitignored — C1 pending (requires user approval to delete per AI_RULES §14).

### Decisions
- Working env for this session = `%TEMP%\dfir_venv`; document in AI_HANDOVER so the next session does not re-derive it.

### Phase 2 — validation (commit `c21cca6`)
- Re-ran full baseline on Windows: backend 53 + collector 7 tests green, ruff clean, alembic at `ca41c1ba0e02`.
- **Verified auth live end-to-end** with `AUTH_ENABLED=true` (login→token, admin 401s, agent-key 401s, enroll+config) — C2 substantively done; no committed automated test yet (add later).
- Confirmed documented gaps still true: B1 (token vestigial), B2 (collectors ignored by agent), S1 (keys on disk), S3 (no ingest size cap), doc drift.
- Wrote `.ai/CURRENT_ANALYSIS.md`; refreshed CHECKPOINT/ROADMAP_STATUS/KNOWN_ISSUES/AI_HANDOVER.

### Phase 3 — completion roadmap
- Wrote `.ai/COMPLETION_ROADMAP.md` (A critical → B high → C medium → D low → F future), each task with files/deps/difficulty/risk/result/validation.
- Execution order locked: A1 → B1(H3) → B2(H1) → B3(H2) → B4(H4) → C1(M1) → C5(M5) → C6(M6) → C3(M3) → C4(M4) → C2(M2) → C7(M7) → D1–D4 → F1–F8.

## What has been accomplished

### Phase 1 (commits `1bef00a` … `578d34d`)
- Removed committed secrets from the index; `.env.example` added; `.env*` gitignored.
- Rewrote `backend/requirements.txt` (UTF-8, top-level, ranged) + added `requirements-dev.txt`.
- Extracted a services layer (`services/ingest_service.py`, `query_service.py`, `detection_service.py`) and made `run_detection_job()` the single pipeline entry point shared by scheduler and `POST /detect`.
- Sigma rule validation + duplicate-id dedup at load; deleted duplicate rule files.
- Added detection run history (`detection_runs` table) and `GET /detection-runs`; `/detect` host scope + rescan; `/artifacts` time/processed filters.
- Opt-in auth (stdlib HMAC JWT-style tokens, per-endpoint agent keys) + sliding-window rate limit in `security.py`.
- 38-test pytest suite (later grown to 53) + ruff config; CI workflow with lint+test+gitleaks.

### Phase 2 (commit `37144db`)
- `backend/Dockerfile` (multi-stage, non-root, healthcheck, migration entrypoint), `docker-compose.yml` (Postgres 16), `.dockerignore`.
- Alembic migrations replacing `Base.metadata.create_all`; initial schema `4823f807fcd2` idempotent on legacy DBs; `Endpoint` model superseding passive host tracking.
- Agent automation: `--enroll`, `--daemon`, push-to-API, idempotent `batch_id` uploads.
- `ci.yml` full delivery: lint+test+gitleaks on push/PR; GHCR build+push+smoke on `v*` tags.
- Collector tests (7) for push/enroll/daemon.

### Phase 3 (commit `af77469`)
- `/dashboard` static vanilla-JS SPA (overview/endpoints/detections/runs/artifacts/audit views; JWT login).
- Endpoint management: `PUT /endpoints/{id}/config` (interval min 10), add-endpoint enroll.
- Manual triggers: `pending_commands` queue + agent poll (run collection now); `POST /detect?host=&rescan=`; `GET /detection-runs`.
- Detection triage lifecycle (`new→acknowledged→fp/tp/reviewed` + notes) via `PATCH /detections/{id}`; migration `ca41c1ba0e02` (PRAGMA-gated triage columns + `audit_logs` + `pending_commands`).
- Ops hardening: `logging_config.py` (JSON logs), `/metrics` (9 Prometheus-style gauges), `/audit-logs`.
- ATT&CK enrichment switched to the **in-repo** STIX dataset (`dfir-refs/cti/enterprise-attack/enterprise-attack.json`) — user approved committing only that single 48 MB file and gitignoring the rest of `dfir-refs/`.
- Repo cleanup (user-approved, per AI_RULES): removed `detection/` tree (incl. its `.env.txt`), `backend/yara_engine.py`, legacy `test_eicar.yar`, `db/.gitkeep`, duplicate sigma rules, empty `SCHEMA.md`/`docs/mitre_mapping.json`/`sample_data/README.md`, `collector/output/` runtime data.
- Docs: ROADMAP (Phase 3 → done), PROJECT_OVERVIEW (schema/API/module/class updates, known-issues resolutions), PHASE3.md written.
- Verified: 53 backend + 7 collector tests green; ruff clean; fresh-DB migration → `ca41c1ba0e02`; `/metrics`, `/health`, `/dashboard`, JSON logging smoke-tested.

## Major architectural decisions

- **Single detection pipeline** (`run_detection_job`) for both trigger paths — prevents scheduler/API drift.
- **Alembic-managed schema** with idempotent migrations for legacy SQLite DBs; startup `migrate_to_head()`.
- **Offline-first detection** (local hash/IP lists + local STIX; live intel fail-soft).
- **Idempotent ingest + first-call-wins command queue** for exactly-once-ish agent behavior.
- **Opt-in auth** (no-op deps when disabled) to keep open-lab demo behavior and tests intact.
- **Native agent / containerized backend** (roadmap principle 5).
- **In-repo STIX bundle** for reproducible offline ATT&CK enrichment.
- **Thin endpoints → services → models** layering with DI.

## Major completed features (see CHECKPOINT.md "Completed features")

Dashboard + endpoint management + manual triggers + triage + audit + metrics (Phase 3); containers/Postgres/CI-CD/agent automation (Phase 2); security/test net/rule hygiene (Phase 1).

## Recent improvements

- Detection failure now records a visible `failed` run (run row committed before work; rollback keeps history).
- `source_run_id` + `analyzed_at` give full audit of what analyzed each artifact.
- JSON logging + audit trail + metrics for ops visibility.
- Rule/duplicate hygiene eliminated double detections.

## Lessons learned

- **Smoke tests mutate the tracked `backend/dfir.db`** — always `git checkout backend/dfir.db` after exercising the live server, or tests run against dirty data.
- **Autogenerated Alembic revisions need PRAGMA guards** for SQLite legacy DBs (`has_table`/`table_info`) or `upgrade head` breaks on existing databases.
- **A user-added `dfir-refs/` is a huge nested clone tree** — committing the whole thing is impossible; whitelist in `.gitignore` + commit only the artifact the code actually consumes.
- **Non-interactive HTTPS push to the private remote needs a PAT**; keep the origin URL clean and pass the token via credential helper/env.
- **`PYTHONPATH=/tmp/opencode/pydeps`** is required to run pytest when deps are installed to a custom prefix (no system pip on the dev box); ruff binary lives at `/tmp/opencode/rufbin/bin/ruff`.
- **Stale docs degrade trust fast**: `PROJECT_SUMMARY.md` still describes Phase 1 only; docstrings still cite deleted files (`SCHEMA.md`, `detection/`). Keep docs in the same commit as code changes.
- **Default-secret warnings**: with `AUTH_ENABLED=false` default, "secure" claims must be explicit that auth is opt-in and default keys are placeholders.
