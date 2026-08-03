# Engineering Handover — for the next AI engineer

You are resuming work on the **DFIR Threat Hunting Framework** on branch `youssef` (head `af77469`). Read `.ai/MODULE_INDEX.md`, `.ai/EXECUTION_FLOW.md`, and `.ai/KNOWN_ISSUES.md` first; this file is the orientation. `AI_RULES.md` at the repo root is binding.

> **Session note (2026-08-03):** As of this continuation session, `.ai/` and `SETUP_GUIDE.md` were untracked; they are committed here. The `.ai/` docs are now version-controlled and authoritative.
>
> **Environment note (IMPORTANT):** This box is **Windows**, Python 3.12.10 system-wide. The handover's `/tmp/opencode/pydeps` + `/tmp/opencode/rufbin` paths are from a Linux dev box and **do not exist here**. Working venv: `%TEMP%\dfir_venv` (created via `python -m venv`). Run backend tests with `& "$env:TEMP\dfir_venv\Scripts\python.exe" -m pytest` from `backend/`; ruff via `& "$env:TEMP\dfir_venv\Scripts\ruff.exe" check .`. The in-repo venvs (`backend/.venv`, `backend/venv`, `collector/venv`) are broken/non-functional on this machine.
>
> **Phase 2 note (2026-08-03):** full independent validation recorded in `.ai/CURRENT_ANALYSIS.md` — 53 backend + 7 collector tests green, ruff clean, migration at head `ca41c1ba0e02`, auth verified live end-to-end. Recommended next task is **H3** (commit `SETUP_GUIDE.md` + refresh `PROJECT_SUMMARY.md`) then **C1** (delete `detection/.env.txt` + `backend/.env.txt`, rotate keys) and **H1/H2/H4**.

## Current architecture (one paragraph)

A FastAPI backend (`backend/`) receives JSON artifact batches from lightweight native agents (`collector/`), stores them (SQLite default, Postgres via `DATABASE_URL`, schema managed by Alembic), and runs a shared detection pipeline (`services/detection_service.run_detection_job`) on an APScheduler cadence (default 30 s) or on-demand via `POST /detect`. The pipeline evaluates Sigma-style rules, embedded YARA matches, known-bad hashes, and network IOC correlation, enriches with ATT&CK from the in-repo STIX dataset, and persists `Detection` rows + `DetectionRun` history + `AuditLog` entries. A static vanilla-JS dashboard at `/dashboard` gives analysts endpoint management, manual collection/detection triggers, run history, triage, and ops views. Auth is opt-in (`AUTH_ENABLED`).

## Current goals / priorities

1. **Ship the checkpoint deliverables**: commit `SETUP_GUIDE.md`; update stale `PROJECT_SUMMARY.md` (NEXT_STEPS H3).
2. **Security**: delete/rotate `detection/.env.txt` keys; verify the auth path end-to-end (NEXT_STEPS C1, C2).
3. **Truthful controls**: make per-endpoint `collectors` config and the enrollment token real (H1, H2).
4. **Docs hygiene**: fix stale references (M5) before adding features.
5. Then Phase 4 (scale/correlation) per `ROADMAP_STATUS.md`.

## Important design decisions (do not reverse casually)

- **Single detection entry point**: `run_detection_job(db, host, rescan, trigger)` is the *only* place detection happens (scheduler + API). Never fork a second detection path.
- **Migrations, not `create_all`**: `backend/main.py` runs `migrate_to_head()` at import. Never reintroduce `Base.metadata.create_all`. New columns go in an Alembic revision (gated with `has_table`/`PRAGMA` for SQLite legacy DBs).
- **Offline-first**: hash list, IP blocklist, and ATT&CK STIX are all local; live intel fails soft. Preserve this — the demo runs on VMs with no internet.
- **Fail-soft everywhere on the agent**: `agent_client.py` network calls never crash a daemon loop. Keep it.
- **Idempotent ingest** by `(host, agent_batch_id)` and **first-call-wins command polling** (`pending → picked_up`) — these prevent duplicate work. Keep the semantics.
- **Thin endpoints / services layer** with `Depends(get_db)` DI. Business logic lives in `services/`, never in route handlers.
- **Open-lab default**: auth OFF by default so a fresh clone demos immediately. Enabling auth must not break existing tests (deps are no-ops when disabled).
- **Native agent, containerized backend**: the collector is intentionally not containerized for production endpoints (roadmap principle 5).

## Coding conventions (from AI_RULES.md + observed practice)

- Python 3.12; type-annotated signatures; module docstrings + public function docstrings (this repo is unusually disciplined — match it).
- `logging` only (no `print()` in service/pipeline logic); CLI progress via `print()` is acceptable in `collector_agent.py` / `push_samples.py`.
- Function target ≤ ~50 lines; extract `_private_helpers()`.
- ruff (line-length 100, E/F/W/I/UP/B, B008 ignored). Run `ruff check .` from `backend/` and `collector/`.
- Import direction: `main.py` → routes → services → models/database. Never upward. Lazy imports OK for optional/heavy deps (mitreattack, yara).
- No duplicate logic: import existing helpers (envelope builder is `collector/modules/common.py::wrap_artifact`).
- Commit messages summarize phase scope (e.g. `phase 3 completed:Dashboard, ...`).

## Repository conventions

- Branch `youssef` is the working branch; remote is private. Push requires a GitHub PAT (non-interactive HTTPS). Origin URL is kept clean (no embedded token).
- Test commands (deps pre-installed in `/tmp/opencode/pydeps` on the usual dev box):
  - Backend: `PYTHONPATH=/tmp/opencode/pydeps python3 -m pytest` (expect 53) from `backend/`.
  - Collector: same pattern from `collector/` (expect 7).
  - Lint: `/tmp/opencode/rufbin/bin/ruff check .` (or `ruff check .` if installed).
  - Migration check: `PYTHONPATH=/tmp/opencode/pydeps python3 -m alembic upgrade head` → head is `ca41c1ba0e02`.
- `.gitignore` has a whitelist for `dfir-refs/` — **only `dfir-refs/cti/enterprise-attack/enterprise-attack.json` is committed**; never `git add` the rest of that tree.
- `backend/dfir.db` is tracked (legacy demo DB). Be careful: smoke tests write to it; restore with `git checkout backend/dfir.db`.
- Sigma rules: canonical files are `rule0NN_*.yml` with unique ids; `load_rules` dedups by id — keep ids unique.

## Things that must never be broken

- The collect → ingest → detect → query loop (AI_RULES #1). After any change, run the test suites.
- The scheduler ↔ `POST /detect` single-pipeline guarantee.
- Idempotency (batch_id) and command-pickup semantics.
- Migration-managed schema; the committed `dfir.db` stays at head revision.
- Fail-soft behavior (enrichment, live intel, agent network calls).
- API contract changes must be called out in the commit message (AI_RULES #1).

## Areas that need caution

- **Never commit the 48 MB STIX aside from the one allowed path** (see .gitignore whitelist); a stray `git add dfir-refs/` would blow up the repo.
- **Do not print or persist secrets.** The PAT is passed via env/credential helper. `detection/.env.txt` must be deleted, not committed.
- **`security.py` default secrets** (`change-me-*`) — don't rely on them in any "secure" claim.
- **Concurrent `/detect` + scheduler** writes on SQLite — don't add more racy writes without considering locking.
- **Tests use a temp DB** (conftest overrides DATABASE_URL) — don't assume tests touch the real `dfir.db`.
- **`triage_updated_by`** propagates from the service call; route doesn't pass actor (defaults "unknown") — fine for now, revisit with real auth.
- Editing `models.py` requires a matching Alembic revision; `create_all` will not happen.

## Recommended first task

H3: `git add SETUP_GUIDE.md`, update `PROJECT_SUMMARY.md` to cover Phases 2–3 (test counts 53/7, containers/CI, dashboard/triage/audit/metrics, STIX bundling, cleanup, commit refs `37144db`, `af77469`), then commit + push to `youssef` (ask the user for the PAT as done previously).

## Recommended development order

1. Critical: C1 (delete/rotate leaked keys), C2 (verify auth e2e).
2. High: H1 (enrollment token), H2 (honor collectors config), H3 (docs commit), H4 (ingest size limit).
3. Medium: M1→M7 (severity from YARA meta, live intel, aggregate metrics, pagination, doc hygiene, offline detection, untrack `dfir.db`).
4. Low + Future: L1–L4, then Phases 4–5 per `NEXT_STEPS.md`.

## Companion docs

- `ROADMAP.md` (authoritative plan) · `PROJECT_OVERVIEW.md` (system-as-is) · `PHASE3.md` (Phase 3 record) · `SETUP_GUIDE.md` (new-user guide, uncommitted).
- `.ai/CHECKPOINT.md` (snapshot) · `.ai/MODULE_INDEX.md` · `.ai/EXECUTION_FLOW.md` · `.ai/DETECTION_PIPELINE.md` · `.ai/ROADMAP_STATUS.md` · `.ai/NEXT_STEPS.md` · `.ai/KNOWN_ISSUES.md` · `.ai/SESSION_HISTORY.md`.
