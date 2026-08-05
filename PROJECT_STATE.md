# PROJECT_STATE.md — DFIR Threat Hunting Framework

**Last updated:** 2026-08-05 (Phases 1-6 complete; fixes applied & tested)

## Architecture understanding

| Component | Tech | Location | Startup | Status |
|---|---|---|---|---|
| Backend | FastAPI + SQLAlchemy(SQLite) + APScheduler + reportlab + paramiko | `backend/` | `docker compose up --build -d` (or `uvicorn main:app`) | WORKING (all audit bugs fixed) |
| Collector agent | Python (psutil, requests) | `collector/` | `python collector_agent.py [--push-url ...]` | WORKING (deps fixed, no hangs/crashes) |
| Detection engine | sigma_rules (YAML) + yara_rules + IOC files + attck_mapper | `backend/` | inside backend | WORKING; ATT&CK enrichment soft-fails w/o STIX dataset (by design) |
| Dashboard | Jinja2 server-rendered | `backend/dashboard.py` + templates | served by backend | WORKING (schema fix applied) |
| Legacy `detection/` | duplicate old engine | `detection/` | NOT used by compose/CI | Secrets removed from git; folder left in place |

## Data flow
Collector (native on endpoint) → POST /ingest → SQLite (hosts/artifacts) → run_detection_job() (30-60s timer or POST /detect) → SQLite detections → generate_report() → reports/*.pdf → Dashboard + REST API. Backend reaches OUT to endpoints via SSH (paramiko) for liveness (TCP), run-now, and hourly orchestration.

## Completed actions (this session)

### Phase 1-2 — Understanding & audit verification
- Read AUDIT_AND_SETUP_GUIDE, READMEs, docker-compose, Dockerfile, requirements, all backend/collector/detection sources, CI workflow, git history/status/diff.
- Classified all 7 audit bugs as STILL BROKEN (see below).
- Working-tree pre-existing mods (uncommitted) already covered part of BUG-2 (venv path), BUG-4 (call-site `since`), BUG-6 (model column), dashboard error display — kept as-is.

### Phase 4 — Fixes applied
| Bug | File(s) | Fix |
|---|---|---|
| BUG-1 CRITICAL | `collector/modules/logs.py` | `ausearch` `check_output` gains `timeout=5`; `subprocess.TimeoutExpired` caught → no more indefinite hang |
| BUG-2 CRITICAL | `backend/endpoint_orchestrator.py` | Poll `stdout.channel.exit_status_ready()` against `deadline = monotonic() + SCAN_TIMEOUT_SECONDS`; raise TimeoutError → no more ignored timeout |
| BUG-3 HIGH | `collector/modules/persistence.py`, `collector/modules/scheduled_tasks.py` | Guard `os.listdir('/var/spool/cron/crontabs')` with try/except (IOError, PermissionError) → non-root runs no longer crash |
| BUG-4 HIGH | `backend/reports.py` | `generate_report(db, host=None, triggered_by='manual', since=None)`; normalizes tz-aware `since` to naive UTC, filters `detected_at >= since` |
| BUG-5 HIGH | `collector/requirements.txt` | Added `requests>=2.31.0` |
| BUG-6 MED/HIGH | `backend/main.py` | `ensure_schema()` after `create_all()`: idempotent `ALTER TABLE endpoints ADD COLUMN last_error TEXT` when missing |
| BUG-7 LOW | `detection/.env.txt` (git rm --cached), `.gitignore` | Secrets untracked; added `detection/.env.txt` to .gitignore; ALSO fixed corrupted UTF-16 tail of `.gitignore` so `backend/ssh_keys/*` ignore now actually works |

### Phase 5 — Testing performed
- `backend/venv` deps present; `import main` + all backend modules OK; `compileall` backend + collector OK.
- ruff (0.16.1): `ruff check .` → All checks passed.
- Unit-level: BUG-1 ausearch timeout honored; BUG-2 hung-channel aborted by deadline; BUG-3 no PermissionError on unreadable cron spool.
- BUG-6: old-schema DB (endpoints w/o last_error) → column auto-added on startup, log line emitted.
- E2E (uvicorn native, temp DB): /health, /ingest (1371 sample artifacts), /detect (2 detections), /detections, /detections/summary, /reports/generate, `since`-scoped report (0 for past detections → BUG-4 verified), /dashboard 200, report download (PDF bytes), /endpoints register, /endpoints/{id}/run-now on unreachable host → clean failure dict + `last_error` populated (no 500).
- Collector smoke: `--only processes,network` writes output files; `--push-url` → 664 live artifacts ingested + 5 live detections (host machine). 
- Docker: `docker compose build backend` OK; throwaway container `dfir-backend-test` → /health OK, /dashboard 200, scheduler running (all 3 jobs), push_samples → detect (2) → report generated. Container removed after test.
- CI-equivalent: sigma rules load (19), curated YARA ruleset compiles, IOC files load.

## Modified files (this session)
- backend/main.py, backend/reports.py, backend/endpoint_orchestrator.py (already dirty before session), backend/endpoints.py (pre-dirty), backend/models.py (pre-dirty), backend/templates/dashboard.html (pre-dirty)
- collector/modules/logs.py, collector/modules/persistence.py, collector/modules/scheduled_tasks.py, collector/requirements.txt
- .gitignore (fixed corruption + BUG-7 entry), detection/.env.txt (git rm --cached)
- AUDIT_AND_SETUP_GUIDE.md (added fix-status banner only)
- PROJECT_STATE.md (this file)

## Remaining issues (accepted, not code bugs)
- No real STIX dataset in repo → ATT&CK name/tactic enrichment returns Nones (soft-fail, by design).
- Agent-side YARA off by default on live endpoints (yara-python not shipped; hash/result embedding still works).
- `endpoint.name` vs collector hostname coupling for report scoping (sample win10 folder hostname is `DESKTOP-A5E108P`) — keep names aligned.
- Rotation of previously exposed API keys is a human action outside this repo.
- v4 legacy Docker container `dfir-backend` still running from sibling dir; V5 deploy uses `container_name: dfir-backend` → must stop v4 container before `docker compose up`.

## Test results
All tests passed (see Phase 5 list).

## Next steps
- Phase 8: commit fixes per phase on branch `youssef`, push (requires auth).
