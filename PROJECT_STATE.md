# PROJECT_STATE.md — DFIR Threat Hunting Framework

**Last updated:** 2026-08-08 (Phases 1-6 + report enhancement + Docker fix + post-audit improvement pass; all verified)

## Architecture understanding

| Component | Tech | Location | Startup | Status |
|---|---|---|---|---|
| Backend | FastAPI + SQLAlchemy(SQLite) + APScheduler + reportlab + paramiko | `backend/` | `docker compose up --build -d` (or `uvicorn main:app`) | WORKING (all audit bugs fixed) |
| Collector agent | Python (psutil, requests) | `collector/` | `python collector_agent.py [--push-url ...]` | WORKING (deps fixed, no hangs/crashes) |
| Detection engine | sigma_rules (YAML) + yara_rules + IOC files + attck_mapper + attack_chain | `backend/` | inside backend | WORKING; ATT&CK enrichment LIVE via dfir-refs STIX mount (2026-08-08) |
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

## Report enhancement (new work, 2026-08-07)
- **`backend/reports.py` rewritten** — PDF now has 6 readable sections:
  1. Executive Summary (report id, generated/trigger/scope, total, severity breakdown)
  2. Detection Sources (artifact type → source description → findings count)
  3. Rules Involved (rule id, title, technique, tactic, severity, match count)
  4. ATT&CK Technique Coverage (technique/name/tactic/count)
  5. Endpoint Details (registered endpoint metadata in scope; falls back to hosts table)
  6. Detection Detail (host, severity-colored, rule, source, technique, detected_at, matched-data preview per artifact type)
- `summary_json` extended with `by_rule`, `by_artifact_type`, `hosts` (dashboard doesn't parse it — safe).
- Verified: compile + import + ruff clean; e2e run over sample data → 6-page PDF; pypdf text extraction confirmed all sections render (installed pypdf into backend venv for test tooling only).
- Observation (pre-existing, not changed): a scheduled detection_cycle can race a manual POST /detect and both create detections from the same unprocessed artifacts (duplicates). Out of scope.

## Docker runtime fix (2026-08-07)
- After the image hardening commit (`e788ed3`), `dfir_backend_V5` crash-looped with `exec /entrypoint.sh: no such file or directory` even though the file existed and was executable in the image.
- Root cause: **CRLF line endings**. Git's Windows autocrlf wrote `\r\n` into `backend/entrypoint.sh`; the kernel read shebang `#!/bin/sh\r`, looked for `/bin/sh\r` (doesn't exist) → ENOENT. Classic Windows symptom.
- Fix: rewrote `backend/entrypoint.sh` as LF (no BOM) and added `.gitattributes` with `*.sh text eol=lf` so it stays LF in the repo and on Windows checkouts.
- Verified: `docker compose build` OK; image contains `/usr/sbin/runuser`, `python`, `uvicorn`, `appuser` (uid 999) after the hardening purges; `docker compose up -d` → container `Up (healthy)`; healthcheck + /dashboard 200; scheduler adds all 3 jobs; `POST /reports/run-now` → 6-section PDF (report `c78de6290a6b`, 14 detections) downloadable via `/reports/{id}/download` (valid `%PDF-` magic).
- Note: `PROJECT_STATE.md`'s old "stop v4 `dfir-backend` container" warning is obsolete — V5 now uses `container_name: dfir_backend_V5`, no name collision.

## Remaining issues (accepted, not code bugs)
- ~~No real STIX dataset in repo → ATT&CK name/tactic enrichment returns Nones (soft-fail, by design).~~ **RESOLVED 2026-08-08:** `dfir-refs/` (MITRE CTI clone) mounted into the backend image; enrichment is now live in the container.
- ~~Agent-side YARA off by default on live endpoints (yara-python not shipped; hash/result embedding still works).~~ **RESOLVED 2026-08-08:** orchestrated scans now pass `--yara-rules`; collector path extraction widened to cron/scheduled-task entries.
- `endpoint.name` vs collector hostname coupling for report scoping (sample win10 folder hostname is `DESKTOP-A5E108P`) — keep names aligned.
- Rotation of previously exposed API keys is a human action outside this repo.
- v4 legacy Docker container `dfir-backend` still running from sibling dir; V5 now uses `container_name: dfir_backend_V5` so there is no name collision.

## Post-audit improvement pass (2026-08-08) — intern PDF §4.3/§4.4 compliance
Applied after the compliance audit, targeting the internship PDF's §4.3 (MITRE ATT&CK mapping, attack-chain reconstruction/visualization) and §4.4 (summary view with recommended actions):

- **ATT&CK enrichment live in the container.** `backend/attck_mapper.py` rewritten: `DFIR_STIX_PATH` env override + robust candidate-path resolution (repo `dfir-refs/`, sibling-tree layout, container mount `/dfir/stix/enterprise-attack.json`). `docker-compose.yml` mounts `./dfir-refs/cti/enterprise-attack:/dfir/stix:ro` and sets `DFIR_STIX_PATH`. Verified in-container: `T1059.001 → PowerShell / execution`, `T1566.001 → Spearphishing Attachment / initial-access`.
- **Attack-chain reconstruction + visualization.** New `backend/attack_chain.py`: groups detected techniques by ATT&CK tactic in canonical kill-chain order (reconnaissance → … → impact), ties broken by first-seen; plus curated technique→recommended-action mapping. Exposed via `GET /detections/chain` (detection_routes.py) and rendered on the dashboard as an ordered phase-flow panel.
- **Recommended actions.** Dashboard "Recommended Actions" panel + new PDF report **section 5 "Attack Chain Reconstruction & Recommended Actions"** (report is now 7 sections; detail moved to 7).
- **YARA enabled in automated orchestration (R9).** `endpoint-manager/manager.py` exec command now passes `--yara-rules /opt/collector/yara_rules`; `backend/endpoint_orchestrator.py` SSH command passes the collector's local `yara_rules` dir; `collector/collector_agent.py` `_extract_exe_paths()` widened to also pull executable paths from crontab/rc.local `entry` lines and scheduled-task `task_to_run`/`raw` fields (and `run_collection` now keeps scheduled_task records in memory for file_scan reuse). Verified end-to-end: cron entry referencing an EICAR-marked script → file_scan found `/opt/dfir_eicar_marker.sh` → 2 YARA matches → detections persisted.

**Modified files (improvement pass):** `backend/attck_mapper.py`, `backend/attack_chain.py` (new), `backend/detection_routes.py`, `backend/dashboard.py`, `backend/reports.py`, `backend/endpoint_orchestrator.py`, `backend/templates/dashboard.html`, `docker-compose.yml`, `endpoint-manager/manager.py`, `collector/collector_agent.py`, `backend/tests/test_attck_mapper.py` (new), `backend/tests/test_attack_chain.py` (new).

**Verified:** `pytest backend/tests` → 22 passed; `ruff check backend endpoint-manager` → clean; live container run-now over an EICAR cron artifact → YARA detection; `/dashboard` renders attack-chain + recommendations; PDF report includes section 5 with enriched technique names.

## Test results
All tests passed (see Phase 5 list).

## Next steps
- Phase 8: commit fixes per phase on branch `youssef`, push (requires auth).
