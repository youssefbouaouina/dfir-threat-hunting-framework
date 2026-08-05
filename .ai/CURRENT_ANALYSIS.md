# Current Implementation Analysis (Phase 2 validation)

> Generated: 2026-08-03 continuation session. This file records an independent validation of the repo vs its documentation. Baseline was re-established on **Windows** (Python 3.12, `%TEMP%\dfir_venv`).

## Baseline verification (reproduced this session)

| Check | Result |
|---|---|
| Backend pytest | **53 passed** (15.9 s) |
| Collector pytest | **7 passed** |
| ruff check (backend + collector) | clean (0 findings) |
| `alembic current` | `ca41c1ba0e02 (head)` on committed `dfir.db` |
| Auth e2e smoke (`AUTH_ENABLED=true`) | ✅ verified live (see below) |
| In-repo venvs | ❌ broken on this machine (`backend/.venv` = Linux layout; `backend/venv` = stale Python 3.14 pointer); use `%TEMP%\dfir_venv` |

### Auth path verified end-to-end (C2)
Ran the app via TestClient with `AUTH_ENABLED=true`, `ADMIN_API_KEY=<test-admin-key>`, `AGENT_API_KEYS=<test-agent-key-1>`:
- `GET /health` (no auth) → 200 ✅
- `GET /hosts` (no auth) → 401 ✅
- `POST /auth/login` correct key → 200, token issued ✅
- `GET /hosts` with bearer token → 200 ✅
- `POST /ingest` wrong agent key → 401 ✅
- `POST /ingest` valid agent key, empty body → 400 (auth passed, ingest validation fired) ✅
- `POST /endpoints/enroll` with agent key → 200, returns endpoint+config ✅
- `GET /metrics` (no auth) → 401 ✅

**Conclusion:** the auth path works end-to-end; the remaining gap is not correctness but the *default-secret* risk (`change-me-*`) and that rate limiting is tied to auth. Smoke test wrote to `backend/dfir.db`; it was restored with `git checkout backend/dfir.db`.

## Architecture status

- **Layering is intact and correct:** `main.py` → routes (`detection_routes`, `endpoint_routes`) → `services/*` → models/database. Import direction respected; `run_detection_job()` is the single detection entry point shared by scheduler + `POST /detect`. ✅
- **Migrations, not `create_all`:** `migrate_to_head()` runs at import; no `create_all` in app code (tests still use `create_all` for isolated temp DBs — acceptable, documented). ✅
- **Offline-first:** local hash list + IP blocklist + in-repo STIX; AbuseIPDB is the only live source and is fail-soft. ✅
- **Idempotent ingest + first-call-wins command queue:** verified in code (`ingest_service`, `endpoint_service.poll_pending_commands`). ✅
- **`dfir-refs/` whitelist:** only `cti/enterprise-attack/enterprise-attack.json` is tracked; `.gitignore` rules verified. ✅

## Code quality status

- Strong docstring discipline; functions mostly under the 50-line target; type-annotated signatures. ✅
- `detection_service.run_detection_job` (~90 lines) exceeds the 50-line guideline and mixes engine dispatch with YARA-specific logic (KNOWN_ISSUES S3) — refactor candidate, not urgent.
- `TRIAGE_STATUSES` duplicated in `schemas.py` + `detection_service.py` (KNOWN_ISSUES S1).
- `push_samples.py` vs `agent_client.push_folder` duplicate folder→ingest logic (KNOWN_ISSUES D5).
- `metrics_service.health_payload` JSON-stringifies `summary` (KNOWN_ISSUES S4) — awkward consumer shape; the dashboard parses it out again.

## Feature status (docs vs implementation)

| Feature | Docs claim | Reality |
|---|---|---|
| Phases 1–3 implemented | ✅ | Matches; tests + ruff reproduce |
| Dashboard SPA | ✅ | `backend/static/` present, served at `/dashboard` |
| Endpoint management | ✅ | `PUT /config`, run-collection, commands queue all implemented |
| Triage lifecycle | ✅ | `PATCH /detections/{id}` + migration `ca41c1ba0e02` |
| Ops: metrics/audit/JSON logs | ✅ | `/metrics`, `/audit-logs`, `logging_config` present |
| Enrollment token returned to agent | ⚠️ DOCS + KNOWN_ISSUES say vestigial (B1) | **Confirmed:** `enroll_endpoint` hashes a token but never returns it; `EndpointOut` has no token field |
| Per-endpoint `collectors` honored by agent | ⚠️ DOCS say ignored (B2) | **Confirmed:** agent `daemon_loop`/`run_collection` never reads `get_endpoint_config(...).collectors`; only interval is used via CLI arg |
| POST /ingest body-size cap | ⚠️ KNOWN_ISSUES S3 says absent | **Confirmed:** no size middleware anywhere |
| OTX/URLhaus/Feodo live intel | ⚠️ env keys only | **Confirmed:** no code beyond AbuseIPDB |
| `Dockerfile.agent` | ⚠️ Phase 2 outstanding | **Confirmed:** absent |
| CI build+push on tag | ⚠️ ROADMAP says untested on a real tag | Not testable here (needs GHCR creds); workflow present |

## Discovered inconsistencies (docs vs code)

1. **`.ai/` was entirely untracked** — the whole AI knowledge base was on disk only. **Fixed** by Phase 1 commit. This was the single biggest continuity risk.
2. `PROJECT_SUMMARY.md` is stale (Phase 1 only; claims 38 tests; says work "not merged into main"; appendix missing Phase 2–3 commits). → H3/M5.
3. `README.md` is a 2-line stub. → M5.
4. `AI_RULES.md` references removed files (`services/detection.py` vs `detection_service.py`, `detection/`, `yara_engine.py`). → M5.
5. `collector/modules/common.py` docstring cites deleted `SCHEMA.md`; `collector_agent.py` usage block shows old `..\detection\yara_rules`. → M5.
6. `PROJECT_OVERVIEW.md` §7.1 lists `ingest_service.py` at backend root and `yara-python`/`mitreattack` as "missing from backend requirements" — both are stale (they ARE in `requirements.txt` now; services live under `services/`). Minor.
7. `ARCHITECTURE.md` referenced by the mission brief does not exist (MODULE_INDEX/EXECUTION_FLOW serve the role).

## Risk assessment

### Security (highest priority)
- **S1 (CRITICAL):** `detection/.env.txt` (3 real keys) + `backend/.env.txt` (1 key) still on disk, gitignored. Must be deleted + keys rotated. **C1.**
- **S2:** default `change-me-*` secrets + `AUTH_ENABLED=false` default → a misconfigured or deployed-open instance is unprotected. Document + warn at startup; C2 verified the flow but defaults remain a footgun.
- **S3:** no `/ingest` body-size cap; rate limit disabled when auth off → open-lab instance floodable. **H4.**
- **S5:** `AGENT_API_KEYS` is a flat env list, no per-endpoint binding. Acceptable for lab, documented.

### Stability / correctness
- B6: manual `POST /detect` not gated vs scheduler → SQLite lock risk at scale; acceptable now.
- B5: endpoint status never flips to `offline` → dashboard health is optimistic. **M6.**
- B3: `/detections/summary` + `/metrics` scan full tables → O(n) per call; fine at demo scale. **M3.**

### Performance
- P1 (full-table scans), P2 (limit-only pagination, no cursor), P4 (`rescan=true` synchronous in-request). All fine at demo scale, deferred to Phase 4/5.

### Data
- W4: `backend/dfir.db` is a tracked binary (merge conflicts + bloat). **M7** requires a user decision.

## Files changed this phase
- `.ai/CURRENT_ANALYSIS.md` (new)
- `.ai/CHECKPOINT.md`, `.ai/AI_HANDOVER.md`, `.ai/SESSION_HISTORY.md`, `.ai/ROADMAP_STATUS.md`, `.ai/KNOWN_ISSUES.md` (refresh; see commit)

## Bottom line
The project is in **good health**: Phases 1–3 are real, reproducible, and documented. Remaining work is a well-scoped backlog (C1/C2/H1–H4/M1–M7) plus Phases 4–5. The main risks are the on-disk leaked keys (S1), doc drift (M5/H3), and the absence of the `.ai/` memory from git history before this session.
