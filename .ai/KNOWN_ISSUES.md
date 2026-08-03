# Known Issues

> **2026-08-03 continuation:** baseline re-validated (73 backend + 9 collector tests, ruff + mypy clean). Auth path verified live (C2 → done; see `.ai/CURRENT_ANALYSIS.md`). `.ai/` memory committed to git this session. Phases A + B + C + D done (H1–H4, A2, M1–M7, L1–L4/D1–D4); open items below updated to reflect fixes.

## Bugs / correctness

- **B1. ~~Enrollment token never returned to the agent~~ → FIXED (H1, commit `6113fc6`).** `enroll_endpoint()` now returns a one-time `enrollment_token` on first enrollment only (hash stored; re-enroll omits token). New `EnrollResponse` schema.- **B2. ~~Per-endpoint `collectors` config has no effect~~ → FIXED (H2, commit `96a5d04`).** Agent daemon now polls the backend config and runs the `collectors` subset + `interval_seconds`; `--only` still applies in one-shot CLI mode.
- **B3. ~~`detections/summary` and `/metrics` scan entire tables~~ → FIXED (M3, commit `77abbd2`).** `detections_summary()` and `metrics_service._summary_counts()` now use SQL `GROUP BY` (`func.count`) — no full-table Python loads.
- **B4. ~~YARA severity hardcoded `high`~~ → FIXED (M1, commit `520750c`).** Embedded YARA matches now take `meta.severity || meta.level || "high"`.
- **B5. ~~Endpoint status never goes `offline`~~ → FIXED (M6, commit `200e639`).** `mark_offline_stale()` + `offline_sweep` scheduler job flip stale endpoints to offline; the config poll acts as a heartbeat that restores `online`.
- **B6. Manual `POST /detect` is not concurrency-gated.** APScheduler is `max_instances=1`, but a manual POST can race a scheduled cycle (SQLite write locking is the only practical guard). *(Phase 4 queue fixes)*
- **B7. `poll_pending_commands` marks all pending commands picked_up on return**, regardless of whether the agent actually executed them (a crash between poll and complete leaves commands stuck in `picked_up`). *(acceptable first-call-wins tradeoff; add timeout-based requeue later)*
- **B8. ~~Agent `push_folder` used one folder-level `batch_id`~~ → FIXED (D2, commit `132b873`).** Backend dedups per `(host, batch_id)`, so a folder-level id collapsed a multi-file run to the first file only (data loss). Now per-file ids (`<batch_id>/<filename>`) keep re-push idempotency while storing every file. Verified in the containerized e2e.
- **B9. Retention re-archival edge case (F3, commit `ccf62a8`).** `retention_service.run_retention` appends to JSONL before the DB delete commits. If the process crashes between the append and the commit, the same rows are appended again on the next sweep (duplicate JSONL lines for that batch). The JSONL archive is append-only by design, so this is a known tradeoff, not data loss — the archived record is identical and harmless. OpenSearch dedups via `_id = {table}-{row_id}`.
- **B10. Legacy audit rows lack hash-chain fields (F4, commit `c503503`).** `AuditLog` rows written before the F4 migration have NULL `prev_hash`/`record_hash`. `verify_audit_chain` deliberately skips legacy NULL-hash rows (chain validated only from the first hashed row onward); tamper-detection on pre-F4 history is therefore unavailable.
- **B11. Team scoping returns 403/empty results when a role's team has no endpoints (F4).** A viewer/analyst whose team matches no `Endpoint.team` sees zero hosts/detections/incidents (empty allow-list is treated as "nothing visible", not "everything"). This is correct but may confuse if a team name is mistyped in `ANALYST_API_KEYS`/`VIEWER_API_KEYS`.

## Architectural weaknesses

- **W1. Single-process backend + in-process scheduler.** No worker queue, no HA; scheduler is coupled to the API process (Phase 4 targets).
- **W2. Legacy `Host` table duplication.** Kept for backwards compat but largely redundant with `Endpoint` (dead-ish state).
- **W3. No file storage.** Only hashes/YARA-match metadata are kept; the pipeline cannot re-scan stored binaries backend-side.
- **W4.** Scheduler/manual share SQLite single DB file. `backend/dfir.db` is now **untracked** (M7, commit `8879160`) — no more merge conflicts/repo bloat.
- **W5. Dashboard is a static fetch-on-view SPA** — has a 15s overview auto-refresh (D3) but still no websocket, no auth refresh (token stored in localStorage, TTL 30 min).

## Performance issues

- **P1.** ~~Full-table counts/loads on `/health`, `/metrics`, `/detections/summary`~~ → FIXED (M3, commit `77abbd2`) for detections; remaining table counts are single `COUNT(*)` queries (cheap at SQLite/Postgres scale).
- **P2.** ~~List endpoints paginate by `limit` + `ORDER BY id DESC` only; no cursor~~ → FIXED (M4, commit `17bb884`): `before_id` cursor on /artifacts, /detections, /detection-runs.
- **P3.** 48 MB STIX JSON loaded into memory and cached by `mitreattack-python` on first enrichment.
- **P4.** `/detect` with `rescan=true` re-analyzes all artifacts synchronously in the request.

## Security issues

- **S1. Leaked API keys on disk.** ~~`detection/.env.txt`~~ (deleted, user-approved) and ~~`backend/.env.txt`~~ (deleted) contained real AbuseIPDB/OTX/URLhaus keys; also present in git history. **Deletion done; key rotation on provider dashboards is a user action still required.** *(Critical)*
- **S2. Default credentials.** ~~`AUTH_ENABLED=true` + placeholder `ADMIN_API_KEY`/`AUTH_SECRET`~~ → FIXED (A2, commit `50e8a34`): startup now raises on placeholder secrets or empty `AGENT_API_KEYS` when auth is enabled. Auth is still OFF by default (`AUTH_ENABLED=false`) for open-lab demo mode.
- **S3. No `/ingest` body-size cap; rate limit inactive when `AUTH_ENABLED=false`.** → FIXED (H4, commits `c25ee12` + `50e8a34`): `enforce_ingest_size` middleware returns 413 over `MAX_INGEST_BYTES` (default 10 MB); `RATE_LIMIT_ENABLED` is now independent of auth (defaults to the auth value).
- **S4. Rate-limit key uses X-Forwarded-For** (untrusted unless behind a proxy) and the store is in-memory (reset on restart).
- **S5. Agent keys are a flat env list** (`AGENT_API_KEYS`) — no per-endpoint key binding, no rotation workflow. *(→ C2/H1)*
- **S6. Tokens are HMAC-signed (stdlib)** — no revocation list, no refresh; fine for demo, weak for production.
- **S7. Human role keys are a flat env list (F4).** `ANALYST_API_KEYS`/`VIEWER_API_KEYS` map one key → one role+team; no per-user identity, no key rotation/lifecycle, no per-key expiry. Team is embedded in the issued token (30 min TTL), so a team change requires re-login.

## Missing documentation

- **D1. ~~`PROJECT_SUMMARY.md` is stale~~ → FIXED (M5, commit `1f72448`)** — rewritten for Phases 1–3.
- **D2. ~~`README.md` is a 1-line stub~~ → FIXED (M5, commit `1f72448`)** — rewritten; root docs refreshed.
- **D3. ~~Stale references in `AI_RULES.md`~~ → FIXED (M5, commit `1f72448`)** — service names corrected, removed files noted as historically removed. `README.md` rewritten. `common.py`, `collector_agent.py`, `PROJECT_OVERVIEW.md` §7.1 de-staled.
- **D4. ~~`SETUP_GUIDE.md` written but uncommitted~~ → FIXED (H3, commit `b2094f0`).**

## Code smells

- **S1. `TRIAGE_STATUSES` duplicated** in `schemas.py` and `detection_service.py` (drift risk).
- **S2. `iocs/*` list formats parsed three times** (hash_checker, ioc_correlation) — could share a parser helper.
- **S3. YARA detection builder inline in `detection_service.run_detection_job`** — the pipeline function is nearing the 50-line limit and mixes engine dispatch with YARA-specific logic.
- **S4. `health_payload` JSON-stringifies `summary`** (a dict as a string) — awkward shape for consumers.
- **S5. Envelope building exists only in `common.wrap_artifact()`** (good), but `push_samples.py` re-implements folder→ingest push with slightly different semantics than `agent_client.push_folder` (duplicate logic risk).

## Duplicate logic

- **D5. `push_samples.py::push_folder` vs `agent_client.push_folder`** — similar folder→`/ingest` push; consider unifying (keep `push_samples.py` as a thin CLI wrapper). Note: `agent_client.push_folder` now uses per-file batch ids (B8 fix); `push_samples.py` does not (uses its own semantics).
- **D6. Host/endpoint last-seen handling** duplicated across `ingest_service` (Host upsert) and `endpoint_service` (Endpoint upsert).

## Missing tests

- **T1.** Auth: no committed automated test for the `AUTH_ENABLED=true` JWT flow, agent-key auth, or 401 paths (verified live earlier; rate limiting + startup guard now covered in `test_security.py`). Consider `test_auth_live.py` for the enabled-path HTTP flow.
- **T2.** No tests for `attck_mapper.enrich_technique` with the real STIX file (mitreattack lazy import path).
- **T3.** Live-feed layer (`AbuseIPDB`/`URLhaus`/`OTX`) and Feodo refresh are now unit-tested with mocked responses (M2, commit `917006b`). Real-key smoke test remains a user/manual step.
- **T4.** No tests for the scheduler job bodies (`_scheduled_detection_run`, `_scheduled_offline_sweep`, `_scheduled_intel_refresh`) — covered indirectly via service tests; a direct test would need to monkeypatch `SessionLocal`.
- **T5.** No tests for `file_scan`/YARA collector module.
- **T6.** No tests for failed-run recording (`run_detection_job` error path) or `rescan=true`.
- **T7.** No tests for dashboard `app.js` behavior (JS has no test harness).
- **T8.** No test for `PATCH /detections/{id}` returning 400 on `triage_updated_by` actor propagation beyond defaults.
- **T9.** Agent→backend loop is covered by the containerized CI e2e job (`agent-e2e`, commit `132b873`) rather than a unit test; the full flow (enroll + one-shot collect + `/artifacts` verification) runs in CI only.
