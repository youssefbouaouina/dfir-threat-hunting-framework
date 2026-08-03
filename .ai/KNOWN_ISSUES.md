# Known Issues

## Bugs / correctness

- **B1. Enrollment token never returned to the agent.** `enroll_endpoint()` (endpoint_service.py) generates `secrets.token_urlsafe(32)` and stores only its SHA-256 hash; the returned payload omits the token. Feature is vestigial. *(→ NEXT_STEPS H1)*
- **B2. Per-endpoint `collectors` config has no effect.** Backend stores/serves it, but `collector_agent.py`/`daemon_loop` always run the full collector set; `--only` is CLI-only. Dashboard "Edit config" is misleading. *(→ H2)*
- **B3. `detections/summary` and `/metrics` scan entire tables.** `detections_summary()` loads all `Detection` rows; `metrics_text()`/`health_payload()` issue full counts (and `summary` re-loads detections). O(n) per call. *(→ M3)*
- **B4. YARA severity hardcoded `high`.** Embedded YARA matches ignore `meta.severity`/`meta.level` in the ruleset. *(→ M1)*
- **B5. Endpoint status never goes `offline`.** Only ever set `online` at enroll. *(→ M6)*
- **B6. Manual `POST /detect` is not concurrency-gated.** APScheduler is `max_instances=1`, but a manual POST can race a scheduled cycle (SQLite write locking is the only practical guard). *(Phase 4 queue fixes)*
- **B7. `poll_pending_commands` marks all pending commands picked_up on return**, regardless of whether the agent actually executed them (a crash between poll and complete leaves commands stuck in `picked_up`). *(acceptable first-call-wins tradeoff; add timeout-based requeue later)*

## Architectural weaknesses

- **W1. Single-process backend + in-process scheduler.** No worker queue, no HA; scheduler is coupled to the API process (Phase 4 targets).
- **W2. Legacy `Host` table duplication.** Kept for backwards compat but largely redundant with `Endpoint` (dead-ish state).
- **W3. No file storage.** Only hashes/YARA-match metadata are kept; the pipeline cannot re-scan stored binaries backend-side.
- **W4. Scheduler/manual share SQLite single DB file** for a tracked binary (`backend/dfir.db`) — merge conflicts and repo bloat.
- **W5. Dashboard is a static fetch-on-view SPA** — no polling, no auth refresh (token stored in localStorage, TTL 30 min).

## Performance issues

- **P1.** Full-table counts/loads on `/health`, `/metrics`, `/detections/summary` (see B3).
- **P2.** List endpoints paginate by `limit` + `ORDER BY id DESC` only — no cursor; page drift at scale.
- **P3.** 48 MB STIX JSON loaded into memory and cached by `mitreattack-python` on first enrichment.
- **P4.** `/detect` with `rescan=true` re-analyzes all artifacts synchronously in the request.

## Security issues

- **S1. Leaked API keys on disk.** `detection/.env.txt` (gitignored dir) contains real AbuseIPDB/OTX/URLhaus keys; also present in git history. **Needs deletion + rotation.** *(Critical)*
- **S2. Default credentials.** `ADMIN_API_KEY=change-me-admin-key`, `AUTH_SECRET=change-me-auth-secret` — a deployed-open or misconfigured instance is unprotected; auth is OFF by default. *(→ C2)*
- **S3. No `/ingest` body-size cap;** rate limit inactive when `AUTH_ENABLED=false`. *(→ H4)*
- **S4. Rate-limit key uses X-Forwarded-For** (untrusted unless behind a proxy) and the store is in-memory (reset on restart).
- **S5. Agent keys are a flat env list** (`AGENT_API_KEYS`) — no per-endpoint key binding, no rotation workflow. *(→ C2/H1)*
- **S6. Tokens are HMAC-signed (stdlib)** — no revocation list, no refresh; fine for demo, weak for production.

## Missing documentation

- **D1. `PROJECT_SUMMARY.md` is stale** (Phase 1 only; claims 38 tests, "never merged into main"). *(→ H3)*
- **D2. `README.md` is a 1-line stub** ("stage Youssef Bouaouina & Amen Ben Salah esprit in NEXTSTEP").
- **D3. Stale references in `AI_RULES.md`** (removed `detection/`, `yara_engine.py`; old service names), `common.py` (cites deleted `SCHEMA.md`), `collector_agent.py` docstring (`..\detection\yara_rules`). *(→ M5)*
- **D4. `SETUP_GUIDE.md` written but uncommitted.** *(→ H3)*

## Code smells

- **S1. `TRIAGE_STATUSES` duplicated** in `schemas.py` and `detection_service.py` (drift risk).
- **S2. `iocs/*` list formats parsed three times** (hash_checker, ioc_correlation) — could share a parser helper.
- **S3. YARA detection builder inline in `detection_service.run_detection_job`** — the pipeline function is nearing the 50-line limit and mixes engine dispatch with YARA-specific logic.
- **S4. `health_payload` JSON-stringifies `summary`** (a dict as a string) — awkward shape for consumers.
- **S5. Envelope building exists only in `common.wrap_artifact()`** (good), but `push_samples.py` re-implements folder→ingest push with slightly different semantics than `agent_client.push_folder` (duplicate logic risk).

## Duplicate logic

- **D5. `push_samples.py::push_folder` vs `agent_client.push_folder`** — similar folder→`/ingest` push; consider unifying (keep `push_samples.py` as a thin CLI wrapper).
- **D6. Host/endpoint last-seen handling** duplicated across `ingest_service` (Host upsert) and `endpoint_service` (Endpoint upsert).

## Missing tests

- **T1.** Auth: no tests for `AUTH_ENABLED=true` JWT flow, agent-key auth, rate limiting (429), or 401 paths.
- **T2.** No tests for `attck_mapper.enrich_technique` with the real STIX file (mitreattack lazy import path).
- **T3.** No tests for `ioc_correlation` live-feed layer (AbuseIPDB mocked) — only local blocklist is covered.
- **T4.** No tests for the scheduler job body (`_scheduled_detection_run`).
- **T5.** No tests for `file_scan`/YARA collector module.
- **T6.** No tests for failed-run recording (`run_detection_job` error path) or `rescan=true`.
- **T7.** No tests for dashboard `app.js` behavior (JS has no test harness).
- **T8.** No test for `PATCH /detections/{id}` returning 400 on `triage_updated_by` actor propagation beyond defaults.
