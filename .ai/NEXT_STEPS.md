# Engineering Backlog / Next Steps

> **2026-08-03 continuation:** the authoritative execution plan is now `.ai/COMPLETION_ROADMAP.md` (per-task files/deps/risk/validation). This backlog is the source list it was derived from. Progress notes: C2 (auth path) verified live this session — see `.ai/CURRENT_ANALYSIS.md`; `.ai/` memory committed to git.

Priorities: **Critical** (security/blocking), **High** (correctness/required), **Medium** (quality/scale), **Low** (polish), **Future** (roadmap Phases 4–5).

## Critical

### C1. Delete/rotate leaked API keys in `detection/.env.txt`
- **Reason:** `detection/` tree was gitignored and removed from git, but `detection/.env.txt` still exists on disk with real AbuseIPDB/OTX/URLhaus keys. Keys were previously committed in history (gitleaks scans history), so they must be considered compromised.
- **Benefit:** Removes a live credential leak on disk.
- **Dependencies:** none. **Complexity:** trivial (file delete + rotate keys on the provider dashboards).
- **Order:** 1.

### C2. Verify + harden the opt-in auth path end-to-end
- **Reason:** `security.py` auth (JWT login, agent keys, rate limit) is unit-tested but the **agent-key path (`AGENT_API_KEYS` + `--api-key`) was never exercised against a running server**; default admin key is `change-me-admin-key`.
- **Benefit:** Confidence that `AUTH_ENABLED=true` deployments actually work; prevents a false sense of security.
- **Dependencies:** none. **Complexity:** small (integration smoke: enable auth, login, enroll, ingest with key, verify 401/429 behavior).
- **Order:** 2.

## High

### H1. ~~Return the enrollment token to the agent~~ ✅ DONE (commit `6113fc6`)
- First enrollment returns `enrollment_token` (once); hash stored, no rotation on re-enroll. `EnrollResponse` schema; agent `--enroll` prints the token. 2 new tests.

### H2. ~~Honor per-endpoint `collectors` config on the agent~~ ✅ DONE (commit `96a5d04`)
- Agent daemon now polls backend config and runs the `collectors` subset + `interval_seconds`; one-shot `--only` still filters. 2 new collector tests (9 total).

### H3. ~~Commit `SETUP_GUIDE.md` (+ update `PROJECT_SUMMARY.md` for Phases 2–3)~~ ✅ DONE (commit `b2094f0`)

### H4. ~~Enforce request-size limit + keep rate limit active independently of auth~~ ✅ DONE (commits `c25ee12`, `50e8a34`)
- `enforce_ingest_size` middleware → 413 over `MAX_INGEST_BYTES` (default 10 MB); `RATE_LIMIT_ENABLED` decoupled from `AUTH_ENABLED` (defaults to the auth value). 3 new tests. Also A2: startup now raises on placeholder secrets + empty `AGENT_API_KEYS` when auth enabled.

## Medium

### M1. ~~Enrich YARA severity from rule meta instead of hardcoding `high`~~ ✅ DONE (commit `520750c`)
- `severity = meta.severity || meta.level || "high"`; 1 new test. Backend 61.

### M2. ~~Real live-IOC coverage (OTX/URLhaus/Feodo) + scheduled feed refresh~~ ✅ DONE (commit `917006b`)
- URLhaus (keyless) + OTX live checks added; `refresh_feodo_blocklist()` writes `iocs/feodo_ips.txt`; scheduler `intel_refresh` job (default 12h); correlation merges curated + feodo lists. 6 new tests. Backend 73.

### M3. ~~Replace full-table scans in metrics/summary with aggregate queries~~ ✅ DONE (commit `77abbd2`)
- `detections_summary()` + `_summary_counts()` now use `func.count` + `group_by`. Backend 65.

### M4. ~~Add pagination + cursor for `/artifacts`, `/detections`, `/detection-runs`~~ ✅ DONE (commit `17bb884`)
- Additive `before_id` cursor (id < before_id); response shape unchanged. 2 new tests. Backend 67.

### M5. ~~Fix stale doc references (AI_RULES, docstrings, README)~~ ✅ DONE (commit `1f72448`)
- README rewritten; AI_RULES service names fixed; common.py/collector_agent.py/PROJECT_OVERVIEW §7.1 de-staled; MODULE_INDEX refreshed.

### M6. ~~Heartbeat/offline detection for endpoints~~ ✅ DONE (commit `200e639`)
- Config poll = heartbeat (`_touch_endpoint` restores online); `mark_offline_stale()` + `offline_sweep` job; env knobs. 3 new tests. Backend 64.

### M7. Reduce repo size / stop tracking `backend/dfir.db` — **pending user decision**
- **Reason:** A tracked binary DB (now with test/demo data) causes merge conflicts and repo bloat; `*.db` is gitignored but `backend/dfir.db` is force-tracked.
- **Benefit:** Cleaner history; avoids binary churn.
- **Dependencies:** user decision (it also serves as demo data). **Complexity:** small.
- **Order:** 13.

## Low

### L1. ~~Add `mypy` gradual typing + `pip-audit` to CI~~ ✅ DONE (commit `af5b401`)
- `[tool.mypy]` (gradual, SQLAlchemy plugin) added; fixed implicit-Optional + module-cache annotations; mypy clean on 33 files. `mypy` + `pip-audit` in `requirements-dev.txt`; CI hard gates for both. Backend 73 tests, ruff + mypy clean.

### L2. ~~`Dockerfile.agent` + containerized e2e test in CI~~ ✅ DONE (commit `132b873`)
- `Dockerfile.agent` (slim Linux, non-root, yara-python); CI `agent-e2e` job builds both images, enrolls + one-shot-collects (processes,network) against a live backend, verifies `/artifacts`. Validated locally with Docker. Also fixed: backend Dockerfile entrypoint chmod (ran after `USER dfir`), and a real bug in `push_folder` — folder-level `batch_id` collapsed multi-file runs to the first file only; now per-file batch ids preserve idempotency while storing every file (9 collector tests).

### L3. ~~Dashboard auto-refresh / websocket for live counts~~ ✅ DONE (commit `9ae3c33`)
- Overview auto-refreshes every 15s (counts + scheduler box); view switches trigger immediate refresh.

### L4. ~~`/scheduler/status` surfaced in the dashboard~~ ✅ DONE (commit `9ae3c33`)
- `#scheduler-box` renders interval/next-run/last-run/last-error; scheduler no longer required for dashboard to load.

## Future (Phases 4–5)

- **F1** ~~Async ingest queue (Redis/RabbitMQ) + workers; `/ingest` returns 202~~ ✅ DONE (commit `5afca4d`) — Redis queue + worker, 202 path, compose redis/worker, CI e2e covers the async loop.
- **F2** ~~Correlation engine: `incidents` + `incident_detections`, same-rule-across-hosts, ATT&CK chain, severity scoring~~ ✅ DONE (commit `46310fb`; router wiring fix `b260b55`).
- **F3** ~~Retention/archival (JSONL) + optional OpenSearch sink~~ ✅ DONE (commit `ccf62a8`) — monthly JSONL + fail-soft OpenSearch bulk index, per-table windows, scheduler sweep, /retention/run + /retention/status.
- **F4** ~~RBAC/team scoping + immutable audit extension~~ ✅ DONE (commit `c503503`) — roles admin/analyst/viewer (`ANALYST_API_KEYS`/`VIEWER_API_KEYS` `key@team`), `current_user`/`require_role`, `Endpoint.team` + `scoped_hosts` across all list/summary endpoints (empty team → nothing), SHA-256 audit hash chain + `/audit-logs/verify`. 14 tests; 115 backend total.
- **F5** ~~Notifications (webhook/email/Slack/Teams)~~ ✅ DONE (2026-08-04 session) — `services/notification_service.py` (webhook + SMTP email, `NOTIFY_*` env, fail-soft), fired from `run_detection_job` (severity threshold) + `mark_offline_stale`; plus host-criticality severity factor (`Endpoint.criticality`, `5f0a1c2d9b73` migration), queue-driven detection worker (`workers/detection_worker.py`), `POST /endpoints/scan-all`, per-endpoint report `GET /endpoints/{id}/report`, dashboard rewritten as a brutalist technical report, and collector enroll helper scripts. 18 new tests (backend 133). *(Phase 4)*
- **F6** ~~pySigma backend + SigmaHQ update pipeline~~ ✅ DONE (2026-08-04 session) — `backend/sigma_engine.py` real pySigma backend (typed condition tree, selectors, NOT, modifiers), 6 native rules, both engines run in `run_detection_job`, `services/sigma_service.py` imports SigmaHQ via local dir or shallow git clone, `GET/POST /sigma/*` (admin, audited), `pysigma>=1.5.0`. 16 tests. *(Phase 5)*
- **F7** ~~IOC feed automation + STIX/TAXII export~~ ✅ DONE (2026-08-04 session) — `Ioc` model (migration `6f7a1b2c3d4e`), `services/intel_service.py` (Feodo/URLhaus/MalwareBazaar/OTX, upsert, fail-soft, scheduler refresh), `/iocs` + `/iocs/status` + `/iocs/refresh` + `/iocs/export/stix` (STIX 2.1 bundle), minimal TAXII 2.1 server in `taxii_routes.py`. 17 tests. *(Phase 5)*
- **F8** ~~k8s/HA, autoscaling, circuit breakers, connection pooling, matviews~~ ✅ DONE (2026-08-04 session) — `k8s/` manifests (3-replica backend + HPA 3–10 + PDB + ingest worker + Postgres StatefulSet), `services/circuit_breaker.py` per-feed breakers, DB pooling env knobs, composite-index migration `7a8b1c2d3e4f`, `StatsSnapshot` + `services/stats_service.py` materialized stats on a scheduler job. 13 tests (incl. k8s YAML validity). *(Phase 5)*

## Suggested implementation order

```
C1 ✅ → C2 ✅ → H1 ✅ → H2 ✅ → H3 ✅ → H4 ✅ (+ A2) → M1 ✅ → M2 ✅ → M3 ✅ → M4 ✅ → M5 ✅ → M6 ✅ → M7 ✅ (dfir.db untracked, commit `8879160`) → L1 ✅ (D1) → L2 ✅ (D2) → L3 ✅ (D3) → L4 ✅ (D4) → F1 ✅ → F2 ✅ → F3 ✅ → F4 ✅ → F5 ✅ → F6..F8
```
All Critical + High items done; Phase C (M-series) done; Phase D (Low) L1–L4 done; **F-series: F1–F8 all done (Phases 4–5: queue, correlation, retention, RBAC/audit, notifications + host criticality, pySigma, IOC feeds + STIX/TAXII, k8s/HA). Remaining: user-side key rotation on provider dashboards + long-running production soak.**
