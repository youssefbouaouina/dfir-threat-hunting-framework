# Engineering Backlog / Next Steps

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

### H1. Return the enrollment token to the agent (or remove the feature)
- **Reason:** `enroll_endpoint()` generates + hashes an enrollment token but **never returns it**; the agent has no way to use it. Vestigial / misleading.
- **Benefit:** Real per-endpoint credential issuance, or less confusing code if removed.
- **Dependencies:** C2 (decide auth model). **Complexity:** small.
- **Order:** 3.

### H2. Honor per-endpoint `collectors` config on the agent
- **Reason:** `PUT /endpoints/{id}/config` stores a `collectors` list that the agent ignores (it always runs the fixed set; `--only` only applies in one-shot CLI mode). Dashboard "Edit config" therefore can't actually restrict collection.
- **Benefit:** Config edits become functional; dashboard control is truthful.
- **Dependencies:** none. **Complexity:** small–medium (config poll → restrict run_collection targets).
- **Order:** 4.

### H3. Commit `SETUP_GUIDE.md` (+ update `PROJECT_SUMMARY.md` for Phases 2–3)
- **Reason:** The requested new-user setup/run guide (Windows host + VMware + 2 VMs) is complete but **untracked**; `PROJECT_SUMMARY.md` describes only Phase 1 and is stale/misleading for reviewers.
- **Benefit:** Deliverable lands in repo; doc consistency for the evaluation committee.
- **Dependencies:** none. **Complexity:** trivial (commit + push with user's PAT).
- **Order:** 5.

### H4. Enforce request-size limit + keep rate limit active independently of auth
- **Reason:** `/ingest` has no body-size cap; rate limiting is silently disabled when `AUTH_ENABLED=false`, so an open-lab instance is trivially floodable.
- **Benefit:** Baseline DoS resistance.
- **Dependencies:** C2. **Complexity:** small (size middleware + split rate-limit enable flag).
- **Order:** 6.

## Medium

### M1. Enrich YARA severity from rule meta instead of hardcoding `high`
- **Reason:** `detection_service.py` hardcodes `severity="high"` for all embedded YARA matches, ignoring each rule's `meta.severity`.
- **Benefit:** More accurate risk display.
- **Dependencies:** none. **Complexity:** small.
- **Order:** 7.

### M2. Real live-IOC coverage (OTX/URLhaus/Feodo) + scheduled feed refresh
- **Reason:** Only AbuseIPDB is implemented; the other keys in `.env.example` are dead config. Roadmap (Phase 5) wants automated feed refresh into `iocs/`.
- **Benefit:** Stronger network detection; makes the blocklists current.
- **Dependencies:** none (can reuse `check_abuseipdb` pattern). **Complexity:** medium.
- **Order:** 8.

### M3. Replace full-table scans in metrics/summary with aggregate queries
- **Reason:** `metrics_service` and `detections_summary` load/count entire tables — fine at demo scale, bad at 100s of endpoints.
- **Benefit:** Cheap `/metrics`, `/health`, `/detections/summary` under load.
- **Dependencies:** none. **Complexity:** small (SQL `count`/`group_by`, or SQLAlchemy `func.count`).
- **Order:** 9.

### M4. Add pagination + cursor for `/artifacts`, `/detections`, `/detection-runs`
- **Reason:** All list endpoints use `limit` with `ORDER BY id DESC`; no cursor/offset → page drift and full scans at scale.
- **Benefit:** Usable with large artifact volumes.
- **Dependencies:** M3. **Complexity:** medium.
- **Order:** 10.

### M5. Fix stale doc references (AI_RULES, docstrings, README)
- **Reason:** `AI_RULES.md` still references removed files (`detection/`, `yara_engine.py`) and old service names (`services/detection.py` vs `detection_service.py`); `common.py` docstring cites deleted `SCHEMA.md`; `collector_agent.py` usage block shows old `..\detection\yara_rules`; `README.md` is a 1-line stub.
- **Benefit:** Trustworthy documentation for the next engineer.
- **Dependencies:** none. **Complexity:** trivial.
- **Order:** 11.

### M6. Heartbeat/offline detection for endpoints
- **Reason:** `status` flips to `online` on enroll but nothing ever sets `offline`; dashboard "status" is optimistic.
- **Benefit:** Honest endpoint health; enables Phase 4 "endpoint offline" notifications.
- **Dependencies:** none. **Complexity:** medium (scheduler sweep comparing `last_seen`).
- **Order:** 12.

### M7. Reduce repo size / stop tracking `backend/dfir.db`
- **Reason:** A tracked binary DB (now with test/demo data) causes merge conflicts and repo bloat; `*.db` is gitignored but `backend/dfir.db` is force-tracked.
- **Benefit:** Cleaner history; avoids binary churn.
- **Dependencies:** user decision (it also serves as demo data). **Complexity:** small.
- **Order:** 13.

## Low

### L1. Add `mypy` gradual typing + `pip-audit` to CI
- **Reason:** Roadmap Phase 1 item not yet done; codebase is already annotated.
- **Benefit:** Type safety + dependency vulnerability scanning.
- **Complexity:** medium. **Order:** 14.

### L2. `Dockerfile.agent` + containerized e2e test in CI
- **Reason:** Phase 2 outstanding item; roadmap wants an end-to-end agent→backend test.
- **Benefit:** CI-verified collection path.
- **Complexity:** medium. **Order:** 15.

### L3. Dashboard auto-refresh / websocket for live counts
- **Reason:** Dashboard only refreshes on view switch or manual buttons.
- **Benefit:** Better ops UX.
- **Complexity:** small. **Order:** 16.

### L4. `/scheduler/status` surfaced in the dashboard
- **Reason:** Endpoint exists; not exposed in UI.
- **Benefit:** Ops visibility.
- **Complexity:** trivial. **Order:** 17.

## Future (Phases 4–5)

- **F1** Async ingest queue (Redis/RabbitMQ) + workers; `/ingest` returns 202. *(Phase 4)*
- **F2** Correlation engine: `incidents` + `incident_detections`, same-rule-across-hosts, ATT&CK chain, severity scoring. *(Phase 4)*
- **F3** Retention/archival (JSONL) + optional OpenSearch sink. *(Phase 4)*
- **F4** RBAC/team scoping + immutable audit extension. *(Phase 4)*
- **F5** Notifications (webhook/email/Slack/Teams). *(Phase 4)*
- **F6** pySigma backend swap + SigmaHQ update pipeline. *(Phase 5)*
- **F7** IOC feed automation + STIX/TAXII export. *(Phase 5)*
- **F8** k8s/HA, autoscaling, circuit breakers, connection pooling, matviews. *(Phase 5)*

## Suggested implementation order

```
C1 → C2 → H1 → H2 → H3 → H4 → M1 → M2 → M3 → M4 → M5 → M6 → M7 → L1 → L2 → L3 → L4 → F1..F8
```
Do all Critical + High items before starting Phase 4 work.
