# Detection Pipeline

The pipeline is a single, shared entry point: `backend/services/detection_service.py::run_detection_job(db, host=None, rescan=False, trigger="manual"|"scheduled")`. Both the background scheduler and `POST /detect` call it, so the two trigger paths cannot drift. All engines consume the same normalized artifact list.

## Stage A — Collectors (producer side, on endpoints)

Each collector module returns a list of wrapped artifacts (`common.wrap_artifact()`): `{host, os, collected_at, artifact_type, data}`.

| Collector | `artifact_type` | Data highlights |
|---|---|---|
| `processes.py` | `process` | pid, name, exe, cmdline |
| `network.py` | `network` | remote_address (`host:port`), status |
| `persistence.py` | `persistence` | registry Run keys (win) / cron, rc.local, systemd (linux) |
| `scheduled_tasks.py` | `scheduled_task` | Windows tasks / Linux timers |
| `logs.py` | `log_event` | Windows Sysmon / Linux syslog (max 200) |
| `file_scan.py` | `file_scan` | path, sha256, size_bytes, **`yara_matches`** (embedded) |

## Stage B — Preprocessing & normalization

- The collector wraps/normalizes records into the standard envelope at the source; the backend stores `data` as JSON verbatim.
- **No field mapping/renaming at ingest** — normalization is implicit (envelope contract between `common.py` and `schemas.ArtifactIn`).
- No schema validation of `data` contents beyond Pydantic shape (`Dict[str, Any]`).

## Stage C — Detection engines (execution order in `run_detection_job`)

1. **Sigma-style behavioral rules** (`sigma_matcher.py`)
   - `load_rules(SIGMA_RULES_DIR)` validates required keys (`id, title, artifact_type, condition`), dedups by `id` (first occurrence wins, deterministic filename sort), skips invalid files with a warning.
   - `evaluate()` matches rules against artifacts by `artifact_type` gating + condition operators:
     - `field: value` — exact match
     - `field: [v1, v2]` — value must be in list
     - `field_contains: [s1, s2]` — case-insensitive substring
   - Detection: `rule_id`, `rule_title`, `technique_id`, `severity` (rule attr, default "unknown").
2. **Embedded YARA results** (backend-side, no YARA engine)
   - The backend runs **no YARA**; the agent runs `curated_ruleset.yar` at file-scan time and embeds `yara_matches[]` in `file_scan.data`.
   - Backend converts each match → detection `yara-<rule>`, `severity="high"` (hardcoded), `technique_id` from rule meta.
3. **Known-bad hash matching** (`hash_checker.py`)
   - Offline: `sha256` in `file_scan.data` looked up in `iocs/known_bad_hashes.txt`.
   - Hit → `rule_id="hash-match"`, `severity="critical"`, `technique_id="T1204"`.
4. **Network IOC correlation** (`ioc_correlation.py`) — two layers, deliberately separated:
   - **Layer 1 (local blocklist):** `iocs/malicious_ips.txt`, checked regardless of private/public (curated list may include lab ranges). Hit → `ioc-local-blocklist`, `T1071`, `high`.
   - **Layer 2 (live feed):** AbuseIPDB check for public IPs only (skip RFC1918/loopback/link-local). Best-effort, soft-fail (missing key / unreachable → skipped). Score ≥50 flags, ≥75 → `high` else `medium`; `ioc-abuseipdb`, `T1071`. In-process `_ip_cache` avoids duplicate lookups.

## Stage D — Threat intelligence

- **ATT&CK enrichment:** every detection with a `technique_id` is enriched via `attck_mapper.enrich_technique()` → name, tactic, description (300 chars) from the **in-repo** STIX dataset (`dfir-refs/cti/enterprise-attack/enterprise-attack.json`, via `mitreattack-python`). Fail-soft: missing dataset → `name=None` (does not crash `/detect`).
- **External intel:** only AbuseIPDB (one live source). OTX/URLhaus/Feodo keys exist in `.env.example` but have **no code**.
- **Offline-first:** local hash list + local IP blocklist + local STIX mean the pipeline works with zero internet.

## Stage E — Correlation (current: minimal)

- No incident correlation. Persisted detections are flat rows.
- Aggregation exists only at reporting: `detections_summary()` counts by technique / severity / host / triage; `DetectionRun.by_severity` / `by_technique` summarize per run.
- No same-rule-across-hosts grouping, no ATT&CK chain reconstruction, no host-criticality weighting (all Phase 4).

## Stage F — Risk scoring (current: rule-level only)

- Severity comes from the rule definition (`severity` attr, default `unknown`) or is hardcoded per engine (`yara-*` high, `hash-match` critical, IOC high/medium).
- No composite score (rule severity × host criticality × IOC confidence). Triage status is separate from severity.
- Dashboard shows severity + triage badge; `/detections/summary` gives per-severity counts.

## Stage G — Reporting / persistence

- Every detection → `Detection` row (`detected_at`, `matched_data` JSON, enrichment, `triage_status="new"`).
- Every pipeline invocation → `DetectionRun` row (trigger, status, host scope, rescan flag, counts, by_severity/by_technique, timestamps) — including failed runs.
- Every pipeline invocation → `audit_logs` entry (`run_detection`).
- Views: dashboard Overview (health cards + summary), Detections table, Detection Runs history, Artifacts explorer, Audit log; `/metrics` exposes aggregate gauges.

## Post-processing

- Scanned artifacts → `processed=1`, `analyzed_at=UTC now`, `source_run_id=<run id>`.
- Idempotency: without `rescan=True`, processed artifacts are never re-analyzed; `rescan=True` re-analyzes everything (e.g. after rule updates).

## Future pipeline improvements (roadmap)

- **Phase 4:** async ingest via message queue (Redis/RabbitMQ) + workers; correlation engine (incidents, same-rule-across-hosts, ATT&CK chain, severity scoring); retention/archival; notifications.
- **Phase 5:** replace custom matcher with a real pySigma backend (keeping rule format via conversion layer); SigmaHQ rule update pipeline in CI; scheduled IOC feed refresh (MalwareBazaar, Feodo, URLhaus, OTX) into `iocs/`/DB; STIX/TAXII export; pagination/matview performance.
- **Within current architecture:** backend-side YARA re-scan of stored files (needs file storage, currently hashes only); per-rule severity from YARA meta instead of hardcoded `high`; live-feed coverage for OTX/URLhaus/Feodo; config-driven collector selection honored by the agent.
