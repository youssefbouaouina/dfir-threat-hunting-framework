# Technical Report — DFIR Threat Hunting Framework

**Internship subject token:** Cyber Security Blue Team / Digital Forensics & Incident Response
**Deliverable:** §7 "A technical report describing the methodology, findings, and lessons learned"
**Authors:** Youssef Bouaouina & Amen Ben Salah (Esprit — NEXTSTEP)
**Date:** 2026-08-08

---

## 1. Introduction

### 1.1 Context

Organizations face growing cyber threats and are expected to not only **detect** incidents but
also **investigate** them, reconstruct what happened, and respond effectively. Detection alone
is not enough; the ability to map attacker behavior and contain impact has become a core
competency for security teams.

### 1.2 Problem addressed

There was no automated, lightweight way to collect endpoint artifacts, run detection, map
observations to MITRE ATT&CK, and produce a structured investigation report automatically. In
particular, the original codebase had no working offline ATT&CK enrichment (the STIX data was
absent), no attack-chain reconstruction/visualization, no recommended actions, and YARA was
not wired into the automated orchestration path.

### 1.3 Objectives

This framework:
1. Collects endpoint artifacts on Windows and Linux (processes, network, persistence,
   scheduled tasks, logs, file scans).
2. Detects suspicious behavior and IOCs using YARA rules and Sigma-style rules,
   plus hash and network-blocklist correlation.
3. Maps detected behavior to MITRE ATT&CK techniques/tactics (offline, STIX-based).
4. Reconstructs and visualizes the attack chain per endpoint.
5. Generates automated investigation PDF reports with a summary, risk levels, and
   recommended actions.
6. Simulates safe attack scenarios (EICAR) to validate the detection pipeline.

---

## 2. Architecture

### 2.1 Overview

```
DASHBOARD
    |
BACKEND API (FastAPI)
    |                     \
endpoint-manager       SSH orchestration (paramiko)
(only Docker access)          |
    |                    VM endpoints (linux/windows)
Linux endpoint containers      (backend_type="vm")
(backend_type="container")
    |                           |
    +--------> POST /ingest <---+
              |
       detection engine -> SQLite -> reports -> dashboard/API
```

### 2.2 Major components

| Component | Location | Technology | Role |
|---|---|---|---|
| Backend | `backend/` | FastAPI, SQLAlchemy (SQLite), APScheduler, reportlab, paramiko | Ingest API, detection engine, reports, dashboard |
| Collector agent | `collector/` | Python (psutil, requests, optional yara) | Runs on the endpoint, gathers artifacts |
| Detection engine | `backend/detection_routes.py` | sigma_matcher + yara_engine + ioc_correlation + hash_checker | Runs rules over unprocessed artifacts |
| ATT&CK mapper | `backend/attck_mapper.py` | mitreattack-python (STIX 2.0) | Enrich detections with technique name/tactic |
| ATT&CK chain | `backend/attack_chain.py` | Python | Attack-chain reconstruction + recommended actions |
| Dashboard | `backend/dashboard.py` + `templates/` | FastAPI + Jinja2 | Endpoint mgmt + summary views |
| Endpoint manager | `endpoint-manager/` | Python (Docker SDK) | Only service touching the Docker socket |
| Endpoint image | `endpoint-images/linux/` | Python + collector | Simulated Linux endpoint running the collector |

### 2.3 Container architecture

Compose runs three services plus one build-only image:

- `backend` (container name `dfir_backend_V5`) — FastAPI, SQLite in a named volume
  (`/app/data/dfir.db`), reports in a named volume (`/app/reports`). Envars set via
  `env_file: ./backend/.env`; STIX bundle bind-mounted read-only at `/dfir/stix`.
  Has a `/health` healthcheck.
- `endpoint-manager` — the **only** service with Docker socket access; enforces a token
  (`ENDPOINT_MANAGER_TOKEN`); backend talks to it over the private `dfir-internal` network.
- `endpoint-linux` — a "build-only" service that produces the endpoint simulation image.
- Named volumes `dfir-data` and `dfir-reports` survive `docker compose down`.

### 2.4 Data flow

```
collector (on endpoint) → POST /ingest → SQLite (artifacts/hosts)
  → run_detection_job() (scheduler 30-60s, or POST /detect)
  → detections table (with ATT&CK enrichment)
  → generate_report() → reports/*.pdf
  → Dashboard + REST API
```

The backend also reaches *out* to endpoints via SSH (paramiko) for VM orchestration: liveness
(TCP) and remote scans.

---

## 3. Methodology — collection & analysis

The collector agent runs natively on the target (container, Linux VM, or Windows VM) and
emits JSON artifact files. The implemented artifact categories (actual modules in
`collector/modules/`):

| Module | Artifact `type` | What is collected |
|---|---|---|
| `processes.py` | `processes` | Running processes with metadata |
| `network.py` | `network` | Active network connections (local/remote address, PID, state) |
| `persistence.py` | `persistence` | Cron / rc.local boot-persistence entries (Linux) |
| `scheduled_tasks.py` | `scheduled_tasks` | Cron spool tasks + (Windows path) scheduled tasks |
| `logs.py` | `logs` | System logs (Linux); **Windows Sysmon Operational log via pywin32** |
| `file_scan.py` | `file_scan` | Interesting files + SHA256 hashes, optional agent-side YARA results |
| `heartbeat.py` (in image) | `heartbeat` | Lightweight agent_version + last_heartbeat |

The collector aggregates output into `artifact_type` JSON documents and pushes them to
`POST /ingest`. On the backend, each `Artifact` row stores the host, OS, type, timestamp, and the
JSON payload as text; a `processed` flag guards against a detection rerun double-processing.

The wider artifact-path extraction also reads executable paths out of cron/rc.local
`entry` lines and scheduled-task fields (`task_to_run`, `raw`, `command`) so those can be
file-scanned for YARA.

---

## 4. Detection

The detection pipeline (`backend/detection_routes.py:run_detection_job`) runs over all
**unprocessed** artifacts and:

1. **Sigma-style behavioral rules** (`backend/sigma_matcher.py` + `backend/sigma_rules/`,
   19 YAML files) against process / persistence / scheduled_task / network / logs artifacts.
2. **YARA results** — the collector scans files agent-side and embeds `yara_matches` in the
   `file_scan` artifact; each match becomes a detection background. (Rules:
   `backend/yara_rules/`, 8 patterns incl. EICAR.)
3. **Known-bad hash matching** (`backend/hash_checker.py`) against
   `backend/iocs/known_bad_hashes.txt` (EICAR hash seeded for demo).
4. **Network IOC correlation** (`backend/ioc_correlation.py`) — local blocklist
   (`backend/iocs/malicious_ips.txt`) and, if `ABUSEIPDB_API_KEY` is set, a live API check.

All detections are persisted (not recomputed each call) with severity, rule id/title,
technique, `matched_data`, and `processed` is flipped so re-runs don't duplicate work.

Orchestration: the backend scheduler triggers detection every `DETECTION_INTERVAL_SECONDS`
(30s locally, 60s default), plus a manual `POST /detect`. Endpoint scans on request
(`POST /endpoints/{id}/run-now`) run the collector over SSH (VMs) or via the
endpoint-manager's `docker exec` (containers), with `--yara-rules` passed so agent-side YARA
runs on configured rules.

---

## 5. MITRE ATT&CK

The mapping and enrichment layer:

- **STIX dataset load**: `backend/attck_mapper.py` — locates the bundle via `DFIR_STIX_PATH`
  or candidate paths, loads it once per process with `MitreAttackData`, and caches.
  - Paths tried: env override → `dfir-refs/cti/enterprise-attack/enterprise-attack.json` →
    container mount `/dfir/stix/enterprise-attack.json`.
  - In the compose stack, the bundle is mounted read-only from
    `./dfir-refs/cti/enterprise-attack`.
- **Enrichment**: every detection's `technique_id` is enriched to `technique_name` and the
  first `kill_chain_phases` tactic. `enrich_technique()` fails soft (returns Nones) if the
  dataset is missing — a missing dataset never crashes `/detect` (by design) but is
  observable via the `error` field.
- **Attack chain**: `backend/attack_chain.py` groups detected techniques by ATT&CK tactic in
  a canonical kill-chain order (recon → resource development → initial access → execution →
  persistence → privilege escalation → defense evasion → credential access → discovery →
  lateral movement → collection → C2 → exfiltration → impact). Exposed via `GET
  /detections/chain` and rendered on the dashboard.
- **Recommended actions**: a curated technique→action map (e.g. T1059.001 execution, T1562
  defense evasion, T1027 evasion) produces `recommended_actions` on the chain endpoint and
  in the PDF report.

---

## 6. Investigation workflow

The end-to-end flow (reproducible in `docs/demo_scenario.md`):

1. **Endpoint creation** (dashboard or API) → backend registers + (containers) the
   endpoint-manager creates the unprivileged container.
2. **Collection**: the endpoint image boots → heartbeat → initial collection; further scans on
   `run-now`, or VM SSH orchestration.
3. **Data pushed to backend** → `POST /ingest` → SQLite.
4. **Detection** → scheduler or manual `POST /detect` → Σigma/YARA/hash/IOC pipeline.
5. **Enrichment** → ATT&CK name/tactic added to every detection.
6. **Attack chain + recommendations** → `GET /detections/chain` → dashboard panels.
7. **Reporting** → `POST /reports/run-now` → 7-section PDF (executive summary, sources,
   rules, ATT&CK coverage, chain + recommended actions, endpoints, detection detail).

---

## 7. Attack simulation / validation

### 7.1 EICAR scenario

Using the **EICAR test file** (standard antivirus test string, not malware):

1. Plant `EICAR-STANDARD-ANTIVIRUS-TEST-FILE` text in a script on the (container) endpoint
   and reference it from a cron entry (persistence).
2. `run-now` → collector extracts the path from the cron entry → file-scans it → agent-side
   YARA matches `EICAR_Test_String` (2 matches) → detections persisted.
3. The same EICAR file bytes hash **(68 bytes,
   `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`)** also validate the
   known-bad-hash path.

This was verified end-to-end during development: the cron-referenced script was found,
scanned, produced 2 YARA matches, and persisted as a `high` severity detection.

### 7.2 Sample data

`sample_data/` includes two collected snapshots (`ns-ubuntu-server`, `win10-vm01`) driven
through the pipeline with `backend/push_samples.py`.

---

## 8. Results

The results below are what was actually observed during development/CI; no numbers are
fabricated.

- **Unit tests**: 23 passed (`pytest backend/tests -q`), ruff clean.
- **Integration lifecycle** (CI, Linux): create endpoint → heartbeat → run-now scan → ingest →
  detect → report → stop → restart/recovery → delete — **ALL PASSED**.
- **STIX enrichment in container**: T1059.001 → "PowerShell"/execution;
  T1566.001 → "Spearphishing Attachment"/initial-access.
- **Dashboard**: renders attack-chain reconstruction + recommended-actions panels.
- **PDF**: 7-section report with enriched names (verified by text extraction).

### 8.1 Compliance mapping to the internship PDF

| Requirement | Status |
|---|---|
| Windows + Linux artifact collection | Implemented (Windows Windows paths present but not validated — see §9) |
| YARA + Sigma detection | Done, wired into orchestration |
| MITRE ATT&CK mapping (TTP) | Done (offline STIX) |
| Attack-chain reconstruction & visualization | Done |
| Automated reports + summary w/ risk levels + recommended actions | Done |
| Safe attack simulation | EICAR scenario, validated |

---

## 9. Limitations

- **Windows Registry persistence**: implemented for Windows in the collector, but was **NOT
  validated at runtime** — no Windows host was available in this environment. Structurally
  consistent, code-reviewed, untested.
- **Sysmon / Windows Event Logs**: `logs.py` has a `Windows: Sysmon Operational` path via
  pywin32, but pywin32 login was not installable/available; the module gracefully skips on
  Linux. Untested on Windows.
- **Process-injection / in-memory techniques** out of scope — the collector reads metadata,
  not memory; T1055 process injection is listed as future work.
- **Port-based C2 detection** is a weak signal on its own (many C2s use 443); complemented
  by IOC correlation, not replaced.
- **Severity is heuristic**, not authoritative (e.g. discovery commands alone are
  low-confidence).
- **Windows container endpoint** (`WINDOWS_CONTAINER_FEASIBILITY.md`) was not exercised in
  this environment.

---

## 10. Lessons learned

1. **STIX must be available at runtime to matter.** Enrichment degrading to Nones is
   invisible unless you check the `error` field — keep the dataset fetch explicit and
   documented.
2. **Windows paths cannot be proven from a Linux machine.** CI cannot substitute a real
   window Sysmon host; cross-platform collector code needs an explicit Windows test.
3. **A scheduled detection cycle can race a manual `POST /detect`, creating duplicates.**
   Out-of-scoped, but worth documenting.
4. **Keep orchestrated scans pass the same flags as manual runs.** Wiring `--yara-rules`
   through both SSH and docker-exec surfaces confidence that automated detection matches
   these conditions.

---

## 11. Future improvements

These are documented improvements, **not** implemented features:

- Validate the full collector on a real Windows endpoint (registry, Sysmon/Security logs).
- Detect in-memory techniques (T1055) via memory scanning.
- Add real threat-intel feeds for the IP/hash allow list (currently seeded manually; AbuseIPDB
  optional live lookups).
- De-duplicate scheduled+manual detection cycles.
- Containerized Windows endpoint support.
- CI exercising the full Windows collector path (requires a Windows runner).