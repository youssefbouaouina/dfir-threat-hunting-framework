# Defense Presentation — DFIR Threat Hunting Framework

A ~15-slide outline for the internship defense. Each slide lists the **title**, **bullet
points**, what to **demonstrate visually** where relevant, and **talking points**. No
screenshots or results are fabricated; the demo follows `docs/demo_scenario.md` and captured
screenshots should be dropped into `docs/img/` as described there.

---

## Slide 1 — Title

- Lightweight DFIR & Threat Hunting Framework for Endpoint Investigation
- Youssef Bouaouina & Amen Ben Salah — Esprit (NEXTSTEP), Cyber Security Blue Team
- Summer internship subject — DFIR / Threat Hunting

> **Talking point:** one-line pitch — collect, detect, map to MITRE ATT&CK, and report
> automatically, all open-source and free.

## Slide 2 — Problem / Motivation

- Detection alone is not enough — teams must reconstruct and respond.
- Manual triage of processes/network/persistence/logs is slow and error-prone.
- SMBs need a **lightweight, automated**, explainable pipeline.

> **Talking points:** mention the internship §1 context (growing threat volume, need for
> reconstruction + response); position the framework as a repeatable *process*, not just a tool.

## Slide 3 — Objectives

- Collect Windows & Linux endpoint artifacts automatically.
- Detect IOCs with YARA + Sigma rules.
- Map threats to MITRE ATT&CK (tactics/techniques).
- Automate structured investigation reports + summary view.
- Validate with safe simulated scenarios.

> **Talking point:** map directly to internship §3.

## Slide 4 — Architecture (high-level)

- Collector agent on endpoints → `POST /ingest` → backend.
- Backend (FastAPI + SQLite) → detection engine → reports → dashboard.
- endpoint-manager (Docker-only access) for container endpoints; SSH orchestration for VMs.

> **Demo:** show the architecture diagram from `docs/` (`ARCHITECTURE_*`) or the README ASCII
> diagram.

## Slide 5 — Endpoint collection

- 6 artifact modules: processes, network, persistence, scheduled tasks, logs, file scans.
- Collector is Python + psutil; runs in an unprivileged container or on Linux/Windows VMs.
- Agent-side YARA enabled via `--yara-rules`.

> **Demo:** `collector/` tree + a sample `file_scan`/`network` JSON artifact.

## Slide 6 — Backend

- FastAPI + SQLAlchemy (SQLite) + APScheduler; PDF via reportlab.
- Ingest API, detections API, endpoints API, dashboard router.
- Docker: named volumes for DB + reports, `/health` healthcheck.

> **Demo:** `curl /health`, `curl /scheduler/status`.

## Slide 7 — Detection pipeline

- Runs over unprocessed artifacts → Σigma behavioral rules → YARA results → hash match →
  network IOC correlation.
- Detections persisted with severity + ATT&CK enrichment; `processed` flag prevents dupes.
- Same `run_detection_job` runs from scheduler or manual `POST /detect`.

> **Demo:** `curl -X POST /detect`, `curl /detections`, `curl /detections/summary`.

## Slide 8 — YARA + Sigma + IOC

- **YARA** (`backend/yara_rules/`): 8 curated patterns (EICAR, PowerShell loader, credential
  dumping, webshells, ingress transfer, shadow-copy deletion).
- **Sigma-style** (`backend/sigma_rules/`): 19 YAML rules across the kill chain.
- **IOC**: local IP blocklist + known-bad hashes; optional AbuseIPDB.

> **Talking point:** deliberately small, documented, explainable ruleset (see
> `docs/RULESET_DOCUMENTATION.md`).

## Slide 9 — MITRE ATT&CK enrichment

- Offline STIX bundle (`mitreattack-python`) → technique name + tactic for each detection.
- Resolves T1059.001 → PowerShell / execution; T1566.001 → Spearphishing Attachment.
- Fetched by `scripts/fetch-stix.sh` (CI + fresh clone consistent).

> **Demo:** show a detection JSON with `technique_id`, `technique_name`, `tactic`.

## Slide 10 — Attack-chain visualization

- `GET /detections/chain` reconstructs tactics in kill-chain order.
- Dashboard "Attack Chain Reconstruction" panel.

> **Demo:** open the dashboard panel; optionally screenshot (placeholder
> `docs/img/02-attack-chain.png`).

## Slide 11 — Dashboard

- Endpoint list + create/start/stop/restart/scan/delete.
- Detection summary, ATT&CK coverage, chain + recommended actions.

> **Demo:** live dashboard at `http://127.0.0.1:8000/dashboard`.

## Slide 12 — Automated PDF reporting

- `POST /reports/run-now` → 7-section PDF (executive summary, sources, rules, ATT&CK
  coverage, chain + recommended actions, endpoints, detection detail).
- Downloadable via `/reports/{id}/download`.

> **Demo:** generate and open the PDF; show §4 coverage + §5 chain/actions.

## Slide 13 — Attack simulation / demo

- Safe **EICAR** scenario (test string, not malware): cron-referenced script → file-scan →
  2 YARA matches → detection persisted.
- Also `sample_data/` (ubuntu + win10 snapshots) driven through `push_samples.py`.
- Full walkthrough: `docs/demo_scenario.md`.

> **Demo:** run the scenario live (or show captured screenshots as placeholders).

## Slide 14 — Validation / results

- Unit tests: 23 passed; ruff clean.
- Integration lifecycle test: create → heartbeat → scan → ingest → detect → report →
  stop → restart → delete — ALL PASSED (CI).
- STIX enrichment verified in-container.
- 7-section PDF validated by text extraction.

> **Talking points:** be precise — only claim what was run; Windows-specific claims are
> explicitly NOT validated (see next slide).

## Slide 15 — Limitations + conclusion

- **Not validated on Windows**: Registry persistence, Sysmon/Event Logs (no Windows host in
  this environment) — documented in `docs/TECHNICAL_REPORT.md` §9.
- Severity is heuristic; port-based C2 is a weak signal; in-memory techniques out of scope.
- Conclusion: a lightweight, tested, offline-capable DFIR pipeline from artifact → ATT&CK
  chain → automated report, with honest, reproducible validation.

> **Talking point:** end on the demo-ability + reproducibility (fresh clone → one command →
> live investigation).
