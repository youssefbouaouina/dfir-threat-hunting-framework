# DFIR Threat Hunting Framework

> Capstone project — **Youssef Bouaouina & Amen Ben Salah** (esprit, NEXTSTEP).

A lightweight, offline-first DFIR threat-hunting platform: lightweight collector
agents run on endpoints and ship artifact batches to a FastAPI backend, which
stores them and runs a multi-engine detection pipeline (Sigma-style behavioral
rules, embedded YARA results, known-bad hash matching, network IOC correlation)
with MITRE ATT&CK enrichment. An analyst dashboard (`/dashboard`) provides
endpoint management, manual collection/detection triggers, detection run
history, triage, audit log, and metrics.

## Quick start

```
# Backend
cd backend
python -m venv .venv && .venv\Scripts\activate   # or: source .venv/bin/activate
pip install -r requirements.txt
python main.py                                    # serves http://127.0.0.1:8000, dashboard at /dashboard

# Collector (on an endpoint/VM)
cd collector
pip install -r requirements.txt
python collector_agent.py --api-url http://<backend>:8000 --enroll
python collector_agent.py --api-url http://<backend>:8000 --daemon --interval 300
```

For a full walkthrough (Windows host + VMware + two VMs) see
[`SETUP_GUIDE.md`](SETUP_GUIDE.md). Auth is opt-in via `AUTH_ENABLED=true`
(see [`backend/.env.example`](backend/.env.example)) — when enabled, the
backend refuses to start with placeholder secrets.

## Documentation

- [`PROJECT_SUMMARY.md`](PROJECT_SUMMARY.md) — phases, decisions, history.
- [`PROJECT_OVERVIEW.md`](PROJECT_OVERVIEW.md) — architecture, data schema, modules, APIs.
- [`ROADMAP.md`](ROADMAP.md) — 5-phase roadmap and status.
- [`SETUP_GUIDE.md`](SETUP_GUIDE.md) — step-by-step lab setup + run.
- [`AI_RULES.md`](AI_RULES.md) — binding rules for any modification.

## Layout

- `backend/` — FastAPI API, services, detection engines, Alembic migrations, static dashboard.
- `collector/` — endpoint agent: collection modules + push/daemon automation.
- `dfir-refs/cti/` — in-repo MITRE ATT&CK STIX dataset (used for enrichment).

## Validation

- Backend: 60 pytest tests, ruff clean. Collector: 9 pytest tests, ruff clean.
- CI (`.github/workflows/ci.yml`) gates lint + tests + gitleaks secret scan.
