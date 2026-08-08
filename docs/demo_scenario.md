# Demo Scenario — End-to-End DFIR Investigation

A reproducible, safe end-to-end run of the framework: fresh clone → endpoint →
detection → ATT&CK chain → PDF report. Everything below was verified against the
actual implementation in this repository.

> **Safety.** This demo uses only the **EICAR test file** (
> `EICAR-STANDARD-ANTIVIRUS-TEST-FILE`), a standard antivirus test string that is
> not malware. No real attack tooling is created or executed. The reserved
> TEST-NET IP range (203.0.113.0/24, RFC 5737) is used for network-based IOCs and
> never routes anywhere real.

Commands are grouped by **where they run**: host, container, or endpoint.

---

## 0. Prerequisites

- Docker with Compose v2
- Bash (for `scripts/fetch-stix.sh`)

## 1. Fresh project setup (host)

```bash
git clone <repo-url>
cd dfir-threat-hunting-framework
cp backend/.env.example backend/.env
bash scripts/fetch-stix.sh
docker compose up --build -d
```

## 2. Starting the backend (host)

```bash
curl http://127.0.0.1:8000/health                 # -> {"status":"ok"}
curl http://127.0.0.1:8000/scheduler/status       # -> 3 scheduler jobs listed
```

## 3. Creating an endpoint (host)

Create a simulated Linux endpoint container (managed by `endpoint-manager`):

```bash
curl -X POST http://127.0.0.1:8000/endpoints \
  -H "Content-Type: application/json" \
  -d '{"name":"linux-demo-01","os":"linux","backend_type":"container"}'
# -> {"id":1, "name":"linux-demo-01", "status":...}  <-- note the numeric id
EP_ID=1
```

## 4. Endpoint heartbeat (automatic)

The endpoint image pushes a heartbeat on boot and periodically. Confirm it was
received (this also proves the collector→backend ingestion path):

```bash
curl http://127.0.0.1:8000/endpoints/$EP_ID
# -> "last_heartbeat": "...", "agent_version": "collector-2.0-endpoint-image"
```

## 5. Injecting a safe test artifact (in endpoint container)

Exec into the running demo endpoint container and plant an EICAR-marked file
referenced from a cron entry (persistence). **EICAR string only — safe:**

```bash
docker exec linux-demo-01 sh -c '
  printf "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n" > /opt/dfir_eicar_marker.sh
  chmod +x /opt/dfir_eicar_marker.sh
  echo "*/5 * * * * root /opt/dfir_eicar_marker.sh" >> /etc/cron.d/dfir-demo'
```

(This mirrors the EICAR scenario used by CI's integration test — the collector's
`_extract_exe_paths()` picks executable paths up from the cron entry and
`file_scan` YARA-matches the script content.)

## 6. Scanning the endpoint (host)

```bash
curl -X POST http://127.0.0.1:8000/endpoints/$EP_ID/run-now
# -> {"scan":{"success":true,"exit_status":0}}
```

The `endpoint-manager` asks the collector inside the container to run (with
`--yara-rules /opt/collector/yara_rules`), which aggregates the artifact files.

## 7. Collector data sent to backend (host)

A subtlety: the `/detections?host=` filter uses the endpoint *name* (what the
collector pushes as `host`), so keep it as `linux-demo-01`:

```bash
curl "http://127.0.0.1:8000/artifacts?host=linux-demo-01&limit=500"
# -> array of processes / network / persistence / scheduled_tasks / file_scan artifacts
```

## 8. Sigma / YARA / IOC detection (host)

Run the detection pipeline manually (the scheduler also runs it every 30s):

```bash
curl -X POST http://127.0.0.1:8000/detect
curl "http://127.0.0.1:8000/detections?host=linux-demo-01"
# e.g. YARA EICAR match, Sigma persistence rule, hash-match against attacker
curl http://127.0.0.1:8000/detections/summary
# -> {"total_detections": N, "by_technique": {...}, "by_severity": {...}, "by_host": {...}}
```

## 9. ATT&CK enrichment (host)

Every detection is tagged with the ATT&CK technique/tactic (from the STIX bundle
fetched in setup). View the enriched values from the detections API:

```bash
curl "http://127.0.0.1:8000/detections?host=linux-demo-01&limit=20" | python3 -m json.tool
# -> each detection carries "technique_id", "technique_name", "tactic"
```

## 10. Attack-chain visualization (host)

```bash
curl "http://127.0.0.1:8000/detections/chain?host=linux-demo-01" | python3 -m json.tool
# -> {"chain": {...phases in tactic order}, "recommended_actions": [...]}
```

Or the dashboard — open <http://127.0.0.1:8000/dashboard>; the "Attack Chain
Reconstruction" panel renders the ordered phase flow, and "Recommended Actions"
lists the mitigations.

## 11. Risk / recommended actions

The chain endpoint already returns `recommended_actions`; the dashboard panel
renders them. Severity is per-detection (`low|medium|high|critical`) and shown in
the detections list and PDF.

## 12. PDF report generation (host)

```bash
curl -X POST http://127.0.0.1:8000/reports/run-now
# -> {"detect_result": {...}, "report": {"run_id": "...", "pdf_filename": "..."}}

# list reports
curl http://127.0.0.1:8000/reports

# download the latest PDF (host)
curl -OJ http://127.0.0.1:8000/reports/<run_id>/download
```

The PDF (7 sections) includes the executive summary, detection sources, rules
involved, ATT&CK technique coverage, attack-chain reconstruction + recommended
actions, endpoint details, and detection detail table.

---

## Optional: feed pre-collected sample data instead of a live endpoint

If the container path is unavailable, the `sample_data/` folders have real
collected artifacts that exercise the same pipeline:

```bash
# run the backend natively with a throwaway DB (host):
#   cd backend && python -m venv .venv && pip install -r requirements.txt
#   uvicorn main:app --port 8000
cd backend
python push_samples.py ../sample_data/2026-07-29_ns-ubuntu-server --url http://127.0.0.1:8000
curl -X POST http://127.0.0.1:8000/detect
```

## Screenshots (placeholders)

- `docs/img/01-dashboard.png` — dashboard with endpoint list + detection summary
- `docs/img/02-attack-chain.png` — Attack Chain Reconstruction panel
- `docs/img/03-recommended-actions.png` — Recommended Actions panel
- `docs/img/04-report-section5.png` — PDF §5 (chain + actions)

These can be captured from the live dashboard after step 6–12 completes. They are
left as placeholders here because they cannot be generated automatically in CI.

## Teardown

```bash
curl -X DELETE "http://127.0.0.1:8000/endpoints/$EP_ID?remove_container=true"
docker compose down
```