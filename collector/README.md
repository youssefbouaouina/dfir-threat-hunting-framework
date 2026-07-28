# Collector Agent

## Setup
```bash
pip install -r requirements.txt
```
(On Windows, this also installs `pywin32` — remember to run the post-install step once:
`python venv\Scripts\pywin32_postinstall.py -install`)

## Run
```bash
python collector_agent.py
```
Writes output to `./output/<date>_<hostname>/*.json`.

Options:
```bash
python collector_agent.py --output C:\temp\dfir_out       # custom output location
python collector_agent.py --only processes,network        # run a subset only
```

Run **elevated** (Administrator on Windows, `sudo` on Linux) for full visibility —
without elevation, some processes/connections owned by other users, and some
log sources, will be silently skipped rather than erroring out.

## Files
- `collector_agent.py` — main entrypoint, orchestrates all modules
- `modules/common.py` — shared schema wrapper + JSON writer
- `modules/processes.py` — running process enumeration
- `modules/network.py` — active network connections
- `modules/persistence.py` — registry Run keys + services (Windows) / cron, rc.local, systemd (Linux)
- `modules/scheduled_tasks.py` — Task Scheduler (Windows) / systemd timers + cron (Linux)
- `modules/logs.py` — Sysmon Operational log (Windows) / journalctl + auditd (Linux)

## Testing an individual module
Each module can be run standalone for quick debugging:
```bash
python -m modules.processes
python -m modules.network
python -m modules.persistence
python -m modules.scheduled_tasks
python -m modules.logs
```
