# Phase 2 — Linux Container Endpoint Feasibility Report

**Verdict: FEASIBLE** for simulating Linux test endpoints, provided the collector runs
*inside* the endpoint container and we treat the container as the simulated host.

## 1. Principle

A container is not a VM: it shares the host kernel and has its own PID, network, mount,
UTS, and IPC namespaces (plus cgroups). The collector inside a container therefore sees:

- **its own namespace's** processes,
- **its own namespace's** network connections,
- **its own** filesystem (container layers + mounts).

For a *simulated* endpoint this is exactly correct — the container **is** the endpoint.
The old design note "a containerized collector would report the container's processes, not
the actual host's" is right, and that is precisely what we want for test endpoints.

## 2. Telemetry mapping in a normal (unprivileged) container

| Collector module | Inside normal container | Requirement / notes |
|---|---|---|
| `processes` (psutil) | ✅ works | sees container PID namespace (sshd/systemd/collector + any injected test process) |
| `network` (psutil) | ✅ works | sees container's network namespace |
| `persistence` — cron / rc.local | ✅ works | `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron/crontabs` readable if present in image |
| `persistence` — `systemctl list-unit-files` | ⚠️ needs systemd | works only if image runs systemd as PID 1 (e.g. `jrei/systemd-ubuntu`) |
| `scheduled_tasks` — `systemctl list-timers` | ⚠️ needs systemd | systemd is **not** run (see §4/§7) |
| `scheduled_tasks` — cron spool | ✅ works | seeded cron entries in the image |
| `logs` — `journalctl` | ⚠️ needs journald | journald is **not** run; module skips gracefully |
| `logs` — `ausearch` (auditd) | ❌ absent | auditd not runnable in container (needs host audit subsystem); module already timeouts/skips gracefully |
| `file_scan` (hash + YARA) | ✅ works | hashes container's own executables; agent-side YARA bundled in the image |

## 3. What requires elevated/privileged (and we will NOT do it)

Full host-equivalent telemetry would need:
- `--pid host` (host PID namespace) — see host processes,
- `--network host` — see host network,
- host filesystem mounts — see host files,
- `--privileged` / extra capabilities — see auditd/kernel events.

**Decision:** none of these are used. Granting them turns a simulated endpoint into a
container-escape vector and contradicts the project's DFIR security posture. The telemetry
we keep is the telemetry of a realistic *test host*, which is the goal.

## 4. Image recommendation

- Base: `python:3.12-slim` (NOT a systemd image — see §7).
- Ship the `collector/` code + deps (psutil, requests, yara-python).
- Agent-side YARA: bundle `backend/yara_rules/` into the image and pass
  `--yara-rules` to the collector.
- Pre-seed persistence data (`/etc/crontab`, `/etc/cron.d`, `/var/spool/cron/crontabs/root`,
  `/etc/rc.local`) so the persistence/scheduled_task modules report realistic data.
- Endpoint containers run with `--cap-drop=ALL --security-opt=no-new-privileges`,
  no host mounts, no host network, no host PID, no privileged.
- A lightweight `heartbeat.py` posts a heartbeat artifact to `/ingest` on a loop
  so the backend can track `last_heartbeat` + `agent_version`.

## 7. Deliberate tradeoff: no systemd in endpoint containers

Running systemd as PID 1 in Docker reliably requires `SYS_ADMIN` (for mounting) plus
cgroup mounts and often a loosened seccomp profile — exactly the capability class
associated with container-escape. Endpoint containers are DFIR test machines that may
be *deliberately* running suspicious/malicious payloads, so giving them `SYS_ADMIN`
would be an unacceptable host-escape risk.

Consequence: the two modules that shell out to `systemctl` / `journalctl`
(`persistence._linux_systemd_services`, `scheduled_tasks._collect_linux_timers`,
`logs._collect_linux_logs` journalctl leg) simply find no `systemctl`/`journalctl`
binary in the image and are skipped gracefully (they already catch `FileNotFoundError`).
All other modules still produce realistic data. This is the correct security-first
tradeoff; systemd telemetry would only be worth it if a non-SYS_ADMIN systemd mode
becomes reliably supported.

## 5. Collector runtime concerns

- Run the collector as root inside the container: it is the simulated host's "root" user
  and grants full psutil visibility of the container namespace. Being root *inside* an
  unprivileged container is acceptable because the container is non-privileged and isolated.
- Non-root execution is also fine (modules already tolerate PermissionErrors), but root
  gives richer telemetry for cron spool, etc.

## 6. Lifecycle & transport

- Container lifecycle (create/start/stop/restart/remove) via the `endpoint-manager`
  service (Docker API over the socket).
- Liveness = `docker inspect` container state (running/stopped), plus `POST /ingest`
  freshness for heartbeat.
- On-demand scan (`Run Now`) = `docker exec` inside the container running
  `python collector_agent.py --push-url http://backend:8000`. No sshd, no SSH keys in
  containers.
