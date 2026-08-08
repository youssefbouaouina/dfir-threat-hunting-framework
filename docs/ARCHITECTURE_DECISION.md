# Phase 4 — Architecture Decision

## Options compared

| Criterion | A: Linux + Windows containers | B: Linux containers + Windows VM | C: B + existing Ubuntu VM | D: Hybrid (containers + VMs, generic model) |
|---|---|---|---|---|
| Technical feasibility | Windows containers need a Windows host + Docker Desktop mode switch | ✅ | ✅ | ✅ |
| DFIR telemetry quality | Windows container telemetry near-empty (no Sysmon, no Task Scheduler) | Windows VM = full | full | full for both OS families |
| Resource usage | Windows images ~5GB+, whole engine switch | Windows VM heavy but only when used | as B | minimal for Linux containers; VM only for Windows |
| Complexity | high (dual container stacks) | moderate | moderate | moderate |
| Security | higher (Windows containers on shared kernel) | good | good | best (isolated manager, unprivileged containers) |
| Docker compatibility | poor (mode switch breaks Linux backend) | good | good | good |
| Dashboard control | Windows lifecycle in containers; poor telemetry | Windows VM limited lifecycle (no safe start/stop) | same | container endpoints get full lifecycle; VM endpoints get check/scan/edit/delete |
| CI/CD compatibility | cannot run Windows containers in Actions | Windows VM not part of CI (Linux endpoints are) | same | Linux container endpoints fully tested in CI |
| Testing capabilities | low for Windows | good | good | good |
| Windows compatibility | poor | excellent | excellent | excellent |
| Linux compatibility | excellent | excellent | excellent | excellent |

## Decision: Option D — hybrid, with a generic endpoint model

```
                DASHBOARD
                    |
             BACKEND API (FastAPI)
                 |            \
   endpoint-manager (only Docker access)   SSH orchestration (paramiko)
        |  narrow API / exec                    |
   Linux endpoint containers              VM endpoints (Linux or Windows)
   (backend_type="container")             (backend_type="vm")
        |                                        |
        +---------->  POST /ingest  <------------+
                            |
                     DFIR detection engine
                            |
                         SQLite + reports + dashboard/API
```

**Why D wins for this project:**
1. **Do not break the current system.** The existing VM/SSH path (Option B/C behavior) is
   untouched; containers are an *additional* endpoint kind, not a replacement.
2. **Honest telemetry.** Windows telemetry only comes from a real Windows OS → Windows VM.
   Linux simulation via containers gives real (namespace-scoped) Linux telemetry.
3. **Security.** A dedicated `endpoint-manager` service is the only component with Docker
   socket access; endpoint containers are unprivileged. The backend itself never sees the
   socket (see Security section).
4. **CI/CD.** Linux container endpoints can be created, scanned, and destroyed entirely
   inside GitHub Actions on Linux runners — free and reproducible. VMs cannot.

## Container scan transport (decision)

- **Container endpoints:** `docker exec` — endpoint-manager runs
  `python collector_agent.py --push-url http://backend:8000` inside the container. No
  sshd, no SSH keys in containers; works headless in CI; liveness = `docker inspect`.
- **VM endpoints:** existing `run_remote_scan()` SSH path unchanged.

Both are exposed behind the same API (`POST /endpoints/{id}/run-now`), selected by
`backend_type`.

## Security boundaries (chosen)

- `endpoint-manager` mounts `/var/run/docker.sock` **read-only** and is the *only* service
  that does.
- It exposes an internal-only, token-authenticated HTTP API restricted to an allow-list:
  `create / start / stop / restart / status / exec / remove / list`.
- Every `create` request is validated server-side and **rejects**: `privileged`, host
  filesystem mounts, host network, host PID namespace, `--cap-add`, and arbitrary image
  pulls (only images pre-declared by configuration).
- Endpoint containers: `--cap-drop=ALL --security-opt=no-new-privileges`, no host
  mounts/network/PID, read-only where possible, internal network only (no published ports).
- Backend ↔ endpoint-manager traffic stays on a private Docker network with a shared secret.
- No TCP Docker API exposure anywhere.

Rationale (per OWASP Docker Cheat Sheet and Docker docs): mounting the raw socket into the
backend would grant any backend compromise immediate host-root; the manager-with-allow-list
reduces that blast radius to a narrow, audited surface.
