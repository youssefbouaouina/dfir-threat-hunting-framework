# Phase 3 — Windows Container Endpoint Feasibility Report

**Verdict: NOT SUITABLE** for this project's DFIR use case. Windows endpoints are handled
by a **managed Windows VM** instead.

## 1. What a Windows container is

Windows containers (Windows Server Core / Nano Server / Windows base images) are not like
Linux containers and not like a Windows VM:

- They **share the Windows host kernel** (process isolation) or run in a lightweight
  Hyper-V VM (hypervisor isolation). Either way the guest is a headless, reduced Windows
  runtime, not a full Windows desktop/server OS image you can point Sysmon at.
- They require a **Windows container host** (Windows Server 2016+ or Windows 10/11
  Pro/Enterprise with Hyper-V). Docker Desktop on this machine runs Linux containers on a
  WSL2 backend; switching to Windows containers is a **global engine-mode switch** that
  stops the Linux backend from running.
- Server Core images are **~5 GB+**, carry Microsoft licensing terms, and pull slowly.
- Windows containers **cannot run on GitHub Actions Linux runners** at all.

## 2. Telemetry that the collector targets — what actually works

| Collector Windows path | In a Windows container | Reality |
|---|---|---|
| Sysmon event log (`win32evtlog`) | ❌ | Sysmon cannot be installed in a container (needs a kernel driver / ETW provider registration) → `log_event` collection is empty |
| `schtasks /query` | ❌ | The Task Scheduler service does **not** run in Windows Server Core containers by default; querying fails |
| Registry Run/RunOnce keys | ⚠️ mostly empty | Container registry is a *differencing hive*; HKLM/HKCU Run keys are effectively empty and reset |
| Services enumeration (pywin32) | ⚠️ partial | A handful of OS services exist; not a realistic endpoint service set |
| Processes (psutil) | ⚠️ reduced | only the container's own processes (python.exe etc.), not a real endpoint process tree |
| Event Logs (general) | ⚠️ minimal | Application/System logs exist but are nearly empty; no security log content of value |
| Windows Defender | ❌ | no real-time AV/Defender telemetry in containers |
| PowerShell / filesystem / YARA | ✅ | `powershell.exe`, filesystem access, and `yara-python` do work for file-level testing |

## 3. What functionality is lost versus a real Windows endpoint

- Kernel-level process/registry/file/network telemetry (no ETW, no Sysmon).
- Task Scheduler persistence visibility.
- Meaningful registry persistence (Run keys empty).
- Defender / security product status.
- Security & system event logs.
- Service-level persistence realism.
- CI integration (GitHub Actions cannot run Windows containers on Linux runners; Windows
  runners drain the free quota 2x and cannot coexist with the Linux stack).

## 4. Recommendation

Use a **Windows VM** as the Windows test endpoint and manage it from the dashboard via the
existing SSH orchestration (`os_type="windows"`). This is what the project already does
with `192.168.50.129` (Ubuntu VM) and the `win10-vm01` sample host, and the SSH transport
already supports Windows (OpenSSH Server is a built-in Windows feature).

Scope for the dashboard on a Windows VM endpoint:
- register / list / check (liveness) / scan / edit / delete — all supported.
- start / stop / restart of the *VM* itself — **not exposed** (requires VM-host tooling
  such as libvirt/vmrun; out of scope and fragile). Container endpoints get full lifecycle;
  VM endpoints do not, by design.

## 5. If a Windows VM is impossible in a given environment

The closest practical architecture that still exercises the pipeline is to run the
collector natively on any Windows host (VM or physical) and register it as a `vm` endpoint
with SSH details — the framework does not care where the collector runs, only that the
backend can SSH to it and it can reach `POST /ingest`.
