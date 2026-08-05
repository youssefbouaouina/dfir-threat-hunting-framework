"""
Collects persistence-relevant artifacts:
  Windows: Run/RunOnce registry keys (HKLM + HKCU), installed services
  Linux:   cron entries, /etc/rc.local, enabled systemd services

Windows-only imports (winreg, pywin32) are done lazily inside the
Windows-specific functions so this module can still be imported on Linux
without raising ImportError.
"""
import os
import platform
import subprocess

from .common import wrap_artifact


def collect_persistence() -> list:
    if platform.system() == "Windows":
        return _collect_windows_persistence()
    return _collect_linux_persistence()


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def _collect_windows_persistence() -> list:
    import winreg

    records = []
    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    for hive, subkey in run_keys:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        data = {
                            "type": "registry_run_key",
                            "hive": hive_name,
                            "key_path": subkey,
                            "value_name": name,
                            "value_data": value,
                        }
                        records.append(wrap_artifact("persistence", data))
                        i += 1
                    except OSError:
                        # No more values under this key
                        break
        except FileNotFoundError:
            continue

    # Installed services (requires pywin32)
    # EnumServicesStatus's status field is a tuple:
    # (ServiceType, CurrentState, ControlsAccepted, Win32ExitCode,
    #  ServiceSpecificExitCode, CheckPoint, WaitHint)
    STATE_MAP = {
        1: "STOPPED",
        2: "START_PENDING",
        3: "STOP_PENDING",
        4: "RUNNING",
        5: "CONTINUE_PENDING",
        6: "PAUSE_PENDING",
        7: "PAUSED",
    }
    try:
        import win32service

        sc_handle = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
        )
        services = win32service.EnumServicesStatus(sc_handle)
        for (short_name, display_name, status) in services:
            current_state = status[1] if status else None
            data = {
                "type": "service",
                "name": short_name,
                "display_name": display_name,
                "status": STATE_MAP.get(current_state, "UNKNOWN"),
            }
            records.append(wrap_artifact("persistence", data))
    except ImportError:
        print("[!] pywin32 not available — skipping service enumeration "
              "(run: pip install pywin32, then pywin32_postinstall.py -install)")

    return records


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

def _collect_linux_persistence() -> list:
    records = []
    records.extend(_linux_cron_entries())
    records.extend(_linux_rc_local())
    records.extend(_linux_systemd_services())
    return records


def _linux_cron_entries() -> list:
    records = []
    candidates = ["/etc/crontab"]
    cron_d = "/etc/cron.d"
    if os.path.isdir(cron_d):
        candidates.extend(os.path.join(cron_d, f) for f in os.listdir(cron_d))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        data = {"type": "cron", "source": path, "entry": line}
                        records.append(wrap_artifact("persistence", data))
        except (IOError, PermissionError):
            continue

    # Per-user crontabs (needs root to read other users')
    spool_dir = "/var/spool/cron/crontabs"
    if os.path.isdir(spool_dir):
        try:
            crontabs = os.listdir(spool_dir)
        except (IOError, PermissionError):
            # /var/spool/cron/crontabs is drwx-wx--T root:crontab — a
            # non-root user cannot list it, and os.listdir raises instead
            # of returning empty. Skip it rather than crash the run (BUG-3).
            crontabs = []
        for user in crontabs:
            try:
                with open(os.path.join(spool_dir, user), "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            data = {"type": "cron", "user": user, "entry": line}
                            records.append(wrap_artifact("persistence", data))
            except (IOError, PermissionError):
                continue

    return records


def _linux_rc_local() -> list:
    records = []
    path = "/etc/rc.local"
    if os.path.isfile(path):
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            data = {"type": "rc.local", "path": path, "content": content}
            records.append(wrap_artifact("persistence", data))
        except (IOError, PermissionError):
            pass
    return records


def _linux_systemd_services() -> list:
    records = []
    try:
        output = subprocess.check_output(
            ["systemctl", "list-unit-files", "--type=service", "--state=enabled"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                data = {"type": "systemd_service", "unit": parts[0], "state": parts[1]}
                records.append(wrap_artifact("persistence", data))
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return records


if __name__ == "__main__":
    import json
    print(json.dumps(collect_persistence()[:5], indent=2, default=str))
