"""
Collects recent log events:
  Windows: Sysmon Operational event log, via pywin32's win32evtlog
  Linux:   journalctl (system journal) + ausearch (auditd), via subprocess

max_events caps how many entries are pulled per run — keep this
reasonable for a "lightweight" framework; tune upward once you're doing
real investigations instead of just testing the pipeline.
"""
import json
import platform
import subprocess

from .common import wrap_artifact


def collect_logs(max_events: int = 200) -> list:
    if platform.system() == "Windows":
        return _collect_windows_sysmon_logs(max_events)
    return _collect_linux_logs(max_events)


# ---------------------------------------------------------------------------
# Windows — Sysmon Operational log
# ---------------------------------------------------------------------------

def _collect_windows_sysmon_logs(max_events: int) -> list:
    records = []
    try:
        import win32evtlog
    except ImportError:
        print("[!] pywin32 not installed — cannot read the Sysmon event log")
        return records

    server = "localhost"
    logtype = "Microsoft-Windows-Sysmon/Operational"

    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
    except Exception as e:
        print(f"[!] Could not open Sysmon log (is Sysmon installed and running?): {e}")
        return records

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    count = 0
    try:
        while count < max_events:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                if count >= max_events:
                    break
                data = {
                    "event_id": event.EventID & 0xFFFF,  # mask off the severity bits
                    "time_generated": str(event.TimeGenerated),
                    "source_name": event.SourceName,
                    "event_category": event.EventCategory,
                    "string_inserts": list(event.StringInserts) if event.StringInserts else [],
                }
                records.append(wrap_artifact("log_event", data))
                count += 1
    finally:
        win32evtlog.CloseEventLog(hand)

    return records


# ---------------------------------------------------------------------------
# Linux — journalctl + auditd
# ---------------------------------------------------------------------------

def _collect_linux_logs(max_events: int) -> list:
    records = []

    try:
        output = subprocess.check_output(
            ["journalctl", "-o", "json", "-n", str(max_events)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        for line in output.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            data = {
                "message": entry.get("MESSAGE"),
                "unit": entry.get("_SYSTEMD_UNIT"),
                "pid": entry.get("_PID"),
                "priority": entry.get("PRIORITY"),
                "timestamp_us": entry.get("__REALTIME_TIMESTAMP"),
            }
            records.append(wrap_artifact("log_event", data))
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] journalctl read failed: {e}")

    # auditd events tagged by the exec_tracking rule set up during VM config.
    # Guarded with a hard timeout: as a non-root user ausearch can block
    # indefinitely waiting on the audit pipe when /var/log/audit is not
    # readable, which would hang the whole collection run (BUG-1).
    try:
        output = subprocess.check_output(
            ["ausearch", "-k", "exec_tracking", "-ts", "recent"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if output.strip():
            data = {"source": "auditd", "key": "exec_tracking", "raw": output[-4000:]}
            records.append(wrap_artifact("log_event", data))
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # ausearch returns non-zero when there are no matching events, which
        # is normal on a quiet system — not treated as an error. A timeout
        # (unreadable audit log as non-root) is likewise skipped, never hung.
        pass

    return records


if __name__ == "__main__":
    print(json.dumps(collect_logs(max_events=10), indent=2, default=str))
