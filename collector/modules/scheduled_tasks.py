"""
Collects scheduled task artifacts:
  Windows: Task Scheduler tasks via `schtasks /query`
  Linux:   systemd timers + per-user cron (overlaps slightly with
           persistence.py's cron collection — kept separate here since
           "scheduled task" and "persistence via cron" are conceptually
           distinct in the framework's ATT&CK mapping later)
"""
import csv
import io
import os
import platform
import subprocess

from .common import wrap_artifact


def collect_scheduled_tasks() -> list:
    if platform.system() == "Windows":
        return _collect_windows_tasks()
    return _collect_linux_timers()


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def _collect_windows_tasks() -> list:
    records = []
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        reader = csv.DictReader(io.StringIO(output))
        for row in reader:
            # schtasks /v repeats the header for each "page" on some Windows
            # versions — skip any row that's actually a re-emitted header
            if row.get("TaskName") == "TaskName":
                continue
            data = {
                "task_name": row.get("TaskName"),
                "status": row.get("Status"),
                "next_run_time": row.get("Next Run Time"),
                "task_to_run": row.get("Task To Run"),
                "run_as_user": row.get("Run As User"),
                "schedule": row.get("Schedule"),
            }
            records.append(wrap_artifact("scheduled_task", data))
    except subprocess.CalledProcessError as e:
        print(f"[!] schtasks query failed: {e}")
    return records


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

def _collect_linux_timers() -> list:
    records = []

    try:
        output = subprocess.check_output(
            ["systemctl", "list-timers", "--all"], text=True, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("NEXT") or "timers listed" in line:
                continue
            data = {"type": "systemd_timer", "raw": line}
            records.append(wrap_artifact("scheduled_task", data))
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    for spool_dir in ("/var/spool/cron/crontabs", "/var/spool/cron"):
        if not os.path.isdir(spool_dir):
            continue
        try:
            users = os.listdir(spool_dir)
        except (IOError, PermissionError):
            # /var/spool/cron/crontabs is drwx-wx--T root:crontab — a
            # non-root user cannot list it. Skip it rather than crash the
            # whole collection run (BUG-3).
            users = []
        for user in users:
            try:
                with open(os.path.join(spool_dir, user), "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            data = {"type": "cron", "user": user, "entry": line}
                            records.append(wrap_artifact("scheduled_task", data))
            except (IOError, PermissionError):
                continue

    return records


if __name__ == "__main__":
    import json
    print(json.dumps(collect_scheduled_tasks()[:5], indent=2, default=str))
