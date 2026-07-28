"""
Collects running process metadata: PID, parent PID, name, executable path,
command line, owning user, and creation time. Cross-platform via psutil.
"""
import psutil

from .common import wrap_artifact


def collect_processes() -> list:
    records = []
    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
    ):
        try:
            info = proc.info
            data = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe": info.get("exe"),
                "cmdline": " ".join(info.get("cmdline") or []),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
            }
            records.append(wrap_artifact("process", data))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process exited mid-scan, or we don't have permission to inspect it
            # (common for system/other-user processes without admin/root) — skip it.
            continue
    return records


if __name__ == "__main__":
    # Quick standalone test: python -m modules.processes
    import json
    print(json.dumps(collect_processes()[:3], indent=2, default=str))
