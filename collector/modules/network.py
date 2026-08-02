"""
Collects active network connections (TCP/UDP, local/remote address, status,
owning PID). Cross-platform via psutil.

NOTE: On Windows, psutil.net_connections() typically needs an elevated
(Administrator) process to see connections belonging to other users.
On Linux, run as root (or via sudo) for full visibility.
"""
import psutil

from .common import wrap_artifact


def collect_network() -> list:
    records = []
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print(
            "[!] Access denied listing all connections — "
            "re-run elevated/root for full visibility"
        )
        connections = []

    for conn in connections:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
        data = {
            "fd": conn.fd,
            "family": str(conn.family),
            "type": str(conn.type),
            "local_address": laddr,
            "remote_address": raddr,
            "status": conn.status,
            "pid": conn.pid,
        }
        records.append(wrap_artifact("network", data))
    return records


if __name__ == "__main__":
    import json
    print(json.dumps(collect_network()[:3], indent=2, default=str))
