"""
Endpoint orchestrator — the backend actively reaches out to registered
endpoints instead of waiting for them to push data.

Uses SSH (via paramiko) as the single transport for BOTH Windows and
Linux endpoints. This is a deliberate simplification: Windows 10/11 has
had a built-in OpenSSH Server optional feature since 2018, so rather
than maintaining two separate remote-execution code paths (SSH for
Linux, WinRM for Windows), one endpoint enables OpenSSH Server and the
exact same orchestration code drives both. Less code, less to test,
less to explain in a defense.

Two operations:
  - check_liveness(endpoint): fast TCP-level reachability check
  - run_remote_scan(endpoint): SSH in, run the collector with
    --push-url pointing back at this backend, so the endpoint pushes
    its own results directly — no file copying, no sample_data/ relay.
"""
import logging
import socket
import time

import paramiko

logger = logging.getLogger("dfir.orchestrator")

LIVENESS_TIMEOUT_SECONDS = 3
SCAN_TIMEOUT_SECONDS = 120


def check_liveness(ip_address: str, port: int) -> tuple[bool, float | None]:
    """Fast TCP-level check — 'can we even reach the SSH port', not a full login.
    Returns (is_online, latency_ms)."""
    start = time.monotonic()
    try:
        with socket.create_connection((ip_address, port), timeout=LIVENESS_TIMEOUT_SECONDS):
            latency_ms = round((time.monotonic() - start) * 1000, 1)
            return True, latency_ms
    except (TimeoutError, OSError):
        return False, None


def run_remote_scan(
    ip_address: str,
    port: int,
    username: str,
    key_path: str,
    remote_collector_path: str,
    push_url: str,
    os_type: str = "linux",
) -> dict:
    """
    SSHes into the endpoint and runs its collector, pointed back at
    this backend's own ingest API via --push-url. Returns a dict with
    success/failure and captured output for logging/debugging.

    os_type controls the command syntax: Linux/macOS use `python3` and
    forward-slash paths; Windows (with OpenSSH Server enabled — a
    built-in optional feature since Windows 10 1809) gets an SSH
    session that runs `cmd.exe` by default, so the command uses `python`
    and Windows path/chaining syntax instead.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip_address,
            port=port,
            username=username,
            key_filename=key_path,
            timeout=LIVENESS_TIMEOUT_SECONDS,
        )
    except (paramiko.SSHException, OSError) as e:
        logger.warning("SSH connection to %s failed: %s", ip_address, e)
        return {"success": False, "error": f"connection failed: {e}"}

    if os_type == "windows":
        # OpenSSH Server on Windows defaults to a cmd.exe session
        command = f'cd /d "{remote_collector_path}" && python collector_agent.py --push-url {push_url}'
    else:
        command = f"cd {remote_collector_path} && python3 collector_agent.py --push-url {push_url}"

    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=SCAN_TIMEOUT_SECONDS)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        return {
            "success": exit_status == 0,
            "exit_status": exit_status,
            "stdout": out[-4000:],  # cap captured output, this is for logging not full audit
            "stderr": err[-2000:],
        }
    except (TimeoutError, paramiko.SSHException) as e:
        return {"success": False, "error": f"command execution failed: {e}"}
    finally:
        client.close()


if __name__ == "__main__":
    # Manual test against the local test sshd set up alongside this file.
    online, latency = check_liveness("127.0.0.1", 2222)
    print(f"Liveness: online={online}, latency={latency}ms")

    result = run_remote_scan(
        ip_address="127.0.0.1",
        port=2222,
        username="root",
        key_path="/root/.ssh/dfir_orchestrator_key",
        remote_collector_path="/tmp",
        push_url="http://127.0.0.1:9999",  # deliberately unreachable, testing the SSH leg only
    )
    print("Remote scan result:", result)
