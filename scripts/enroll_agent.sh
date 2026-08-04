#!/usr/bin/env bash
# DFIR endpoint enrollment — one-shot collect + push, then daemon.
# Usage:  ./enroll_agent.sh <BACKEND_URL> [COLLECT_INTERVAL_SECONDS]
# Example: ./enroll_agent.sh http://192.168.56.1:8000 300
#
# Installs the collector's Python deps, enrolls this host with the backend,
# pushes one collection batch immediately, then runs as a daemon that
# collects + pushes every interval (default 300s).
set -euo pipefail

BACKEND_URL="${1:?usage: ./enroll_agent.sh <BACKEND_URL> [COLLECT_INTERVAL_SECONDS]}"
INTERVAL="${2:-300}"
COLLECTOR_DIR="$(cd "$(dirname "$0")/../collector" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 not found. Install it first (apt install python3 python3-pip python3-venv)." >&2
  exit 1
fi

echo "[*] Installing collector dependencies..."
python3 -m venv "$COLLECTOR_DIR/.venv" 2>/dev/null || true
"$COLLECTOR_DIR/.venv/bin/pip" install -q -r "$COLLECTOR_DIR/requirements.txt"

echo "[*] Enrolling with backend at $BACKEND_URL ..."
"$COLLECTOR_DIR/.venv/bin/python" "$COLLECTOR_DIR/collector_agent.py" \
  --api-url "$BACKEND_URL" --enroll

echo "[*] Starting daemon (collect + push every ${INTERVAL}s) ..."
"$COLLECTOR_DIR/.venv/bin/python" "$COLLECTOR_DIR/collector_agent.py" \
  --api-url "$BACKEND_URL" --daemon --interval "$INTERVAL"
