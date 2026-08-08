#!/bin/sh
# DFIR endpoint entrypoint — waits for the backend, sends a heartbeat, runs an
# initial collection, then loops on an interval. On-demand scans are triggered
# separately by the endpoint-manager via `docker exec`.
set -e

PUSH_URL="${ENDPOINT_PUSH_URL:-http://backend:8000}"
INTERVAL="${ENDPOINT_COLLECT_INTERVAL:-300}"
RULES_DIR="${YARA_RULES_DIR:-/opt/collector/yara_rules}"

echo "[dfir-endpoint] waiting for backend at ${PUSH_URL}/health ..."
i=0
until python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('${PUSH_URL}/health', timeout=3).status == 200 else 1)" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        echo "[dfir-endpoint] backend not reachable after ~120s; continuing anyway"
        break
    fi
    sleep 2
done

python /opt/collector/heartbeat.py "${PUSH_URL}" || echo "[dfir-endpoint] heartbeat push failed (non-fatal)"

echo "[dfir-endpoint] running initial collection"
python /opt/collector/collector_agent.py --push-url "${PUSH_URL}" --yara-rules "${RULES_DIR}"

echo "[dfir-endpoint] entering heartbeat/collection loop (every ${INTERVAL}s)"
while true; do
    sleep "${INTERVAL}"
    python /opt/collector/heartbeat.py "${PUSH_URL}" || true
    python /opt/collector/collector_agent.py --push-url "${PUSH_URL}" --yara-rules "${RULES_DIR}" \
        || echo "[dfir-endpoint] collection run failed (will retry next interval)"
done
