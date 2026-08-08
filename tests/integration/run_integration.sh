#!/usr/bin/env bash
# DFIR endpoint lifecycle integration test.
#
# Assumes a running compose stack (backend + endpoint-manager) with the endpoint
# image available to the manager, and the backend reachable at $API_URL.
#
# Verifies the full real communication path:
#   create endpoint -> container created -> heartbeat -> scan (collector inside
#   container -> push -> /ingest) -> detect -> report -> stop -> restart -> recovery
#   -> delete (container removed).
set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:8000}"
EP_NAME="linux-test-$(date +%s)"

say() { echo ""; echo "[integration] $1"; }

say "waiting for backend at ${API_URL}/health ..."
for i in $(seq 1 60); do
  if curl -fsS "${API_URL}/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS "${API_URL}/health" >/dev/null || { echo "FAIL: backend never became healthy"; exit 1; }

say "creating container endpoint '${EP_NAME}'"
CREATE="$(curl -fsS -X POST "${API_URL}/endpoints" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"${EP_NAME}\",\"os\":\"linux\",\"backend_type\":\"container\"}")"
echo "${CREATE}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('id'), d; print('  registered id =', d['id'])"
EP_ID="$(echo "${CREATE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")"

say "waiting for heartbeat (endpoint image pushes /ingest on boot) ..."
HEARTBEAT=""
for i in $(seq 1 90); do
  EP="$(curl -fsS "${API_URL}/endpoints/${EP_ID}")"
  HEARTBEAT="$(echo "${EP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('last_heartbeat') or '')")"
  [ -n "${HEARTBEAT}" ] && break
  sleep 2
done
[ -n "${HEARTBEAT}" ] || { echo "FAIL: no heartbeat received"; curl -fsS "${API_URL}/endpoints/${EP_ID}"; exit 1; }
say "heartbeat OK: ${HEARTBEAT}"

say "scanning endpoint (run-now -> docker exec collector -> push -> detect -> report)"
SCAN="$(curl -fsS -X POST "${API_URL}/endpoints/${EP_ID}/run-now")"
echo "${SCAN}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['scan']['success'], d; print('  scan OK, exit_status =', d['scan'].get('exit_status'))"

say "verifying artifacts were ingested"
COUNT="$(curl -fsS "${API_URL}/artifacts?host=${EP_NAME}&limit=500" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")"
[ "${COUNT}" -gt 0 ] || { echo "FAIL: no artifacts for ${EP_NAME}"; exit 1; }
say "artifacts OK: ${COUNT}"

say "verifying detections and report exist"
DETS="$(curl -fsS "${API_URL}/detections?host=${EP_NAME}" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")"
say "detections for endpoint: ${DETS}"
curl -fsS "${API_URL}/reports" | python3 -c "import sys,json; assert len(json.load(sys.stdin)) > 0, 'no reports'; print('  report history OK')"

say "stopping endpoint (container)"
curl -fsS -X POST "${API_URL}/endpoints/${EP_ID}/stop" >/dev/null
sleep 3
STATUS="$(curl -fsS "${API_URL}/endpoints/${EP_ID}" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")"
[ "${STATUS}" = "offline" ] || { echo "FAIL: expected offline after stop, got ${STATUS}"; exit 1; }
say "stopped OK"

say "restarting endpoint and verifying recovery"
curl -fsS -X POST "${API_URL}/endpoints/${EP_ID}/restart" >/dev/null
RECOVER=""
for i in $(seq 1 60); do
  EP="$(curl -fsS "${API_URL}/endpoints/${EP_ID}")"
  RECOVER="$(echo "${EP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status') or '')")"
  [ "${RECOVER}" = "online" ] && break
  sleep 2
done
[ "${RECOVER}" = "online" ] || { echo "FAIL: endpoint did not recover"; curl -fsS "${API_URL}/endpoints/${EP_ID}"; exit 1; }
say "recovery OK"

say "deleting endpoint (and its container)"
curl -fsS -X DELETE "${API_URL}/endpoints/${EP_ID}?remove_container=true" >/dev/null
curl -fsS "${API_URL}/endpoints/${EP_ID}" >/dev/null 2>&1 && { echo "FAIL: endpoint still present"; exit 1; }
say "delete OK"

echo ""
echo "[integration] ALL PASSED"
