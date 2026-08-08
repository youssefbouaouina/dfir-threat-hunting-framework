#!/usr/bin/env bash
# Fetch the MITRE ATT&CK Enterprise bundle used by the backend's
# ATT&CK enrichment layer (backend/attck_mapper.py).
#
# The full MITRE CTI repo (dfir-refs/) is ~442MB / 43k files and is intentionally
# NOT committed to git. Instead, only the single enterprise-attack.json bundle
# that the backend reads is downloaded, to the exact path docker-compose.yml
# mounts read-only into the backend container:
#
#   ./dfir-refs/cti/enterprise-attack:/dfir/stix:ro
#
# This is the same source/command used by the CI workflow
# (.github/workflows/ci-cd.yml -> "Fetch MITRE ATT&CK STIX bundle"), so local
# and CI setups always agree.
#
# Usage:
#     bash scripts/fetch-stix.sh            # download once
#     bash scripts/fetch-stix.sh --force    # force a re-download
#
# Idempotent: if the bundle already exists it is left untouched.
set -euo pipefail

URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DEST_DIR="dfir-refs/cti/enterprise-attack"
DEST="${DEST_DIR}/enterprise-attack.json"

FORCE="${1:-}"

if [ "${FORCE}" != "--force" ] && [ -s "${DEST}" ]; then
    echo "[fetch-stix] ${DEST} already present ('--force' to re-download)."
    exit 0
fi

mkdir -p "${DEST_DIR}"
TMP="${DEST}.tmp.$$"
trap 'rm -f "${TMP}"' EXIT

echo "[fetch-stix] downloading MITRE ATT&CK enterprise bundle..."
if command -v curl >/dev/null 2>&1; then
    curl -fSL --retry 3 --retry-delay 2 -o "${TMP}" "${URL}"
elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 -O "${TMP}" "${URL}"
else
    echo "ERROR: neither curl nor wget is available." >&2
    exit 1
fi

if [ ! -s "${TMP}" ]; then
    echo "ERROR: download produced an empty file. Check network / URL, and retry." >&2
    exit 1
fi

mv "${TMP}" "${DEST}"
echo "OK: ${DEST}"
ls -lh "${DEST}"