#!/bin/sh
set -e

# Ensure the SQLite DB + reports directories are writable by the app.
# Running as root here only to fix ownership, then we drop privileges
# to the unprivileged appuser for the actual server process. This keeps
# the image secure AND works with volumes created by older root-running
# images of this same project (their files are root-owned).
if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /app/data /app/reports
    exec runuser -u appuser -- "$@"
fi

exec "$@"
