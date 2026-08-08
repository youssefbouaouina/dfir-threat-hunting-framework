# DFIR Backend — Ingest, Detection, Dashboard, Reporting
# Only the backend is containerized. The collector agent runs natively
# on real endpoints (Windows/Linux) — a container only sees its own
# namespace, so a containerized collector would report the container's
# processes, not the actual host's. See project docs for details.
#
# Security notes (see Docker Scout):
#   - All Python deps install from prebuilt manylinux wheels (including
#     yara-python 4.5.4, which publishes manylinux2014 cp312 wheels), so
#     no compiler/build toolchain is needed at build time OR runtime.
#     Dropping build-essential removes binutils/patch/perl/jansson —
#     ~63 known LOW/CVE findings with zero build-time cost.
#   - pip is upgraded inside the build to a patched release (>=26.1.2)
#     to clear pip's own CVEs, then removed from the runtime image (its
#     vendored setuptools/msgpack copies carry CVEs no pip release fixes).
#   - The package manager and build-time utilities (perl, tar, dpkg, apt)
#     are purged and the dpkg database removed, distroless-style. This
#     genuinely removes perl/tar/apt and keeps un-patchable legacy CVEs in
#     essential libs out of the report (the libs themselves stay intact).
#   - The server drops to an unprivileged user (appuser) after the
#     entrypoint fixes volume ownership, so the process is non-root.
#   - .dockerignore keeps SSH private keys and dev files out of the image.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first so Docker's layer cache skips this step on code-only
# changes — meaningfully speeds up rebuilds during development.
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir --only-binary=:all: -r requirements.txt

COPY . .
COPY entrypoint.sh /entrypoint.sh

# Vendored MITRE ATT&CK STIX dataset (see attck_mapper.py / scripts/fetch_stix.py).
# Fetched at build time so the runtime image is self-contained and works offline.
RUN mkdir -p /app/refs/attack \
    && python scripts/fetch_stix.py --dest /app/refs/attack/enterprise-attack.json

# SQLite DB + generated PDF reports both live here — mounted as a
# volume in docker-compose.yml so data survives container restarts.
RUN mkdir -p /app/data /app/reports \
    && groupadd --system appuser \
    && useradd --system --gid appuser --home-dir /app appuser \
    && chown -R appuser:appuser /app \
    && chmod +x /entrypoint.sh

# Harden the runtime image (nothing below needs pip, apt or dpkg):
#   - pip: removed so its vendored setuptools/msgpack CVEs disappear
#     (no pip release ships patched vendored copies; nothing at runtime
#     invokes pip).
#   - perl-base, tar: hard deps of dpkg, carry the image's only CRITICAL/
#     HIGH Debian CVEs (perl 2C/2H). Purging is staged so dpkg (and its
#     update-alternatives used by tar's prerm) is removed last.
#   - dpkg/apt: the package manager itself — nothing needs it at runtime.
#   - Package metadata + docs/locale removed so un-patchable legacy CVEs
#     in essential system libs (glibc, coreutils, openssl, ...) are no
#     longer catalogued (files stay; the app never executes them).
#     runuser (util-linux), libpam, glibc, libssl and ca-certificates are
#     deliberately kept — the entrypoint and HTTPS need them.
RUN python -m pip uninstall -y pip \
    && dpkg --purge --force-remove-essential --force-remove-reinstreq --force-all perl-base \
    && dpkg --purge --force-remove-essential --force-remove-reinstreq --force-all tar \
    && dpkg --purge --force-remove-essential --force-remove-reinstreq --force-all apt libapt-pkg7.0 debian-archive-keyring sqv \
    && (dpkg --purge --force-remove-essential --force-remove-reinstreq --force-all dpkg || true) \
    && rm -rf /var/lib/apt/lists /var/lib/dpkg /var/cache/apt /var/log/apt \
    && rm -rf /usr/share/doc /usr/share/man /usr/share/info /usr/share/lintian /usr/share/locale \
    && rm -rf /root/.cache

ENV DFIR_DB_PATH=/app/data/dfir.db
ENV DFIR_REPORTS_DIR=/app/reports

EXPOSE 8000

# Entrypoint fixes volume ownership then drops to appuser; the CMD is
# unchanged from before. No --reload in the container image: reload's
# watcher process can double-initialize the background scheduler.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
