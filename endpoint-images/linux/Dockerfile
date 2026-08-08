# DFIR Linux endpoint simulation image.
#
# The container IS the simulated host: the collector (running inside) sees this
# container's processes/filesystem/network and pushes them to the backend.
#
# SECURITY: this image must be run WITHOUT --privileged, WITHOUT capability adds,
# WITHOUT host mounts/network/PID — the endpoint-manager enforces that. No systemd
# by design: running systemd reliably in Docker requires SYS_ADMIN + cgroup mounts,
# which would hand a possibly-compromised test endpoint escape capabilities.
# systemctl/journalctl sources are intentionally absent (the collector modules
# already skip them gracefully); persistence data is pre-seeded below so the
# persistence/scheduled_task modules report realistic test data.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Collector deps (yara-python ships manylinux wheels for x86_64).
COPY collector/requirements.txt /opt/collector/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: -r /opt/collector/requirements.txt \
    && python -m pip install --no-cache-dir --only-binary=:all: yara-python==4.5.4

COPY collector/ /opt/collector/
COPY backend/yara_rules/ /opt/collector/yara_rules/

# Pre-seed persistence artifacts so the persistence/scheduled_tasks modules report
# realistic data even though no cron/systemd daemon runs in this container.
RUN mkdir -p /etc/cron.d /var/spool/cron/crontabs /var/cache/dfir \
    && printf '%s\n' \
       '# /etc/crontab: system-wide crontab' \
       '17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly' \
       '25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )' \
       '47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )' \
       '*/15 *  * * *   root    /usr/local/bin/dfir_heartbeat_check.sh' \
       > /etc/crontab \
    && printf '%s\n' \
       'SHELL=/bin/bash' \
       'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin' \
       '0 2 * * * root /opt/collector/collector_agent.py --only persistence,logs --push-url "http://backend:8000"' \
       > /etc/cron.d/dfir-test \
    && printf '%s\n' \
       '# dfir test persistence (seeded)' \
       '@reboot root /usr/local/bin/dfir_heartbeat_check.sh' \
       '0 4 * * *  root  /opt/dfir/scheduled_cleanup.sh' \
       '30 3 * * *  root  /opt/dfir/logrotate_daily.sh' \
       > /var/spool/cron/crontabs/root \
    && printf '%s\n' \
       '#!/bin/sh' \
       '# seeded dfir test rc.local' \
       'echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true' \
       'exit 0' \
       > /etc/rc.local \
    && chmod +x /etc/rc.local

COPY endpoint-images/linux/entrypoint.sh /usr/local/bin/dfir_entrypoint.sh
COPY endpoint-images/linux/heartbeat.py /opt/collector/heartbeat.py
RUN chmod +x /usr/local/bin/dfir_entrypoint.sh

ENV ENDPOINT_PUSH_URL="http://backend:8000" \
    ENDPOINT_COLLECT_INTERVAL="300"

CMD ["/usr/local/bin/dfir_entrypoint.sh"]
