"""Alerting hooks (Phase 4 / F5): webhook + email notifications.

Notifies on the two things analysts care about most:
  * new high/critical detections (from the detection pipeline), and
  * endpoints that transitioned offline (from the offline sweep).

Both channels are opt-in via env vars and both are strictly fail-soft — an
unreachable webhook or a bad SMTP config must never fail the detection run or
the sweep that triggered the alert. Notification config is read from the
environment at call time so tests and dev instances can flip it cheaply.
"""
import json
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Iterable, List

import requests

logger = logging.getLogger("dfir.notification_service")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def notifications_enabled() -> bool:
    """True when at least one notification channel is configured."""
    return bool(os.getenv("NOTIFY_WEBHOOK_URL")) or _smtp_configured()


def min_severity_rank() -> int:
    """Rank threshold above which detections trigger alerts (default: high)."""
    level = os.getenv("NOTIFY_MIN_SEVERITY", "high").lower()
    return _SEVERITY_RANK.get(level, _SEVERITY_RANK["high"])


def _smtp_configured() -> bool:
    return bool(os.getenv("NOTIFY_SMTP_HOST") and os.getenv("NOTIFY_EMAIL_TO"))


def _webhook_payload(
    kind: str, title: str, severity: str, detail: dict
) -> dict:
    return {
        "event": f"dfir.{kind}",
        "severity": severity,
        "title": title,
        "detail": detail,
    }


def _send_webhook(payload: dict) -> bool:
    url = os.getenv("NOTIFY_WEBHOOK_URL")
    if not url:
        return False
    secret = os.getenv("NOTIFY_WEBHOOK_SECRET")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-DFIR-Signature"] = secret
    try:
        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=5)
        resp.raise_for_status()
        return True
    except Exception:  # noqa: BLE001 — alerts must never break the caller
        logger.warning("Webhook notification to %s failed", url, exc_info=True)
        return False


def _send_email(subject: str, body: str) -> bool:
    if not _smtp_configured():
        return False
    host = os.getenv("NOTIFY_SMTP_HOST", "")
    port = int(os.getenv("NOTIFY_SMTP_PORT", "587"))
    user = os.getenv("NOTIFY_SMTP_USER")
    password = os.getenv("NOTIFY_SMTP_PASSWORD")
    from_addr = os.getenv("NOTIFY_EMAIL_FROM", user or "dfir@localhost")
    to_addrs = [a.strip() for a in os.getenv("NOTIFY_EMAIL_TO", "").split(",") if a.strip()]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            if user and password:
                server.starttls()
                server.ehlo()
                server.login(user, password)
            server.send_message(msg)
        return True
    except Exception:  # noqa: BLE001 — alerts must never break the caller
        logger.warning("Email notification to %s failed", host, exc_info=True)
        return False


def notify_detections(detections: List[dict]) -> None:
    """Sends alerts for detections at or above NOTIFY_MIN_SEVERITY.

    `detections` is a list of detection dicts (as produced by the detection
    pipeline, before persistence is required). Each qualifying detection fires
    independently so the webhook/email carries a single actionable item.
    """
    if not notifications_enabled():
        return
    threshold = min_severity_rank()
    for d in detections:
        severity = str(d.get("severity") or "unknown").lower()
        if _SEVERITY_RANK.get(severity, 0) < threshold:
            continue
        title = (
            f"[{severity.upper()}] {d.get('rule_title') or d.get('rule_id', '')} "
            f"on {d.get('host')}"
        )
        detail = {
            "host": d.get("host"),
            "rule_id": d.get("rule_id"),
            "technique_id": d.get("technique_id"),
            "artifact_type": d.get("artifact_type"),
        }
        _send_webhook(_webhook_payload("detection", title, severity, detail))
        _send_email(title, json.dumps(detail, indent=2))


def notify_endpoint_offline(hostnames: Iterable[str]) -> None:
    """Alerts that one or more endpoints went offline (missing heartbeat)."""
    hosts = list(hostnames)
    if not hosts or not notifications_enabled():
        return
    title = f"{len(hosts)} endpoint(s) went offline: {', '.join(hosts)}"
    detail = {"hostnames": hosts}
    _send_webhook(_webhook_payload("endpoint_offline", title, "high", detail))
    _send_email(title, json.dumps(detail, indent=2))
