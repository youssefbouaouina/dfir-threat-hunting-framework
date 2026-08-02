"""Structured JSON logging for the DFIR backend (Phase 3 ops hardening).

When LOG_FORMAT=json, the root logger emits single-line JSON records that are
easy to ship to a log aggregator (filebeat, Splunk, etc.). Default is the
standard human-readable format so local development stays readable.

Usage: call configure_logging() once at app import.
"""
import json
import logging
import os
import sys
import time


class JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter — no third-party dependency."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key in ("task_id", "endpoint", "host", "status"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload)


def configure_logging() -> None:
    """Configures the root logger based on LOG_FORMAT (default: human-readable)."""
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = os.getenv("LOG_FORMAT", "plain").lower()

    root = logging.getLogger()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
    root.handlers = [handler]
