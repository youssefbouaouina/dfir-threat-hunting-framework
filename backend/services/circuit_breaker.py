"""Generic circuit breaker (Phase 5 / F8).

Protects downstream dependencies (external intel feeds, notification
channels) from being hammered when they are down. States:

    closed    — normal operation; calls pass through, failures counted.
    open      — after `failure_threshold` consecutive failures the breaker
                trips; calls fail fast (CircuitOpenError) without reaching
                the dependency, letting it recover.
    half_open — after `reset_timeout_seconds` the breaker lets one probe
                call through; success closes it, failure re-opens it.

Thread-safe: feed refreshes and the scheduler run on worker threads, so the
counters are guarded by a lock.
"""
import logging
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class CircuitOpenError(RuntimeError):
    """Raised when a circuit is open and the call fails fast."""


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        reset_timeout_seconds: int = 60,
    ) -> None:
        self.name = name
        self.failure_threshold = max(1, int(failure_threshold))
        self.reset_timeout_seconds = max(0, int(reset_timeout_seconds))
        self._state = "closed"  # closed | open | half_open
        self._failure_count = 0
        self._opened_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    def status(self) -> dict:
        """Snapshot of breaker state for /iocs/status + operational dashboards."""
        with self._lock:
            return {
                "name": self.name,
                "state": self._state,
                "failure_count": self._failure_count,
                "opened_at": self._opened_at or None,
            }

    def call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Runs fn through the breaker. Raises CircuitOpenError when open."""
        with self._lock:
            if self._state == "open":
                if time.monotonic() - self._opened_at >= self.reset_timeout_seconds:
                    self._state = "half_open"
                else:
                    raise CircuitOpenError(f"circuit '{self.name}' is open")

        try:
            result = fn(*args, **kwargs)
        except Exception:
            self._record_failure()
            raise
        self._record_success()
        return result

    def _record_success(self) -> None:
        with self._lock:
            self._failure_count = 0
            if self._state == "half_open":
                logger.info("Circuit '%s' recovered (probe succeeded)", self.name)
            self._state = "closed"

    def _record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            if self._state == "half_open" or self._failure_count >= self.failure_threshold:
                self._state = "open"
                self._opened_at = time.monotonic()
                logger.warning(
                    "Circuit '%s' opened after %d consecutive failure(s)",
                    self.name,
                    self._failure_count,
                )

    def reset(self) -> None:
        """Manually closes the breaker (admin override, e.g. after fixing a feed)."""
        with self._lock:
            self._state = "closed"
            self._failure_count = 0
            self._opened_at = 0.0
