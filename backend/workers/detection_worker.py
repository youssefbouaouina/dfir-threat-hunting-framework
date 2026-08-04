"""
Queue-driven detection worker (Phase 4 / F5).

Consumes unprocessed artifacts on a fixed cadence and runs them through the
same `run_detection_job` pipeline the scheduler and the manual POST /detect
route use — one implementation, three trigger paths. This worker is the
"detection worker consumes unprocessed artifacts via a scheduled sweep" item
from the roadmap: the API stays responsive and detection cadence is decoupled
from request handling.

Run with the same DATABASE_URL as the API:

    DATABASE_URL=postgresql+psycopg2://dfir:dfir@db:5432/dfir \
    python -m workers.detection_worker

The loop is crash-tolerant: a failed cycle is logged and the next sweep tries
again; a KeyboardInterrupt stops cleanly.
"""
import logging
import time
from typing import Optional

from database import SessionLocal
from logging_config import configure_logging
from services.detection_service import run_detection_job

logger = logging.getLogger("dfir.detection_worker")

DEFAULT_INTERVAL_SECONDS = 30.0


def run_one_sweep(db=None) -> Optional[dict]:
    """Runs one detection cycle over all unprocessed artifacts.

    Exposed as a module-level function so unit tests can drive it with a
    session-scoped DB without running the blocking loop. Returns the run
    summary, or None when there was nothing to analyze.
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        result = run_detection_job(db, trigger="worker")
        if not result or result["artifacts_scanned"] == 0:
            return None
        return result
    finally:
        if own_session:
            db.close()


def run_loop(interval_seconds: float = DEFAULT_INTERVAL_SECONDS) -> None:
    """Blocks forever sweeping the detection pipeline on a fixed cadence."""
    configure_logging()
    logger.info(
        "Detection worker started (sweep every %ss)",
        interval_seconds,
    )
    while True:
        try:
            result = run_one_sweep()
            if result:
                logger.info(
                    "Detection sweep: %s artifact(s) scanned, %s detection(s) found",
                    result["artifacts_scanned"],
                    result["detections_found"],
                )
            time.sleep(interval_seconds)
        except KeyboardInterrupt:
            logger.info("Detection worker stopped by signal")
            break


if __name__ == "__main__":
    run_loop()
