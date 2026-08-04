"""
Background scheduler — automatically runs the detection pipeline on a
fixed interval instead of requiring a manual POST /detect call.

Design decisions worth knowing:
  - Detection is decoupled from ingest on purpose. Running detection
    synchronously inside /ingest would slow down every single ingest
    call, which gets painful once you have many endpoints reporting in
    concurrently (the whole point of the next project phase). A
    periodic sweep that picks up whatever's unprocessed is the pattern
    real EDR/SIEM backends actually use.
  - BackgroundScheduler (thread-based) is used rather than
    AsyncIOScheduler — our DB work is plain synchronous SQLAlchemy, so
    a plain thread-based scheduler is the simpler correct choice here.
  - max_instances=1 + coalesce=True prevents two detection cycles ever
    running concurrently, and prevents a pile-up of missed runs firing
    all at once if one cycle ever takes longer than the interval.
"""
import logging
import os

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from database import SessionLocal
from detection_routes import run_detection_job

logger = logging.getLogger("dfir.scheduler")

DETECTION_INTERVAL_SECONDS = int(os.getenv("DETECTION_INTERVAL_SECONDS", "60"))

scheduler = BackgroundScheduler()


def _scheduled_detection_run():
    """The job body — opens its own DB session (can't reuse a request-scoped one)."""
    db = SessionLocal()
    try:
        result = run_detection_job(db)
        if result["artifacts_scanned"] > 0:
            logger.info(
                "Scheduled detection run: %s artifact(s) scanned, %s detection(s) found",
                result["artifacts_scanned"],
                result["detections_found"],
            )
    except Exception:
        # A failed cycle should never crash the scheduler thread or the
        # app — log it and let the next scheduled run try again.
        logger.exception("Scheduled detection run failed")
    finally:
        db.close()


def start_scheduler():
    if scheduler.running:
        return
    scheduler.add_job(
        _scheduled_detection_run,
        trigger=IntervalTrigger(seconds=DETECTION_INTERVAL_SECONDS),
        id="detection_cycle",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Detection scheduler started — running every %s seconds", DETECTION_INTERVAL_SECONDS)


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Detection scheduler stopped")


def get_status() -> dict:
    job = scheduler.get_job("detection_cycle")
    return {
        "running": scheduler.running,
        "interval_seconds": DETECTION_INTERVAL_SECONDS,
        "next_run_time": str(job.next_run_time) if job else None,
    }
