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
from services.detection_service import run_detection_job
from services.endpoint_service import mark_offline_stale
from services.intel_service import refresh_all_feeds as refresh_all_intel_feeds
from services.retention_service import run_retention
from services.stats_service import compute_all as compute_all_stats

logger = logging.getLogger("dfir.scheduler")

DETECTION_INTERVAL_SECONDS = int(os.getenv("DETECTION_INTERVAL_SECONDS", "30"))
OFFLINE_SWEEP_INTERVAL_SECONDS = int(os.getenv("OFFLINE_SWEEP_INTERVAL_SECONDS", "60"))
OFFLINE_STALE_AFTER_SECONDS = int(os.getenv("OFFLINE_STALE_AFTER_SECONDS", "900"))
INTEL_REFRESH_INTERVAL_SECONDS = int(os.getenv("INTEL_REFRESH_INTERVAL_SECONDS", "43200"))
RETENTION_SWEEP_INTERVAL_SECONDS = int(os.getenv("RETENTION_SWEEP_INTERVAL_SECONDS", "3600"))
STATS_INTERVAL_SECONDS = int(os.getenv("STATS_INTERVAL_SECONDS", "60"))

scheduler = BackgroundScheduler()


def _scheduled_detection_run():
    """The job body — opens its own DB session (can't reuse a request-scoped one)."""
    db = SessionLocal()
    try:
        result = run_detection_job(db, trigger="scheduled")
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


def _scheduled_offline_sweep():
    """M6: flips endpoints that stopped polling to offline (own DB session)."""
    db = SessionLocal()
    try:
        mark_offline_stale(db, stale_after_seconds=OFFLINE_STALE_AFTER_SECONDS)
    except Exception:
        logger.exception("Offline sweep failed")
    finally:
        db.close()


def _scheduled_intel_refresh():
    """F7: refreshes the intel feeds (Feodo/URLhaus/MalwareBazaar/OTX) into the
    iocs table + iocs/feodo_ips.txt. Fail-soft per feed, own DB session."""
    db = SessionLocal()
    try:
        summary = refresh_all_intel_feeds(db)
        total = summary["total_inserted"] + summary["total_updated"]
        if total:
            logger.info("Intel refresh: %d IOC(s) upserted (%d new, %d updated)", total,
                        summary["total_inserted"], summary["total_updated"])
        else:
            logger.warning("Intel refresh produced no update (offline or no new entries)")
    except Exception:
        logger.exception("Intel refresh failed")
    finally:
        db.close()


def _scheduled_retention_sweep():
    """F3: archives + deletes rows past their retention window (no-op when disabled)."""
    db = SessionLocal()
    try:
        summary = run_retention(db)
        total = sum(t["deleted"] for t in summary.values())
        if total:
            logger.info("Retention sweep: archived/deleted %d row(s)", total)
    except Exception:
        logger.exception("Retention sweep failed")
    finally:
        db.close()


def _scheduled_stats_compute():
    """F8: recomputes the materialized stats snapshots (own DB session)."""
    db = SessionLocal()
    try:
        result = compute_all_stats(db)
        logger.info(
            "Stats recompute done at %s (metrics=%s)",
            result["computed_at"],
            list(result["metrics"]),
        )
    except Exception:
        logger.exception("Stats recompute failed")
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
    scheduler.add_job(
        _scheduled_offline_sweep,
        trigger=IntervalTrigger(seconds=OFFLINE_SWEEP_INTERVAL_SECONDS),
        id="offline_sweep",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.add_job(
        _scheduled_intel_refresh,
        trigger=IntervalTrigger(seconds=INTEL_REFRESH_INTERVAL_SECONDS),
        id="intel_refresh",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.add_job(
        _scheduled_retention_sweep,
        trigger=IntervalTrigger(seconds=RETENTION_SWEEP_INTERVAL_SECONDS),
        id="retention_sweep",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.add_job(
        _scheduled_stats_compute,
        trigger=IntervalTrigger(seconds=STATS_INTERVAL_SECONDS),
        id="stats_compute",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Detection scheduler started — running every %s seconds", DETECTION_INTERVAL_SECONDS
    )


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
