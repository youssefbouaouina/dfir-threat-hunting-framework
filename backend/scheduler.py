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
from datetime import UTC, datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from database import SessionLocal
from detection_routes import run_detection_job

logger = logging.getLogger("dfir.scheduler")

DETECTION_INTERVAL_SECONDS = int(os.getenv("DETECTION_INTERVAL_SECONDS", "60"))
LIVENESS_INTERVAL_SECONDS = int(os.getenv("LIVENESS_INTERVAL_SECONDS", "60"))
ORCHESTRATION_INTERVAL_SECONDS = int(os.getenv("ORCHESTRATION_INTERVAL_SECONDS", "3600"))
BACKEND_PUSH_URL = os.getenv("BACKEND_PUSH_URL", "http://192.168.50.1:8000")

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


def _liveness_sweep():
    """Fast, frequent check — container endpoints query Docker state via the
    endpoint-manager; VM endpoints check 'is the SSH port reachable'. Updates
    each endpoint's status so the dashboard's online/offline badges stay current
    without the page load itself doing any blocking network calls."""
    import models
    from container_manager_client import EndpointManagerError, container_status
    from endpoint_orchestrator import check_liveness

    db = SessionLocal()
    try:
        endpoints = db.query(models.Endpoint).filter(models.Endpoint.enabled == 1).all()
        for ep in endpoints:
            if ep.backend_type == "container":
                try:
                    state = container_status(ep.container_name)
                    online = state.get("running", False)
                except EndpointManagerError:
                    online = False
                ep.status = "online" if online else "offline"
            else:
                online, _latency = check_liveness(ep.ip_address, ep.ssh_port)
                ep.status = "online" if online else "offline"
            ep.last_checked_at = datetime.now(UTC)
        db.commit()
        if endpoints:
            logger.info("Liveness sweep: checked %s endpoint(s)", len(endpoints))
    except Exception:
        logger.exception("Liveness sweep failed")
    finally:
        db.close()


def _hourly_orchestration_cycle():
    """The big automatic cycle: for every enabled, currently-online endpoint,
    run the collector (which pushes its own results) — container endpoints via
    docker exec, VM endpoints via SSH — then detect and report."""
    import models
    from container_manager_client import EndpointManagerError, exec_collector
    from endpoint_orchestrator import run_remote_scan
    from reports import generate_report

    db = SessionLocal()
    try:
        endpoints = db.query(models.Endpoint).filter(
            models.Endpoint.enabled == 1, models.Endpoint.status == "online"
        ).all()
        logger.info("Orchestration cycle starting for %s online endpoint(s)", len(endpoints))

        for ep in endpoints:
            if ep.backend_type == "container":
                try:
                    result = exec_collector(
                        ep.container_name,
                        push_url=os.getenv("ENDPOINT_PUSH_URL", "http://backend:8000"),
                    )
                    result["success"] = bool(result.get("success", True))
                except EndpointManagerError as e:
                    result = {"success": False, "error": str(e)}
            else:
                result = run_remote_scan(
                    ip_address=ep.ip_address,
                    port=ep.ssh_port,
                    username=ep.ssh_username,
                    key_path=ep.ssh_key_path,
                    remote_collector_path=ep.remote_collector_path,
                    push_url=BACKEND_PUSH_URL,
                    os_type=ep.os,
                )
            if result["success"]:
                ep.last_scan_at = datetime.now(UTC)
                db.commit()
                run_detection_job(db)
                generate_report(db, host=ep.name, triggered_by="scheduled")
                logger.info("Orchestration cycle: %s scanned + reported OK", ep.name)
            else:
                logger.warning("Orchestration cycle: %s scan failed — %s", ep.name, result.get("error"))
    except Exception:
        logger.exception("Orchestration cycle failed")
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
        _liveness_sweep,
        trigger=IntervalTrigger(seconds=LIVENESS_INTERVAL_SECONDS),
        id="liveness_cycle",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.add_job(
        _hourly_orchestration_cycle,
        trigger=IntervalTrigger(seconds=ORCHESTRATION_INTERVAL_SECONDS),
        id="orchestration_cycle",
        max_instances=1,
        coalesce=True,
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler started — detection every %ss, liveness every %ss, orchestration every %ss",
        DETECTION_INTERVAL_SECONDS, LIVENESS_INTERVAL_SECONDS, ORCHESTRATION_INTERVAL_SECONDS,
    )


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")


def get_status() -> dict:
    detection_job = scheduler.get_job("detection_cycle")
    orchestration_job = scheduler.get_job("orchestration_cycle")
    return {
        "running": scheduler.running,
        "detection_interval_seconds": DETECTION_INTERVAL_SECONDS,
        "liveness_interval_seconds": LIVENESS_INTERVAL_SECONDS,
        "orchestration_interval_seconds": ORCHESTRATION_INTERVAL_SECONDS,
        "detection_next_run": str(detection_job.next_run_time) if detection_job else None,
        "orchestration_next_run": str(orchestration_job.next_run_time) if orchestration_job else None,
    }
