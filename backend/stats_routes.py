"""
Materialized stats routes (Phase 5 / F8).

Thin HTTP layer over stats_service: reads the precomputed aggregation
(GET /stats/summary) and forces a recompute (POST /stats/recompute, admin +
audited). The scheduler keeps the snapshots fresh on STATS_INTERVAL_SECONDS.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from security import current_user, require_admin
from services import stats_service
from services.audit_service import log_action

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/summary", dependencies=[Depends(require_admin)])
def stats_summary(
    metric: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Returns the cached materialized aggregation(s) for the dashboard.

    Cold-start recomputes on first use. Without `metric`, every snapshot is
    returned along with its computed_at timestamps.
    """
    if metric is None:
        return {"snapshots": stats_service.snapshot_status(db)}
    try:
        return {metric: stats_service.get_snapshot(db, metric)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/recompute", dependencies=[Depends(require_admin)])
def stats_recompute(
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Forces a recompute of every materialized metric now."""
    result = stats_service.compute_all(db)
    log_action(
        db,
        "stats_recompute",
        actor=user.get("subject") if user else "unknown",
        detail={"computed_at": result["computed_at"]},
    )
    return result
