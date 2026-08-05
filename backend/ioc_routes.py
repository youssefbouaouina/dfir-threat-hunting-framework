"""
IOC feed management routes (Phase 5 / F7).

Exposes the automated intel-feed pipeline: listing the persisted indicators,
viewing refresh status, triggering a manual refresh (admin-only, audited),
and exporting the set as a STIX 2.1 bundle. The TAXII 2.1 server surface
lives in taxii_routes.py.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from security import current_user, require_admin
from services import intel_service
from services.audit_service import log_action

router = APIRouter(prefix="/iocs", tags=["iocs"])


@router.get("", dependencies=[Depends(require_admin)])
def list_iocs(
    ioc_type: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    active: Optional[int] = Query(default=None, ge=0, le=1),
    limit: int = Query(default=100, ge=1, le=500),
    before_id: Optional[int] = Query(
        default=None, gt=0, description="cursor: only ids < before_id"
    ),
    db: Session = Depends(get_db),
):
    """Lists persisted IOCs, newest first, filterable by type/source/active."""
    return intel_service.list_iocs(
        db,
        ioc_type=ioc_type,
        source=source,
        active=active,
        limit=limit,
        before_id=before_id,
    )


@router.get("/status", dependencies=[Depends(require_admin)])
def ioc_status(db: Session = Depends(get_db)):
    """Aggregated IOC counts by source/type + active total + feed circuit states."""
    return intel_service.ioc_status(db)


@router.post("/breakers/reset", dependencies=[Depends(require_admin)])
def reset_breaker(
    feed: str = Query(description="feed name (feodo|urlhaus|malwarebazaar|otx)"),
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Manually closes a tripped feed circuit breaker (after fixing the upstream)."""
    if not intel_service.reset_breaker(feed):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown feed '{feed}' — must be one of "
                f"{list(intel_service.ALL_FEEDS)}"
            ),
        )
    log_action(
        db,
        "ioc_breaker_reset",
        actor=user.get("subject") if user else "unknown",
        detail={"feed": feed},
    )
    return {"feed": feed, "state": "closed"}


@router.post("/refresh", dependencies=[Depends(require_admin)])
def ioc_refresh(
    feeds: Optional[str] = Query(default=None, description="comma-separated feed subset"),
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Fetches + upserts the intel feeds now (default: all configured feeds).

    Fail-soft per feed: a dead feed records an error instead of failing the
    request. Succeeds (with empty fetched counts) when a feed needs a key
    that is not configured, so a keyless instance stays usable.
    """
    feed_list = None
    if feeds:
        feed_list = tuple(f.strip() for f in feeds.split(",") if f.strip())
        unknown = [f for f in feed_list if f not in intel_service.ALL_FEEDS]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unknown feed(s) {unknown} — must be one of "
                    f"{list(intel_service.ALL_FEEDS)}"
                ),
            )
    summary = intel_service.refresh_all_feeds(db, feeds=feed_list)
    log_action(
        db,
        "ioc_refresh",
        actor=user.get("subject") if user else "unknown",
        detail={"feeds": {k: v for k, v in summary["feeds"].items()}},
    )
    return summary


@router.get("/export/stix", dependencies=[Depends(require_admin)])
def export_stix(
    ioc_type: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Exports the active IOC set as a STIX 2.1 bundle (spec_version '2.1')."""
    iocs = intel_service.list_iocs(db, ioc_type=ioc_type, source=source, limit=500)
    return intel_service.export_stix_bundle(iocs)
