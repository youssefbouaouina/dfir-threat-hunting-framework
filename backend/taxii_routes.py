"""
Minimal TAXII 2.1 server surface (Phase 5 / F7).

Implements the read-only subset of TAXII 2.1 that lets external platforms
(SIEMs, threat-intel platforms) consume the framework's IOC set over the
standard protocol:

    GET /taxii/                            -> discovery document
    GET /taxii/api/                        -> API root information
    GET /taxii/api/collections/            -> collection listing
    GET /taxii/api/collections/{id}/objects/ -> STIX 2.1 objects (indicators)

All endpoints are read-only (can_write=False). Discovery/root/collection
envelopes are generated in intel_service.taxii_* and the objects payload is
the STIX 2.1 bundle built from the persisted iocs table.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from database import get_db
from security import require_admin
from services import intel_service

router = APIRouter(prefix="/taxii", tags=["taxii"])

_TAXII_COLLECTION_ID = intel_service._TAXII_COLLECTION_ID


def _host(request: Request) -> str:
    return str(request.base_url).rstrip("/")


@router.get("", dependencies=[Depends(require_admin)])
def discovery(request: Request):
    return intel_service.taxii_discovery(host=_host(request))


@router.get("/api", dependencies=[Depends(require_admin)])
def api_root_info(request: Request):
    return intel_service.taxii_api_root(host=_host(request))


@router.get("/api/collections", dependencies=[Depends(require_admin)])
def collections(request: Request):
    return intel_service.taxii_collections(host=_host(request))


@router.get("/api/collections/{collection_id}/objects", dependencies=[Depends(require_admin)])
def collection_objects(
    collection_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    ioc_type: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Returns the collection's STIX 2.1 indicator objects (newest first)."""
    if collection_id != _TAXII_COLLECTION_ID:
        raise HTTPException(status_code=404, detail=f"Unknown collection '{collection_id}'")
    iocs = intel_service.list_iocs(db, ioc_type=ioc_type, limit=limit)
    return intel_service.taxii_objects(iocs)
