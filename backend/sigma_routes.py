"""
Sigma rule management routes (Phase 5 / F6).

Exposes the SigmaHQ update pipeline and the current state of the pySigma
rule set: what's loaded, how many rules map to our collector schema, and
the result of the last refresh. POST /sigma/refresh is admin-only and
audited (feeds + manual updates are state changes).
"""
import os

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from security import current_user, require_admin
from services import sigma_service
from services.audit_service import log_action
from services.detection_service import NATIVE_SIGMA_RULES_DIR
from sigma_engine import (
    DEFAULT_SEVERITY,
    _artifact_type_for_rule,
    _rule_technique_id,
    load_rules,
    summarize,
)

router = APIRouter()


def _rule_metadata(rule) -> dict:
    return {
        "id": str(rule.id),
        "title": rule.title,
        "level": rule.level or DEFAULT_SEVERITY,
        "status": rule.status,
        "technique_id": _rule_technique_id(rule),
        "artifact_type": _artifact_type_for_rule(rule),
    }


@router.get("/sigma/status", dependencies=[Depends(require_admin)])
def sigma_status():
    """Loaded-rule counts (mapped/unmapped) + last SigmaHQ refresh record."""
    rules = load_rules(NATIVE_SIGMA_RULES_DIR) if os.path.isdir(NATIVE_SIGMA_RULES_DIR) else []
    return {
        "rules_dir": NATIVE_SIGMA_RULES_DIR,
        "loaded_rules": summarize(rules),
        "refresh": sigma_service.get_refresh_status(sigma_service.DEFAULT_TARGET_DIR),
    }


@router.get("/sigma/rules", dependencies=[Depends(require_admin)])
def sigma_rules(limit: int = Query(default=100, ge=1, le=1000)):
    """Lists the currently loaded native Sigma rules (metadata only)."""
    rules = load_rules(NATIVE_SIGMA_RULES_DIR) if os.path.isdir(NATIVE_SIGMA_RULES_DIR) else []
    return [_rule_metadata(r) for r in rules[:limit]]


@router.post("/sigma/refresh", dependencies=[Depends(require_admin)])
def sigma_refresh(
    source: str = Query(default="local", description="'local' dir or 'github' clone"),
    user: dict = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Imports compatible rules from the requested source into sigma_rules/native/sigmahq/."""
    try:
        summary = sigma_service.refresh_sigma_rules(source=source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    log_action(
        db,
        "sigma_refresh",
        actor=user.get("subject") if user else "unknown",
        detail=summary,
    )
    return summary
