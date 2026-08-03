"""
API authentication, authorization (RBAC) and rate limiting for the DFIR backend.

Credential model (chosen for DFIR operations, not generic web apps):
  * Agents (headless endpoints)      -> long-lived API keys, one per endpoint,
                                        presented as `Authorization: Bearer <key>`.
  * Humans (analysts / admins)       -> short-lived HMAC-signed tokens obtained
                                        from POST /auth/login (TTL enforced).

Phase 4 (F4) adds role-based access control + team scoping:
  * Three roles: admin, analyst, viewer.
      - admin   — full access (manage config, run detection, triage, everything)
      - analyst — read + triage + trigger detection (no config/inventory writes)
      - viewer  — read-only
  * Tokens carry a `role` and an optional `team` claim. Human credentials map
    to (role, team) via env:
      - ADMIN_API_KEY     -> admin (no team scope; sees everything)
      - ANALYST_API_KEYS  -> comma-separated "key@team" entries -> analyst
      - VIEWER_API_KEYS   -> comma-separated "key@team" entries -> viewer
    A token issued without a team claim is unscoped (sees everything within
    its role). A team-scoped user only ever sees that team's endpoints and
    the detections/artifacts/incidents belonging to those hosts (F4c).

Everything is OPT-IN: when AUTH_ENABLED is false every dependency is a no-op,
preserving the existing open-lab behavior and all current tests. When enabled,
missing/invalid credentials raise 401, insufficient role raises 403, and
over-limit requests raise 429.

No secrets are ever logged. Tokens use stdlib only (base64/hmac/hashlib) so the
module has zero hard runtime dependencies beyond FastAPI.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

load_dotenv()

logger = logging.getLogger(__name__)

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)

# ---------------------------------------------------------------------------
# Env-driven configuration
# ---------------------------------------------------------------------------

AUTH_ENABLED: bool = os.getenv("AUTH_ENABLED", "false").lower() in ("1", "true", "yes")
ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "change-me-admin-key")
AUTH_SECRET: str = os.getenv("AUTH_SECRET", "change-me-auth-secret")
TOKEN_TTL_SECONDS: int = int(os.getenv("TOKEN_TTL_SECONDS", "1800"))
AGENT_API_KEYS: Dict[str, str] = {}  # key -> label (one per enrolled endpoint)
for _key in os.getenv("AGENT_API_KEYS", "").split(","):
    _key = _key.strip()
    if _key:
        AGENT_API_KEYS[_key] = "agent"


def _parse_human_keys(raw: str, role: str) -> Dict[str, dict]:
    """Parses "key@team,key2@team2" env entries into key -> {role, team}."""
    mapping: Dict[str, dict] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        key, _, team = entry.partition("@")
        mapping[key] = {"role": role, "team": team or None}
    return mapping


# key -> {"role": ..., "team": ...|None} for human credentials.
HUMAN_API_KEYS: Dict[str, dict] = {}
HUMAN_API_KEYS.update(_parse_human_keys(os.getenv("ADMIN_API_KEY", ""), ROLE_ADMIN))
HUMAN_API_KEYS.update(_parse_human_keys(os.getenv("ANALYST_API_KEYS", ""), ROLE_ANALYST))
HUMAN_API_KEYS.update(_parse_human_keys(os.getenv("VIEWER_API_KEYS", ""), ROLE_VIEWER))

_bearer = HTTPBearer(auto_error=False)

if AUTH_ENABLED:
    _DEFAULTS = ("change-me-admin-key", "change-me-auth-secret", "")
    if ADMIN_API_KEY in _DEFAULTS or AUTH_SECRET in _DEFAULTS:
        raise RuntimeError(
            "AUTH_ENABLED=true but ADMIN_API_KEY/AUTH_SECRET are still the default "
            "placeholder values — refusing to start with a broken security config. "
            "Set strong secrets in the environment (see backend/.env.example)."
        )
    if not AGENT_API_KEYS:
        raise RuntimeError(
            "AUTH_ENABLED=true but AGENT_API_KEYS is empty — no agent keys configured, "
            "so /ingest and /endpoints would reject every agent. Set at least one key."
        )


def _reject() -> HTTPException:
    return HTTPException(status_code=401, detail="Authentication required")


def _forbidden() -> HTTPException:
    return HTTPException(status_code=403, detail="Insufficient role")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(payload: Dict[str, object]) -> str:
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    digest = _b64url(
        hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{body}.{digest}"


def _verify_token(token: str) -> bool:
    return _decode_token(token) is not None


def _decode_token(token: str) -> Optional[dict]:
    try:
        body, _, digest = token.partition(".")
        expected = _b64url(
            hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(digest, expected):
            return None
        payload = json.loads(_b64url_decode(body))
        if not isinstance(payload, dict) or int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def issue_token(
    subject: str,
    role: str = ROLE_ADMIN,
    team: Optional[str] = None,
    ttl_seconds: int = TOKEN_TTL_SECONDS,
) -> str:
    """Issues a short-lived signed token for a human user (admin/analyst/viewer)."""
    payload: Dict[str, object] = {
        "sub": subject,
        "role": role if role in ROLES else ROLE_VIEWER,
        "team": team,
        "exp": int(time.time()) + int(ttl_seconds),
    }
    return _sign(payload)


# ---------------------------------------------------------------------------
# FastAPI dependencies (no-ops when auth is disabled)
# ---------------------------------------------------------------------------

def require_agent(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[str]:
    """Dependency for agent endpoints (e.g. /ingest). Returns the key label."""
    if not AUTH_ENABLED:
        return None
    if creds is None or creds.scheme.lower() != "bearer" or creds.credentials not in AGENT_API_KEYS:
        raise _reject()
    return AGENT_API_KEYS[creds.credentials]


def _resolve_human(creds: HTTPAuthorizationCredentials) -> Optional[dict]:
    """Returns {role, team, subject} for a human credential (key or token)."""
    if hmac.compare_digest(creds.credentials, ADMIN_API_KEY):
        return {"role": ROLE_ADMIN, "team": None, "subject": "admin"}
    if creds.credentials in HUMAN_API_KEYS:
        info = HUMAN_API_KEYS[creds.credentials]
        return {"role": info["role"], "team": info["team"], "subject": info["role"]}
    payload = _decode_token(creds.credentials)
    if payload:
        return {
            "role": payload.get("role", ROLE_VIEWER),
            "team": payload.get("team"),
            "subject": payload.get("sub", "user"),
        }
    return None


def current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[dict]:
    """Dependency yielding the authenticated human's {role, team, subject}.

    Returns None when auth is disabled (open-lab mode), so callers that treat
    `None` as "unscoped admin" keep working unchanged.
    """
    if not AUTH_ENABLED:
        return None
    if creds is None or creds.scheme.lower() != "bearer":
        raise _reject()
    user = _resolve_human(creds)
    if user is None:
        raise _reject()
    return user


def require_role(*roles: str):
    """Factory: builds a dependency enforcing membership in one of `roles`."""
    allowed = set(roles)

    def _dependency(
        user: Optional[dict] = Depends(current_user),
    ) -> Optional[dict]:
        if user is None:
            return None  # auth off -> open mode
        if user["role"] not in allowed:
            raise _forbidden()
        return user

    return _dependency


def require_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[str]:
    """Dependency for admin endpoints. Accepts the admin key or a signed token."""
    if not AUTH_ENABLED:
        return None
    if creds is None or creds.scheme.lower() != "bearer":
        raise _reject()
    if hmac.compare_digest(creds.credentials, ADMIN_API_KEY) or _verify_token(creds.credentials):
        return "admin"
    raise _reject()


def authenticate_login(api_key: str) -> dict:
    """Validates credentials for POST /auth/login; returns {role, team}.

    Accepts any configured human credential (admin/analyst/viewer key).
    """
    if hmac.compare_digest(api_key, ADMIN_API_KEY):
        return {"role": ROLE_ADMIN, "team": None}
    info = HUMAN_API_KEYS.get(api_key)
    if info:
        return {"role": info["role"], "team": info["team"]}
    return {}


# ---------------------------------------------------------------------------
# Rate limiting (sliding window, per client)
# ---------------------------------------------------------------------------

_RATE_WINDOW_SECONDS: int = int(os.getenv("RATE_WINDOW_SECONDS", "60"))
_RATE_MAX_REQUESTS: int = int(os.getenv("RATE_MAX_REQUESTS", "300"))
# Independent of AUTH_ENABLED so an open-lab instance is still flood-resistant.
# Defaults to the auth state to preserve the pre-split behavior.
_RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", str(AUTH_ENABLED).lower()) in (
    "1",
    "true",
    "yes",
)
_hits: Dict[str, Deque[float]] = defaultdict(deque)


def _client_key(request: Request) -> str:
    # X-Forwarded-For is only a soft hint here (untrusted unless behind a proxy);
    # fall back to the socket peer when absent.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(request: Request) -> None:
    """Sliding-window rate limiter per client.

    Active when RATE_LIMIT_ENABLED (default: same as AUTH_ENABLED) — deliberately
    decoupled from auth so an open-lab instance still gets basic DoS resistance.
    """
    if not _RATE_LIMIT_ENABLED:
        return
    key = _client_key(request)
    now = time.time()
    window = _hits[key]
    while window and now - window[0] > _RATE_WINDOW_SECONDS:
        window.popleft()
    if len(window) >= _RATE_MAX_REQUESTS:
        logger.warning("Rate limit exceeded for client %s", key)
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    window.append(now)

