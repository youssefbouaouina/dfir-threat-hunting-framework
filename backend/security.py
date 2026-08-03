"""
API authentication and rate limiting for the DFIR backend.

Credential model (chosen for DFIR operations, not generic web apps):
  * Agents (headless endpoints)      -> long-lived API keys, one per endpoint,
                                        presented as `Authorization: Bearer <key>`.
  * Admins/analysts (human users)    -> short-lived HMAC-signed tokens obtained
                                        from POST /auth/login (TTL enforced).

Everything is OPT-IN: when AUTH_ENABLED is false every dependency is a no-op,
preserving the existing open-lab behavior and all current tests. When enabled,
missing/invalid credentials raise 401 and over-limit requests raise 429.

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

_bearer = HTTPBearer(auto_error=False)

if AUTH_ENABLED and AUTH_SECRET in ("", "change-me-auth-secret"):
    logger.warning("AUTH_ENABLED=true but AUTH_SECRET is the default — set a strong secret")


def _reject() -> HTTPException:
    return HTTPException(status_code=401, detail="Authentication required")


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
    try:
        body, _, digest = token.partition(".")
        expected = _b64url(
            hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(digest, expected):
            return False
        payload = json.loads(_b64url_decode(body))
        return isinstance(payload, dict) and int(payload.get("exp", 0)) >= int(time.time())
    except (ValueError, TypeError, json.JSONDecodeError):
        return False


def issue_token(subject: str, ttl_seconds: int = TOKEN_TTL_SECONDS) -> str:
    """Issues a short-lived signed token for a human user (admin/analyst)."""
    payload = {"sub": subject, "exp": int(time.time()) + int(ttl_seconds)}
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


def require_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[str]:
    """Dependency for analyst/admin endpoints. Accepts the admin key or a signed token."""
    if not AUTH_ENABLED:
        return None
    if creds is None or creds.scheme.lower() != "bearer":
        raise _reject()
    if hmac.compare_digest(creds.credentials, ADMIN_API_KEY) or _verify_token(creds.credentials):
        return "admin"
    raise _reject()


def authenticate_login(api_key: str) -> bool:
    """Validates credentials for POST /auth/login (admin key)."""
    return hmac.compare_digest(api_key, ADMIN_API_KEY)


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
