"""Tests for security.py — token issuance/verification and auth dependencies.

The module reads config at import time (AUTH_ENABLED=false in tests), so the
dependency behavior is exercised by toggling the module attribute directly.
"""
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

import security


@pytest.fixture(autouse=True)
def _enable_auth(monkeypatch):
    monkeypatch.setattr(security, "AUTH_ENABLED", True)
    monkeypatch.setattr(security, "ADMIN_API_KEY", "admin-key")
    monkeypatch.setattr(security, "AGENT_API_KEYS", {"agent-key": "agent-01"})
    monkeypatch.setattr(security, "_RATE_LIMIT_ENABLED", True)


def _creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_issue_and_verify_token():
    token = security.issue_token("admin")
    assert security._verify_token(token)


def test_token_tampered_is_rejected():
    token = security.issue_token("admin")
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    assert not security._verify_token(tampered)


def test_expired_token_is_rejected():
    token = security.issue_token("admin", ttl_seconds=-10)
    assert not security._verify_token(token)


def test_require_admin_accepts_key():
    assert security.require_admin(_creds("admin-key")) == "admin"


def test_require_admin_accepts_signed_token():
    token = security.issue_token("admin")
    assert security.require_admin(_creds(token)) == "admin"


def test_require_admin_rejects_bad_credentials():
    with pytest.raises(HTTPException) as exc:
        security.require_admin(_creds("wrong"))
    assert exc.value.status_code == 401


def test_require_agent_accepts_enrolled_key():
    assert security.require_agent(_creds("agent-key")) == "agent-01"


def test_require_agent_rejects_unknown_key():
    with pytest.raises(HTTPException) as exc:
        security.require_agent(_creds("nope"))
    assert exc.value.status_code == 401


def test_require_admin_missing_credentials():
    with pytest.raises(HTTPException):
        security.require_admin(None)


def test_authenticate_login_matches_admin_key():
    assert security.authenticate_login("admin-key")
    assert not security.authenticate_login("wrong")


def test_rate_limit_blocks_after_max(monkeypatch):
    monkeypatch.setattr(security, "_RATE_MAX_REQUESTS", 3)

    class FakeRequest:
        client = type("C", (), {"host": "1.2.3.4"})()
        headers = {}

    for _ in range(3):
        security.rate_limit(FakeRequest())
    with pytest.raises(HTTPException) as exc:
        security.rate_limit(FakeRequest())
    assert exc.value.status_code == 429


def test_rate_limit_active_without_auth(monkeypatch):
    """H4: rate limiting is decoupled from AUTH_ENABLED."""
    from collections import defaultdict, deque

    monkeypatch.setattr(security, "AUTH_ENABLED", False)
    monkeypatch.setattr(security, "_RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(security, "_RATE_MAX_REQUESTS", 1)
    monkeypatch.setattr(security, "_hits", defaultdict(deque))

    class FakeRequest:
        client = type("C", (), {"host": "5.6.7.8"})()
        headers = {}

    security.rate_limit(FakeRequest())  # first request passes
    with pytest.raises(HTTPException) as exc:
        security.rate_limit(FakeRequest())
    assert exc.value.status_code == 429


def test_rate_limit_disabled_explicitly(monkeypatch):
    """H4: RATE_LIMIT_ENABLED=false disables the limiter even with auth on."""
    from collections import defaultdict, deque

    monkeypatch.setattr(security, "AUTH_ENABLED", True)
    monkeypatch.setattr(security, "_RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(security, "_RATE_MAX_REQUESTS", 1)
    monkeypatch.setattr(security, "_hits", defaultdict(deque))

    class FakeRequest:
        client = type("C", (), {"host": "9.9.9.9"})()
        headers = {}

    for _ in range(5):  # no 429 expected
        security.rate_limit(FakeRequest())
