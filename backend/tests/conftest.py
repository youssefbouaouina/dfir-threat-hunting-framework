"""Pytest fixtures for the DFIR backend.

Sets DFIR_DB_PATH to a throwaway SQLite file BEFORE any backend module is
imported, then exposes a FastAPI TestClient bound to the app. The scheduler
runs inside the TestClient lifespan but with a huge detection interval so it
never interferes with assertions.
"""
import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="dfir-test-")
os.environ["DFIR_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ.setdefault("DETECTION_INTERVAL_SECONDS", "999999")
os.environ.setdefault("LIVENESS_INTERVAL_SECONDS", "999999")
os.environ.setdefault("ORCHESTRATION_INTERVAL_SECONDS", "999999")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

import main as main_module


@pytest.fixture(autouse=True)
def _clean_db():
    """Shared-process SQLite is reused across tests; wipe all tables before each
    test so assertions about counts/duplicates are deterministic."""
    from sqlalchemy import text

    from database import engine

    with engine.begin() as conn:
        for table in ("detections", "artifacts", "hosts", "endpoints", "reports"):
            conn.execute(text(f"DELETE FROM {table}"))
    yield


@pytest.fixture()
def client():
    with TestClient(main_module.app) as c:
        yield c
