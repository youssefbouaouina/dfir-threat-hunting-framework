"""Shared pytest fixtures for the DFIR backend test suite.

A session-wide temp SQLite is used for the app's default engine (so tests
never touch the real dfir.db), and each test gets an isolated in-memory
database via dependency_overrides on get_db.
"""
import os
import sys
import tempfile

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

_TEST_DB_DIR = tempfile.mkdtemp(prefix="dfir_pytest_")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_DIR}/base.db"
os.environ.setdefault("AUTH_ENABLED", "false")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import main as app_module  # noqa: E402
import models  # noqa: E402
from database import get_db  # noqa: E402


def _build_testing_session(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/test.db", connect_args={"check_same_thread": False}
    )
    models.Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)


@pytest.fixture()
def db_session(tmp_path):
    """An isolated DB session per test, for direct service-level tests."""
    testing_session = _build_testing_session(tmp_path)
    session = testing_session()
    yield session
    session.close()


@pytest.fixture()
def client(tmp_path):
    """A TestClient with get_db overridden to a fresh per-test database.

    Not used as a context manager, so the FastAPI lifespan (and therefore the
    background scheduler) does not run during tests.
    """
    testing_session = _build_testing_session(tmp_path)

    def _get_db():
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app_module.app.dependency_overrides[get_db] = _get_db
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    test_client.close()
