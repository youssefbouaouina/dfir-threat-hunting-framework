"""
Database engine and session setup for the DFIR backend.
Uses SQLite by default, matching the "lightweight" requirement from the
project brief. Override with DATABASE_URL to point at Postgres etc. (Phase 2).

Phase 5 (F8) adds connection-pool tuning for the server databases: pool_size /
max_overflow / pool_recycle / pool_pre_ping are env-driven and applied only to
non-SQLite URLs (SQLite's SingletonThreadPool has no such knobs and Postgres is
where connection churn actually hurts).
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dfir.db")

# check_same_thread=False is required for SQLite when used with FastAPI's
# threaded request handling — safe here since each request gets its own
# session via get_db(). The kwarg is SQLite-only, so it is applied only when
# the URL actually points at SQLite (PostgreSQL/psycopg2 rejects unknown
# connect_args as invalid DSN options).
_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

# --- Connection pool tuning (F8) -------------------------------------------
# Only meaningful for a real server DB (Postgres). QueuePool defaults would be
# pool_size=5 / max_overflow=10; these let operators size the pool to their
# workload without code changes.
_pool_kwargs = {}
if not DATABASE_URL.startswith("sqlite") and os.getenv("DB_POOL_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
):
    _pool_kwargs = {
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "20")),
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE_SECONDS", "1800")),
        "pool_pre_ping": os.getenv("DB_POOL_PRE_PING", "true").lower() in ("1", "true", "yes"),
    }

engine = create_engine(DATABASE_URL, connect_args=_connect_args, **_pool_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session and always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
