"""
Database engine and session setup for the DFIR backend.
Uses SQLite by default, matching the "lightweight" requirement from the
project brief. Override with DATABASE_URL to point at Postgres etc. (Phase 2).
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

engine = create_engine(DATABASE_URL, connect_args=_connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session and always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
