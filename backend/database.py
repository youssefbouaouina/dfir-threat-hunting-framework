"""
Database engine and session setup for the DFIR backend.
Uses SQLite, matching the "lightweight" requirement from the project brief.
The .db file is created automatically on first run, in this same folder.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# DFIR_DB_PATH lets Docker point this at a mounted volume
# (/app/data/dfir.db) without any code change — same source runs
# identically containerized or native. Defaults to the same local file
# used throughout local/native development so nothing breaks for
# anyone not using Docker yet.
DB_PATH = os.getenv("DFIR_DB_PATH", "./dfir.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# check_same_thread=False is required for SQLite when used with FastAPI's
# threaded request handling — safe here since each request gets its own
# session via get_db().
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session and always closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
