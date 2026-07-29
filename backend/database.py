"""
Database engine and session setup for the DFIR backend.
Uses SQLite, matching the "lightweight" requirement from the project brief.
The .db file is created automatically on first run, in this same folder.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./dfir.db"

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
