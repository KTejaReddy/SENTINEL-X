"""SQLAlchemy engine + session management.

Default local database is SQLite (zero-dependency local development).
Production deployments use PostgreSQL via DATABASE_URL.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import JSON, MetaData, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import JSON as SA_JSON
from sqlalchemy.dialects.postgresql import JSONB

from .config import settings

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _connect_args() -> dict:
    if settings.DATABASE_URL.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args(),
    pool_pre_ping=True,
    future=True,
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, connection_record):  # pragma: no cover
    if settings.DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context manager for use outside request handlers (workers, seed)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def json_type() -> SA_JSON:
    """JSON column type that maps to JSONB on PostgreSQL and TEXT on SQLite."""
    return JSON().with_variant(JSONB(), "postgresql")


def init_db() -> None:
    """Create all tables (used for tests / first-run bootstrap).

    Production uses Alembic migrations; this is a convenience for local dev.
    """
    from . import models  # noqa: F401  (register all tables)

    Base.metadata.create_all(bind=engine)
