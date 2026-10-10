"""Database engine, session factory, and declarative base."""

from collections.abc import Generator
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from vaultsync_server.config import settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""


def create_db_engine(url: str | None = None) -> Engine:
    """Create and configure SQLAlchemy engine with SQLite foreign key enforcement."""
    db_url = url or settings.database_url
    connect_args: dict[str, Any] = {}

    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(
        db_url,
        connect_args=connect_args,
        echo=settings.debug,
        future=True,
    )

    if db_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding an isolated database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
