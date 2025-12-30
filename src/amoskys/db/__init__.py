"""
AMOSKYS Database Configuration

Central database configuration and connection management.
All SQLAlchemy models should inherit from the Base defined here.

Usage:
    from amoskys.db import Base, get_engine, get_session

    # In models:
    class User(Base):
        __tablename__ = "users"
        ...

    # In application:
    engine = get_engine()
    Session = get_session()
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)
from sqlalchemy.sql import func

__all__ = [
    "Base",
    "TimestampMixin",
    "get_engine",
    "get_session",
    "get_session_context",
]


# =============================================================================
# Database URL Configuration
# =============================================================================


def get_database_url() -> str:
    """
    Get database URL from environment or use default SQLite.

    Environment Variables:
        DATABASE_URL: Full database URL
        AMOSKYS_DB_TYPE: Database type (sqlite, postgresql)
        AMOSKYS_DB_PATH: Path for SQLite database

    Returns:
        Database connection URL
    """
    # Check for explicit DATABASE_URL first
    if url := os.environ.get("DATABASE_URL"):
        return url

    # Check for database type configuration
    db_type = os.environ.get("AMOSKYS_DB_TYPE", "sqlite")

    if db_type == "sqlite":
        db_path = os.environ.get(
            "AMOSKYS_DB_PATH",
            os.path.join(
                os.path.dirname(__file__), "..", "..", "..", "data", "amoskys.db"
            ),
        )
        # Resolve to absolute path
        db_path = os.path.abspath(db_path)
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        return f"sqlite:///{db_path}"

    elif db_type == "postgresql":
        host = os.environ.get("AMOSKYS_DB_HOST", "localhost")
        port = os.environ.get("AMOSKYS_DB_PORT", "5432")
        name = os.environ.get("AMOSKYS_DB_NAME", "amoskys")
        user = os.environ.get("AMOSKYS_DB_USER", "amoskys")
        password = os.environ.get("AMOSKYS_DB_PASSWORD", "")
        return f"postgresql://{user}:{password}@{host}:{port}/{name}"

    else:
        raise ValueError(f"Unsupported database type: {db_type}")


# =============================================================================
# SQLAlchemy Base and Mixins
# =============================================================================


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class TimestampMixin:
    """
    Mixin that adds created_at and updated_at timestamps to models.

    Usage:
        class User(TimestampMixin, Base):
            __tablename__ = "users"
            ...
    """

    created_at: Mapped[datetime] = mapped_column(
        default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# =============================================================================
# Engine and Session Management
# =============================================================================

# Module-level engine cache
_engine = None
_SessionLocal = None


def get_engine(url: str | None = None, **kwargs: Any):
    """
    Get or create the SQLAlchemy engine.

    Args:
        url: Optional database URL (uses get_database_url() if not provided)
        **kwargs: Additional arguments passed to create_engine

    Returns:
        SQLAlchemy Engine instance
    """
    global _engine

    if _engine is None:
        database_url = url or get_database_url()

        # Default engine arguments
        engine_args: dict[str, Any] = {
            "echo": os.environ.get("AMOSKYS_DB_ECHO", "").lower() == "true",
            "pool_pre_ping": True,  # Verify connections before use
        }

        # SQLite-specific settings
        if database_url.startswith("sqlite"):
            engine_args["connect_args"] = {"check_same_thread": False}

        engine_args.update(kwargs)
        _engine = create_engine(database_url, **engine_args)

    return _engine


def get_session() -> sessionmaker[Session]:
    """
    Get the session factory.

    Returns:
        Configured sessionmaker instance
    """
    global _SessionLocal

    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )

    return _SessionLocal


@contextmanager
def get_session_context() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.

    Automatically handles commit/rollback and session cleanup.

    Usage:
        with get_session_context() as session:
            user = session.query(User).first()
            user.name = "New Name"
            # Commits automatically on exit

    Yields:
        SQLAlchemy Session instance
    """
    SessionLocal = get_session()
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """
    Initialize the database by creating all tables.

    This should be called once at application startup or during migrations.
    """
    from amoskys.auth import models  # noqa: F401 - Import to register models

    Base.metadata.create_all(bind=get_engine())


def reset_engine() -> None:
    """
    Reset the engine (useful for testing).
    """
    global _engine, _SessionLocal
    if _engine:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
