"""
AMOSKYS Web Database Configuration

Separate database for web-related data including:
- User accounts and authentication
- Sessions
- Audit logs
- Agent tokens and deployments

This keeps web/user data separate from core telemetry data.

Usage:
    from amoskys.db.web_db import get_web_session_context, init_web_db

    with get_web_session_context() as session:
        user = session.query(User).first()
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from amoskys.db import Base

__all__ = [
    "get_web_database_url",
    "get_web_engine",
    "get_web_session",
    "get_web_session_context",
    "init_web_db",
    "reset_web_engine",
]


# =============================================================================
# Web Database URL Configuration
# =============================================================================


def get_web_database_url() -> str:
    """
    Get web database URL from environment or use default SQLite.

    The web database stores user accounts, sessions, audit logs, and
    agent management data - separate from core telemetry.

    Environment Variables:
        WEB_DATABASE_URL: Full database URL for web data
        AMOSKYS_WEB_DB_PATH: Path for SQLite web database

    Returns:
        Database connection URL for web data
    """
    # Check for explicit WEB_DATABASE_URL first
    if url := os.environ.get("WEB_DATABASE_URL"):
        return url

    # Default to SQLite in web/data directory
    db_path = os.environ.get(
        "AMOSKYS_WEB_DB_PATH",
        os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "web", "data", "amoskys_web.db"
        ),
    )
    # Resolve to absolute path
    db_path = os.path.abspath(db_path)
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return f"sqlite:///{db_path}"


# =============================================================================
# Engine and Session Management
# =============================================================================

# Module-level engine cache for web database
_web_engine = None
_WebSessionLocal = None


def get_web_engine(url: str | None = None, **kwargs: Any):
    """
    Get or create the SQLAlchemy engine for web database.

    Args:
        url: Optional database URL (uses get_web_database_url() if not provided)
        **kwargs: Additional arguments passed to create_engine

    Returns:
        SQLAlchemy Engine instance for web database
    """
    global _web_engine

    if _web_engine is None:
        database_url = url or get_web_database_url()

        # Default engine arguments
        engine_args: dict[str, Any] = {
            "echo": os.environ.get("AMOSKYS_DB_ECHO", "").lower() == "true",
            "pool_pre_ping": True,  # Verify connections before use
        }

        # SQLite-specific settings
        if database_url.startswith("sqlite"):
            engine_args["connect_args"] = {"check_same_thread": False}

        engine_args.update(kwargs)
        _web_engine = create_engine(database_url, **engine_args)

    return _web_engine


def get_web_session() -> sessionmaker[Session]:
    """
    Get the session factory for web database.

    Returns:
        Configured sessionmaker instance for web database
    """
    global _WebSessionLocal

    if _WebSessionLocal is None:
        _WebSessionLocal = sessionmaker(
            bind=get_web_engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )

    return _WebSessionLocal


@contextmanager
def get_web_session_context() -> Generator[Session, None, None]:
    """
    Context manager for web database sessions.

    Automatically handles commit/rollback and session cleanup.

    Usage:
        with get_web_session_context() as session:
            user = session.query(User).first()
            user.name = "New Name"
            # Commits automatically on exit

    Yields:
        SQLAlchemy Session instance for web database
    """
    SessionLocal = get_web_session()
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_web_db() -> None:
    """
    Initialize the web database by creating all tables.

    This creates tables for:
    - Users
    - Sessions
    - Email verification tokens
    - Password reset tokens
    - Auth audit logs
    - Agent tokens
    - Deployed agents
    """
    # Import models to register them with Base
    from amoskys.auth import models as auth_models  # noqa: F401
    from amoskys.agents import models as agent_models  # noqa: F401

    Base.metadata.create_all(bind=get_web_engine())


def reset_web_engine() -> None:
    """
    Reset the web engine (useful for testing).
    """
    global _web_engine, _WebSessionLocal
    if _web_engine:
        _web_engine.dispose()
    _web_engine = None
    _WebSessionLocal = None
