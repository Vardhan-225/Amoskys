"""
Tests for amoskys.db — Database Configuration & Connection Management.

Covers:
  - get_database_url (SQLite, PostgreSQL, explicit DATABASE_URL, unsupported)
  - Base declarative base
  - TimestampMixin
  - get_engine (caching, SQLite-specific args)
  - get_session (caching, sessionmaker configuration)
  - get_session_context (commit, rollback, close)
  - init_db
  - reset_engine
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures — reset module-level caches between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_db_module():
    """Reset the module-level engine and session caches before each test."""
    import amoskys.db as db_mod

    db_mod._engine = None
    db_mod._SessionLocal = None
    yield
    # Clean up again after
    if db_mod._engine is not None:
        try:
            db_mod._engine.dispose()
        except Exception:
            pass
    db_mod._engine = None
    db_mod._SessionLocal = None


# ---------------------------------------------------------------------------
# Tests: get_database_url
# ---------------------------------------------------------------------------


class TestGetDatabaseUrl:
    def test_explicit_database_url(self):
        from amoskys.db import get_database_url

        with patch.dict(
            "os.environ", {"DATABASE_URL": "postgresql://u:p@host/db"}, clear=False
        ):
            url = get_database_url()
            assert url == "postgresql://u:p@host/db"

    def test_sqlite_default(self):
        from amoskys.db import get_database_url

        env = {"AMOSKYS_DB_TYPE": "sqlite", "AMOSKYS_DB_PATH": "/tmp/test_amoskys.db"}
        with patch.dict("os.environ", env, clear=False):
            # Remove DATABASE_URL if present
            import os

            os.environ.pop("DATABASE_URL", None)
            url = get_database_url()
            assert url.startswith("sqlite:///")
            assert "test_amoskys.db" in url

    @patch("os.makedirs")
    def test_sqlite_creates_directory(self, mock_makedirs):
        from amoskys.db import get_database_url

        env = {
            "AMOSKYS_DB_TYPE": "sqlite",
            "AMOSKYS_DB_PATH": "/tmp/deep/dir/amoskys.db",
        }
        with patch.dict("os.environ", env, clear=False):
            import os

            os.environ.pop("DATABASE_URL", None)
            get_database_url()
            mock_makedirs.assert_called_once_with("/tmp/deep/dir", exist_ok=True)

    def test_postgresql_url(self):
        from amoskys.db import get_database_url

        env = {
            "AMOSKYS_DB_TYPE": "postgresql",
            "AMOSKYS_DB_HOST": "dbhost",
            "AMOSKYS_DB_PORT": "5433",
            "AMOSKYS_DB_NAME": "mydb",
            "AMOSKYS_DB_USER": "myuser",
            "AMOSKYS_DB_PASSWORD": "mypass",
        }
        with patch.dict("os.environ", env, clear=False):
            import os

            os.environ.pop("DATABASE_URL", None)
            url = get_database_url()
            assert url == "postgresql://myuser:mypass@dbhost:5433/mydb"

    def test_unsupported_db_type_raises(self):
        from amoskys.db import get_database_url

        with patch.dict("os.environ", {"AMOSKYS_DB_TYPE": "mongo"}, clear=False):
            import os

            os.environ.pop("DATABASE_URL", None)
            with pytest.raises(ValueError, match="Unsupported database type: mongo"):
                get_database_url()

    def test_sqlite_default_when_no_env(self):
        """When no env vars set, defaults to sqlite."""
        import os

        from amoskys.db import get_database_url

        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("AMOSKYS_DB_TYPE", None)
        url = get_database_url()
        assert url.startswith("sqlite:///")


# ---------------------------------------------------------------------------
# Tests: Base & TimestampMixin
# ---------------------------------------------------------------------------


class TestBaseAndMixin:
    def test_base_is_declarative(self):
        from amoskys.db import Base

        assert hasattr(Base, "metadata")
        # DeclarativeBase subclasses have a registry and metadata
        assert hasattr(Base, "registry")

    def test_timestamp_mixin_has_columns(self):
        from amoskys.db import TimestampMixin

        assert hasattr(TimestampMixin, "created_at")
        assert hasattr(TimestampMixin, "updated_at")


# ---------------------------------------------------------------------------
# Tests: get_engine
# ---------------------------------------------------------------------------


class TestGetEngine:
    @patch("amoskys.db.create_engine")
    @patch("amoskys.db.get_database_url", return_value="sqlite:///test.db")
    def test_creates_engine_with_defaults(self, mock_url, mock_create):
        import amoskys.db as db_mod

        mock_engine = MagicMock()
        mock_create.return_value = mock_engine

        engine = db_mod.get_engine()

        assert engine is mock_engine
        mock_create.assert_called_once()
        # Check SQLite-specific args
        args, kwargs = mock_create.call_args
        assert args[0] == "sqlite:///test.db"
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["connect_args"] == {"check_same_thread": False}

    @patch("amoskys.db.create_engine")
    @patch("amoskys.db.get_database_url", return_value="postgresql://u:p@h/d")
    def test_no_check_same_thread_for_postgres(self, mock_url, mock_create):
        import amoskys.db as db_mod

        mock_create.return_value = MagicMock()
        db_mod.get_engine()

        _, kwargs = mock_create.call_args
        assert "connect_args" not in kwargs

    @patch("amoskys.db.create_engine")
    def test_caches_engine(self, mock_create):
        import amoskys.db as db_mod

        mock_create.return_value = MagicMock()
        e1 = db_mod.get_engine(url="sqlite:///test.db")
        e2 = db_mod.get_engine()
        assert e1 is e2
        mock_create.assert_called_once()

    @patch("amoskys.db.create_engine")
    def test_custom_url_override(self, mock_create):
        import amoskys.db as db_mod

        mock_create.return_value = MagicMock()
        db_mod.get_engine(url="sqlite:///custom.db")

        args, _ = mock_create.call_args
        assert args[0] == "sqlite:///custom.db"

    @patch("amoskys.db.create_engine")
    def test_echo_enabled_via_env(self, mock_create):
        import amoskys.db as db_mod

        mock_create.return_value = MagicMock()
        with patch.dict("os.environ", {"AMOSKYS_DB_ECHO": "true"}, clear=False):
            db_mod.get_engine(url="sqlite:///test.db")
            _, kwargs = mock_create.call_args
            assert kwargs["echo"] is True


# ---------------------------------------------------------------------------
# Tests: get_session
# ---------------------------------------------------------------------------


class TestGetSession:
    @patch("amoskys.db.get_engine")
    @patch("amoskys.db.sessionmaker")
    def test_creates_sessionmaker(self, mock_sm, mock_engine):
        import amoskys.db as db_mod

        mock_engine.return_value = MagicMock()
        mock_factory = MagicMock()
        mock_sm.return_value = mock_factory

        result = db_mod.get_session()

        assert result is mock_factory
        mock_sm.assert_called_once_with(
            bind=mock_engine.return_value,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )

    @patch("amoskys.db.get_engine")
    @patch("amoskys.db.sessionmaker")
    def test_caches_session_factory(self, mock_sm, mock_engine):
        import amoskys.db as db_mod

        mock_engine.return_value = MagicMock()
        mock_sm.return_value = MagicMock()

        s1 = db_mod.get_session()
        s2 = db_mod.get_session()
        assert s1 is s2
        mock_sm.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: get_session_context
# ---------------------------------------------------------------------------


class TestGetSessionContext:
    @patch("amoskys.db.get_session")
    def test_commits_on_success(self, mock_get_session):
        import amoskys.db as db_mod

        mock_session = MagicMock()
        mock_factory = MagicMock(return_value=mock_session)
        mock_get_session.return_value = mock_factory

        with db_mod.get_session_context() as session:
            assert session is mock_session

        mock_session.commit.assert_called_once()
        mock_session.rollback.assert_not_called()
        mock_session.close.assert_called_once()

    @patch("amoskys.db.get_session")
    def test_rollback_on_exception(self, mock_get_session):
        import amoskys.db as db_mod

        mock_session = MagicMock()
        mock_factory = MagicMock(return_value=mock_session)
        mock_get_session.return_value = mock_factory

        with pytest.raises(ValueError):
            with db_mod.get_session_context() as session:
                raise ValueError("test error")

        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()
        mock_session.close.assert_called_once()

    @patch("amoskys.db.get_session")
    def test_close_always_called(self, mock_get_session):
        import amoskys.db as db_mod

        mock_session = MagicMock()
        mock_factory = MagicMock(return_value=mock_session)
        mock_get_session.return_value = mock_factory

        try:
            with db_mod.get_session_context():
                raise RuntimeError("boom")
        except RuntimeError:
            pass

        mock_session.close.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: init_db
# ---------------------------------------------------------------------------


class TestInitDb:
    @patch("amoskys.db.get_engine")
    @patch("amoskys.db.Base")
    def test_init_db_creates_tables(self, mock_base, mock_engine):
        import amoskys.db as db_mod

        mock_eng = MagicMock()
        mock_engine.return_value = mock_eng

        with patch.dict(
            "sys.modules",
            {"amoskys.auth": MagicMock(), "amoskys.auth.models": MagicMock()},
        ):
            db_mod.init_db()

        mock_base.metadata.create_all.assert_called_once_with(bind=mock_eng)


# ---------------------------------------------------------------------------
# Tests: reset_engine
# ---------------------------------------------------------------------------


class TestResetEngine:
    @patch("amoskys.db.create_engine")
    def test_reset_disposes_and_clears(self, mock_create):
        import amoskys.db as db_mod

        mock_eng = MagicMock()
        mock_create.return_value = mock_eng

        # Create engine first
        db_mod.get_engine(url="sqlite:///test.db")
        assert db_mod._engine is not None

        # Reset
        db_mod.reset_engine()

        mock_eng.dispose.assert_called_once()
        assert db_mod._engine is None
        assert db_mod._SessionLocal is None

    def test_reset_when_no_engine_is_noop(self):
        import amoskys.db as db_mod

        db_mod._engine = None
        db_mod._SessionLocal = None
        # Should not raise
        db_mod.reset_engine()
        assert db_mod._engine is None
