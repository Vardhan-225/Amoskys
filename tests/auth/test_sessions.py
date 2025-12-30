"""
Tests for AMOSKYS Session Management

Comprehensive test coverage for:
- Session creation and token handling
- Session validation with all security checks
- Session refresh and sliding expiry
- Session revocation (single and bulk)
- Session limit enforcement
- Expired session cleanup

Test Philosophy:
    Sessions are the gateway to authenticated access. We test
    every security boundary and edge case rigorously.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Generator
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from amoskys.auth.models import (
    AuditEventType,
    AuthAuditLog,
    Session,
    User,
    UserRole,
)
from amoskys.auth.password import hash_password
from amoskys.auth.sessions import (
    SessionConfig,
    SessionValidationResult,
    _enforce_session_limit,
    cleanup_expired_sessions,
    create_session,
    get_session_config,
    get_user_active_sessions,
    refresh_session,
    reset_session_config,
    revoke_all_user_sessions,
    revoke_session,
    validate_session,
)
from amoskys.auth.tokens import hash_token
from amoskys.db import Base

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="function")
def engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="function")
def db(engine) -> Generator[DbSession, None, None]:
    """Create a database session for testing."""
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def test_user(db: DbSession) -> User:
    """Create a test user."""
    user = User(
        email="test@example.com",
        email_normalized="test@example.com",
        password_hash=hash_password("TestPassword123!"),
        full_name="Test User",
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def test_config() -> SessionConfig:
    """Create a test session config."""
    return SessionConfig(
        session_lifetime_hours=24,
        idle_timeout_hours=2,
        max_sessions_per_user=5,
        enable_ip_binding=False,
        enable_ua_binding=False,
    )


@pytest.fixture(autouse=True)
def reset_config():
    """Reset session config before each test."""
    reset_session_config()
    yield
    reset_session_config()


# =============================================================================
# SessionConfig Tests
# =============================================================================


class TestSessionConfig:
    """Tests for session configuration."""

    def test_default_values(self) -> None:
        """Test default config values."""
        config = SessionConfig()
        assert config.session_lifetime_hours == 24
        assert config.idle_timeout_hours == 2
        assert config.max_sessions_per_user == 10
        assert config.enable_ip_binding is False
        assert config.enable_ua_binding is False
        assert config.token_bytes == 32

    def test_custom_values(self) -> None:
        """Test custom config values."""
        config = SessionConfig(
            session_lifetime_hours=12,
            idle_timeout_hours=1,
            max_sessions_per_user=3,
            enable_ip_binding=True,
            enable_ua_binding=True,
        )
        assert config.session_lifetime_hours == 12
        assert config.idle_timeout_hours == 1
        assert config.max_sessions_per_user == 3
        assert config.enable_ip_binding is True
        assert config.enable_ua_binding is True


class TestGetSessionConfig:
    """Tests for get_session_config function."""

    def test_loads_from_environment(self) -> None:
        """Test config loads from environment variables."""
        with patch.dict(
            os.environ,
            {
                "AMOSKYS_SESSION_LIFETIME_HOURS": "48",
                "AMOSKYS_SESSION_IDLE_TIMEOUT_HOURS": "4",
                "AMOSKYS_SESSION_MAX_PER_USER": "20",
                "AMOSKYS_SESSION_BIND_IP": "true",
                "AMOSKYS_SESSION_BIND_UA": "true",
            },
            clear=False,
        ):
            reset_session_config()
            config = get_session_config()

            assert config.session_lifetime_hours == 48
            assert config.idle_timeout_hours == 4
            assert config.max_sessions_per_user == 20
            assert config.enable_ip_binding is True
            assert config.enable_ua_binding is True

    def test_caches_config(self) -> None:
        """Test config is cached after first load."""
        config1 = get_session_config()
        config2 = get_session_config()
        assert config1 is config2


# =============================================================================
# Session Creation Tests
# =============================================================================


class TestCreateSession:
    """Tests for session creation."""

    def test_creates_session_successfully(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test successful session creation."""
        token, session = create_session(
            db,
            test_user,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 Test",
            config=test_config,
        )

        # Token should be returned
        assert token is not None
        assert len(token) >= 20  # URL-safe base64 of 32 bytes

        # Session should be created
        assert session is not None
        assert session.user_id == test_user.id
        assert session.ip_address == "192.168.1.1"
        assert session.user_agent == "Mozilla/5.0 Test"
        assert session.revoked_at is None

        # Token hash should be stored, not plaintext
        assert session.session_token_hash == hash_token(token)
        assert session.session_token_hash != token

        # Expiry should be set
        assert session.expires_at > datetime.utcnow()

    def test_creates_audit_log(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test session creation logs audit event."""
        token, session = create_session(
            db,
            test_user,
            ip_address="10.0.0.1",
            config=test_config,
        )
        db.commit()

        # Find audit log
        audit = (
            db.query(AuthAuditLog)
            .filter(AuthAuditLog.event_type == AuditEventType.SESSION_CREATED)
            .first()
        )

        assert audit is not None
        assert audit.user_id == test_user.id
        assert audit.ip_address == "10.0.0.1"

    def test_truncates_long_user_agent(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test long user agents are truncated."""
        long_ua = "X" * 600
        token, session = create_session(
            db,
            test_user,
            user_agent=long_ua,
            config=test_config,
        )

        assert len(session.user_agent) == 500

    def test_enforces_session_limit(
        self,
        db: DbSession,
        test_user: User,
    ) -> None:
        """Test max sessions per user is enforced."""
        config = SessionConfig(max_sessions_per_user=3)

        # Create 5 sessions (limit is 3)
        tokens = []
        for i in range(5):
            token, _ = create_session(db, test_user, config=config)
            tokens.append(token)
            db.commit()

        # Should only have 3 active sessions
        active = get_user_active_sessions(db, test_user.id)
        assert len(active) == 3


# =============================================================================
# Session Validation Tests
# =============================================================================


class TestValidateSession:
    """Tests for session validation."""

    def test_valid_session(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test validation of a valid session."""
        token, session = create_session(db, test_user, config=test_config)
        db.commit()

        result = validate_session(db, token, config=test_config)

        assert result.is_valid is True
        assert result.user is not None
        assert result.user.id == test_user.id
        assert result.session is not None
        assert result.session.id == session.id
        assert result.error is None
        assert result.error_code is None

    def test_invalid_token_format(
        self,
        db: DbSession,
        test_config: SessionConfig,
    ) -> None:
        """Test rejection of malformed tokens."""
        result = validate_session(db, "short", config=test_config)

        assert result.is_valid is False
        assert result.error_code == "INVALID_TOKEN"

    def test_empty_token(
        self,
        db: DbSession,
        test_config: SessionConfig,
    ) -> None:
        """Test rejection of empty tokens."""
        result = validate_session(db, "", config=test_config)

        assert result.is_valid is False
        assert result.error_code == "INVALID_TOKEN"

    def test_nonexistent_session(
        self,
        db: DbSession,
        test_config: SessionConfig,
    ) -> None:
        """Test rejection of tokens with no matching session."""
        fake_token = "nonexistent_session_token_that_is_long_enough"
        result = validate_session(db, fake_token, config=test_config)

        assert result.is_valid is False
        assert result.error_code == "SESSION_NOT_FOUND"

    def test_revoked_session(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test rejection of revoked sessions."""
        token, session = create_session(db, test_user, config=test_config)
        session.revoked_at = datetime.utcnow()
        db.commit()

        result = validate_session(db, token, config=test_config)

        assert result.is_valid is False
        assert result.error_code == "SESSION_REVOKED"

    def test_expired_session(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test rejection of expired sessions."""
        token, session = create_session(db, test_user, config=test_config)
        # Set expiry to past
        session.expires_at = datetime.utcnow() - timedelta(hours=1)
        db.commit()

        result = validate_session(db, token, config=test_config)

        assert result.is_valid is False
        assert result.error_code == "SESSION_EXPIRED"

    def test_idle_timeout(
        self,
        db: DbSession,
        test_user: User,
    ) -> None:
        """Test rejection of sessions that exceeded idle timeout."""
        config = SessionConfig(idle_timeout_hours=1)
        token, session = create_session(db, test_user, config=config)
        # Set last activity to past the idle timeout
        session.last_active_at = datetime.utcnow() - timedelta(hours=2)
        db.commit()

        result = validate_session(db, token, config=config)

        assert result.is_valid is False
        assert result.error_code == "SESSION_IDLE_TIMEOUT"

    def test_ip_binding_mismatch(
        self,
        db: DbSession,
        test_user: User,
    ) -> None:
        """Test rejection when IP binding is enabled and IP changes."""
        config = SessionConfig(enable_ip_binding=True)
        token, session = create_session(
            db,
            test_user,
            ip_address="1.1.1.1",
            config=config,
        )
        db.commit()

        result = validate_session(
            db,
            token,
            ip_address="2.2.2.2",
            config=config,
        )

        assert result.is_valid is False
        assert result.error_code == "SESSION_IP_MISMATCH"

    def test_ip_binding_same_ip(
        self,
        db: DbSession,
        test_user: User,
    ) -> None:
        """Test session valid when IP binding enabled and IP matches."""
        config = SessionConfig(enable_ip_binding=True)
        token, session = create_session(
            db,
            test_user,
            ip_address="1.1.1.1",
            config=config,
        )
        db.commit()

        result = validate_session(
            db,
            token,
            ip_address="1.1.1.1",
            config=config,
        )

        assert result.is_valid is True

    def test_user_agent_binding_mismatch(
        self,
        db: DbSession,
        test_user: User,
    ) -> None:
        """Test rejection when UA binding is enabled and UA changes."""
        config = SessionConfig(enable_ua_binding=True)
        token, session = create_session(
            db,
            test_user,
            user_agent="Chrome",
            config=config,
        )
        db.commit()

        result = validate_session(
            db,
            token,
            user_agent="Firefox",
            config=config,
        )

        assert result.is_valid is False
        assert result.error_code == "SESSION_UA_MISMATCH"

    def test_disabled_user(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test rejection when user account is disabled."""
        token, session = create_session(db, test_user, config=test_config)
        test_user.is_active = False
        db.commit()

        result = validate_session(db, token, config=test_config)

        assert result.is_valid is False
        assert result.error_code == "ACCOUNT_DISABLED"

    def test_locked_user(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test rejection when user account is locked."""
        token, session = create_session(db, test_user, config=test_config)
        test_user.locked_until = datetime.utcnow() + timedelta(hours=1)
        db.commit()

        result = validate_session(db, token, config=test_config)

        assert result.is_valid is False
        assert result.error_code == "ACCOUNT_LOCKED"

    def test_updates_last_active(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test that validation updates last_active_at."""
        token, session = create_session(db, test_user, config=test_config)
        original_activity = session.last_active_at
        db.commit()

        # Small delay to ensure timestamp differs
        import time

        time.sleep(0.01)

        result = validate_session(db, token, config=test_config, update_activity=True)
        db.commit()

        assert result.is_valid is True
        # Refresh to get updated value
        db.refresh(session)
        assert session.last_active_at >= original_activity


# =============================================================================
# Session Validation Result Tests
# =============================================================================


class TestSessionValidationResult:
    """Tests for SessionValidationResult dataclass."""

    def test_success_factory(self, test_user: User) -> None:
        """Test success factory method."""
        session = Session(user_id=test_user.id, session_token_hash="hash")
        result = SessionValidationResult.success(test_user, session)

        assert result.is_valid is True
        assert result.user is test_user
        assert result.session is session
        assert result.error is None
        assert result.error_code is None

    def test_failure_factory(self) -> None:
        """Test failure factory method."""
        result = SessionValidationResult.failure(
            "Session expired",
            "SESSION_EXPIRED",
        )

        assert result.is_valid is False
        assert result.user is None
        assert result.session is None
        assert result.error == "Session expired"
        assert result.error_code == "SESSION_EXPIRED"


# =============================================================================
# Session Refresh Tests
# =============================================================================


class TestRefreshSession:
    """Tests for session refresh."""

    def test_extends_expiry(
        self,
        db: DbSession,
        test_user: User,
    ) -> None:
        """Test refresh extends session expiry."""
        config = SessionConfig(session_lifetime_hours=24)
        token, session = create_session(db, test_user, config=config)
        original_expiry = session.expires_at
        db.commit()

        # Simulate time passing
        import time

        time.sleep(0.01)

        refreshed = refresh_session(db, session, config=config)
        db.commit()

        assert refreshed.expires_at >= original_expiry

    def test_updates_last_active(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test refresh updates last_active_at."""
        token, session = create_session(db, test_user, config=test_config)
        original_active = session.last_active_at
        db.commit()

        import time

        time.sleep(0.01)

        refreshed = refresh_session(db, session, config=test_config)

        assert refreshed.last_active_at >= original_active


# =============================================================================
# Session Revocation Tests
# =============================================================================


class TestRevokeSession:
    """Tests for single session revocation."""

    def test_revokes_session(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test session is marked as revoked."""
        token, session = create_session(db, test_user, config=test_config)
        db.commit()

        revoke_session(db, session, reason="test_logout")
        db.commit()

        assert session.revoked_at is not None

    def test_creates_audit_log(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test revocation creates audit log."""
        token, session = create_session(db, test_user, config=test_config)
        db.commit()

        revoke_session(
            db,
            session,
            reason="user_logout",
            ip_address="10.0.0.1",
        )
        db.commit()

        audit = (
            db.query(AuthAuditLog)
            .filter(AuthAuditLog.event_type == AuditEventType.SESSION_REVOKED)
            .first()
        )

        assert audit is not None
        assert audit.user_id == test_user.id

    def test_revoked_session_invalid(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test revoked sessions fail validation."""
        token, session = create_session(db, test_user, config=test_config)
        db.commit()

        revoke_session(db, session)
        db.commit()

        result = validate_session(db, token, config=test_config)
        assert result.is_valid is False
        assert result.error_code == "SESSION_REVOKED"


class TestRevokeAllUserSessions:
    """Tests for bulk session revocation."""

    def test_revokes_all_sessions(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test all user sessions are revoked."""
        # Create multiple sessions
        tokens = []
        for _ in range(3):
            token, _ = create_session(db, test_user, config=test_config)
            tokens.append(token)
        db.commit()

        count = revoke_all_user_sessions(db, test_user.id, reason="security_event")
        db.commit()

        assert count == 3

        # All sessions should be invalid
        for token in tokens:
            result = validate_session(db, token, config=test_config)
            assert result.is_valid is False

    def test_except_current_session(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test revocation can exclude current session."""
        # Create multiple sessions
        tokens_and_sessions = []
        for _ in range(3):
            token, session = create_session(db, test_user, config=test_config)
            tokens_and_sessions.append((token, session))
        db.commit()

        # Keep the first session
        keep_token, keep_session = tokens_and_sessions[0]

        count = revoke_all_user_sessions(
            db,
            test_user.id,
            except_session_id=keep_session.id,
        )
        db.commit()

        assert count == 2

        # Kept session should still be valid
        result = validate_session(db, keep_token, config=test_config)
        assert result.is_valid is True

        # Others should be invalid
        for token, session in tokens_and_sessions[1:]:
            result = validate_session(db, token, config=test_config)
            assert result.is_valid is False


# =============================================================================
# Session Query Tests
# =============================================================================


class TestGetUserActiveSessions:
    """Tests for querying active sessions."""

    def test_returns_active_sessions(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test returns only active sessions."""
        # Create sessions
        for _ in range(3):
            create_session(db, test_user, config=test_config)
        db.commit()

        active = get_user_active_sessions(db, test_user.id)
        assert len(active) == 3

    def test_excludes_revoked(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test excludes revoked sessions."""
        token1, session1 = create_session(db, test_user, config=test_config)
        token2, session2 = create_session(db, test_user, config=test_config)
        session1.revoked_at = datetime.utcnow()
        db.commit()

        active = get_user_active_sessions(db, test_user.id)
        assert len(active) == 1
        assert active[0].id == session2.id

    def test_excludes_expired(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test excludes expired sessions."""
        token1, session1 = create_session(db, test_user, config=test_config)
        token2, session2 = create_session(db, test_user, config=test_config)
        session1.expires_at = datetime.utcnow() - timedelta(hours=1)
        db.commit()

        active = get_user_active_sessions(db, test_user.id)
        assert len(active) == 1
        assert active[0].id == session2.id


# =============================================================================
# Cleanup Tests
# =============================================================================


class TestCleanupExpiredSessions:
    """Tests for session cleanup."""

    def test_removes_old_expired_sessions(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test cleanup removes old expired sessions."""
        token, session = create_session(db, test_user, config=test_config)
        session_id = session.id  # Save ID before deletion
        # Set expiry to more than 1 day ago
        session.expires_at = datetime.utcnow() - timedelta(days=2)
        db.commit()

        count = cleanup_expired_sessions(db)
        db.commit()

        assert count == 1

        # Session should be deleted - query by saved ID
        remaining = db.query(Session).filter(Session.id == session_id).first()
        assert remaining is None

    def test_removes_old_revoked_sessions(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test cleanup removes old revoked sessions."""
        token, session = create_session(db, test_user, config=test_config)
        # Set revocation to more than 1 day ago
        session.revoked_at = datetime.utcnow() - timedelta(days=2)
        db.commit()

        count = cleanup_expired_sessions(db)
        db.commit()

        assert count == 1

    def test_keeps_recent_sessions(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test cleanup keeps recently expired/revoked sessions."""
        token, session = create_session(db, test_user, config=test_config)
        # Set expiry to just a few hours ago (within 1 day)
        session.expires_at = datetime.utcnow() - timedelta(hours=2)
        db.commit()

        count = cleanup_expired_sessions(db)
        db.commit()

        # Should not be deleted yet
        assert count == 0


# =============================================================================
# Session Limit Enforcement Tests
# =============================================================================


class TestEnforceSessionLimit:
    """Tests for session limit enforcement."""

    def test_removes_oldest_sessions(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test oldest sessions are removed when limit exceeded."""
        # Create 5 sessions with known order
        sessions = []
        for i in range(5):
            token, session = create_session(db, test_user, config=test_config)
            sessions.append(session)
            db.commit()

        # Enforce limit of 3
        removed = _enforce_session_limit(db, test_user.id, 3)
        db.commit()

        assert removed == 2

        # Newest 3 should remain active
        active = get_user_active_sessions(db, test_user.id)
        assert len(active) == 3


# =============================================================================
# Integration Tests
# =============================================================================


class TestSessionIntegration:
    """Integration tests for session management."""

    def test_full_session_lifecycle(
        self,
        db: DbSession,
        test_user: User,
        test_config: SessionConfig,
    ) -> None:
        """Test complete session lifecycle: create → validate → refresh → revoke."""
        # Create
        token, session = create_session(
            db,
            test_user,
            ip_address="192.168.1.1",
            user_agent="TestClient/1.0",
            config=test_config,
        )
        db.commit()
        original_expiry = session.expires_at

        # Validate
        result = validate_session(db, token, config=test_config)
        assert result.is_valid is True

        # Refresh (simulate time passing by manually adjusting)
        import time

        time.sleep(0.01)
        refreshed = refresh_session(db, session, config=test_config)
        db.commit()
        assert refreshed.expires_at >= original_expiry

        # Revoke
        revoke_session(db, session, reason="user_logout")
        db.commit()

        # Should no longer validate
        result = validate_session(db, token, config=test_config)
        assert result.is_valid is False
        assert result.error_code == "SESSION_REVOKED"

    def test_module_exports(self) -> None:
        """Test all expected functions are exported from auth module."""
        from amoskys.auth import (
            SessionConfig,
            SessionValidationResult,
            cleanup_expired_sessions,
            create_session,
            get_session_config,
            get_user_active_sessions,
            refresh_session,
            reset_session_config,
            revoke_all_user_sessions,
            revoke_session,
            validate_session,
        )

        # All should be importable
        assert SessionConfig is not None
        assert SessionValidationResult is not None
        assert callable(create_session)
        assert callable(validate_session)
        assert callable(refresh_session)
        assert callable(revoke_session)
        assert callable(revoke_all_user_sessions)
        assert callable(get_user_active_sessions)
        assert callable(cleanup_expired_sessions)
