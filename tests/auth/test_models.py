"""
Tests for AMOSKYS Authentication Data Models.

These tests verify the SQLAlchemy models for the auth system:
- User account creation and relationships
- Session management
- Token lifecycle (email verification, password reset)
- Audit logging
- Enum types and constraints

Test Strategy:
    - Use in-memory SQLite for fast, isolated tests
    - Each test gets a fresh database session
    - Test both happy path and edge cases
"""

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from amoskys.auth.models import (
    AuditEventType,
    AuthAuditLog,
    EmailVerificationToken,
    MFAType,
    PasswordResetToken,
)
from amoskys.auth.models import Session as AuthSession
from amoskys.auth.models import (
    User,
    UserRole,
)
from amoskys.db import Base

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="function")
def db_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    # Enable foreign key support in SQLite
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Create a fresh database session for each test."""
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def sample_user(db_session: Session) -> User:
    """Create a sample user for testing."""
    user = User(
        email="Test.User@Example.com",
        email_normalized="test.user@example.com",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$fakehash",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# =============================================================================
# User Model Tests
# =============================================================================


class TestUserModel:
    """Tests for the User model."""

    def test_create_user_minimal(self, db_session: Session):
        """Create user with minimal required fields."""
        user = User(
            email="user@example.com",
            email_normalized="user@example.com",
            password_hash="$argon2id$v=19$test",
        )
        db_session.add(user)
        db_session.commit()

        assert user.id is not None
        assert len(user.id) == 36  # UUID format
        assert user.is_active is True
        assert user.is_verified is False
        assert user.role == UserRole.USER
        assert user.mfa_enabled is False
        assert user.mfa_type == MFAType.NONE
        assert user.failed_login_count == 0

    def test_create_user_full(self, db_session: Session):
        """Create user with all fields."""
        user = User(
            email="Full.User@Example.com",
            email_normalized="full.user@example.com",
            password_hash="$argon2id$v=19$test",
            full_name="Full User",
            avatar_url="https://example.com/avatar.png",
            timezone="America/New_York",
            role=UserRole.ADMIN,
            is_verified=True,
            mfa_enabled=True,
            mfa_type=MFAType.TOTP,
            mfa_secret="encrypted_secret",
        )
        db_session.add(user)
        db_session.commit()

        assert user.full_name == "Full User"
        assert user.role == UserRole.ADMIN
        assert user.mfa_type == MFAType.TOTP

    def test_email_uniqueness(self, db_session: Session, sample_user: User):
        """Email should be unique."""
        from sqlalchemy.exc import IntegrityError

        duplicate = User(
            email="Different@Email.com",
            email_normalized="test.user@example.com",  # Same normalized email
            password_hash="hash",
        )
        db_session.add(duplicate)

        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_normalize_email(self, db_session: Session):
        """Email normalization should work."""
        user = User(
            email="  Upper.Case@Example.COM  ",
            email_normalized="",
            password_hash="hash",
        )
        user.normalize_email()

        assert user.email_normalized == "upper.case@example.com"

    def test_timestamps_auto_set(self, db_session: Session):
        """Created/updated timestamps should be set automatically."""
        user = User(
            email="time@example.com",
            email_normalized="time@example.com",
            password_hash="hash",
        )
        db_session.add(user)
        db_session.commit()

        assert user.created_at is not None
        assert user.updated_at is not None

    def test_user_repr(self, sample_user: User):
        """User repr should be useful for debugging."""
        repr_str = repr(sample_user)
        assert "User" in repr_str
        assert sample_user.id[:8] in repr_str


# =============================================================================
# Session Model Tests
# =============================================================================


class TestSessionModel:
    """Tests for the Session model."""

    def test_create_session(self, db_session: Session, sample_user: User):
        """Create a session for a user."""
        session = AuthSession(
            user_id=sample_user.id,
            session_token_hash="a" * 64,  # SHA-256 hex
            expires_at=datetime.utcnow() + timedelta(hours=24),
            user_agent="Mozilla/5.0 Test",
            ip_address="192.168.1.1",
        )
        db_session.add(session)
        db_session.commit()

        assert session.id is not None
        assert session.user_id == sample_user.id
        assert session.is_valid is True

    def test_session_is_valid_not_expired(self, db_session: Session, sample_user: User):
        """Valid session should return is_valid=True."""
        session = AuthSession(
            user_id=sample_user.id,
            session_token_hash="b" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(session)
        db_session.commit()

        assert session.is_valid is True

    def test_session_is_valid_expired(self, db_session: Session, sample_user: User):
        """Expired session should return is_valid=False."""
        session = AuthSession(
            user_id=sample_user.id,
            session_token_hash="c" * 64,
            expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired
        )
        db_session.add(session)
        db_session.commit()

        assert session.is_valid is False

    def test_session_is_valid_revoked(self, db_session: Session, sample_user: User):
        """Revoked session should return is_valid=False."""
        session = AuthSession(
            user_id=sample_user.id,
            session_token_hash="d" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            revoked_at=datetime.utcnow(),  # Revoked
        )
        db_session.add(session)
        db_session.commit()

        assert session.is_valid is False

    def test_session_cascade_delete(self, db_session: Session, sample_user: User):
        """Sessions should be deleted when user is deleted."""
        session = AuthSession(
            user_id=sample_user.id,
            session_token_hash="e" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(session)
        db_session.commit()
        session_id = session.id

        # Delete user
        db_session.delete(sample_user)
        db_session.commit()

        # Session should be gone
        result = db_session.query(AuthSession).filter_by(id=session_id).first()
        assert result is None


# =============================================================================
# Email Verification Token Tests
# =============================================================================


class TestEmailVerificationToken:
    """Tests for EmailVerificationToken model."""

    def test_create_token(self, db_session: Session, sample_user: User):
        """Create email verification token."""
        token = EmailVerificationToken(
            user_id=sample_user.id,
            token_hash="f" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )
        db_session.add(token)
        db_session.commit()

        assert token.id is not None
        assert token.is_valid is True
        assert token.consumed_at is None

    def test_token_consumed(self, db_session: Session, sample_user: User):
        """Consumed token should return is_valid=False."""
        token = EmailVerificationToken(
            user_id=sample_user.id,
            token_hash="g" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=24),
            consumed_at=datetime.utcnow(),
        )
        db_session.add(token)
        db_session.commit()

        assert token.is_valid is False

    def test_token_expired(self, db_session: Session, sample_user: User):
        """Expired token should return is_valid=False."""
        token = EmailVerificationToken(
            user_id=sample_user.id,
            token_hash="h" * 64,
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        db_session.add(token)
        db_session.commit()

        assert token.is_valid is False


# =============================================================================
# Password Reset Token Tests
# =============================================================================


class TestPasswordResetToken:
    """Tests for PasswordResetToken model."""

    def test_create_token(self, db_session: Session, sample_user: User):
        """Create password reset token."""
        token = PasswordResetToken(
            user_id=sample_user.id,
            token_hash="i" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(token)
        db_session.commit()

        assert token.id is not None
        assert token.is_valid is True

    def test_token_short_expiry(self, db_session: Session, sample_user: User):
        """Password reset tokens typically have short expiry."""
        # Simulate a token that expired 30 minutes ago
        token = PasswordResetToken(
            user_id=sample_user.id,
            token_hash="j" * 64,
            expires_at=datetime.utcnow() - timedelta(minutes=30),
        )
        db_session.add(token)
        db_session.commit()

        assert token.is_valid is False


# =============================================================================
# Auth Audit Log Tests
# =============================================================================


class TestAuthAuditLog:
    """Tests for AuthAuditLog model."""

    def test_create_audit_log(self, db_session: Session, sample_user: User):
        """Create audit log entry."""
        log = AuthAuditLog(
            user_id=sample_user.id,
            event_type=AuditEventType.LOGIN_SUCCESS,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )
        db_session.add(log)
        db_session.commit()

        assert log.id is not None
        assert log.event_type == AuditEventType.LOGIN_SUCCESS
        assert log.created_at is not None

    def test_audit_log_without_user(self, db_session: Session):
        """Audit log can exist without user (e.g., failed login)."""
        log = AuthAuditLog(
            user_id=None,
            event_type=AuditEventType.LOGIN_FAILURE,
            ip_address="10.0.0.1",
        )
        log.event_metadata = {
            "email": "unknown@example.com",
            "reason": "user_not_found",
        }
        db_session.add(log)
        db_session.commit()

        assert log.id is not None
        assert log.user_id is None
        assert log.event_metadata["email"] == "unknown@example.com"

    def test_audit_log_metadata(self, db_session: Session, sample_user: User):
        """Audit log metadata should serialize/deserialize correctly."""
        log = AuthAuditLog(
            user_id=sample_user.id,
            event_type=AuditEventType.SETTINGS_CHANGED,
        )
        log.event_metadata = {
            "changes": ["timezone", "full_name"],
            "old_timezone": "UTC",
            "new_timezone": "America/New_York",
        }
        db_session.add(log)
        db_session.commit()

        # Refresh and check metadata
        db_session.refresh(log)
        assert log.event_metadata["changes"] == ["timezone", "full_name"]

    def test_audit_log_set_null_on_user_delete(
        self, db_session: Session, sample_user: User
    ):
        """Audit logs should persist with NULL user_id when user deleted."""
        log = AuthAuditLog(
            user_id=sample_user.id,
            event_type=AuditEventType.LOGIN_SUCCESS,
        )
        db_session.add(log)
        db_session.commit()
        log_id = log.id

        # Delete user
        db_session.delete(sample_user)
        db_session.commit()

        # Log should still exist with NULL user_id
        result = db_session.query(AuthAuditLog).filter_by(id=log_id).first()
        assert result is not None
        assert result.user_id is None

    def test_all_event_types_valid(self, db_session: Session):
        """All event types should be usable."""
        for event_type in AuditEventType:
            log = AuthAuditLog(event_type=event_type)
            db_session.add(log)

        db_session.commit()
        count = db_session.query(AuthAuditLog).count()
        assert count == len(AuditEventType)


# =============================================================================
# Relationship Tests
# =============================================================================


class TestRelationships:
    """Tests for model relationships."""

    def test_user_sessions_relationship(self, db_session: Session, sample_user: User):
        """User should have access to their sessions."""
        session1 = AuthSession(
            user_id=sample_user.id,
            session_token_hash="k" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        session2 = AuthSession(
            user_id=sample_user.id,
            session_token_hash="l" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=2),
        )
        db_session.add_all([session1, session2])
        db_session.commit()

        # Access through relationship
        db_session.refresh(sample_user)
        sessions = list(sample_user.sessions)
        assert len(sessions) == 2

    def test_session_user_relationship(self, db_session: Session, sample_user: User):
        """Session should have access to its user."""
        session = AuthSession(
            user_id=sample_user.id,
            session_token_hash="m" * 64,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(session)
        db_session.commit()

        db_session.refresh(session)
        assert session.user.email == sample_user.email


# =============================================================================
# Enum Tests
# =============================================================================


class TestEnums:
    """Tests for enum types."""

    def test_user_role_values(self):
        """UserRole should have expected values."""
        assert UserRole.USER.value == "user"
        assert UserRole.ADMIN.value == "admin"

    def test_mfa_type_values(self):
        """MFAType should have expected values."""
        assert MFAType.NONE.value == "none"
        assert MFAType.TOTP.value == "totp"
        assert MFAType.EMAIL.value == "email"

    def test_audit_event_types_comprehensive(self):
        """AuditEventType should cover all security events."""
        event_names = [e.value for e in AuditEventType]

        # Core auth events
        assert "login_success" in event_names
        assert "login_failure" in event_names
        assert "logout" in event_names
        assert "signup" in event_names

        # Email verification
        assert "email_verified" in event_names

        # Password
        assert "password_reset_request" in event_names
        assert "password_reset_complete" in event_names

        # MFA
        assert "mfa_enabled" in event_names
        assert "mfa_disabled" in event_names

        # Sessions
        assert "session_revoked" in event_names
