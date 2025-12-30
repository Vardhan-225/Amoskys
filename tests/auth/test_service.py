"""
Tests for AMOSKYS Authentication Service

Comprehensive test coverage for:
- User signup flow
- Email verification
- Login with password
- Logout (single and all devices)
- Password reset flow
- Password change
- Account lockout

Test Philosophy:
    The auth service is the security perimeter. Every edge case
    and attack vector must be tested.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from amoskys.auth.models import (
    AuditEventType,
    AuthAuditLog,
    EmailVerificationToken,
    MFAType,
    PasswordResetToken,
    Session,
    User,
    UserRole,
)
from amoskys.auth.password import hash_password
from amoskys.auth.service import (
    AuthResult,
    AuthService,
    AuthServiceConfig,
    LoginResult,
    PasswordResetResult,
    SignupResult,
)
from amoskys.auth.sessions import SessionConfig
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
def auth_config() -> AuthServiceConfig:
    """Create test auth configuration."""
    return AuthServiceConfig(
        email_verification_hours=24,
        password_reset_hours=1,
        max_login_attempts=3,
        lockout_minutes=15,
        require_email_verification=True,
    )


@pytest.fixture
def session_config() -> SessionConfig:
    """Create test session configuration."""
    return SessionConfig(
        session_lifetime_hours=24,
        idle_timeout_hours=2,
        max_sessions_per_user=5,
    )


@pytest.fixture
def auth_service(
    db: DbSession,
    auth_config: AuthServiceConfig,
    session_config: SessionConfig,
) -> AuthService:
    """Create auth service for testing."""
    return AuthService(db, config=auth_config, session_config=session_config)


@pytest.fixture
def verified_user(db: DbSession) -> User:
    """Create a verified test user."""
    user = User(
        email="verified@example.com",
        email_normalized="verified@example.com",
        password_hash=hash_password("VerifiedPass123!"),
        full_name="Verified User",
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def unverified_user(db: DbSession) -> User:
    """Create an unverified test user."""
    user = User(
        email="unverified@example.com",
        email_normalized="unverified@example.com",
        password_hash=hash_password("UnverifiedPass123!"),
        full_name="Unverified User",
        role=UserRole.USER,
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    db.commit()
    return user


# =============================================================================
# Signup Tests
# =============================================================================


class TestSignup:
    """Tests for user signup."""

    def test_signup_success(self, auth_service: AuthService) -> None:
        """Test successful signup."""
        result = auth_service.signup(
            email="newuser@example.com",
            password="SecurePassword123!",
            full_name="New User",
            ip_address="192.168.1.1",
        )

        assert result.success is True
        assert result.user is not None
        assert result.user.email == "newuser@example.com"
        assert result.user.email_normalized == "newuser@example.com"
        assert result.user.is_verified is False  # Verification required
        assert result.verification_token is not None

    def test_signup_normalizes_email(self, auth_service: AuthService) -> None:
        """Test email is normalized to lowercase."""
        result = auth_service.signup(
            email="  NewUser@EXAMPLE.COM  ",
            password="SecurePassword123!",
        )

        assert result.success is True
        assert result.user.email == "NewUser@EXAMPLE.COM"
        assert result.user.email_normalized == "newuser@example.com"

    def test_signup_duplicate_email(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test signup fails with duplicate email."""
        result = auth_service.signup(
            email="verified@example.com",
            password="SecurePassword123!",
        )

        assert result.success is False
        assert result.error_code == "EMAIL_EXISTS"

    def test_signup_duplicate_email_case_insensitive(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test signup fails with case-variant duplicate email."""
        result = auth_service.signup(
            email="VERIFIED@EXAMPLE.COM",
            password="SecurePassword123!",
        )

        assert result.success is False
        assert result.error_code == "EMAIL_EXISTS"

    def test_signup_weak_password(self, auth_service: AuthService) -> None:
        """Test signup fails with weak password."""
        result = auth_service.signup(
            email="newuser@example.com",
            password="weak",
        )

        assert result.success is False
        assert result.error_code == "INVALID_PASSWORD"

    def test_signup_creates_verification_token(
        self,
        auth_service: AuthService,
        db: DbSession,
    ) -> None:
        """Test signup creates email verification token."""
        result = auth_service.signup(
            email="tokentest@example.com",
            password="SecurePassword123!",
        )

        assert result.success is True

        # Check token was stored
        token_record = (
            db.query(EmailVerificationToken)
            .filter(EmailVerificationToken.user_id == result.user.id)
            .first()
        )
        assert token_record is not None
        assert token_record.token_hash == hash_token(result.verification_token)

    def test_signup_creates_audit_log(
        self,
        auth_service: AuthService,
        db: DbSession,
    ) -> None:
        """Test signup creates audit log entry."""
        result = auth_service.signup(
            email="auditlog@example.com",
            password="SecurePassword123!",
            ip_address="10.0.0.1",
        )

        db.commit()

        audit = (
            db.query(AuthAuditLog)
            .filter(AuthAuditLog.event_type == AuditEventType.SIGNUP)
            .first()
        )
        assert audit is not None
        assert audit.user_id == result.user.id
        assert audit.ip_address == "10.0.0.1"

    def test_signup_without_verification_required(
        self,
        db: DbSession,
        session_config: SessionConfig,
    ) -> None:
        """Test signup when verification is not required."""
        config = AuthServiceConfig(require_email_verification=False)
        service = AuthService(db, config=config, session_config=session_config)

        result = service.signup(
            email="noverify@example.com",
            password="SecurePassword123!",
        )

        assert result.success is True
        assert result.user.is_verified is True
        assert result.verification_token is None


# =============================================================================
# Email Verification Tests
# =============================================================================


class TestEmailVerification:
    """Tests for email verification."""

    def test_verify_email_success(
        self,
        auth_service: AuthService,
        db: DbSession,
    ) -> None:
        """Test successful email verification."""
        # Create user and get verification token
        signup_result = auth_service.signup(
            email="toverify@example.com",
            password="SecurePassword123!",
        )
        db.commit()

        # Verify email
        result = auth_service.verify_email(signup_result.verification_token)
        db.commit()

        assert result.success is True

        # User should now be verified
        user = db.get(User, signup_result.user.id)
        assert user.is_verified is True

    def test_verify_email_invalid_token(self, auth_service: AuthService) -> None:
        """Test verification fails with invalid token."""
        result = auth_service.verify_email("invalid_token_here")

        assert result.success is False
        assert result.error_code == "INVALID_TOKEN"

    def test_verify_email_expired_token(
        self,
        auth_service: AuthService,
        db: DbSession,
    ) -> None:
        """Test verification fails with expired token."""
        signup_result = auth_service.signup(
            email="expired@example.com",
            password="SecurePassword123!",
        )

        # Expire the token
        token = (
            db.query(EmailVerificationToken)
            .filter(EmailVerificationToken.user_id == signup_result.user.id)
            .first()
        )
        token.expires_at = datetime.utcnow() - timedelta(hours=1)
        db.commit()

        result = auth_service.verify_email(signup_result.verification_token)

        assert result.success is False
        assert result.error_code == "INVALID_TOKEN"

    def test_verify_email_already_used(
        self,
        auth_service: AuthService,
        db: DbSession,
    ) -> None:
        """Test verification fails if token already used."""
        signup_result = auth_service.signup(
            email="doubleuse@example.com",
            password="SecurePassword123!",
        )
        db.commit()

        # First verification
        result1 = auth_service.verify_email(signup_result.verification_token)
        db.commit()
        assert result1.success is True

        # Second attempt should fail
        result2 = auth_service.verify_email(signup_result.verification_token)
        assert result2.success is False
        assert result2.error_code == "INVALID_TOKEN"

    def test_resend_verification_email(
        self,
        auth_service: AuthService,
        unverified_user: User,
        db: DbSession,
    ) -> None:
        """Test resending verification email."""
        result = auth_service.resend_verification_email(
            email="unverified@example.com",
        )

        assert result.success is True
        assert result.verification_token is not None

    def test_resend_verification_already_verified(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test resend fails for already verified user."""
        result = auth_service.resend_verification_email(
            email="verified@example.com",
        )

        assert result.success is False
        assert result.error_code == "ALREADY_VERIFIED"


# =============================================================================
# Login Tests
# =============================================================================


class TestLogin:
    """Tests for user login."""

    def test_login_success(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test successful login."""
        result = auth_service.login(
            email="verified@example.com",
            password="VerifiedPass123!",
            ip_address="192.168.1.1",
            user_agent="TestClient/1.0",
        )

        assert result.success is True
        assert result.user is not None
        assert result.user.id == verified_user.id
        assert result.session_token is not None
        assert result.requires_mfa is False

    def test_login_wrong_password(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test login fails with wrong password."""
        result = auth_service.login(
            email="verified@example.com",
            password="WrongPassword123!",
        )

        assert result.success is False
        assert result.error_code == "INVALID_CREDENTIALS"

    def test_login_nonexistent_user(self, auth_service: AuthService) -> None:
        """Test login fails for nonexistent user."""
        result = auth_service.login(
            email="nonexistent@example.com",
            password="SomePassword123!",
        )

        assert result.success is False
        assert result.error_code == "INVALID_CREDENTIALS"

    def test_login_unverified_user(
        self,
        auth_service: AuthService,
        unverified_user: User,
    ) -> None:
        """Test login fails for unverified user."""
        result = auth_service.login(
            email="unverified@example.com",
            password="UnverifiedPass123!",
        )

        assert result.success is False
        assert result.error_code == "EMAIL_NOT_VERIFIED"

    def test_login_disabled_account(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test login fails for disabled account."""
        verified_user.is_active = False
        db.commit()

        result = auth_service.login(
            email="verified@example.com",
            password="VerifiedPass123!",
        )

        assert result.success is False
        assert result.error_code == "ACCOUNT_INACTIVE"

    def test_login_account_lockout(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test account locks after too many failed attempts."""
        # Try wrong password 3 times (config.max_login_attempts)
        for _ in range(3):
            auth_service.login(
                email="verified@example.com",
                password="WrongPassword!",
            )
            db.commit()

        # Account should be locked
        result = auth_service.login(
            email="verified@example.com",
            password="VerifiedPass123!",  # Even correct password fails
        )

        assert result.success is False
        assert result.error_code == "ACCOUNT_LOCKED"

    def test_login_resets_failed_attempts(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test successful login resets failed attempts."""
        # Fail once
        auth_service.login(
            email="verified@example.com",
            password="WrongPassword!",
        )
        db.commit()

        db.refresh(verified_user)
        assert verified_user.failed_login_count == 1

        # Success resets counter
        auth_service.login(
            email="verified@example.com",
            password="VerifiedPass123!",
        )
        db.commit()

        db.refresh(verified_user)
        assert verified_user.failed_login_count == 0

    def test_login_updates_last_login(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test login updates last_login_at timestamp."""
        original = verified_user.last_login_at

        auth_service.login(
            email="verified@example.com",
            password="VerifiedPass123!",
        )
        db.commit()

        db.refresh(verified_user)
        assert verified_user.last_login_at is not None
        if original:
            assert verified_user.last_login_at >= original


# =============================================================================
# Logout Tests
# =============================================================================


class TestLogout:
    """Tests for user logout."""

    def test_logout_success(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test successful logout."""
        # Login first
        login_result = auth_service.login(
            email="verified@example.com",
            password="VerifiedPass123!",
        )
        db.commit()

        # Logout
        result = auth_service.logout(login_result.session_token)
        db.commit()

        assert result.success is True

        # Session should be invalid
        from amoskys.auth.sessions import validate_session

        validation = validate_session(db, login_result.session_token)
        assert validation.is_valid is False

    def test_logout_invalid_session(self, auth_service: AuthService) -> None:
        """Test logout with invalid session."""
        result = auth_service.logout("invalid_session_token_here")

        assert result.success is False
        assert result.error_code == "INVALID_SESSION"

    def test_logout_all_devices(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test logout from all devices."""
        # Create multiple sessions
        tokens = []
        for _ in range(3):
            result = auth_service.login(
                email="verified@example.com",
                password="VerifiedPass123!",
            )
            tokens.append(result.session_token)
            db.commit()

        # Logout all sessions
        result = auth_service.logout_all(verified_user.id)
        db.commit()

        assert result.success is True

        # All sessions should be invalid
        from amoskys.auth.sessions import validate_session

        assert validate_session(db, tokens[0]).is_valid is False
        assert validate_session(db, tokens[1]).is_valid is False
        assert validate_session(db, tokens[2]).is_valid is False


# =============================================================================
# Password Reset Tests
# =============================================================================


class TestPasswordReset:
    """Tests for password reset flow."""

    def test_request_reset_success(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test password reset request."""
        result = auth_service.request_password_reset(
            email="verified@example.com",
        )

        assert result.success is True
        assert result.reset_token is not None

    def test_request_reset_unknown_email(
        self,
        auth_service: AuthService,
    ) -> None:
        """Test reset request doesn't reveal unknown emails."""
        result = auth_service.request_password_reset(
            email="unknown@example.com",
        )

        # Should return success (don't reveal if email exists)
        assert result.success is True
        assert result.reset_token is None

    def test_reset_password_success(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test password reset with valid token."""
        # Request reset
        reset_result = auth_service.request_password_reset(
            email="verified@example.com",
        )
        db.commit()

        # Reset password
        result = auth_service.reset_password(
            token=reset_result.reset_token,
            new_password="NewSecurePass456!",
        )
        db.commit()

        assert result.success is True

        # Should be able to login with new password
        login_result = auth_service.login(
            email="verified@example.com",
            password="NewSecurePass456!",
        )
        assert login_result.success is True

    def test_reset_password_invalid_token(
        self,
        auth_service: AuthService,
    ) -> None:
        """Test reset fails with invalid token."""
        result = auth_service.reset_password(
            token="invalid_token",
            new_password="NewPassword123!",
        )

        assert result.success is False
        assert result.error_code == "INVALID_TOKEN"

    def test_reset_password_revokes_sessions(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test password reset revokes all sessions."""
        # Login to create session
        login_result = auth_service.login(
            email="verified@example.com",
            password="VerifiedPass123!",
        )
        db.commit()

        # Request and complete reset
        reset_result = auth_service.request_password_reset(
            email="verified@example.com",
        )
        db.commit()

        auth_service.reset_password(
            token=reset_result.reset_token,
            new_password="NewSecurePass456!",
        )
        db.commit()

        # Old session should be invalid
        from amoskys.auth.sessions import validate_session

        validation = validate_session(db, login_result.session_token)
        assert validation.is_valid is False


# =============================================================================
# Password Change Tests
# =============================================================================


class TestPasswordChange:
    """Tests for authenticated password change."""

    def test_change_password_success(
        self,
        auth_service: AuthService,
        verified_user: User,
        db: DbSession,
    ) -> None:
        """Test password change with correct current password."""
        result = auth_service.change_password(
            user_id=verified_user.id,
            current_password="VerifiedPass123!",
            new_password="NewSecurePass456!",
        )
        db.commit()

        assert result.success is True

        # Should be able to login with new password
        login_result = auth_service.login(
            email="verified@example.com",
            password="NewSecurePass456!",
        )
        assert login_result.success is True

    def test_change_password_wrong_current(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test change fails with wrong current password."""
        result = auth_service.change_password(
            user_id=verified_user.id,
            current_password="WrongPassword!",
            new_password="NewSecurePass456!",
        )

        assert result.success is False
        assert result.error_code == "INVALID_PASSWORD"

    def test_change_password_weak_new(
        self,
        auth_service: AuthService,
        verified_user: User,
    ) -> None:
        """Test change fails with weak new password."""
        result = auth_service.change_password(
            user_id=verified_user.id,
            current_password="VerifiedPass123!",
            new_password="weak",
        )

        assert result.success is False
        assert result.error_code == "INVALID_NEW_PASSWORD"


# =============================================================================
# Integration Tests
# =============================================================================


class TestAuthServiceIntegration:
    """Integration tests for auth service."""

    def test_full_signup_to_login_flow(
        self,
        auth_service: AuthService,
        db: DbSession,
    ) -> None:
        """Test complete user journey: signup → verify → login."""
        # Signup
        signup_result = auth_service.signup(
            email="journey@example.com",
            password="JourneyPass123!",
            full_name="Journey User",
        )
        db.commit()
        assert signup_result.success is True

        # Can't login yet (unverified)
        login_attempt = auth_service.login(
            email="journey@example.com",
            password="JourneyPass123!",
        )
        assert login_attempt.success is False
        assert login_attempt.error_code == "EMAIL_NOT_VERIFIED"

        # Verify email
        verify_result = auth_service.verify_email(signup_result.verification_token)
        db.commit()
        assert verify_result.success is True

        # Now can login
        login_result = auth_service.login(
            email="journey@example.com",
            password="JourneyPass123!",
        )
        assert login_result.success is True
        assert login_result.session_token is not None

    def test_module_exports(self) -> None:
        """Test all expected classes are exported from auth module."""
        from amoskys.auth import (
            AuthResult,
            AuthService,
            AuthServiceConfig,
            LoginResult,
            PasswordResetResult,
            SignupResult,
        )

        assert AuthService is not None
        assert AuthServiceConfig is not None
        assert AuthResult is not None
        assert SignupResult is not None
        assert LoginResult is not None
        assert PasswordResetResult is not None
