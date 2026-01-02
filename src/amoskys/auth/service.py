"""
AMOSKYS Authentication Service

High-level authentication service providing complete auth workflows:
- User signup with email verification
- Login with optional MFA
- Password reset flow
- Session management
- Account management

This is the primary interface for auth operations. It orchestrates:
- Database operations (models)
- Password hashing (password.py)
- Token generation (tokens.py)
- Session management (sessions.py)
- Email notifications (notifications/)
- Audit logging

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    This service layer abstracts away the complexity of secure
    authentication. The frontend only needs to call these methods
    and handle the responses - all security logic is here.

Usage:
    from amoskys.auth.service import AuthService
    from amoskys.db import get_session_context

    with get_session_context() as db:
        auth = AuthService(db)
        result = auth.signup(email="user@example.com", password="SecurePass123!")
        if result.success:
            # User created, verification email sent
            pass
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session as DbSession

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
from amoskys.auth.password import hash_password, needs_rehash, verify_password
from amoskys.auth.password_policy import validate_password
from amoskys.auth.sessions import (
    SessionConfig,
    SessionValidationResult,
    create_session,
    get_session_config,
    revoke_all_user_sessions,
    revoke_session,
    validate_session,
)
from amoskys.auth.tokens import (
    generate_token,
    hash_token,
)
from amoskys.common.logging import get_logger

__all__ = [
    "AuthService",
    "AuthServiceConfig",
    "AuthResult",
    "SignupResult",
    "LoginResult",
    "PasswordResetResult",
]

logger = get_logger(__name__)


def _utcnow() -> datetime:
    """Get current UTC time as naive datetime for database compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class AuthServiceConfig:
    """Configuration for the AuthService."""

    # Email verification settings
    email_verification_hours: int = 24
    require_email_verification: bool = True

    # Password reset settings
    password_reset_hours: int = 1

    # Account lockout settings
    max_login_attempts: int = 5
    lockout_minutes: int = 15

    # Session settings (optional override)
    session_config: Optional[SessionConfig] = None


# =============================================================================
# Result Types
# =============================================================================


@dataclass
class AuthResult:
    """Base result type for auth operations."""

    success: bool
    error: Optional[str] = None
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "success": self.success,
            "error": self.error,
            "error_code": self.error_code,
        }


@dataclass
class SignupResult(AuthResult):
    """Result of signup operation."""

    user: Optional[User] = None
    verification_token: Optional[str] = None  # Raw token for email

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        result = super().to_dict()
        if self.user:
            result["user"] = {
                "id": str(self.user.id),
                "email": self.user.email,
            }
        return result


@dataclass
class LoginResult(AuthResult):
    """Result of login operation."""

    user: Optional[User] = None
    session: Optional[Session] = None
    session_token: Optional[str] = None  # Raw token for cookie
    requires_mfa: bool = False
    mfa_methods: List[MFAType] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        result = super().to_dict()
        if self.user:
            result["user"] = {
                "id": str(self.user.id),
                "email": self.user.email,
                "full_name": self.user.full_name,
            }
        result["requires_mfa"] = self.requires_mfa
        if self.mfa_methods:
            result["mfa_methods"] = [m.value for m in self.mfa_methods]
        return result


@dataclass
class PasswordResetResult(AuthResult):
    """Result of password reset request."""

    reset_token: Optional[str] = None  # Raw token for email

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        # Never expose token in API response - it's for email only
        return super().to_dict()


# =============================================================================
# Authentication Service
# =============================================================================


class AuthService:
    """
    High-level authentication service.

    This class provides the complete auth workflow for the application.
    All security logic is encapsulated here.
    """

    def __init__(
        self,
        db: DbSession,
        config: Optional[AuthServiceConfig] = None,
        session_config: Optional[SessionConfig] = None,
    ):
        """
        Initialize the auth service.

        Args:
            db: SQLAlchemy database session
            config: Optional auth service configuration
            session_config: Optional session configuration override
        """
        self.db = db
        self.config = config or AuthServiceConfig()
        self.session_config = (
            session_config or self.config.session_config or get_session_config()
        )

    # =========================================================================
    # Signup
    # =========================================================================

    def signup(
        self,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> SignupResult:
        """
        Register a new user account.

        Args:
            email: User's email address
            password: User's password (will be validated and hashed)
            full_name: Optional display name
            ip_address: IP address of the request (for audit)
            user_agent: User agent string (for audit)

        Returns:
            SignupResult with user and verification token if successful
        """
        # Normalize email
        email_clean = email.strip()
        email_normalized = email_clean.lower()

        # Check for existing user
        existing = (
            self.db.query(User)
            .filter(User.email_normalized == email_normalized)
            .first()
        )
        if existing:
            logger.warning(
                "signup_duplicate_email",
                email_normalized=email_normalized,
            )
            return SignupResult(
                success=False,
                error="An account with this email already exists",
                error_code="EMAIL_EXISTS",
            )

        # Validate password
        password_result = validate_password(password)
        if not password_result.is_valid:
            return SignupResult(
                success=False,
                error=(
                    password_result.errors[0]
                    if password_result.errors
                    else "Invalid password"
                ),
                error_code="INVALID_PASSWORD",
            )

        # Create user
        user = User(
            email=email_clean,
            email_normalized=email_normalized,
            password_hash=hash_password(password),
            full_name=full_name,
            role=UserRole.USER,
            is_active=True,
            is_verified=not self.config.require_email_verification,
        )
        self.db.add(user)
        self.db.flush()  # Get user ID without committing

        # Create email verification token
        verification_token = None
        if self.config.require_email_verification:
            verification_token = generate_token()
            token_record = EmailVerificationToken(
                user_id=user.id,
                token_hash=hash_token(verification_token),
                expires_at=_utcnow()
                + timedelta(hours=self.config.email_verification_hours),
            )
            self.db.add(token_record)

        # Create audit log
        self._log_audit(
            event_type=AuditEventType.SIGNUP,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"email": email_normalized},
        )

        self.db.commit()

        logger.info(
            "user_signup_success",
            user_id=str(user.id),
            email_normalized=email_normalized,
        )

        return SignupResult(
            success=True,
            user=user,
            verification_token=verification_token,
        )

    # =========================================================================
    # Email Verification
    # =========================================================================

    def verify_email(
        self,
        token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuthResult:
        """
        Verify a user's email address.

        Args:
            token: The verification token from the email
            ip_address: IP address of the request
            user_agent: User agent string

        Returns:
            AuthResult indicating success or failure
        """
        token_hash = hash_token(token)

        # Find valid token
        token_record = (
            self.db.query(EmailVerificationToken)
            .filter(
                EmailVerificationToken.token_hash == token_hash,
                EmailVerificationToken.consumed_at.is_(None),
                EmailVerificationToken.expires_at > _utcnow(),
            )
            .first()
        )

        if not token_record:
            logger.warning("email_verification_invalid_token")
            return AuthResult(
                success=False,
                error="Invalid or expired verification token",
                error_code="INVALID_TOKEN",
            )

        # Get user
        user = self.db.query(User).filter(User.id == token_record.user_id).first()
        if not user:
            return AuthResult(
                success=False,
                error="User not found",
                error_code="USER_NOT_FOUND",
            )

        # Mark user as verified
        user.is_verified = True

        # Mark token as consumed
        token_record.consumed_at = _utcnow()

        # Audit log
        self._log_audit(
            event_type=AuditEventType.EMAIL_VERIFIED,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.commit()

        logger.info(
            "email_verification_success",
            user_id=str(user.id),
        )

        return AuthResult(success=True)

    def resend_verification_email(
        self,
        email: str,
        ip_address: Optional[str] = None,
    ) -> SignupResult:
        """
        Resend verification email for unverified account.

        Args:
            email: User's email address
            ip_address: IP address of the request

        Returns:
            SignupResult with new verification token if successful
        """
        email_normalized = email.strip().lower()

        # Find user
        user = (
            self.db.query(User)
            .filter(User.email_normalized == email_normalized)
            .first()
        )

        if not user:
            # Don't reveal whether user exists
            logger.info("resend_verification_user_not_found", email=email_normalized)
            return SignupResult(
                success=True,  # Pretend success for security
            )

        if user.is_verified:
            return SignupResult(
                success=False,
                error="Email is already verified",
                error_code="ALREADY_VERIFIED",
            )

        # Invalidate old tokens
        self.db.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.consumed_at.is_(None),
        ).update({"consumed_at": _utcnow()})

        # Create new token
        verification_token = generate_token()
        token_record = EmailVerificationToken(
            user_id=user.id,
            token_hash=hash_token(verification_token),
            expires_at=_utcnow()
            + timedelta(hours=self.config.email_verification_hours),
        )
        self.db.add(token_record)

        self.db.commit()

        logger.info(
            "resend_verification_email",
            user_id=str(user.id),
        )

        return SignupResult(
            success=True,
            user=user,
            verification_token=verification_token,
        )

    # =========================================================================
    # Login
    # =========================================================================

    def login(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> LoginResult:
        """
        Authenticate user with email and password.

        Args:
            email: User's email address
            password: User's password
            ip_address: IP address of the request
            user_agent: User agent string

        Returns:
            LoginResult with session token if successful
        """
        email_normalized = email.strip().lower()

        # Find user
        user = (
            self.db.query(User)
            .filter(User.email_normalized == email_normalized)
            .first()
        )

        if not user:
            logger.warning("login_user_not_found", email=email_normalized)
            return LoginResult(
                success=False,
                error="Invalid email or password",
                error_code="INVALID_CREDENTIALS",
            )

        # Check if account is locked
        if user.locked_until and user.locked_until > _utcnow():
            remaining = (user.locked_until - _utcnow()).total_seconds() // 60
            logger.warning(
                "login_account_locked",
                user_id=str(user.id),
                remaining_minutes=remaining,
            )
            return LoginResult(
                success=False,
                error=f"Account is locked. Try again in {int(remaining)} minutes",
                error_code="ACCOUNT_LOCKED",
            )

        # Check if account is active
        if not user.is_active:
            logger.warning("login_account_inactive", user_id=str(user.id))
            return LoginResult(
                success=False,
                error="Account is deactivated",
                error_code="ACCOUNT_INACTIVE",
            )

        # Verify password
        if not verify_password(password, user.password_hash):
            # Increment failed attempts
            user.failed_login_count = (user.failed_login_count or 0) + 1

            # Check if we should lock the account
            if user.failed_login_count >= self.config.max_login_attempts:
                user.locked_until = _utcnow() + timedelta(
                    minutes=self.config.lockout_minutes
                )
                self._log_audit(
                    event_type=AuditEventType.ACCOUNT_LOCKED,
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"failed_attempts": user.failed_login_count},
                )
                logger.warning(
                    "account_locked_too_many_attempts",
                    user_id=str(user.id),
                    failed_attempts=user.failed_login_count,
                )

            self._log_audit(
                event_type=AuditEventType.LOGIN_FAILURE,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            self.db.commit()

            return LoginResult(
                success=False,
                error="Invalid email or password",
                error_code="INVALID_CREDENTIALS",
            )

        # Check email verification
        if self.config.require_email_verification and not user.is_verified:
            logger.warning("login_email_not_verified", user_id=str(user.id))
            return LoginResult(
                success=False,
                error="Please verify your email before logging in",
                error_code="EMAIL_NOT_VERIFIED",
            )

        # Rehash password if needed
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            logger.info("password_rehashed", user_id=str(user.id))

        # Clear failed attempts on successful login
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = _utcnow()

        # Check if MFA is required
        if user.mfa_enabled and user.mfa_type and user.mfa_type != MFAType.NONE:
            self.db.commit()

            return LoginResult(
                success=True,
                user=user,
                requires_mfa=True,
                mfa_methods=[user.mfa_type],
            )

        # Create session
        token, session = create_session(
            db=self.db,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            config=self.session_config,
        )

        self._log_audit(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"session_id": session.id},
        )

        self.db.commit()

        logger.info(
            "login_success",
            user_id=str(user.id),
            session_id=str(session.id),
        )

        return LoginResult(
            success=True,
            user=user,
            session=session,
            session_token=token,
        )

    # =========================================================================
    # Logout
    # =========================================================================

    def logout(
        self,
        session_token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuthResult:
        """
        Log out by revoking the current session.

        Args:
            session_token: The session token to revoke
            ip_address: IP address of the request
            user_agent: User agent string

        Returns:
            AuthResult indicating success or failure
        """
        # Validate and get session first
        result = validate_session(
            db=self.db,
            session_token=session_token,
            ip_address=None,  # Don't validate IP for logout
            user_agent=None,
            config=self.session_config,
        )

        if not result.is_valid:
            return AuthResult(
                success=False,
                error="Invalid or expired session",
                error_code="INVALID_SESSION",
            )

        session = result.session

        # Revoke the session
        revoke_session(
            db=self.db,
            session=session,
        )

        self._log_audit(
            event_type=AuditEventType.LOGOUT,
            user_id=session.user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"session_id": session.id},
        )
        self.db.commit()

        logger.info(
            "logout_success",
            user_id=str(session.user_id),
            session_id=str(session.id),
        )

        return AuthResult(success=True)

    def logout_all(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuthResult:
        """
        Log out from all devices by revoking all sessions.

        Args:
            user_id: The user ID to revoke all sessions for
            ip_address: IP address of the request
            user_agent: User agent string

        Returns:
            AuthResult indicating success or failure
        """
        count = revoke_all_user_sessions(db=self.db, user_id=user_id)

        self._log_audit(
            event_type=AuditEventType.SESSION_REVOKED,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"sessions_revoked": count, "reason": "logout_all"},
        )

        self.db.commit()

        logger.info(
            "logout_all_success",
            user_id=str(user_id),
            sessions_revoked=count,
        )

        return AuthResult(success=True)

    # =========================================================================
    # Password Reset
    # =========================================================================

    def request_password_reset(
        self,
        email: str,
        ip_address: Optional[str] = None,
    ) -> PasswordResetResult:
        """
        Request a password reset.

        Args:
            email: User's email address
            ip_address: IP address of the request

        Returns:
            PasswordResetResult with reset token if user exists
        """
        email_normalized = email.strip().lower()

        # Find user
        user = (
            self.db.query(User)
            .filter(User.email_normalized == email_normalized)
            .first()
        )

        if not user:
            # Don't reveal whether user exists
            logger.info("password_reset_user_not_found", email=email_normalized)
            return PasswordResetResult(success=True)  # Pretend success

        # Invalidate old tokens
        self.db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
        ).update({"consumed_at": _utcnow()})

        # Create new token
        reset_token = generate_token()
        token_record = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(reset_token),
            expires_at=_utcnow() + timedelta(hours=self.config.password_reset_hours),
        )
        self.db.add(token_record)

        self._log_audit(
            event_type=AuditEventType.PASSWORD_RESET_REQUEST,
            user_id=user.id,
            ip_address=ip_address,
        )

        self.db.commit()

        logger.info(
            "password_reset_requested",
            user_id=str(user.id),
        )

        return PasswordResetResult(
            success=True,
            reset_token=reset_token,
        )

    def reset_password(
        self,
        token: str,
        new_password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuthResult:
        """
        Reset password using a reset token.

        Args:
            token: The password reset token
            new_password: The new password
            ip_address: IP address of the request
            user_agent: User agent string

        Returns:
            AuthResult indicating success or failure
        """
        token_hash = hash_token(token)

        # Find valid token
        token_record = (
            self.db.query(PasswordResetToken)
            .filter(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.consumed_at.is_(None),
                PasswordResetToken.expires_at > _utcnow(),
            )
            .first()
        )

        if not token_record:
            logger.warning("password_reset_invalid_token")
            return AuthResult(
                success=False,
                error="Invalid or expired reset token",
                error_code="INVALID_TOKEN",
            )

        # Get user
        user = self.db.query(User).filter(User.id == token_record.user_id).first()
        if not user:
            return AuthResult(
                success=False,
                error="User not found",
                error_code="USER_NOT_FOUND",
            )

        # Validate new password
        password_result = validate_password(new_password)
        if not password_result.is_valid:
            return AuthResult(
                success=False,
                error=(
                    password_result.errors[0]
                    if password_result.errors
                    else "Invalid password"
                ),
                error_code="INVALID_PASSWORD",
            )

        # Update password
        user.password_hash = hash_password(new_password)
        user.password_changed_at = _utcnow()

        # Auto-verify email if not already verified
        # Users who can reset their password clearly have access to their email
        if not user.is_verified:
            user.is_verified = True
            user.verified_at = _utcnow()
            logger.info(
                "email_auto_verified_via_password_reset",
                user_id=str(user.id),
                email=user.email,
            )

        # Mark token as consumed
        token_record.consumed_at = _utcnow()

        # Clear lockout
        user.failed_login_count = 0
        user.locked_until = None

        # Revoke all sessions (security measure)
        revoke_all_user_sessions(db=self.db, user_id=user.id)

        self._log_audit(
            event_type=AuditEventType.PASSWORD_RESET_COMPLETE,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.commit()

        logger.info(
            "password_reset_success",
            user_id=str(user.id),
        )

        return AuthResult(success=True)

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuthResult:
        """
        Change password for authenticated user.

        Args:
            user_id: The user's ID
            current_password: Current password for verification
            new_password: The new password
            ip_address: IP address of the request
            user_agent: User agent string

        Returns:
            AuthResult indicating success or failure
        """
        # Get user
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return AuthResult(
                success=False,
                error="User not found",
                error_code="USER_NOT_FOUND",
            )

        # Verify current password
        if not verify_password(current_password, user.password_hash):
            self._log_audit(
                event_type=AuditEventType.LOGIN_FAILURE,  # Password verification failed
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"context": "password_change"},
            )
            return AuthResult(
                success=False,
                error="Current password is incorrect",
                error_code="INVALID_PASSWORD",
            )

        # Validate new password
        password_result = validate_password(new_password)
        if not password_result.is_valid:
            return AuthResult(
                success=False,
                error=(
                    password_result.errors[0]
                    if password_result.errors
                    else "Invalid password"
                ),
                error_code="INVALID_NEW_PASSWORD",
            )

        # Update password
        user.password_hash = hash_password(new_password)
        user.password_changed_at = _utcnow()

        self._log_audit(
            event_type=AuditEventType.PASSWORD_CHANGED,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.db.commit()

        logger.info(
            "password_changed",
            user_id=str(user.id),
        )

        return AuthResult(success=True)

    # =========================================================================
    # Session Validation
    # =========================================================================

    def validate_and_refresh_session(
        self,
        token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> SessionValidationResult:
        """
        Validate a session token and refresh if needed.

        This is the primary session validation method for middleware.

        Args:
            token: The session token
            ip_address: IP address of the request
            user_agent: User agent string

        Returns:
            SessionValidationResult with is_valid, user, session, error
        """
        result = validate_session(
            db=self.db,
            session_token=token,
            ip_address=ip_address,
            user_agent=user_agent,
            config=self.session_config,
        )

        if result.is_valid:
            self.db.commit()  # Save any refresh updates

        return result

    def get_current_user(self, session: Session) -> Optional[User]:
        """
        Get the user for a session.

        Args:
            session: The validated session

        Returns:
            User object or None
        """
        return self.db.query(User).filter(User.id == session.user_id).first()

    # =========================================================================
    # Account Management
    # =========================================================================

    def unlock_account(
        self,
        user_id: str,
        admin_user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuthResult:
        """
        Unlock a locked account (admin operation).

        Args:
            user_id: The user ID to unlock
            admin_user_id: The admin performing the action
            ip_address: IP address of the request

        Returns:
            AuthResult indicating success or failure
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return AuthResult(
                success=False,
                error="User not found",
                error_code="USER_NOT_FOUND",
            )

        user.failed_login_count = 0
        user.locked_until = None

        self._log_audit(
            event_type=AuditEventType.ACCOUNT_UNLOCKED,
            user_id=user.id,
            ip_address=ip_address,
            details={"admin_user_id": admin_user_id} if admin_user_id else None,
        )

        self.db.commit()

        logger.info(
            "account_unlocked",
            user_id=str(user.id),
            admin_id=str(admin_user_id) if admin_user_id else None,
        )

        return AuthResult(success=True)

    def deactivate_account(
        self,
        user_id: str,
        reason: Optional[str] = None,
        admin_user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuthResult:
        """
        Deactivate a user account.

        Args:
            user_id: The user ID to deactivate
            reason: Reason for deactivation
            admin_user_id: The admin performing the action
            ip_address: IP address of the request

        Returns:
            AuthResult indicating success or failure
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return AuthResult(
                success=False,
                error="User not found",
                error_code="USER_NOT_FOUND",
            )

        user.is_active = False

        # Revoke all sessions
        revoke_all_user_sessions(db=self.db, user_id=user.id)

        self._log_audit(
            event_type=AuditEventType.SETTINGS_CHANGED,
            user_id=user.id,
            ip_address=ip_address,
            details={
                "action": "account_deactivated",
                "reason": reason,
                "admin_user_id": admin_user_id,
            },
        )

        self.db.commit()

        logger.info(
            "account_deactivated",
            user_id=str(user.id),
            admin_id=str(admin_user_id) if admin_user_id else None,
        )

        return AuthResult(success=True)

    def reactivate_account(
        self,
        user_id: str,
        admin_user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> AuthResult:
        """
        Reactivate a deactivated account.

        Args:
            user_id: The user ID to reactivate
            admin_user_id: The admin performing the action
            ip_address: IP address of the request

        Returns:
            AuthResult indicating success or failure
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return AuthResult(
                success=False,
                error="User not found",
                error_code="USER_NOT_FOUND",
            )

        user.is_active = True
        user.failed_login_count = 0
        user.locked_until = None

        self._log_audit(
            event_type=AuditEventType.SETTINGS_CHANGED,
            user_id=user.id,
            ip_address=ip_address,
            details={
                "action": "account_reactivated",
                "admin_user_id": admin_user_id,
            },
        )

        self.db.commit()

        logger.info(
            "account_reactivated",
            user_id=str(user.id),
            admin_id=str(admin_user_id) if admin_user_id else None,
        )

        return AuthResult(success=True)

    # =========================================================================
    # Audit Logging
    # =========================================================================

    def _log_audit(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create an audit log entry."""
        audit_log = AuthAuditLog(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,
        )
        if details:
            audit_log.event_metadata = details
        self.db.add(audit_log)

    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        event_types: Optional[List[AuditEventType]] = None,
        limit: int = 100,
    ) -> List[AuthAuditLog]:
        """
        Get audit logs with optional filters.

        Args:
            user_id: Filter by user ID
            event_types: Filter by event types
            limit: Maximum number of records

        Returns:
            List of audit log entries
        """
        query = self.db.query(AuthAuditLog)

        if user_id:
            query = query.filter(AuthAuditLog.user_id == user_id)

        if event_types:
            query = query.filter(AuthAuditLog.event_type.in_(event_types))

        query = query.order_by(AuthAuditLog.created_at.desc())
        query = query.limit(limit)

        return query.all()
