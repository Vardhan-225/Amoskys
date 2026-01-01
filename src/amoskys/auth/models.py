"""
AMOSKYS Authentication Data Models

SQLAlchemy models for the authentication and authorization system.
These models support:
- User accounts with secure password storage
- Server-side session management
- Email verification workflows
- Password reset workflows
- Security audit logging

Design Principles:
    1. Never store plaintext tokens or passwords (hashes only)
    2. All tokens have explicit expiration
    3. Cascade deletes protect referential integrity
    4. Audit logging for security-critical events
    5. Prepared for MFA and multi-tenant extensions

Schema Version: 1.0.0 (P3-001)

Example Usage:
    >>> from amoskys.auth.models import User
    >>> from amoskys.auth.password import hash_password
    >>> user = User(
    ...     email="user@example.com",
    ...     email_normalized="user@example.com",
    ...     password_hash=hash_password("SecurePass123!"),
    ... )
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from amoskys.db import Base, TimestampMixin

__all__ = [
    # Enums
    "UserRole",
    "MFAType",
    "AuditEventType",
    # Models
    "User",
    "Session",
    "EmailVerificationToken",
    "PasswordResetToken",
    "AuthAuditLog",
]


# =============================================================================
# Enum Types
# =============================================================================


class UserRole(str, enum.Enum):
    """User authorization roles."""

    USER = "user"
    ADMIN = "admin"


class MFAType(str, enum.Enum):
    """Multi-factor authentication types."""

    NONE = "none"
    TOTP = "totp"  # Time-based One-Time Password (Google Authenticator, etc.)
    EMAIL = "email"  # Email-based OTP


class AuditEventType(str, enum.Enum):
    """Security audit event types for auth operations."""

    # Account lifecycle
    SIGNUP = "signup"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ACCOUNT_SUSPENDED = "account_suspended"
    ACCOUNT_DELETED = "account_deleted"
    SETTINGS_CHANGED = "settings_changed"

    # Authentication
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"

    # Email verification
    EMAIL_VERIFICATION_SENT = "email_verification_sent"
    EMAIL_VERIFIED = "email_verified"

    # Password management
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_COMPLETE = "password_reset_complete"
    PASSWORD_CHANGED = "password_changed"

    # MFA
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFIED = "mfa_verified"
    MFA_FAILED = "mfa_failed"

    # Session management
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    SESSION_EXPIRED = "session_expired"

    # API keys
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"


# =============================================================================
# User Model
# =============================================================================


class User(TimestampMixin, Base):
    """
    Core user account model.

    Security Features:
        - Password stored as Argon2id hash (never plaintext)
        - Email normalized for case-insensitive lookups
        - MFA support with encrypted TOTP secret
        - Soft-disable via is_active flag
        - Email verification tracking

    Attributes:
        id: UUID primary key
        email: User's email address (display format)
        email_normalized: Lowercase email for lookups
        password_hash: Argon2id hash of password
        full_name: Optional display name
        role: Authorization role (user/admin)
        is_active: Account enabled flag
        is_verified: Email verified flag
        mfa_enabled: MFA active flag
        mfa_type: Type of MFA (none/totp/email)
        mfa_secret: Encrypted TOTP secret
        last_login_at: Last successful login timestamp
        password_changed_at: Last password change timestamp
    """

    __tablename__ = "users"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Email (stored in original case, normalized version for lookups)
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )
    email_normalized: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    # Password (Argon2id hash)
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Profile
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500))
    timezone: Mapped[str] = mapped_column(
        String(50),
        default="UTC",
        nullable=False,
    )

    # Authorization
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", create_constraint=True),
        default=UserRole.USER,
        nullable=False,
    )

    # Account status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # MFA configuration
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    mfa_type: Mapped[MFAType] = mapped_column(
        Enum(MFAType, name="mfa_type", create_constraint=True),
        default=MFAType.NONE,
        nullable=False,
    )
    mfa_secret: Mapped[Optional[str]] = mapped_column(
        String(255),
    )  # Encrypted TOTP secret

    # Backup codes (JSON array of hashed codes)
    backup_codes_hash: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamps
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Security: Failed login tracking for rate limiting
    failed_login_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationships
    sessions: Mapped[List["Session"]] = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    email_verification_tokens: Mapped[List["EmailVerificationToken"]] = relationship(
        "EmailVerificationToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    password_reset_tokens: Mapped[List["PasswordResetToken"]] = relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    audit_logs: Mapped[List["AuthAuditLog"]] = relationship(
        "AuthAuditLog",
        back_populates="user",
        passive_deletes=True,  # Let DB handle SET NULL, don't cascade delete
        lazy="dynamic",
    )

    def normalize_email(self) -> None:
        """Normalize email for consistent lookups."""
        if self.email:
            self.email_normalized = self.email.strip().lower()

    def __repr__(self) -> str:
        return f"<User id={self.id[:8]}... email={self.email}>"


# =============================================================================
# Session Model
# =============================================================================


class Session(TimestampMixin, Base):
    """
    Server-side session for authenticated users.

    Security Features:
        - Session token stored as hash (never plaintext)
        - Explicit expiration for automatic cleanup
        - Revocation support for forced logout
        - IP/User-Agent tracking for anomaly detection
        - Last activity tracking for idle timeout

    Attributes:
        id: UUID primary key
        user_id: Foreign key to User
        session_token_hash: SHA-256 hash of session token
        user_agent: Browser/client user agent string
        ip_address: Client IP address (IPv4 or IPv6)
        expires_at: Session expiration timestamp
        revoked_at: Revocation timestamp (if revoked)
        last_active_at: Last request timestamp
    """

    __tablename__ = "sessions"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # User relationship
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Session token (hash only, never store plaintext)
    session_token_hash: Mapped[str] = mapped_column(
        String(64),  # SHA-256 hex digest
        nullable=False,
        index=True,
    )

    # Client identification
    user_agent: Mapped[Optional[str]] = mapped_column(String(500))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv4 or IPv6

    # Lifecycle
    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        index=True,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_active_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationship
    user: Mapped[User] = relationship("User", back_populates="sessions")

    # Indexes
    __table_args__ = (
        Index("ix_sessions_user_expires", "user_id", "expires_at"),
        Index("ix_sessions_token_hash", "session_token_hash"),
    )

    @property
    def is_valid(self) -> bool:
        """Check if session is currently valid (not expired or revoked)."""
        now = datetime.utcnow()
        if self.revoked_at is not None:
            return False
        if self.expires_at < now:
            return False
        return True

    def __repr__(self) -> str:
        return f"<Session id={self.id[:8]}... user_id={self.user_id[:8]}...>"


# =============================================================================
# Email Verification Token Model
# =============================================================================


class EmailVerificationToken(TimestampMixin, Base):
    """
    Token for email verification during signup.

    Security Features:
        - Token stored as hash (never plaintext)
        - Explicit expiration (typically 24 hours)
        - Single-use (consumed_at tracking)
        - Cascade delete with user

    Workflow:
        1. User signs up → token generated, hash stored, plaintext emailed
        2. User clicks link → plaintext token submitted
        3. System hashes submitted token, compares with stored hash
        4. If match and not expired → mark consumed, verify user

    Attributes:
        id: UUID primary key
        user_id: Foreign key to User
        token_hash: SHA-256 hash of verification token
        expires_at: Token expiration timestamp
        consumed_at: When token was used (null if unused)
    """

    __tablename__ = "email_verification_tokens"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # User relationship
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Token (hash only)
    token_hash: Mapped[str] = mapped_column(
        String(64),  # SHA-256 hex digest
        nullable=False,
    )

    # Lifecycle
    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationship
    user: Mapped[User] = relationship(
        "User",
        back_populates="email_verification_tokens",
    )

    # Indexes
    __table_args__ = (Index("ix_email_tokens_user_expires", "user_id", "expires_at"),)

    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired or consumed)."""
        now = datetime.utcnow()
        if self.consumed_at is not None:
            return False
        if self.expires_at < now:
            return False
        return True

    def __repr__(self) -> str:
        return f"<EmailVerificationToken id={self.id[:8]}...>"


# =============================================================================
# Password Reset Token Model
# =============================================================================


class PasswordResetToken(TimestampMixin, Base):
    """
    Token for password reset workflow.

    Security Features:
        - Token stored as hash (never plaintext)
        - Short expiration (typically 1 hour)
        - Single-use (consumed_at tracking)
        - Cascade delete with user

    Workflow:
        1. User requests reset → token generated, hash stored, plaintext emailed
        2. User clicks link → plaintext token submitted with new password
        3. System hashes submitted token, compares with stored hash
        4. If match and not expired → update password, mark consumed

    Attributes:
        id: UUID primary key
        user_id: Foreign key to User
        token_hash: SHA-256 hash of reset token
        expires_at: Token expiration timestamp
        consumed_at: When token was used (null if unused)
    """

    __tablename__ = "password_reset_tokens"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # User relationship
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Token (hash only)
    token_hash: Mapped[str] = mapped_column(
        String(64),  # SHA-256 hex digest
        nullable=False,
    )

    # Lifecycle
    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Relationship
    user: Mapped[User] = relationship(
        "User",
        back_populates="password_reset_tokens",
    )

    # Indexes
    __table_args__ = (
        Index("ix_password_reset_tokens_user_expires", "user_id", "expires_at"),
    )

    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired or consumed)."""
        now = datetime.utcnow()
        if self.consumed_at is not None:
            return False
        if self.expires_at < now:
            return False
        return True

    def __repr__(self) -> str:
        return f"<PasswordResetToken id={self.id[:8]}...>"


# =============================================================================
# Auth Audit Log Model
# =============================================================================


class AuthAuditLog(Base):
    """
    Security audit log for authentication events.

    Purpose:
        - Security incident investigation
        - Compliance reporting
        - Anomaly detection
        - User activity transparency

    Note:
        - Uses SET NULL on user delete to preserve audit history
        - No updated_at (logs are immutable)
        - Metadata field for event-specific details

    Attributes:
        id: UUID primary key
        user_id: Foreign key to User (nullable for pre-auth events)
        event_type: Type of security event
        ip_address: Client IP address
        user_agent: Client user agent string
        metadata: JSON field for event-specific data
        created_at: Event timestamp
    """

    __tablename__ = "auth_audit_log"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # User relationship (nullable for pre-auth events like failed logins)
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )

    # Event details
    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, name="audit_event_type", create_constraint=True),
        nullable=False,
        index=True,
    )

    # Client identification
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv4 or IPv6
    user_agent: Mapped[Optional[str]] = mapped_column(String(500))

    # Event-specific metadata (JSON)
    # Examples:
    #   - LOGIN_FAILURE: {"reason": "invalid_password", "email": "user@..."}
    #   - SESSION_REVOKED: {"session_id": "...", "reason": "user_request"}
    event_metadata_json: Mapped[Optional[str]] = mapped_column(
        Text,
        name="event_metadata",
    )

    # Timestamp (no updated_at - logs are immutable)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    # Relationship
    user: Mapped[Optional[User]] = relationship(
        "User",
        back_populates="audit_logs",
    )

    # Indexes for common queries
    __table_args__ = (
        Index("ix_audit_log_user_created", "user_id", "created_at"),
        Index("ix_audit_log_event_created", "event_type", "created_at"),
    )

    @property
    def event_metadata(self) -> Optional[Dict[str, Any]]:
        """Parse event metadata JSON."""
        if self.event_metadata_json:
            import json

            return json.loads(self.event_metadata_json)
        return None

    @event_metadata.setter
    def event_metadata(self, value: Optional[Dict[str, Any]]) -> None:
        """Serialize event metadata to JSON."""
        if value is not None:
            import json

            self.event_metadata_json = json.dumps(value)
        else:
            self.event_metadata_json = None

    def __repr__(self) -> str:
        return f"<AuthAuditLog id={self.id[:8]}... event={self.event_type.value}>"
