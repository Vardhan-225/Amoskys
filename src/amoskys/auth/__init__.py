# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/src/amoskys/auth/__init__.py
"""
AMOSKYS Authentication & Authorization Module

Enterprise-grade security infrastructure providing:
- Cryptographically secure token generation (P3-004)
- Argon2id password hashing (P3-002)
- Configurable password policies (P3-003)
- SQLAlchemy data models for auth (P3-001)
- Server-side session management (P3-005)
- Email notifications for auth workflows (P3-006)

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Security is not a feature, it's the foundation. Every auth
    decision is made with the assumption that attackers are present
    and actively trying to compromise the system.

Usage:
    # Password hashing
    from amoskys.auth import hash_password, verify_password

    # Token generation
    from amoskys.auth import generate_token, hash_token

    # Session management
    from amoskys.auth import create_session, validate_session

    # Models
    from amoskys.auth import User, Session
"""

# Tokens (P3-004)
from amoskys.auth.tokens import (
    generate_api_key,
    generate_backup_codes,
    generate_numeric_code,
    generate_token,
    generate_token_with_expiry,
    hash_token,
    verify_token,
)

# Password hashing (P3-002)
from amoskys.auth.password import (
    hash_password,
    needs_rehash,
    verify_password,
)

# Password policy (P3-003)
from amoskys.auth.password_policy import (
    PasswordPolicy,
    PasswordValidationResult,
    is_common_password,
    validate_password,
)

# Models (P3-001)
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

# Session management (P3-005)
from amoskys.auth.sessions import (
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

__all__ = [
    # Tokens
    "generate_token",
    "generate_numeric_code",
    "hash_token",
    "generate_token_with_expiry",
    "verify_token",
    "generate_api_key",
    "generate_backup_codes",
    # Password hashing
    "hash_password",
    "verify_password",
    "needs_rehash",
    # Password policy
    "PasswordPolicy",
    "PasswordValidationResult",
    "validate_password",
    "is_common_password",
    # Models
    "User",
    "Session",
    "EmailVerificationToken",
    "PasswordResetToken",
    "AuthAuditLog",
    "UserRole",
    "MFAType",
    "AuditEventType",
    # Session management
    "SessionConfig",
    "SessionValidationResult",
    "get_session_config",
    "reset_session_config",
    "create_session",
    "validate_session",
    "refresh_session",
    "revoke_session",
    "revoke_all_user_sessions",
    "get_user_active_sessions",
    "cleanup_expired_sessions",
]
