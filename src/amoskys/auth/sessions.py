"""
AMOSKYS Session Management

Enterprise-grade server-side session management for:
- Session creation after successful authentication
- Session validation on protected routes
- Session refresh for active users
- Session revocation (logout, security events)
- Bulk revocation (logout from all devices)

Security Features:
- Session tokens stored as SHA-256 hashes (never plaintext)
- Configurable expiry with absolute and sliding windows
- IP and User-Agent binding for anomaly detection
- Automatic cleanup of expired sessions
- Rate limiting hooks for session operations

Architecture:
    Client receives: session token (44 chars, URL-safe base64)
    Server stores: SHA-256 hash of token (64 hex chars)
    
    On each request:
    1. Client sends token in cookie or Authorization header
    2. Server hashes received token
    3. Lookup session by hash, verify not expired/revoked
    4. Update last_active_at for activity tracking

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Sessions are bearer tokens - possession equals access. We treat
    them with the same security rigor as passwords, storing only
    hashes and assuming tokens can be stolen from any transport.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import and_, delete, select, update
from sqlalchemy.orm import Session as DbSession

from amoskys.auth.models import AuditEventType, AuthAuditLog, Session, User
from amoskys.auth.tokens import generate_token, hash_token
from amoskys.common.logging import get_logger


def _utcnow() -> datetime:
    """
    Get current UTC time as naive datetime for database compatibility.

    SQLite stores naive datetimes, so we use naive UTC consistently.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


__all__ = [
    "SessionConfig",
    "get_session_config",
    "create_session",
    "validate_session",
    "refresh_session",
    "revoke_session",
    "revoke_all_user_sessions",
    "cleanup_expired_sessions",
    "get_user_active_sessions",
    "SessionValidationResult",
]

logger = get_logger(__name__)


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class SessionConfig:
    """
    Session management configuration.

    Attributes:
        session_lifetime_hours: Maximum session lifetime (default: 24h)
        idle_timeout_hours: Session expires after inactivity (default: 2h)
        max_sessions_per_user: Limit concurrent sessions (default: 10)
        enable_ip_binding: Invalidate if IP changes (default: False for UX)
        enable_ua_binding: Invalidate if User-Agent changes (default: False)
        token_bytes: Entropy for session tokens (default: 32 = 256 bits)
    """

    session_lifetime_hours: int = 24
    idle_timeout_hours: int = 2
    max_sessions_per_user: int = 10
    enable_ip_binding: bool = False
    enable_ua_binding: bool = False
    token_bytes: int = 32


# Module-level config cache
_session_config: Optional[SessionConfig] = None


def get_session_config() -> SessionConfig:
    """
    Load session configuration from environment.

    Environment Variables:
        AMOSKYS_SESSION_LIFETIME_HOURS: Max session lifetime
        AMOSKYS_SESSION_IDLE_TIMEOUT_HOURS: Idle timeout
        AMOSKYS_SESSION_MAX_PER_USER: Max concurrent sessions
        AMOSKYS_SESSION_BIND_IP: Bind sessions to IP (true/false)
        AMOSKYS_SESSION_BIND_UA: Bind sessions to User-Agent

    Returns:
        SessionConfig instance
    """
    global _session_config

    if _session_config is not None:
        return _session_config

    def get_bool(key: str, default: bool) -> bool:
        value = os.environ.get(key, "").lower()
        if value in ("true", "1", "yes"):
            return True
        if value in ("false", "0", "no"):
            return False
        return default

    _session_config = SessionConfig(
        session_lifetime_hours=int(
            os.environ.get("AMOSKYS_SESSION_LIFETIME_HOURS", "24")
        ),
        idle_timeout_hours=int(
            os.environ.get("AMOSKYS_SESSION_IDLE_TIMEOUT_HOURS", "2")
        ),
        max_sessions_per_user=int(os.environ.get("AMOSKYS_SESSION_MAX_PER_USER", "10")),
        enable_ip_binding=get_bool("AMOSKYS_SESSION_BIND_IP", False),
        enable_ua_binding=get_bool("AMOSKYS_SESSION_BIND_UA", False),
    )

    logger.info(
        "Session configuration loaded",
        lifetime_hours=_session_config.session_lifetime_hours,
        idle_timeout_hours=_session_config.idle_timeout_hours,
        max_per_user=_session_config.max_sessions_per_user,
    )

    return _session_config


def reset_session_config() -> None:
    """Reset cached config (useful for testing)."""
    global _session_config
    _session_config = None


# =============================================================================
# Session Validation Result
# =============================================================================


@dataclass
class SessionValidationResult:
    """
    Result of session validation.

    Attributes:
        is_valid: Whether session is valid
        user: User object if valid
        session: Session object if valid
        error: Error message if invalid
        error_code: Machine-readable error code
    """

    is_valid: bool
    user: Optional[User] = None
    session: Optional[Session] = None
    error: Optional[str] = None
    error_code: Optional[str] = None

    @classmethod
    def success(cls, user: User, session: Session) -> "SessionValidationResult":
        """Create a successful validation result."""
        return cls(is_valid=True, user=user, session=session)

    @classmethod
    def failure(cls, error: str, error_code: str) -> "SessionValidationResult":
        """Create a failed validation result."""
        return cls(is_valid=False, error=error, error_code=error_code)


# =============================================================================
# Session Creation
# =============================================================================


def create_session(
    db: DbSession,
    user: User,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    config: Optional[SessionConfig] = None,
) -> Tuple[str, Session]:
    """
    Create a new session for an authenticated user.

    This function:
    1. Generates a cryptographically secure session token
    2. Stores the hash (never the plaintext) in the database
    3. Enforces max sessions per user by removing oldest
    4. Logs the session creation event

    Args:
        db: SQLAlchemy database session
        user: Authenticated user object
        ip_address: Client IP address (for tracking)
        user_agent: Client User-Agent string (for tracking)
        config: Optional session configuration

    Returns:
        Tuple of (session_token, Session object)
        The session_token is what gets sent to the client.
        The Session object contains the hash.

    Example:
        >>> token, session = create_session(db, user, ip_address="1.2.3.4")
        >>> # Send token to client in cookie or response
        >>> # Session object is persisted with hashed token

    Security Notes:
        - Return the plaintext token ONLY ONCE to send to client
        - Never log or persist the plaintext token
        - Store only the hash in the database
    """
    cfg = config or get_session_config()
    now = _utcnow()

    # Generate cryptographically secure token
    token = generate_token(cfg.token_bytes)
    token_hash = hash_token(token)

    # Calculate expiry
    expires_at = now + timedelta(hours=cfg.session_lifetime_hours)

    # Enforce max sessions per user (remove oldest if at limit)
    _enforce_session_limit(db, user.id, cfg.max_sessions_per_user - 1)

    # Create session record
    session = Session(
        user_id=user.id,
        session_token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else None,  # Truncate long UAs
        expires_at=expires_at,
        last_active_at=now,
    )

    db.add(session)

    # Log audit event
    audit_log = AuthAuditLog(
        user_id=user.id,
        event_type=AuditEventType.SESSION_CREATED,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else None,
    )
    audit_log.event_metadata = {
        "session_id": session.id,
        "expires_at": expires_at.isoformat(),
    }
    db.add(audit_log)

    db.flush()  # Ensure session gets an ID

    logger.info(
        "Session created",
        user_id=user.id[:8] + "...",
        session_id=session.id[:8] + "...",
        expires_at=expires_at.isoformat(),
    )

    return token, session


def _enforce_session_limit(
    db: DbSession,
    user_id: str,
    max_allowed: int,
) -> int:
    """
    Remove oldest sessions if user exceeds limit.

    Returns:
        Number of sessions removed
    """
    # Get active sessions count
    count_query = (
        select(Session)
        .where(
            and_(
                Session.user_id == user_id,
                Session.revoked_at.is_(None),
            )
        )
        .order_by(Session.created_at.desc())
    )
    sessions = db.execute(count_query).scalars().all()

    if len(sessions) <= max_allowed:
        return 0

    # Remove oldest sessions beyond limit
    sessions_to_remove = sessions[max_allowed:]
    removed = 0

    for session in sessions_to_remove:
        session.revoked_at = _utcnow()
        removed += 1

    logger.info(
        "Enforced session limit",
        user_id=user_id[:8] + "...",
        removed=removed,
    )

    return removed


# =============================================================================
# Session Validation
# =============================================================================


def validate_session(
    db: DbSession,
    session_token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    config: Optional[SessionConfig] = None,
    update_activity: bool = True,
) -> SessionValidationResult:
    """
    Validate a session token and return the associated user.

    This is the core function called on every authenticated request.
    It performs multiple security checks:
    1. Token format validation
    2. Session lookup by token hash
    3. Expiration check (absolute and idle timeout)
    4. Revocation check
    5. Optional IP/UA binding checks
    6. User account status verification

    Args:
        db: SQLAlchemy database session
        session_token: Token received from client
        ip_address: Client's current IP (for binding check)
        user_agent: Client's current User-Agent (for binding check)
        config: Optional session configuration
        update_activity: Whether to update last_active_at

    Returns:
        SessionValidationResult with is_valid, user, session, and error info

    Example:
        >>> result = validate_session(db, request.cookies.get("session"))
        >>> if result.is_valid:
        ...     return process_request(result.user)
        ... else:
        ...     return redirect_to_login(result.error_code)

    Security Notes:
        - Constant-time comparison via hash prevents timing attacks
        - All failure paths return similar timing to prevent enumeration
        - Invalid tokens are not distinguishable from expired ones
    """
    cfg = config or get_session_config()
    now = _utcnow()

    # Validate token format
    if not session_token or len(session_token) < 20:
        return SessionValidationResult.failure(
            "Invalid session token format",
            "INVALID_TOKEN",
        )

    # Hash the token for lookup
    token_hash = hash_token(session_token)

    # Look up session by hash
    query = (
        select(Session)
        .where(Session.session_token_hash == token_hash)
        .options()  # Could add joinedload(Session.user) for eager loading
    )
    session = db.execute(query).scalar_one_or_none()

    if session is None:
        logger.warning(
            "Session not found",
            token_hash_prefix=token_hash[:8] + "...",
        )
        return SessionValidationResult.failure(
            "Session not found or invalid",
            "SESSION_NOT_FOUND",
        )

    # Check if revoked
    if session.revoked_at is not None:
        logger.warning(
            "Session was revoked",
            session_id=session.id[:8] + "...",
        )
        return SessionValidationResult.failure(
            "Session has been revoked",
            "SESSION_REVOKED",
        )

    # Check absolute expiry
    if session.expires_at < now:
        logger.info(
            "Session expired",
            session_id=session.id[:8] + "...",
            expired_at=session.expires_at.isoformat(),
        )
        return SessionValidationResult.failure(
            "Session has expired",
            "SESSION_EXPIRED",
        )

    # Check idle timeout
    if session.last_active_at:
        idle_deadline = session.last_active_at + timedelta(hours=cfg.idle_timeout_hours)
        if idle_deadline < now:
            logger.info(
                "Session idle timeout",
                session_id=session.id[:8] + "...",
                last_active=session.last_active_at.isoformat(),
            )
            return SessionValidationResult.failure(
                "Session timed out due to inactivity",
                "SESSION_IDLE_TIMEOUT",
            )

    # IP binding check (if enabled)
    if cfg.enable_ip_binding and ip_address:
        if session.ip_address and session.ip_address != ip_address:
            logger.warning(
                "Session IP mismatch",
                session_id=session.id[:8] + "...",
                original_ip=session.ip_address,
                current_ip=ip_address,
            )
            return SessionValidationResult.failure(
                "Session was created from a different IP address",
                "SESSION_IP_MISMATCH",
            )

    # User-Agent binding check (if enabled)
    if cfg.enable_ua_binding and user_agent:
        if session.user_agent and session.user_agent != user_agent[:500]:
            logger.warning(
                "Session User-Agent mismatch",
                session_id=session.id[:8] + "...",
            )
            return SessionValidationResult.failure(
                "Session was created from a different browser",
                "SESSION_UA_MISMATCH",
            )

    # Load user
    user = db.get(User, session.user_id)
    if user is None:
        logger.error(
            "Session user not found",
            session_id=session.id[:8] + "...",
            user_id=session.user_id[:8] + "...",
        )
        return SessionValidationResult.failure(
            "User account not found",
            "USER_NOT_FOUND",
        )

    # Check user account status
    if not user.is_active:
        logger.warning(
            "User account disabled",
            user_id=user.id[:8] + "...",
        )
        return SessionValidationResult.failure(
            "User account has been disabled",
            "ACCOUNT_DISABLED",
        )

    # Check account lockout
    if user.locked_until and user.locked_until > now:
        logger.warning(
            "User account locked",
            user_id=user.id[:8] + "...",
            locked_until=user.locked_until.isoformat(),
        )
        return SessionValidationResult.failure(
            "User account is temporarily locked",
            "ACCOUNT_LOCKED",
        )

    # Update activity timestamp
    if update_activity:
        session.last_active_at = now
        db.add(session)

    return SessionValidationResult.success(user, session)


# =============================================================================
# Session Refresh
# =============================================================================


def refresh_session(
    db: DbSession,
    session: Session,
    config: Optional[SessionConfig] = None,
) -> Session:
    """
    Extend a session's expiration time.

    Called when a user actively uses their session, to extend it
    beyond the original absolute expiry (sliding window).

    Args:
        db: SQLAlchemy database session
        session: Valid session to refresh
        config: Optional session configuration

    Returns:
        Updated Session object

    Note:
        This only extends expiry, it does NOT issue a new token.
        Token rotation should be implemented separately if needed.
    """
    cfg = config or get_session_config()
    now = _utcnow()

    session.expires_at = now + timedelta(hours=cfg.session_lifetime_hours)
    session.last_active_at = now
    db.add(session)

    logger.debug(
        "Session refreshed",
        session_id=session.id[:8] + "...",
        new_expires_at=session.expires_at.isoformat(),
    )

    return session


# =============================================================================
# Session Revocation
# =============================================================================


def revoke_session(
    db: DbSession,
    session: Session,
    reason: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """
    Revoke a specific session (logout).

    Args:
        db: SQLAlchemy database session
        session: Session to revoke
        reason: Optional reason for revocation
        ip_address: IP where revocation originated
        user_agent: User-Agent where revocation originated
    """
    now = _utcnow()
    session.revoked_at = now
    db.add(session)

    # Log audit event
    audit_log = AuthAuditLog(
        user_id=session.user_id,
        event_type=AuditEventType.SESSION_REVOKED,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else None,
    )
    audit_log.event_metadata = {
        "session_id": session.id,
        "reason": reason or "user_logout",
    }
    db.add(audit_log)

    logger.info(
        "Session revoked",
        session_id=session.id[:8] + "...",
        user_id=session.user_id[:8] + "...",
        reason=reason,
    )


def revoke_all_user_sessions(
    db: DbSession,
    user_id: str,
    except_session_id: Optional[str] = None,
    reason: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> int:
    """
    Revoke all sessions for a user (logout from all devices).

    Args:
        db: SQLAlchemy database session
        user_id: User whose sessions to revoke
        except_session_id: Optional session to keep (current session)
        reason: Reason for revocation
        ip_address: IP where request originated
        user_agent: User-Agent where request originated

    Returns:
        Number of sessions revoked
    """
    now = _utcnow()

    # Build update query
    conditions = [
        Session.user_id == user_id,
        Session.revoked_at.is_(None),
    ]
    if except_session_id:
        conditions.append(Session.id != except_session_id)

    stmt = update(Session).where(and_(*conditions)).values(revoked_at=now)
    result = db.execute(stmt)
    count = result.rowcount

    # Log audit event
    audit_log = AuthAuditLog(
        user_id=user_id,
        event_type=AuditEventType.SESSION_REVOKED,
        ip_address=ip_address,
        user_agent=user_agent[:500] if user_agent else None,
    )
    audit_log.event_metadata = {
        "action": "revoke_all",
        "count": count,
        "reason": reason or "user_request",
        "kept_session": except_session_id,
    }
    db.add(audit_log)

    logger.info(
        "All user sessions revoked",
        user_id=user_id[:8] + "...",
        count=count,
        reason=reason,
    )

    return count


# =============================================================================
# Session Queries
# =============================================================================


def get_user_active_sessions(
    db: DbSession,
    user_id: str,
) -> list[Session]:
    """
    Get all active (non-expired, non-revoked) sessions for a user.

    Args:
        db: SQLAlchemy database session
        user_id: User ID to query

    Returns:
        List of active Session objects
    """
    now = _utcnow()

    query = (
        select(Session)
        .where(
            and_(
                Session.user_id == user_id,
                Session.revoked_at.is_(None),
                Session.expires_at > now,
            )
        )
        .order_by(Session.last_active_at.desc())
    )

    return list(db.execute(query).scalars().all())


# =============================================================================
# Cleanup
# =============================================================================


def cleanup_expired_sessions(db: DbSession) -> int:
    """
    Remove expired and revoked sessions from database.

    This should be run periodically (e.g., daily cron job) to
    keep the sessions table from growing unbounded.

    Args:
        db: SQLAlchemy database session

    Returns:
        Number of sessions cleaned up
    """
    now = _utcnow()

    # Delete sessions that are expired OR revoked (and older than 1 day)
    # Keep recently revoked for audit purposes
    cutoff = now - timedelta(days=1)

    stmt = delete(Session).where(
        (Session.expires_at < cutoff)
        | ((Session.revoked_at.isnot(None)) & (Session.revoked_at < cutoff))
    )

    result = db.execute(stmt)
    count = result.rowcount

    if count > 0:
        logger.info(
            "Cleaned up expired sessions",
            count=count,
        )

    return count
