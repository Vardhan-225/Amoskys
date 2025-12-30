"""
Password hashing and verification using Argon2id.

AMOSKYS uses Argon2id, the winner of the Password Hashing Competition,
as its exclusive password hashing algorithm. This module provides a
simple, secure interface that follows these security principles:

1. Never store or log plaintext passwords
2. Use strong defaults tuned for 2024+ hardware
3. Support transparent rehashing when parameters are upgraded
4. Fail securely - errors return False, never leak timing info

Security Parameters (OWASP 2024 recommendations):
    - time_cost=3: Number of iterations (increases CPU cost)
    - memory_cost=64MB: Memory required (defeats GPU attacks)
    - parallelism=4: Thread count (scales with modern CPUs)
    - hash_len=32: Output size in bytes (256 bits)
    - salt_len=16: Salt size in bytes (128 bits, auto-generated)

Example Usage:
    >>> from amoskys.auth.password import hash_password, verify_password
    >>> stored_hash = hash_password("user_password")
    >>> verify_password("user_password", stored_hash)
    True
    >>> verify_password("wrong_password", stored_hash)
    False

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Password storage is the one place where "good enough" security
    isn't good enough. We use the strongest available algorithm with
    parameters that make offline cracking economically infeasible.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

from amoskys.common.logging import get_logger

__all__ = [
    "hash_password",
    "verify_password",
    "needs_rehash",
]

logger = get_logger(__name__)

# =============================================================================
# Argon2id Configuration
# =============================================================================
#
# These parameters are tuned for:
# - ~300ms hash time on modern server hardware
# - 64MB memory per hash (defeats GPU parallelism)
# - Resistance to side-channel attacks (Argon2id hybrid mode)
#
# When upgrading parameters:
# 1. Create new PasswordHasher with stronger params
# 2. Existing hashes will still verify (params stored in hash)
# 3. needs_rehash() will return True for old hashes
# 4. Re-hash on next successful login
#
_hasher = PasswordHasher(
    time_cost=3,  # iterations
    memory_cost=64 * 1024,  # 64 MB in KiB
    parallelism=4,  # threads
    hash_len=32,  # output bytes
    salt_len=16,  # salt bytes
)


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id.

    This function generates a new random salt and produces a hash
    string that includes the algorithm, parameters, salt, and hash.
    The output is safe to store directly in a database.

    Args:
        password: Plaintext password from user input.
            SECURITY: This value MUST NOT be logged or persisted.

    Returns:
        Argon2 encoded hash string in the format:
        $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

    Raises:
        ValueError: If password is empty or None.

    Example:
        >>> hashed = hash_password("my_secure_password")
        >>> hashed.startswith("$argon2id$")
        True

    Security Notes:
        - Each call generates a unique salt (no salt reuse)
        - The hash includes all parameters for future verification
        - Timing is consistent regardless of password content
    """
    if not password:
        raise ValueError("Password cannot be empty")

    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored Argon2 hash.

    Uses argon2's constant-time comparison internally to prevent
    timing attacks. Any error condition returns False rather than
    raising an exception, following the principle of failing securely.

    Args:
        password: Plaintext password from user input.
            SECURITY: This value MUST NOT be logged.
        stored_hash: Previously computed hash from database.
            Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

    Returns:
        True if password matches the hash, False otherwise.
        Also returns False for invalid hash formats or empty inputs.

    Example:
        >>> hashed = hash_password("correct_password")
        >>> verify_password("correct_password", hashed)
        True
        >>> verify_password("wrong_password", hashed)
        False

    Security Notes:
        - Comparison is constant-time (no timing side-channels)
        - Invalid hashes return False (no information leakage)
        - Failed attempts should be rate-limited by caller
    """
    if not password or not stored_hash:
        return False

    try:
        _hasher.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        # Password doesn't match - this is expected for wrong passwords
        return False
    except InvalidHash:
        # Hash format is invalid - could indicate DB corruption or tampering
        # Log for security monitoring but don't expose details to caller
        logger.error(
            "Invalid password hash encountered during verification",
            extra={"hash_prefix": stored_hash[:15] if len(stored_hash) > 15 else "***"},
        )
        return False
    except Exception:
        # Catch any unexpected errors and fail securely
        logger.exception("Unexpected error during password verification")
        return False


def needs_rehash(stored_hash: str) -> bool:
    """
    Check if an existing hash should be rehashed with current parameters.

    Call this after a successful login. If it returns True, the user's
    password should be re-hashed with hash_password() and the new hash
    stored. This enables transparent parameter upgrades without forcing
    all users to reset their passwords.

    Args:
        stored_hash: Previously computed hash from database.

    Returns:
        True if the hash uses outdated parameters and should be rehashed.
        Also returns True for invalid hashes (caller should force reset).

    Example:
        >>> # In login flow:
        >>> if verify_password(password, user.password_hash):
        ...     if needs_rehash(user.password_hash):
        ...         user.password_hash = hash_password(password)
        ...         db.session.commit()

    Security Notes:
        - Only call after successful verification
        - Invalid hashes return True (force password reset)
        - This enables gradual security upgrades
    """
    if not stored_hash:
        return True

    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHash:
        # Invalid hash format - treat as needing rehash
        # The caller should handle this by forcing a password reset
        logger.warning(
            "Invalid hash passed to needs_rehash; treating as needing rehash",
            extra={"hash_prefix": stored_hash[:15] if len(stored_hash) > 15 else "***"},
        )
        return True
    except Exception:
        # Fail safely - if we can't check, assume rehash needed
        logger.exception("Unexpected error checking if rehash needed")
        return True
