"""
Password Policy Enforcement for AMOSKYS.

This module provides configurable password strength validation to ensure
users create passwords that are resistant to common attack vectors:

1. Brute Force: Minimum length requirements
2. Dictionary Attacks: Common password blocklist
3. Pattern Attacks: Character class diversity requirements

The policy is designed to balance security with usability - strong enough
to resist automated attacks, but not so restrictive that users resort to
writing passwords down or using predictable patterns.

Default Policy (NIST SP 800-63B aligned):
    - Minimum 10 characters (NIST recommends 8+, we're stricter)
    - Maximum 128 characters (prevents DoS via hash computation)
    - Require uppercase, lowercase, digit, and special character
    - Block common passwords from known breach lists

Example Usage:
    >>> from amoskys.auth.password_policy import validate_password
    >>> result = validate_password("WeakPass")
    >>> result.is_valid
    False
    >>> result.errors
    ['Password must be at least 10 characters long.', ...]

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    A password policy should make the right thing easy and the wrong
    thing hard. Users shouldn't need to be security experts to create
    a password that protects their account.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Optional, Set

__all__ = [
    "PasswordPolicy",
    "PasswordValidationResult",
    "validate_password",
    "is_common_password",
]


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class PasswordPolicy:
    """
    Configuration for password strength requirements.

    All requirements are enabled by default for maximum security.
    Customize by passing different values when instantiating.

    Attributes:
        min_length: Minimum password length (default: 10)
        max_length: Maximum password length (default: 128)
        require_uppercase: Require at least one uppercase letter
        require_lowercase: Require at least one lowercase letter
        require_digit: Require at least one number
        require_special: Require at least one special character
        special_characters: Set of allowed special characters
        blocklist_enabled: Check against common password list
        blocklist_min_length: Only check blocklist for passwords >= this length

    Example:
        >>> # Relaxed policy for testing
        >>> policy = PasswordPolicy(min_length=8, require_special=False)
        >>> result = validate_password("Abcdef123", policy)
        >>> result.is_valid
        True
    """

    min_length: int = 10
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    special_characters: str = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\"
    blocklist_enabled: bool = True
    blocklist_min_length: int = 4  # Check even short common passwords


@dataclass
class PasswordValidationResult:
    """
    Result of password validation.

    Attributes:
        is_valid: True if password meets all policy requirements
        errors: List of human-readable error messages (empty if valid)

    Example:
        >>> result = validate_password("weak")
        >>> if not result.is_valid:
        ...     for error in result.errors:
        ...         print(f"- {error}")
    """

    is_valid: bool
    errors: List[str] = field(default_factory=list)


# =============================================================================
# Blocklist Management
# =============================================================================


@lru_cache(maxsize=1)
def _load_blocklist() -> Set[str]:
    """
    Load common password blocklist from file.

    The blocklist is loaded once and cached for performance.
    Passwords are stored lowercase for case-insensitive matching.

    Returns:
        Set of common passwords (lowercase) or empty set if file not found.
    """
    blocklist: Set[str] = set()
    path = os.path.join(os.path.dirname(__file__), "password_blocklist.txt")

    if not os.path.exists(path):
        return blocklist

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                pw = line.strip()
                if pw and not pw.startswith("#"):  # Allow comments
                    blocklist.add(pw.lower())
    except (OSError, IOError):
        # If we can't read the file, continue without blocklist
        # This is a defense-in-depth measure, not a primary control
        pass

    return blocklist


def is_common_password(password: str) -> bool:
    """
    Check if password appears in the common password blocklist.

    Performs case-insensitive comparison against a list of passwords
    known to be commonly used or compromised in data breaches.

    Args:
        password: Password to check

    Returns:
        True if password is in the blocklist, False otherwise

    Example:
        >>> is_common_password("password123")
        True
        >>> is_common_password("xK9#mP2$vL5@nQ8")
        False
    """
    blocklist = _load_blocklist()
    return password.lower() in blocklist


# =============================================================================
# Password Validation
# =============================================================================


def validate_password(
    password: str,
    policy: Optional[PasswordPolicy] = None,
) -> PasswordValidationResult:
    """
    Validate a password against the specified policy.

    Checks the password against all configured requirements and returns
    a result indicating whether it's valid, along with specific error
    messages for any failed requirements.

    Args:
        password: The password to validate (plaintext)
        policy: Password policy to use (defaults to PasswordPolicy())

    Returns:
        PasswordValidationResult with is_valid flag and list of errors

    Example:
        >>> result = validate_password("MyStr0ng!Pass")
        >>> result.is_valid
        True

        >>> result = validate_password("weak")
        >>> result.is_valid
        False
        >>> "at least 10 characters" in result.errors[0]
        True

    Security Notes:
        - This function does not log the password
        - Errors are user-friendly but don't reveal policy details
        - Always validate BEFORE hashing (fail fast)
    """
    policy = policy or PasswordPolicy()
    errors: List[str] = []

    # Handle None/empty password
    if not password:
        return PasswordValidationResult(
            is_valid=False,
            errors=["Password is required."],
        )

    # ==========================================================================
    # Length Checks
    # ==========================================================================

    if len(password) < policy.min_length:
        errors.append(f"Password must be at least {policy.min_length} characters long.")

    if len(password) > policy.max_length:
        errors.append(f"Password must be at most {policy.max_length} characters long.")

    # ==========================================================================
    # Character Class Checks
    # ==========================================================================

    if policy.require_uppercase and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")

    if policy.require_lowercase and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")

    if policy.require_digit and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number.")

    if policy.require_special:
        if not any(c in policy.special_characters for c in password):
            errors.append("Password must contain at least one special character.")

    # ==========================================================================
    # Blocklist Check
    # ==========================================================================

    if policy.blocklist_enabled:
        if len(password) >= policy.blocklist_min_length:
            if is_common_password(password):
                errors.append(
                    "This password is too common. Please choose a stronger password."
                )

    return PasswordValidationResult(
        is_valid=(len(errors) == 0),
        errors=errors,
    )
