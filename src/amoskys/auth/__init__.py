"""
AMOSKYS Authentication & Authorization Module

Enterprise-grade security infrastructure providing:
- Cryptographically secure token generation
- Argon2id password hashing
- Configurable password policies
- Server-side session management
- Multi-factor authentication support

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Security is not a feature, it's the foundation. Every auth
    decision is made with the assumption that attackers are present
    and actively trying to compromise the system.
"""

from amoskys.auth.password_policy import (
    PasswordPolicy,
    PasswordValidationResult,
    is_common_password,
    validate_password,
)

__all__ = [
    # Password policy
    "PasswordPolicy",
    "PasswordValidationResult",
    "validate_password",
    "is_common_password",
]
