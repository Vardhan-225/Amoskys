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

from amoskys.auth.password import (
    hash_password,
    needs_rehash,
    verify_password,
)

__all__ = [
    # Password utilities
    "hash_password",
    "verify_password",
    "needs_rehash",
]
