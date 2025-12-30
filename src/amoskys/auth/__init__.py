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

from amoskys.auth.tokens import (
    generate_api_key,
    generate_backup_codes,
    generate_numeric_code,
    generate_token,
    generate_token_with_expiry,
    hash_token,
    verify_token,
)

__all__ = [
    # Token utilities
    "generate_token",
    "generate_numeric_code",
    "hash_token",
    "generate_token_with_expiry",
    "verify_token",
    "generate_api_key",
    "generate_backup_codes",
]
