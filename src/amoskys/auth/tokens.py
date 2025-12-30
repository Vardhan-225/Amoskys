"""
AMOSKYS Secure Token Utilities

Cryptographically secure token generation for:
- Email verification tokens
- Password reset tokens
- MFA backup codes
- API keys
- Session tokens

Security Principles:
- Uses Python's `secrets` module for cryptographic randomness
- Never stores plaintext tokens - only hashes
- Constant-time comparison to prevent timing attacks
- URL-safe encoding for tokens sent via email/URL

Design Philosophy (Akash Thanneeru + Claude Supremacy):
    Tokens are the keys to the kingdom. They must be unpredictable,
    unguessable, and unforgeable. We treat every token as if it were
    a password, because functionally, it is.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Tuple


def generate_token(length_bytes: int = 32) -> str:
    """
    Generate a cryptographically secure URL-safe token.

    Uses Python's `secrets` module which sources randomness from
    the operating system's cryptographically secure random number
    generator (e.g., /dev/urandom on Unix, CryptGenRandom on Windows).

    Args:
        length_bytes: Number of random bytes to generate.
            Default is 32 bytes (256 bits), which provides:
            - 256 bits of entropy
            - Resistance to brute force (2^256 guesses needed)
            - More than sufficient for any security token use case

    Returns:
        URL-safe base64-encoded token string.
        The returned string is approximately 4/3 * length_bytes characters.

    Example:
        >>> token = generate_token()
        >>> len(token)  # ~43 characters for 32 bytes
        43
        >>> token = generate_token(16)  # Shorter token
        >>> len(token)  # ~22 characters for 16 bytes
        22

    Security Note:
        - Never log the returned token
        - Store only the hash in the database
        - Send to user via secure channel (HTTPS, encrypted email)
    """
    if length_bytes < 16:
        raise ValueError("Token length must be at least 16 bytes for security")
    return secrets.token_urlsafe(length_bytes)


def generate_numeric_code(digits: int = 6) -> str:
    """
    Generate a cryptographically secure numeric OTP code.

    Used for:
    - Email-based MFA codes
    - SMS verification codes (if ever implemented)
    - Short-lived verification codes

    Args:
        digits: Number of digits in the code.
            Default is 6, which provides:
            - 1 million possible values (10^6)
            - Suitable for time-limited codes with rate limiting
            - Standard for TOTP/HOTP compatibility

    Returns:
        Zero-padded numeric string of exactly `digits` length.

    Example:
        >>> code = generate_numeric_code()
        >>> len(code)
        6
        >>> code.isdigit()
        True
        >>> code = generate_numeric_code(8)
        >>> len(code)
        8

    Security Note:
        Numeric codes have lower entropy than alphanumeric tokens.
        ALWAYS combine with:
        - Short expiry time (5-10 minutes)
        - Rate limiting (max 3-5 attempts)
        - Account lockout after failures
    """
    if digits < 4:
        raise ValueError("Code must have at least 4 digits for security")
    if digits > 10:
        raise ValueError("Code cannot exceed 10 digits")

    max_value = 10**digits - 1
    code = secrets.randbelow(max_value + 1)
    return str(code).zfill(digits)


def hash_token(token: str) -> str:
    """
    Hash a token for secure storage using SHA-256.

    We NEVER store plaintext tokens in the database. Instead:
    1. Generate token → send to user
    2. Hash token → store in database
    3. User submits token → hash and compare to stored hash

    SHA-256 is appropriate here because:
    - Tokens are already high-entropy random strings
    - No salt needed (unlike passwords) because tokens are unique
    - Fast hashing is acceptable for random data (unlike passwords)
    - Provides 256-bit collision resistance

    Args:
        token: The plaintext token to hash.

    Returns:
        Hexadecimal SHA-256 hash of the token (64 characters).

    Example:
        >>> token = generate_token()
        >>> token_hash = hash_token(token)
        >>> len(token_hash)
        64
        >>> token_hash != token
        True

    Security Note:
        The hash is deterministic - same input always produces same output.
        This is by design and required for verification to work.
    """
    if not token:
        raise ValueError("Cannot hash empty token")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token_with_expiry(
    lifetime_minutes: int = 60,
    token_bytes: int = 32,
) -> Tuple[str, str, datetime]:
    """
    Generate a token along with its hash and expiry timestamp.

    This is the primary function for creating verification tokens.
    It returns everything needed for the typical workflow:
    1. Send `plaintext_token` to user (email link, API response)
    2. Store `token_hash` and `expires_at` in database
    3. When user submits token, verify with `verify_token()`

    Args:
        lifetime_minutes: How long the token remains valid.
            Recommended values:
            - Email verification: 24 hours (1440 minutes)
            - Password reset: 1 hour (60 minutes)
            - MFA codes: 5-10 minutes
        token_bytes: Size of the random token in bytes.
            Default 32 bytes (256 bits) is suitable for most cases.

    Returns:
        Tuple of (plaintext_token, token_hash, expires_at):
        - plaintext_token: URL-safe token to send to user
        - token_hash: SHA-256 hash to store in database
        - expires_at: UTC datetime when token expires

    Example:
        >>> token, token_hash, expires = generate_token_with_expiry(60)
        >>> len(token) > 0
        True
        >>> len(token_hash) == 64
        True
        >>> expires > datetime.now(timezone.utc)
        True

    Security Note:
        - ONLY send `plaintext_token` to the user
        - ONLY store `token_hash` in the database
        - NEVER log the plaintext token
    """
    if lifetime_minutes < 1:
        raise ValueError("Token lifetime must be at least 1 minute")
    if lifetime_minutes > 43200:  # 30 days
        raise ValueError("Token lifetime cannot exceed 30 days")

    token = generate_token(token_bytes)
    token_hash = hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=lifetime_minutes)

    return token, token_hash, expires_at


def verify_token(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a user-submitted token against a stored hash.

    Uses constant-time comparison via `secrets.compare_digest()`
    to prevent timing attacks. In a timing attack, an attacker
    measures response times to infer information about the secret.

    Verification Flow:
    1. User submits plaintext token
    2. Hash the submitted token
    3. Compare to stored hash using constant-time comparison
    4. Return True only if they match exactly

    Args:
        plaintext: The token submitted by the user.
        stored_hash: The hash retrieved from the database.

    Returns:
        True if the token matches, False otherwise.

    Example:
        >>> token = generate_token()
        >>> token_hash = hash_token(token)
        >>> verify_token(token, token_hash)
        True
        >>> verify_token("wrong_token", token_hash)
        False
        >>> verify_token(token, "wrong_hash")
        False

    Security Note:
        - Always use this function for token comparison
        - Never use `==` directly (vulnerable to timing attacks)
        - Log failed verification attempts for security monitoring
    """
    if not plaintext or not stored_hash:
        return False

    try:
        computed_hash = hash_token(plaintext)
        return secrets.compare_digest(computed_hash, stored_hash)
    except (ValueError, TypeError):
        # Invalid input - treat as verification failure
        return False


def generate_api_key(prefix: str = "amk") -> Tuple[str, str]:
    """
    Generate an API key with a human-readable prefix.

    API keys are used for programmatic access and should be:
    - Easily identifiable (prefix helps with key rotation)
    - High entropy (256 bits)
    - Revocable (store hash, not plaintext)

    Format: {prefix}_{random_token}
    Example: amk_Abc123xyz...

    Args:
        prefix: Short identifier prefix (2-5 characters).
            Helps identify key type/version for rotation.

    Returns:
        Tuple of (api_key, key_hash):
        - api_key: The full API key to give to the user (ONCE)
        - key_hash: Hash to store in database

    Example:
        >>> key, key_hash = generate_api_key("amk")
        >>> key.startswith("amk_")
        True
        >>> len(key_hash) == 64
        True

    Security Note:
        - Show the API key to the user ONLY ONCE at creation
        - Store only the hash in the database
        - User must save the key; it cannot be recovered
    """
    if not prefix or len(prefix) < 2 or len(prefix) > 5:
        raise ValueError("Prefix must be 2-5 characters")
    if not prefix.isalnum():
        raise ValueError("Prefix must be alphanumeric")

    token = generate_token(32)
    api_key = f"{prefix}_{token}"
    key_hash = hash_token(api_key)

    return api_key, key_hash


def generate_backup_codes(
    count: int = 10, code_length: int = 8
) -> list[Tuple[str, str]]:
    """
    Generate MFA backup codes.

    Backup codes are one-time use codes for account recovery
    when the primary MFA device is unavailable.

    Args:
        count: Number of backup codes to generate (default 10).
        code_length: Length of each code in characters (default 8).

    Returns:
        List of (plaintext_code, code_hash) tuples.
        Display plaintext codes to user, store hashes in database.

    Example:
        >>> codes = generate_backup_codes(10)
        >>> len(codes)
        10
        >>> all(len(code) == 8 for code, _ in codes)
        True

    Security Note:
        - Show codes to user ONCE at MFA setup
        - Mark each code as "consumed" after use
        - Each code can only be used once
    """
    if count < 1 or count > 20:
        raise ValueError("Count must be between 1 and 20")
    if code_length < 6 or code_length > 16:
        raise ValueError("Code length must be between 6 and 16")

    codes = []
    for _ in range(count):
        # Generate alphanumeric code (easier to type than base64)
        code = "".join(
            secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")  # No I/O/0/1 (ambiguous)
            for _ in range(code_length)
        )
        code_hash = hash_token(code)
        codes.append((code, code_hash))

    return codes
