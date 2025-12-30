"""
Tests for AMOSKYS Secure Token Utilities.

Comprehensive test coverage for all token generation and verification functions.
Tests security properties including:
- Entropy and randomness
- Hash correctness
- Constant-time comparison
- Edge cases and error handling
"""

import re
from datetime import datetime, timedelta, timezone

import pytest

from amoskys.auth.tokens import (
    generate_api_key,
    generate_backup_codes,
    generate_numeric_code,
    generate_token,
    generate_token_with_expiry,
    hash_token,
    verify_token,
)


class TestGenerateToken:
    """Tests for generate_token function."""

    def test_default_length(self):
        """Default token should be ~43 chars (32 bytes base64)."""
        token = generate_token()
        # 32 bytes → 43 chars in URL-safe base64
        assert len(token) >= 42
        assert len(token) <= 44

    def test_custom_length(self):
        """Token length should scale with byte count."""
        token_16 = generate_token(16)
        token_64 = generate_token(64)
        # 16 bytes → ~22 chars, 64 bytes → ~86 chars
        assert len(token_16) < len(token_64)
        assert len(token_16) >= 20
        assert len(token_64) >= 80

    def test_uniqueness(self):
        """Each generated token should be unique."""
        tokens = {generate_token() for _ in range(1000)}
        assert len(tokens) == 1000  # All unique

    def test_url_safe(self):
        """Token should only contain URL-safe characters."""
        token = generate_token()
        # URL-safe base64 uses A-Z, a-z, 0-9, -, _
        assert re.match(r"^[A-Za-z0-9_-]+$", token)

    def test_minimum_length_enforced(self):
        """Should reject tokens shorter than 16 bytes."""
        with pytest.raises(ValueError, match="at least 16 bytes"):
            generate_token(8)

    def test_minimum_length_boundary(self):
        """Should accept exactly 16 bytes."""
        token = generate_token(16)
        assert len(token) >= 20


class TestGenerateNumericCode:
    """Tests for generate_numeric_code function."""

    def test_default_length(self):
        """Default code should be 6 digits."""
        code = generate_numeric_code()
        assert len(code) == 6
        assert code.isdigit()

    def test_custom_length(self):
        """Should generate code with specified digits."""
        code_4 = generate_numeric_code(4)
        code_8 = generate_numeric_code(8)
        assert len(code_4) == 4
        assert len(code_8) == 8
        assert code_4.isdigit()
        assert code_8.isdigit()

    def test_zero_padding(self):
        """Low values should be zero-padded."""
        # Generate many codes to increase chance of getting a low value
        codes = [generate_numeric_code(6) for _ in range(1000)]
        # All should be exactly 6 digits
        assert all(len(c) == 6 for c in codes)
        assert all(c.isdigit() for c in codes)

    def test_uniqueness(self):
        """Codes should have reasonable uniqueness."""
        codes = [generate_numeric_code(6) for _ in range(100)]
        # With 1M possible values, 100 samples should be mostly unique
        unique_codes = set(codes)
        assert len(unique_codes) >= 95  # Allow some collision

    def test_minimum_digits_enforced(self):
        """Should reject codes with fewer than 4 digits."""
        with pytest.raises(ValueError, match="at least 4 digits"):
            generate_numeric_code(3)

    def test_maximum_digits_enforced(self):
        """Should reject codes with more than 10 digits."""
        with pytest.raises(ValueError, match="cannot exceed 10"):
            generate_numeric_code(11)

    def test_boundary_values(self):
        """Should accept boundary values 4 and 10."""
        code_4 = generate_numeric_code(4)
        code_10 = generate_numeric_code(10)
        assert len(code_4) == 4
        assert len(code_10) == 10


class TestHashToken:
    """Tests for hash_token function."""

    def test_returns_sha256_hex(self):
        """Hash should be 64-character hex string."""
        token = generate_token()
        token_hash = hash_token(token)
        assert len(token_hash) == 64
        assert re.match(r"^[a-f0-9]+$", token_hash)

    def test_deterministic(self):
        """Same input should always produce same hash."""
        token = generate_token()
        hash1 = hash_token(token)
        hash2 = hash_token(token)
        assert hash1 == hash2

    def test_different_inputs_different_hashes(self):
        """Different tokens should produce different hashes."""
        token1 = generate_token()
        token2 = generate_token()
        hash1 = hash_token(token1)
        hash2 = hash_token(token2)
        assert hash1 != hash2

    def test_empty_token_rejected(self):
        """Should reject empty token."""
        with pytest.raises(ValueError, match="empty token"):
            hash_token("")

    def test_unicode_handling(self):
        """Should handle unicode tokens correctly."""
        token = "test_token_🔐"
        token_hash = hash_token(token)
        assert len(token_hash) == 64


class TestGenerateTokenWithExpiry:
    """Tests for generate_token_with_expiry function."""

    def test_returns_tuple_of_three(self):
        """Should return (token, hash, expires_at)."""
        result = generate_token_with_expiry()
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_token_is_valid(self):
        """Token should be valid URL-safe string."""
        token, _, _ = generate_token_with_expiry()
        assert len(token) >= 42
        assert re.match(r"^[A-Za-z0-9_-]+$", token)

    def test_hash_matches_token(self):
        """Hash should match the token."""
        token, token_hash, _ = generate_token_with_expiry()
        assert verify_token(token, token_hash)

    def test_expiry_is_future(self):
        """Expiry should be in the future."""
        _, _, expires_at = generate_token_with_expiry(60)
        now = datetime.now(timezone.utc)
        assert expires_at > now

    def test_expiry_matches_lifetime(self):
        """Expiry should match specified lifetime."""
        lifetime = 120  # 2 hours
        _, _, expires_at = generate_token_with_expiry(lifetime)
        now = datetime.now(timezone.utc)
        expected = now + timedelta(minutes=lifetime)
        # Allow 1 second tolerance
        assert abs((expires_at - expected).total_seconds()) < 1

    def test_minimum_lifetime_enforced(self):
        """Should reject lifetime less than 1 minute."""
        with pytest.raises(ValueError, match="at least 1 minute"):
            generate_token_with_expiry(0)

    def test_maximum_lifetime_enforced(self):
        """Should reject lifetime more than 30 days."""
        with pytest.raises(ValueError, match="cannot exceed 30 days"):
            generate_token_with_expiry(50000)

    def test_custom_token_bytes(self):
        """Should respect custom token byte size."""
        token, _, _ = generate_token_with_expiry(60, token_bytes=64)
        # 64 bytes → ~86 chars
        assert len(token) >= 80


class TestVerifyToken:
    """Tests for verify_token function."""

    def test_valid_token_verification(self):
        """Should return True for matching token and hash."""
        token = generate_token()
        token_hash = hash_token(token)
        assert verify_token(token, token_hash) is True

    def test_invalid_token_verification(self):
        """Should return False for non-matching token."""
        token = generate_token()
        token_hash = hash_token(token)
        assert verify_token("wrong_token", token_hash) is False

    def test_wrong_hash_verification(self):
        """Should return False for wrong hash."""
        token = generate_token()
        wrong_hash = "a" * 64
        assert verify_token(token, wrong_hash) is False

    def test_empty_token_returns_false(self):
        """Should return False for empty token."""
        token_hash = hash_token("some_token")
        assert verify_token("", token_hash) is False

    def test_empty_hash_returns_false(self):
        """Should return False for empty hash."""
        token = generate_token()
        assert verify_token(token, "") is False

    def test_none_values_return_false(self):
        """Should return False for None values."""
        token = generate_token()
        token_hash = hash_token(token)
        assert verify_token(None, token_hash) is False  # type: ignore
        assert verify_token(token, None) is False  # type: ignore

    def test_integration_with_generate_with_expiry(self):
        """Should work with generate_token_with_expiry output."""
        token, token_hash, _ = generate_token_with_expiry()
        assert verify_token(token, token_hash) is True
        assert verify_token("tampered", token_hash) is False


class TestGenerateApiKey:
    """Tests for generate_api_key function."""

    def test_default_prefix(self):
        """Should use default 'amk' prefix."""
        key, _ = generate_api_key()
        assert key.startswith("amk_")

    def test_custom_prefix(self):
        """Should use custom prefix."""
        key, _ = generate_api_key("test")
        assert key.startswith("test_")

    def test_key_format(self):
        """Key should be prefix_token format."""
        key, _ = generate_api_key("api")
        # Split on first underscore only (token may contain underscores)
        parts = key.split("_", 1)
        assert len(parts) == 2
        assert parts[0] == "api"
        assert len(parts[1]) >= 42  # Token part

    def test_hash_matches_key(self):
        """Hash should match the full API key."""
        key, key_hash = generate_api_key()
        assert verify_token(key, key_hash) is True

    def test_uniqueness(self):
        """Each API key should be unique."""
        keys = {generate_api_key()[0] for _ in range(100)}
        assert len(keys) == 100

    def test_prefix_validation_too_short(self):
        """Should reject prefix shorter than 2 chars."""
        with pytest.raises(ValueError, match="2-5 characters"):
            generate_api_key("a")

    def test_prefix_validation_too_long(self):
        """Should reject prefix longer than 5 chars."""
        with pytest.raises(ValueError, match="2-5 characters"):
            generate_api_key("toolong")

    def test_prefix_validation_non_alphanumeric(self):
        """Should reject non-alphanumeric prefix."""
        with pytest.raises(ValueError, match="alphanumeric"):
            generate_api_key("a-b")


class TestGenerateBackupCodes:
    """Tests for generate_backup_codes function."""

    def test_default_count(self):
        """Should generate 10 codes by default."""
        codes = generate_backup_codes()
        assert len(codes) == 10

    def test_custom_count(self):
        """Should generate specified number of codes."""
        codes = generate_backup_codes(5)
        assert len(codes) == 5

    def test_code_length(self):
        """Each code should be 8 characters by default."""
        codes = generate_backup_codes()
        for code, _ in codes:
            assert len(code) == 8

    def test_custom_code_length(self):
        """Should respect custom code length."""
        codes = generate_backup_codes(5, code_length=12)
        for code, _ in codes:
            assert len(code) == 12

    def test_codes_are_uppercase_alphanumeric(self):
        """Codes should be uppercase letters and numbers."""
        codes = generate_backup_codes()
        for code, _ in codes:
            # Should only contain allowed characters (no I, O, 0, 1)
            assert re.match(r"^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]+$", code)

    def test_hash_matches_code(self):
        """Each hash should match its code."""
        codes = generate_backup_codes()
        for code, code_hash in codes:
            assert verify_token(code, code_hash) is True

    def test_codes_are_unique(self):
        """All codes should be unique."""
        codes = generate_backup_codes(20)
        code_values = [code for code, _ in codes]
        assert len(set(code_values)) == len(code_values)

    def test_count_validation_too_low(self):
        """Should reject count less than 1."""
        with pytest.raises(ValueError, match="between 1 and 20"):
            generate_backup_codes(0)

    def test_count_validation_too_high(self):
        """Should reject count more than 20."""
        with pytest.raises(ValueError, match="between 1 and 20"):
            generate_backup_codes(25)

    def test_length_validation_too_short(self):
        """Should reject code length less than 6."""
        with pytest.raises(ValueError, match="between 6 and 16"):
            generate_backup_codes(10, code_length=4)

    def test_length_validation_too_long(self):
        """Should reject code length more than 16."""
        with pytest.raises(ValueError, match="between 6 and 16"):
            generate_backup_codes(10, code_length=20)


class TestSecurityProperties:
    """Tests for security properties of token functions."""

    def test_tokens_have_sufficient_entropy(self):
        """Tokens should have enough randomness to be unpredictable."""
        # Generate 10000 tokens and check for patterns
        tokens = [generate_token() for _ in range(10000)]

        # All unique
        assert len(set(tokens)) == 10000

        # No common prefix (would indicate poor randomness)
        first_chars = [t[0] for t in tokens]
        char_counts = {}
        for c in first_chars:
            char_counts[c] = char_counts.get(c, 0) + 1

        # No character should appear more than ~20% of the time
        # (with 64 possible chars, expected is ~1.5%)
        max_count = max(char_counts.values())
        assert max_count < 2000  # Less than 20%

    def test_numeric_codes_are_uniformly_distributed(self):
        """Numeric codes should be roughly uniformly distributed."""
        codes = [int(generate_numeric_code(4)) for _ in range(10000)]

        # Split into 10 buckets
        bucket_size = 1000
        buckets = [0] * 10
        for code in codes:
            bucket = code // bucket_size
            buckets[bucket] += 1

        # Each bucket should have roughly 1000 codes (10% each)
        # Allow 50% variance (500-1500 per bucket)
        for count in buckets:
            assert 500 <= count <= 1500

    def test_constant_time_comparison(self):
        """verify_token should use constant-time comparison."""
        # We can't directly test timing, but we can verify
        # that the function uses secrets.compare_digest
        import inspect

        from amoskys.auth import tokens

        source = inspect.getsource(tokens.verify_token)
        assert "compare_digest" in source
