"""
Tests for AMOSKYS Argon2id password hashing module.

These tests verify the security properties of our password hashing
implementation including:
- Correct hash/verify round-trips
- Rejection of wrong passwords
- Graceful handling of invalid hashes
- Rehash detection for parameter upgrades

Test Categories:
    1. Happy Path Tests - Normal operation
    2. Security Tests - Edge cases and attack resistance
    3. Rehash Tests - Parameter upgrade detection
    4. Error Handling Tests - Invalid input handling
"""

import pytest
from argon2 import PasswordHasher

from amoskys.auth.password import hash_password, needs_rehash, verify_password


class TestHashPassword:
    """Tests for hash_password function."""

    def test_returns_argon2id_hash(self):
        """Hash should be in Argon2id format."""
        hashed = hash_password("TestPassword123!")
        assert hashed.startswith("$argon2id$")

    def test_hash_contains_parameters(self):
        """Hash should include algorithm parameters."""
        hashed = hash_password("TestPassword123!")
        # Should contain version, memory, time, parallelism
        # Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        assert "$v=" in hashed
        assert "m=" in hashed
        assert "t=" in hashed
        assert "p=" in hashed

    def test_hash_is_not_plaintext(self):
        """Hash should never equal the plaintext password."""
        password = "MySecurePassword123!"
        hashed = hash_password(password)
        assert hashed != password
        assert password not in hashed

    def test_each_hash_is_unique(self):
        """Same password should produce different hashes (unique salts)."""
        password = "SamePassword123!"
        hashes = {hash_password(password) for _ in range(10)}
        assert len(hashes) == 10  # All unique

    def test_empty_password_raises(self):
        """Empty password should raise ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            hash_password("")

    def test_none_password_raises(self):
        """None password should raise ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            hash_password(None)  # type: ignore

    def test_unicode_password_works(self):
        """Unicode passwords should hash correctly."""
        password = "パスワード123!🔐"
        hashed = hash_password(password)
        assert hashed.startswith("$argon2id$")
        assert verify_password(password, hashed) is True

    def test_long_password_works(self):
        """Long passwords should hash correctly."""
        password = "A" * 1000
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True


class TestVerifyPassword:
    """Tests for verify_password function."""

    def test_correct_password_returns_true(self):
        """Correct password should verify successfully."""
        password = "Sup3r_Str0ng!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_wrong_password_returns_false(self):
        """Wrong password should return False."""
        password = "CorrectP@ss1"
        hashed = hash_password(password)
        assert verify_password("WrongP@ss1", hashed) is False

    def test_similar_password_returns_false(self):
        """Password differing by one character should fail."""
        password = "MyPassword123!"
        hashed = hash_password(password)
        # Different by one char
        assert verify_password("MyPassword123?", hashed) is False
        assert verify_password("myPassword123!", hashed) is False
        assert verify_password("MyPassword123", hashed) is False

    def test_empty_password_returns_false(self):
        """Empty password should return False, not raise."""
        hashed = hash_password("SomePassword123!")
        assert verify_password("", hashed) is False

    def test_none_password_returns_false(self):
        """None password should return False, not raise."""
        hashed = hash_password("SomePassword123!")
        assert verify_password(None, hashed) is False  # type: ignore

    def test_empty_hash_returns_false(self):
        """Empty hash should return False, not raise."""
        assert verify_password("password", "") is False

    def test_none_hash_returns_false(self):
        """None hash should return False, not raise."""
        assert verify_password("password", None) is False  # type: ignore

    def test_invalid_hash_returns_false(self):
        """Invalid hash format should return False, not raise."""
        assert verify_password("password", "not-a-valid-hash") is False
        assert verify_password("password", "$argon2id$invalid") is False
        assert verify_password("password", "random-garbage-string") is False

    def test_truncated_hash_returns_false(self):
        """Truncated hash should return False."""
        hashed = hash_password("TestPassword123!")
        truncated = hashed[:30]
        assert verify_password("TestPassword123!", truncated) is False

    def test_modified_hash_returns_false(self):
        """Modified hash should return False."""
        hashed = hash_password("TestPassword123!")
        # Modify one character in the hash portion
        modified = hashed[:-5] + "XXXXX"
        assert verify_password("TestPassword123!", modified) is False


class TestNeedsRehash:
    """Tests for needs_rehash function."""

    def test_fresh_hash_does_not_need_rehash(self):
        """Hash created with current parameters shouldn't need rehash."""
        password = "SomeP@ssword1"
        hashed = hash_password(password)
        assert needs_rehash(hashed) is False

    def test_invalid_hash_needs_rehash(self):
        """Invalid hash format should be treated as needing rehash."""
        assert needs_rehash("not-a-valid-hash") is True
        assert needs_rehash("$argon2id$invalid") is True

    def test_empty_hash_needs_rehash(self):
        """Empty hash should need rehash."""
        assert needs_rehash("") is True

    def test_none_hash_needs_rehash(self):
        """None hash should need rehash."""
        assert needs_rehash(None) is True  # type: ignore

    def test_old_parameters_need_rehash(self):
        """Hash with weaker parameters should need rehash."""
        # Create a hasher with weaker parameters
        weak_hasher = PasswordHasher(
            time_cost=1,  # Weaker than our default of 3
            memory_cost=16 * 1024,  # 16MB vs our 64MB
            parallelism=1,  # 1 vs our 4
        )
        weak_hash = weak_hasher.hash("TestPassword")

        # Our needs_rehash should detect this needs upgrading
        assert needs_rehash(weak_hash) is True


class TestSecurityProperties:
    """Tests for security-critical properties."""

    def test_hash_length_is_consistent(self):
        """Hash length should be consistent for security analysis."""
        hashes = [hash_password(f"Password{i}!") for i in range(10)]
        lengths = {len(h) for h in hashes}
        # All hashes should be similar length (salt/hash portions fixed)
        assert max(lengths) - min(lengths) <= 10  # Small variance from encoding

    def test_verification_time_is_consistent(self):
        """Verification should take similar time for correct and wrong passwords.

        Note: This is a weak timing test. Real timing attack resistance
        comes from argon2's constant-time comparison.
        """
        import time

        password = "TestPassword123!"
        hashed = hash_password(password)

        # Time correct verification
        start = time.perf_counter()
        for _ in range(10):
            verify_password(password, hashed)
        correct_time = time.perf_counter() - start

        # Time incorrect verification
        start = time.perf_counter()
        for _ in range(10):
            verify_password("WrongPassword123!", hashed)
        wrong_time = time.perf_counter() - start

        # Times should be similar (within 50% - generous for test stability)
        ratio = max(correct_time, wrong_time) / min(correct_time, wrong_time)
        assert ratio < 1.5, f"Timing difference too large: {ratio}"

    def test_hash_roundtrip_integration(self):
        """Full integration test of hash/verify/rehash workflow."""
        password = "IntegrationTest123!"

        # Hash the password
        hashed = hash_password(password)

        # Verify works
        assert verify_password(password, hashed) is True

        # Fresh hash doesn't need rehash
        assert needs_rehash(hashed) is False

        # Wrong password fails
        assert verify_password("WrongPassword", hashed) is False


class TestModuleImports:
    """Test that module exports are correct."""

    def test_can_import_from_auth_module(self):
        """Functions should be importable from amoskys.auth."""
        from amoskys.auth import hash_password, needs_rehash, verify_password

        assert callable(hash_password)
        assert callable(verify_password)
        assert callable(needs_rehash)

    def test_all_exports_are_documented(self):
        """All __all__ exports should be importable."""
        from amoskys.auth import password

        for name in password.__all__:
            assert hasattr(password, name), f"{name} in __all__ but not defined"
