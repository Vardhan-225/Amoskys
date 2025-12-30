"""
Tests for AMOSKYS Password Policy Enforcement.

These tests verify that password validation correctly enforces:
- Length requirements (min/max)
- Character class requirements (uppercase, lowercase, digit, special)
- Common password blocklist
- Custom policy configurations

Test Categories:
    1. Happy Path - Valid passwords pass
    2. Length Validation - Min/max enforcement
    3. Character Class Validation - Required character types
    4. Blocklist Validation - Common password rejection
    5. Custom Policy - Policy customization
    6. Edge Cases - Empty, None, Unicode, etc.
"""

import pytest

from amoskys.auth.password_policy import (
    PasswordPolicy,
    PasswordValidationResult,
    is_common_password,
    validate_password,
)


class TestValidPasswordsPass:
    """Tests for passwords that should pass validation."""

    def test_strong_password_passes_default_policy(self):
        """Strong password with all requirements should pass."""
        pwd = "Str0ng!Passw0rd"
        result = validate_password(pwd)
        assert result.is_valid is True
        assert result.errors == []

    def test_exactly_min_length_passes(self):
        """Password at exactly minimum length should pass."""
        pwd = "Abcdef1!@#"  # 10 chars
        assert len(pwd) == 10
        result = validate_password(pwd)
        assert result.is_valid is True

    def test_long_password_passes(self):
        """Long password within limit should pass."""
        pwd = "A" * 50 + "a" * 50 + "1" + "!"
        result = validate_password(pwd)
        assert result.is_valid is True

    def test_unicode_password_passes(self):
        """Password with unicode characters should be accepted."""
        pwd = "Päsšwörd1!🔐"
        result = validate_password(pwd)
        assert result.is_valid is True

    def test_all_special_characters_accepted(self):
        """All defined special characters should satisfy the requirement."""
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\"
        for char in special_chars:
            pwd = f"Abcdefgh1{char}"
            result = validate_password(pwd)
            assert result.is_valid is True, f"Special char '{char}' should be accepted"


class TestLengthValidation:
    """Tests for password length requirements."""

    def test_too_short_password_fails(self):
        """Password shorter than min_length should fail."""
        pwd = "Ab1!"  # 4 chars, need 10
        result = validate_password(pwd)
        assert result.is_valid is False
        assert any("at least 10 characters" in e for e in result.errors)

    def test_one_char_below_min_fails(self):
        """Password one character below minimum should fail."""
        pwd = "Abcdef1!@"  # 9 chars
        assert len(pwd) == 9
        result = validate_password(pwd)
        assert result.is_valid is False
        assert any("at least" in e for e in result.errors)

    def test_too_long_password_fails(self):
        """Password exceeding max_length should fail."""
        pwd = "Aa1!" + "x" * 200  # 204 chars
        result = validate_password(pwd)
        assert result.is_valid is False
        assert any("at most 128 characters" in e for e in result.errors)

    def test_exactly_max_length_passes(self):
        """Password at exactly max_length should pass."""
        # 128 chars total: 1 upper + 1 lower + 1 digit + 1 special + 124 filler
        pwd = "A" + "a" * 124 + "1" + "!" + "b"
        assert len(pwd) == 128
        result = validate_password(pwd)
        assert result.is_valid is True

    def test_custom_min_length(self):
        """Custom minimum length should be enforced."""
        policy = PasswordPolicy(min_length=8)
        pwd = "Abcde1!@"  # 8 chars
        result = validate_password(pwd, policy)
        assert result.is_valid is True

    def test_custom_max_length(self):
        """Custom maximum length should be enforced."""
        policy = PasswordPolicy(max_length=20)
        pwd = "Aa1!" + "x" * 50  # 54 chars
        result = validate_password(pwd, policy)
        assert result.is_valid is False
        assert any("at most 20 characters" in e for e in result.errors)


class TestCharacterClassValidation:
    """Tests for character class requirements."""

    def test_missing_uppercase_fails(self):
        """Password without uppercase should fail."""
        pwd = "onlylowercase1!"
        result = validate_password(pwd)
        assert result.is_valid is False
        assert any("uppercase letter" in e for e in result.errors)

    def test_missing_lowercase_fails(self):
        """Password without lowercase should fail."""
        pwd = "ONLYUPPERCASE1!"
        result = validate_password(pwd)
        assert result.is_valid is False
        assert any("lowercase letter" in e for e in result.errors)

    def test_missing_digit_fails(self):
        """Password without digit should fail."""
        pwd = "NoDigitsHere!"
        result = validate_password(pwd)
        assert result.is_valid is False
        assert any("number" in e for e in result.errors)

    def test_missing_special_fails(self):
        """Password without special character should fail."""
        pwd = "NoSpecialChar1"
        result = validate_password(pwd)
        assert result.is_valid is False
        assert any("special character" in e for e in result.errors)

    def test_multiple_missing_classes(self):
        """Password missing multiple classes should report all errors."""
        pwd = "onlylowercase"
        result = validate_password(pwd)
        assert result.is_valid is False
        # Should have errors for: length, uppercase, digit, special
        assert len(result.errors) >= 3
        assert any("uppercase" in e for e in result.errors)
        assert any("number" in e for e in result.errors)
        assert any("special character" in e for e in result.errors)

    def test_custom_special_characters(self):
        """Custom special character set should be respected."""
        policy = PasswordPolicy(special_characters="@#$")
        # This should fail - ! is not in custom set
        pwd = "Abcdefgh1!"
        result = validate_password(pwd, policy)
        assert result.is_valid is False

        # This should pass - @ is in custom set
        pwd = "Abcdefgh1@"
        result = validate_password(pwd, policy)
        assert result.is_valid is True


class TestBlocklistValidation:
    """Tests for common password blocklist."""

    def test_common_password_fails(self):
        """Known common password should be rejected."""
        result = validate_password("password")
        assert result.is_valid is False
        assert any("too common" in e for e in result.errors)

    def test_common_password_case_insensitive(self):
        """Blocklist check should be case-insensitive."""
        for pwd in ["PASSWORD", "Password", "pAsSwOrD"]:
            result = validate_password(pwd)
            assert any(
                "too common" in e for e in result.errors
            ), f"{pwd} should be blocked"

    def test_is_common_password_function(self):
        """is_common_password should return correct results."""
        assert is_common_password("password") is True
        assert is_common_password("password123") is True
        assert is_common_password("qwerty") is True
        assert is_common_password("xK9mP2vL5nQ8zY7") is False

    def test_blocklist_disabled(self):
        """When blocklist is disabled, common passwords not rejected for that reason."""
        policy = PasswordPolicy(blocklist_enabled=False)
        # "password" still fails due to other requirements, but not blocklist
        result = validate_password("password", policy)
        assert result.is_valid is False
        # Should NOT have the "too common" error
        assert not any("too common" in e for e in result.errors)

    def test_blocklist_min_length(self):
        """Short passwords below blocklist_min_length skip blocklist check."""
        policy = PasswordPolicy(blocklist_min_length=10, blocklist_enabled=True)
        # "test" is in blocklist but only 4 chars, below min
        result = validate_password("test", policy)
        # Should fail for other reasons but not blocklist
        assert not any("too common" in e for e in result.errors)


class TestCustomPolicyOverrides:
    """Tests for custom policy configurations."""

    def test_disable_uppercase_requirement(self):
        """Disabling uppercase requirement should allow lowercase-only."""
        policy = PasswordPolicy(require_uppercase=False)
        pwd = "onlylowercase1!"
        result = validate_password(pwd, policy)
        assert result.is_valid is True

    def test_disable_lowercase_requirement(self):
        """Disabling lowercase requirement should allow uppercase-only."""
        policy = PasswordPolicy(require_lowercase=False)
        pwd = "ONLYUPPERCASE1!"
        result = validate_password(pwd, policy)
        assert result.is_valid is True

    def test_disable_digit_requirement(self):
        """Disabling digit requirement should allow alpha-only."""
        policy = PasswordPolicy(require_digit=False)
        pwd = "NoDigitsHere!"
        result = validate_password(pwd, policy)
        assert result.is_valid is True

    def test_disable_special_requirement(self):
        """Disabling special requirement should allow alphanumeric."""
        policy = PasswordPolicy(require_special=False)
        pwd = "Abcdef1234"
        result = validate_password(pwd, policy)
        assert result.is_valid is True

    def test_minimal_policy(self):
        """Very relaxed policy should only enforce length."""
        policy = PasswordPolicy(
            min_length=4,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
            blocklist_enabled=False,
        )
        pwd = "abcd"
        result = validate_password(pwd, policy)
        assert result.is_valid is True

    def test_strict_policy(self):
        """Stricter policy with longer minimum."""
        policy = PasswordPolicy(min_length=16)
        pwd = "Str0ng!Pass"  # 11 chars
        result = validate_password(pwd, policy)
        assert result.is_valid is False
        assert any("at least 16 characters" in e for e in result.errors)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_password_fails(self):
        """Empty password should fail with appropriate error."""
        result = validate_password("")
        assert result.is_valid is False
        assert any("required" in e.lower() for e in result.errors)

    def test_none_password_fails(self):
        """None password should fail gracefully."""
        result = validate_password(None)  # type: ignore
        assert result.is_valid is False
        assert any("required" in e.lower() for e in result.errors)

    def test_whitespace_only_fails(self):
        """Whitespace-only password should fail."""
        result = validate_password("          ")  # 10 spaces
        assert result.is_valid is False
        # Missing uppercase, lowercase, digit, special

    def test_password_with_spaces_works(self):
        """Password with embedded spaces should be valid if meets requirements."""
        pwd = "My Pass phrase 1!"
        result = validate_password(pwd)
        assert result.is_valid is True

    def test_newline_in_password(self):
        """Password with newline should be handled."""
        pwd = "Abcdef1!\nxyz"
        result = validate_password(pwd)
        # Should pass if meets requirements (newline doesn't break it)
        assert result.is_valid is True

    def test_tab_in_password(self):
        """Password with tab should be handled."""
        pwd = "Abcdef1!\txyz"
        result = validate_password(pwd)
        assert result.is_valid is True


class TestPasswordValidationResult:
    """Tests for PasswordValidationResult dataclass."""

    def test_valid_result_structure(self):
        """Valid result should have correct structure."""
        result = validate_password("Str0ng!Passw0rd")
        assert isinstance(result, PasswordValidationResult)
        assert result.is_valid is True
        assert isinstance(result.errors, list)
        assert len(result.errors) == 0

    def test_invalid_result_structure(self):
        """Invalid result should contain error messages."""
        result = validate_password("weak")
        assert isinstance(result, PasswordValidationResult)
        assert result.is_valid is False
        assert isinstance(result.errors, list)
        assert len(result.errors) > 0
        # All errors should be strings
        assert all(isinstance(e, str) for e in result.errors)


class TestModuleExports:
    """Tests for module exports."""

    def test_all_exports_importable(self):
        """All __all__ exports should be importable."""
        from amoskys.auth import password_policy

        for name in password_policy.__all__:
            assert hasattr(password_policy, name)

    def test_default_policy_is_secure(self):
        """Default PasswordPolicy should have secure defaults."""
        policy = PasswordPolicy()
        assert policy.min_length >= 8
        assert policy.max_length <= 256
        assert policy.require_uppercase is True
        assert policy.require_lowercase is True
        assert policy.require_digit is True
        assert policy.require_special is True
        assert policy.blocklist_enabled is True
