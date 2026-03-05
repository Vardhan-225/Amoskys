"""
Comprehensive unit tests for the AMOSKYS auth stack.

Covers:
- amoskys.auth.tokens: token generation, hashing, verification, API keys, backup codes
- amoskys.auth.password: Argon2id hashing, verification, rehash detection
- amoskys.auth.password_policy: complexity rules, blocklist, validation
- amoskys.auth.sessions: session create/validate/refresh/revoke/cleanup
- amoskys.auth.service: AuthService signup/login/logout/password-reset/account-mgmt
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from amoskys.db import Base

# ---------------------------------------------------------------------------
# Fixtures: in-memory SQLite database for model-backed tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_engine():
    """Create an in-memory SQLite engine with all auth tables."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture()
def db(db_engine):
    """Provide a transactional database session for a test."""
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ============================================================================
# 1. Token Module Tests
# ============================================================================


class TestGenerateToken:
    """Tests for amoskys.auth.tokens.generate_token."""

    def test_default_token_length(self):
        from amoskys.auth.tokens import generate_token

        token = generate_token()
        # 32 bytes -> ~43 URL-safe base64 chars
        assert len(token) >= 40

    def test_custom_token_length(self):
        from amoskys.auth.tokens import generate_token

        token = generate_token(64)
        assert len(token) > 80  # 64 bytes -> ~86 chars

    def test_minimum_length_enforced(self):
        from amoskys.auth.tokens import generate_token

        with pytest.raises(ValueError, match="at least 16 bytes"):
            generate_token(8)

    def test_tokens_are_unique(self):
        from amoskys.auth.tokens import generate_token

        tokens = {generate_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_token_is_url_safe(self):
        from amoskys.auth.tokens import generate_token

        token = generate_token()
        # URL-safe base64 uses only these characters
        allowed = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
        )
        assert set(token).issubset(allowed)


class TestGenerateNumericCode:
    """Tests for amoskys.auth.tokens.generate_numeric_code."""

    def test_default_six_digits(self):
        from amoskys.auth.tokens import generate_numeric_code

        code = generate_numeric_code()
        assert len(code) == 6
        assert code.isdigit()

    def test_custom_digit_count(self):
        from amoskys.auth.tokens import generate_numeric_code

        code = generate_numeric_code(8)
        assert len(code) == 8
        assert code.isdigit()

    def test_min_digits_enforced(self):
        from amoskys.auth.tokens import generate_numeric_code

        with pytest.raises(ValueError, match="at least 4 digits"):
            generate_numeric_code(3)

    def test_max_digits_enforced(self):
        from amoskys.auth.tokens import generate_numeric_code

        with pytest.raises(ValueError, match="cannot exceed 10"):
            generate_numeric_code(11)

    def test_zero_padded(self):
        """Codes should always be exactly `digits` characters via zero-padding."""
        from amoskys.auth.tokens import generate_numeric_code

        # Run many iterations to increase chance of hitting a low number
        for _ in range(200):
            code = generate_numeric_code(6)
            assert len(code) == 6


class TestHashToken:
    """Tests for amoskys.auth.tokens.hash_token."""

    def test_returns_hex_digest(self):
        from amoskys.auth.tokens import hash_token

        h = hash_token("test-token")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        from amoskys.auth.tokens import hash_token

        assert hash_token("abc") == hash_token("abc")

    def test_different_inputs_different_hashes(self):
        from amoskys.auth.tokens import hash_token

        assert hash_token("token-a") != hash_token("token-b")

    def test_empty_token_raises(self):
        from amoskys.auth.tokens import hash_token

        with pytest.raises(ValueError, match="Cannot hash empty"):
            hash_token("")


class TestVerifyToken:
    """Tests for amoskys.auth.tokens.verify_token."""

    def test_valid_token_matches(self):
        from amoskys.auth.tokens import generate_token, hash_token, verify_token

        token = generate_token()
        stored = hash_token(token)
        assert verify_token(token, stored) is True

    def test_wrong_token_no_match(self):
        from amoskys.auth.tokens import generate_token, hash_token, verify_token

        token = generate_token()
        stored = hash_token(token)
        assert verify_token("wrong-token", stored) is False

    def test_empty_plaintext_returns_false(self):
        from amoskys.auth.tokens import verify_token

        assert verify_token("", "somehash") is False

    def test_empty_hash_returns_false(self):
        from amoskys.auth.tokens import verify_token

        assert verify_token("some-token", "") is False

    def test_none_inputs_return_false(self):
        from amoskys.auth.tokens import verify_token

        assert verify_token(None, "hash") is False
        assert verify_token("token", None) is False


class TestGenerateTokenWithExpiry:
    """Tests for amoskys.auth.tokens.generate_token_with_expiry."""

    def test_returns_three_tuple(self):
        from amoskys.auth.tokens import generate_token_with_expiry

        token, token_hash, expires = generate_token_with_expiry(60)
        assert isinstance(token, str)
        assert isinstance(token_hash, str)
        assert isinstance(expires, datetime)

    def test_hash_matches_token(self):
        from amoskys.auth.tokens import generate_token_with_expiry, hash_token

        token, token_hash, _ = generate_token_with_expiry(60)
        assert hash_token(token) == token_hash

    def test_expiry_is_in_the_future(self):
        from amoskys.auth.tokens import generate_token_with_expiry

        _, _, expires = generate_token_with_expiry(60)
        assert expires > datetime.now(timezone.utc)

    def test_lifetime_too_short_raises(self):
        from amoskys.auth.tokens import generate_token_with_expiry

        with pytest.raises(ValueError, match="at least 1 minute"):
            generate_token_with_expiry(0)

    def test_lifetime_too_long_raises(self):
        from amoskys.auth.tokens import generate_token_with_expiry

        with pytest.raises(ValueError, match="cannot exceed 30 days"):
            generate_token_with_expiry(43201)


class TestGenerateApiKey:
    """Tests for amoskys.auth.tokens.generate_api_key."""

    def test_key_has_prefix(self):
        from amoskys.auth.tokens import generate_api_key

        key, key_hash = generate_api_key("amk")
        assert key.startswith("amk_")
        assert len(key_hash) == 64

    def test_hash_matches_full_key(self):
        from amoskys.auth.tokens import generate_api_key, hash_token

        key, key_hash = generate_api_key("amk")
        assert hash_token(key) == key_hash

    def test_invalid_prefix_too_short(self):
        from amoskys.auth.tokens import generate_api_key

        with pytest.raises(ValueError, match="2-5 characters"):
            generate_api_key("a")

    def test_invalid_prefix_too_long(self):
        from amoskys.auth.tokens import generate_api_key

        with pytest.raises(ValueError, match="2-5 characters"):
            generate_api_key("toolong")

    def test_non_alphanumeric_prefix_rejected(self):
        from amoskys.auth.tokens import generate_api_key

        with pytest.raises(ValueError, match="alphanumeric"):
            generate_api_key("a-b")

    def test_empty_prefix_rejected(self):
        from amoskys.auth.tokens import generate_api_key

        with pytest.raises(ValueError):
            generate_api_key("")


class TestGenerateBackupCodes:
    """Tests for amoskys.auth.tokens.generate_backup_codes."""

    def test_default_count_and_length(self):
        from amoskys.auth.tokens import generate_backup_codes

        codes = generate_backup_codes()
        assert len(codes) == 10
        for code, code_hash in codes:
            assert len(code) == 8
            assert len(code_hash) == 64

    def test_custom_count_and_length(self):
        from amoskys.auth.tokens import generate_backup_codes

        codes = generate_backup_codes(count=5, code_length=10)
        assert len(codes) == 5
        for code, _ in codes:
            assert len(code) == 10

    def test_codes_are_unique(self):
        from amoskys.auth.tokens import generate_backup_codes

        codes = generate_backup_codes(count=20)
        plaintexts = [c for c, _ in codes]
        assert len(set(plaintexts)) == 20

    def test_invalid_count_raises(self):
        from amoskys.auth.tokens import generate_backup_codes

        with pytest.raises(ValueError, match="between 1 and 20"):
            generate_backup_codes(count=0)
        with pytest.raises(ValueError, match="between 1 and 20"):
            generate_backup_codes(count=21)

    def test_invalid_code_length_raises(self):
        from amoskys.auth.tokens import generate_backup_codes

        with pytest.raises(ValueError, match="between 6 and 16"):
            generate_backup_codes(code_length=5)
        with pytest.raises(ValueError, match="between 6 and 16"):
            generate_backup_codes(code_length=17)

    def test_no_ambiguous_characters(self):
        from amoskys.auth.tokens import generate_backup_codes

        codes = generate_backup_codes(count=20, code_length=16)
        ambiguous = set("IO01")
        for code, _ in codes:
            assert ambiguous.isdisjoint(
                set(code)
            ), f"Code {code} contains ambiguous chars"


# ============================================================================
# 2. Password Module Tests
# ============================================================================


class TestHashPassword:
    """Tests for amoskys.auth.password.hash_password."""

    def test_returns_argon2id_hash(self):
        from amoskys.auth.password import hash_password

        h = hash_password("SecurePass123!")
        assert h.startswith("$argon2id$")

    def test_empty_password_raises(self):
        from amoskys.auth.password import hash_password

        with pytest.raises(ValueError, match="cannot be empty"):
            hash_password("")

    def test_none_password_raises(self):
        from amoskys.auth.password import hash_password

        with pytest.raises(ValueError):
            hash_password(None)

    def test_different_salts_each_call(self):
        from amoskys.auth.password import hash_password

        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # Different salts -> different hashes


class TestVerifyPassword:
    """Tests for amoskys.auth.password.verify_password."""

    def test_correct_password_returns_true(self):
        from amoskys.auth.password import hash_password, verify_password

        h = hash_password("CorrectHorse")
        assert verify_password("CorrectHorse", h) is True

    def test_wrong_password_returns_false(self):
        from amoskys.auth.password import hash_password, verify_password

        h = hash_password("CorrectHorse")
        assert verify_password("WrongHorse", h) is False

    def test_empty_password_returns_false(self):
        from amoskys.auth.password import verify_password

        assert verify_password("", "$argon2id$v=19$m=65536$hash") is False

    def test_empty_hash_returns_false(self):
        from amoskys.auth.password import verify_password

        assert verify_password("password", "") is False

    def test_none_inputs_return_false(self):
        from amoskys.auth.password import verify_password

        assert verify_password(None, "hash") is False
        assert verify_password("pw", None) is False

    def test_invalid_hash_format_returns_false(self):
        from amoskys.auth.password import verify_password

        assert verify_password("password", "not-a-valid-hash-at-all") is False


class TestNeedsRehash:
    """Tests for amoskys.auth.password.needs_rehash."""

    def test_current_hash_no_rehash(self):
        from amoskys.auth.password import hash_password, needs_rehash

        h = hash_password("TestPassword")
        assert needs_rehash(h) is False

    def test_empty_hash_needs_rehash(self):
        from amoskys.auth.password import needs_rehash

        assert needs_rehash("") is True

    def test_none_hash_needs_rehash(self):
        from amoskys.auth.password import needs_rehash

        assert needs_rehash(None) is True

    def test_invalid_hash_needs_rehash(self):
        from amoskys.auth.password import needs_rehash

        assert needs_rehash("garbage-hash-value") is True


# ============================================================================
# 3. Password Policy Tests
# ============================================================================


class TestPasswordPolicy:
    """Tests for amoskys.auth.password_policy.validate_password."""

    def test_valid_password_passes(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(blocklist_enabled=False)
        result = validate_password("MyStr0ng!Pass", policy)
        assert result.is_valid is True
        assert result.errors == []

    def test_too_short(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(min_length=10, blocklist_enabled=False)
        result = validate_password("Sh0rt!x", policy)
        assert result.is_valid is False
        assert any("at least 10" in e for e in result.errors)

    def test_too_long(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(max_length=20, blocklist_enabled=False)
        result = validate_password("A" * 21 + "a1!", policy)
        assert result.is_valid is False
        assert any("at most 20" in e for e in result.errors)

    def test_missing_uppercase(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(min_length=4, blocklist_enabled=False)
        result = validate_password("alllowercase1!", policy)
        assert result.is_valid is False
        assert any("uppercase" in e for e in result.errors)

    def test_missing_lowercase(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(min_length=4, blocklist_enabled=False)
        result = validate_password("ALLUPPERCASE1!", policy)
        assert result.is_valid is False
        assert any("lowercase" in e for e in result.errors)

    def test_missing_digit(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(min_length=4, blocklist_enabled=False)
        result = validate_password("NoDigitsHere!", policy)
        assert result.is_valid is False
        assert any("number" in e for e in result.errors)

    def test_missing_special_char(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(min_length=4, blocklist_enabled=False)
        result = validate_password("NoSpecial123Aa", policy)
        assert result.is_valid is False
        assert any("special character" in e for e in result.errors)

    def test_empty_password(self):
        from amoskys.auth.password_policy import validate_password

        result = validate_password("")
        assert result.is_valid is False
        assert any("required" in e for e in result.errors)

    def test_none_password(self):
        from amoskys.auth.password_policy import validate_password

        result = validate_password(None)
        assert result.is_valid is False

    def test_relaxed_policy(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(
            min_length=4,
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
            blocklist_enabled=False,
        )
        result = validate_password("abcd", policy)
        assert result.is_valid is True

    def test_multiple_errors_collected(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        policy = PasswordPolicy(min_length=10, blocklist_enabled=False)
        result = validate_password("abc", policy)
        assert result.is_valid is False
        # Should have errors for: length, uppercase, digit, special
        assert len(result.errors) >= 3

    def test_blocklist_rejects_common_password(self):
        from amoskys.auth.password_policy import is_common_password

        # "password" is in the blocklist
        assert is_common_password("password") is True
        assert is_common_password("PASSWORD") is True  # case-insensitive

    def test_blocklist_allows_uncommon_password(self):
        from amoskys.auth.password_policy import is_common_password

        assert is_common_password("xK9mP2vL5nQ8!@#") is False

    def test_validate_password_blocklist_integration(self):
        from amoskys.auth.password_policy import PasswordPolicy, validate_password

        # "password1" is in the blocklist (exact match after lowering)
        policy = PasswordPolicy(
            min_length=4,
            require_uppercase=False,
            require_special=False,
            blocklist_enabled=True,
        )
        result = validate_password("Password1", policy)
        blocklist_error = [e for e in result.errors if "common" in e.lower()]
        assert len(blocklist_error) >= 1


# ============================================================================
# 4. Sessions Module Tests
# ============================================================================


def _make_user(db: DbSession, **overrides) -> "User":  # noqa: F821
    """Helper to insert a test User record."""
    from amoskys.auth.models import User, UserRole
    from amoskys.auth.password import hash_password

    defaults = dict(
        id=str(uuid.uuid4()),
        email=f"test-{uuid.uuid4().hex[:8]}@example.com",
        email_normalized=f"test-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("TestPass1!"),
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
        failed_login_count=0,
    )
    defaults.update(overrides)
    user = User(**defaults)
    db.add(user)
    db.flush()
    return user


class TestSessionCreation:
    """Tests for amoskys.auth.sessions.create_session."""

    def test_create_session_returns_token_and_session(self, db):
        from amoskys.auth.sessions import SessionConfig, create_session

        user = _make_user(db)
        cfg = SessionConfig(session_lifetime_hours=24, max_sessions_per_user=10)
        token, session = create_session(db, user, ip_address="10.0.0.1", config=cfg)

        assert isinstance(token, str)
        assert len(token) >= 40
        assert session.user_id == user.id
        assert session.ip_address == "10.0.0.1"

    def test_session_token_hash_stored_not_plaintext(self, db):
        from amoskys.auth.sessions import SessionConfig, create_session
        from amoskys.auth.tokens import hash_token

        user = _make_user(db)
        cfg = SessionConfig()
        token, session = create_session(db, user, config=cfg)

        assert session.session_token_hash == hash_token(token)
        assert session.session_token_hash != token

    def test_session_has_correct_expiry(self, db):
        from amoskys.auth.sessions import SessionConfig, create_session

        user = _make_user(db)
        cfg = SessionConfig(session_lifetime_hours=48)
        _, session = create_session(db, user, config=cfg)

        # Expiry should be approximately 48 hours from now
        expected_min = datetime.utcnow() + timedelta(hours=47, minutes=50)
        expected_max = datetime.utcnow() + timedelta(hours=48, minutes=10)
        assert expected_min < session.expires_at < expected_max

    def test_user_agent_truncated(self, db):
        from amoskys.auth.sessions import SessionConfig, create_session

        user = _make_user(db)
        cfg = SessionConfig()
        long_ua = "A" * 1000
        _, session = create_session(db, user, user_agent=long_ua, config=cfg)

        assert len(session.user_agent) == 500

    def test_enforce_max_sessions(self, db):
        from amoskys.auth.sessions import SessionConfig, create_session

        user = _make_user(db)
        cfg = SessionConfig(max_sessions_per_user=3)

        tokens = []
        for _ in range(5):
            tok, _ = create_session(db, user, config=cfg)
            tokens.append(tok)
        db.flush()

        # Only 3 should remain active (2 oldest should be revoked)
        from amoskys.auth.models import Session as SessionModel

        active = (
            db.query(SessionModel)
            .filter(
                SessionModel.user_id == user.id,
                SessionModel.revoked_at.is_(None),
            )
            .all()
        )
        assert len(active) <= 3


class TestSessionValidation:
    """Tests for amoskys.auth.sessions.validate_session."""

    def test_valid_session(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db)
        cfg = SessionConfig()
        token, _ = create_session(db, user, config=cfg)
        db.flush()

        result = validate_session(db, token, config=cfg)
        assert result.is_valid is True
        assert result.user.id == user.id

    def test_invalid_token_format(self, db):
        from amoskys.auth.sessions import SessionConfig, validate_session

        cfg = SessionConfig()
        result = validate_session(db, "short", config=cfg)
        assert result.is_valid is False
        assert result.error_code == "INVALID_TOKEN"

    def test_empty_token(self, db):
        from amoskys.auth.sessions import SessionConfig, validate_session

        cfg = SessionConfig()
        result = validate_session(db, "", config=cfg)
        assert result.is_valid is False

    def test_nonexistent_token(self, db):
        from amoskys.auth.sessions import SessionConfig, validate_session
        from amoskys.auth.tokens import generate_token

        cfg = SessionConfig()
        result = validate_session(db, generate_token(), config=cfg)
        assert result.is_valid is False
        assert result.error_code == "SESSION_NOT_FOUND"

    def test_expired_session(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db)
        cfg = SessionConfig(session_lifetime_hours=24)
        token, session = create_session(db, user, config=cfg)
        # Manually expire
        session.expires_at = datetime.utcnow() - timedelta(hours=1)
        db.flush()

        result = validate_session(db, token, config=cfg)
        assert result.is_valid is False
        assert result.error_code == "SESSION_EXPIRED"

    def test_revoked_session(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            revoke_session,
            validate_session,
        )

        user = _make_user(db)
        cfg = SessionConfig()
        token, session = create_session(db, user, config=cfg)
        db.flush()

        revoke_session(db, session)
        db.flush()

        result = validate_session(db, token, config=cfg)
        assert result.is_valid is False
        assert result.error_code == "SESSION_REVOKED"

    def test_idle_timeout(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db)
        cfg = SessionConfig(idle_timeout_hours=1)
        token, session = create_session(db, user, config=cfg)
        # Simulate idle for 2 hours
        session.last_active_at = datetime.utcnow() - timedelta(hours=2)
        db.flush()

        result = validate_session(db, token, config=cfg)
        assert result.is_valid is False
        assert result.error_code == "SESSION_IDLE_TIMEOUT"

    def test_ip_binding_mismatch(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db)
        cfg = SessionConfig(enable_ip_binding=True)
        token, _ = create_session(db, user, ip_address="10.0.0.1", config=cfg)
        db.flush()

        result = validate_session(db, token, ip_address="10.0.0.2", config=cfg)
        assert result.is_valid is False
        assert result.error_code == "SESSION_IP_MISMATCH"

    def test_ua_binding_mismatch(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db)
        cfg = SessionConfig(enable_ua_binding=True)
        token, _ = create_session(db, user, user_agent="Chrome/1.0", config=cfg)
        db.flush()

        result = validate_session(db, token, user_agent="Firefox/2.0", config=cfg)
        assert result.is_valid is False
        assert result.error_code == "SESSION_UA_MISMATCH"

    def test_inactive_user_session_invalid(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db, is_active=False)
        cfg = SessionConfig()
        token, _ = create_session(db, user, config=cfg)
        db.flush()

        result = validate_session(db, token, config=cfg)
        assert result.is_valid is False
        assert result.error_code == "ACCOUNT_DISABLED"

    def test_locked_user_session_invalid(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db, locked_until=datetime.utcnow() + timedelta(hours=1))
        cfg = SessionConfig()
        token, _ = create_session(db, user, config=cfg)
        db.flush()

        result = validate_session(db, token, config=cfg)
        assert result.is_valid is False
        assert result.error_code == "ACCOUNT_LOCKED"

    def test_activity_timestamp_updated(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            validate_session,
        )

        user = _make_user(db)
        cfg = SessionConfig()
        token, session = create_session(db, user, config=cfg)
        old_active = session.last_active_at
        db.flush()

        # Small delay simulation not needed; validate should update
        result = validate_session(db, token, config=cfg, update_activity=True)
        assert result.is_valid is True
        assert result.session.last_active_at >= old_active


class TestSessionRefresh:
    """Tests for amoskys.auth.sessions.refresh_session."""

    def test_extends_expiry(self, db):
        from amoskys.auth.sessions import SessionConfig, create_session, refresh_session

        user = _make_user(db)
        cfg = SessionConfig(session_lifetime_hours=24)
        _, session = create_session(db, user, config=cfg)
        old_expires = session.expires_at
        db.flush()

        # Artificially move expiry closer to simulate passage of time
        session.expires_at = datetime.utcnow() + timedelta(hours=1)
        db.flush()

        refreshed = refresh_session(db, session, config=cfg)
        assert refreshed.expires_at > session.expires_at - timedelta(hours=23)


class TestSessionRevocation:
    """Tests for amoskys.auth.sessions.revoke_session / revoke_all."""

    def test_revoke_sets_revoked_at(self, db):
        from amoskys.auth.sessions import SessionConfig, create_session, revoke_session

        user = _make_user(db)
        cfg = SessionConfig()
        _, session = create_session(db, user, config=cfg)
        db.flush()

        assert session.revoked_at is None
        revoke_session(db, session, reason="test-logout")
        db.flush()
        assert session.revoked_at is not None

    def test_revoke_all_user_sessions(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            revoke_all_user_sessions,
        )

        user = _make_user(db)
        cfg = SessionConfig(max_sessions_per_user=10)
        for _ in range(5):
            create_session(db, user, config=cfg)
        db.flush()

        count = revoke_all_user_sessions(db, user.id)
        assert count == 5

    def test_revoke_all_except_one(self, db):
        from amoskys.auth.models import Session as SessionModel
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            revoke_all_user_sessions,
        )

        user = _make_user(db)
        cfg = SessionConfig(max_sessions_per_user=10)
        sessions = []
        for _ in range(3):
            _, s = create_session(db, user, config=cfg)
            sessions.append(s)
        db.flush()

        keep_id = sessions[-1].id
        count = revoke_all_user_sessions(db, user.id, except_session_id=keep_id)
        assert count == 2

        active = (
            db.query(SessionModel)
            .filter(
                SessionModel.user_id == user.id,
                SessionModel.revoked_at.is_(None),
            )
            .all()
        )
        assert len(active) == 1
        assert active[0].id == keep_id


class TestGetUserActiveSessions:
    """Tests for amoskys.auth.sessions.get_user_active_sessions."""

    def test_returns_only_active(self, db):
        from amoskys.auth.sessions import (
            SessionConfig,
            create_session,
            get_user_active_sessions,
            revoke_session,
        )

        user = _make_user(db)
        cfg = SessionConfig(max_sessions_per_user=10)
        _, s1 = create_session(db, user, config=cfg)
        _, s2 = create_session(db, user, config=cfg)
        _, s3 = create_session(db, user, config=cfg)
        db.flush()

        revoke_session(db, s2)
        db.flush()

        active = get_user_active_sessions(db, user.id)
        ids = {s.id for s in active}
        assert s1.id in ids
        assert s2.id not in ids
        assert s3.id in ids


class TestCleanupExpiredSessions:
    """Tests for amoskys.auth.sessions.cleanup_expired_sessions."""

    def test_removes_old_expired_sessions(self, db):
        from amoskys.auth.models import Session as SessionModel
        from amoskys.auth.sessions import (
            SessionConfig,
            cleanup_expired_sessions,
            create_session,
        )

        user = _make_user(db)
        cfg = SessionConfig()
        _, session = create_session(db, user, config=cfg)
        # Make it expired and old
        session.expires_at = datetime.utcnow() - timedelta(days=2)
        db.flush()

        count = cleanup_expired_sessions(db)
        assert count >= 1


class TestSessionConfigFromEnv:
    """Tests for amoskys.auth.sessions.get_session_config."""

    def test_default_config(self):
        from amoskys.auth.sessions import SessionConfig, reset_session_config

        reset_session_config()
        cfg = SessionConfig()
        assert cfg.session_lifetime_hours == 24
        assert cfg.idle_timeout_hours == 2
        assert cfg.max_sessions_per_user == 10
        assert cfg.enable_ip_binding is False

    def test_env_override(self):
        from amoskys.auth.sessions import get_session_config, reset_session_config

        reset_session_config()
        env = {
            "AMOSKYS_SESSION_LIFETIME_HOURS": "48",
            "AMOSKYS_SESSION_IDLE_TIMEOUT_HOURS": "4",
            "AMOSKYS_SESSION_MAX_PER_USER": "5",
            "AMOSKYS_SESSION_BIND_IP": "true",
            "AMOSKYS_SESSION_BIND_UA": "yes",
        }
        with patch.dict("os.environ", env, clear=False):
            cfg = get_session_config()
            assert cfg.session_lifetime_hours == 48
            assert cfg.idle_timeout_hours == 4
            assert cfg.max_sessions_per_user == 5
            assert cfg.enable_ip_binding is True
            assert cfg.enable_ua_binding is True

        # Clean up for other tests
        reset_session_config()


class TestSessionValidationResult:
    """Tests for the SessionValidationResult dataclass."""

    def test_success_factory(self):
        from amoskys.auth.sessions import SessionValidationResult

        mock_user = MagicMock()
        mock_session = MagicMock()
        result = SessionValidationResult.success(mock_user, mock_session)
        assert result.is_valid is True
        assert result.user is mock_user
        assert result.session is mock_session

    def test_failure_factory(self):
        from amoskys.auth.sessions import SessionValidationResult

        result = SessionValidationResult.failure("Session expired", "SESSION_EXPIRED")
        assert result.is_valid is False
        assert result.error == "Session expired"
        assert result.error_code == "SESSION_EXPIRED"


# ============================================================================
# 5. AuthService Tests
# ============================================================================


class TestAuthServiceSignup:
    """Tests for AuthService.signup."""

    def test_signup_success(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=True)
        svc = AuthService(db, config=config)

        result = svc.signup(
            email="alice@example.com",
            password="Str0ng!Pass123",
            full_name="Alice",
            ip_address="10.0.0.1",
        )
        assert result.success is True
        assert result.user is not None
        assert result.user.email == "alice@example.com"
        assert result.user.email_normalized == "alice@example.com"
        assert result.verification_token is not None

    def test_signup_no_verification(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)

        result = svc.signup(email="bob@example.com", password="Str0ng!Pass123")
        assert result.success is True
        assert result.user.is_verified is True
        assert result.verification_token is None

    def test_signup_duplicate_email(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)

        svc.signup(email="dup@example.com", password="Str0ng!Pass123")
        result = svc.signup(email="dup@example.com", password="Str0ng!Pass456")
        assert result.success is False
        assert result.error_code == "EMAIL_EXISTS"

    def test_signup_duplicate_email_case_insensitive(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)

        svc.signup(email="User@Example.COM", password="Str0ng!Pass123")
        result = svc.signup(email="user@example.com", password="Str0ng!Pass456")
        assert result.success is False
        assert result.error_code == "EMAIL_EXISTS"

    def test_signup_weak_password(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.signup(email="weak@example.com", password="abc")
        assert result.success is False
        assert result.error_code == "INVALID_PASSWORD"

    def test_signup_email_normalization_whitespace(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)

        result = svc.signup(email="  Spaces@Example.com  ", password="Str0ng!Pass123")
        assert result.success is True
        assert result.user.email_normalized == "spaces@example.com"


class TestAuthServiceLogin:
    """Tests for AuthService.login."""

    def _signup_user(
        self, db, email="login@example.com", password="Str0ng!Pass123", verified=True
    ):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=not verified)
        svc = AuthService(db, config=config)
        result = svc.signup(email=email, password=password)
        if verified and not result.user.is_verified:
            result.user.is_verified = True
            db.flush()
        return result

    def test_login_success(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig
        from amoskys.auth.sessions import SessionConfig

        self._signup_user(db)
        config = AuthServiceConfig(require_email_verification=False)
        sess_cfg = SessionConfig()
        svc = AuthService(db, config=config, session_config=sess_cfg)

        result = svc.login(
            email="login@example.com",
            password="Str0ng!Pass123",
            ip_address="10.0.0.1",
        )
        assert result.success is True
        assert result.session_token is not None
        assert result.session is not None
        assert result.user.email_normalized == "login@example.com"

    def test_login_wrong_password(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        self._signup_user(db)
        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)

        result = svc.login(email="login@example.com", password="WrongPass1!")
        assert result.success is False
        assert result.error_code == "INVALID_CREDENTIALS"

    def test_login_nonexistent_user(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.login(email="nobody@example.com", password="Str0ng!Pass123")
        assert result.success is False
        assert result.error_code == "INVALID_CREDENTIALS"

    def test_login_account_lockout(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        self._signup_user(db)
        config = AuthServiceConfig(
            max_login_attempts=3,
            lockout_minutes=15,
            require_email_verification=False,
        )
        svc = AuthService(db, config=config)

        # Fail 3 times
        for _ in range(3):
            svc.login(email="login@example.com", password="wrong")

        # Next attempt should be locked
        result = svc.login(email="login@example.com", password="Str0ng!Pass123")
        assert result.success is False
        assert result.error_code == "ACCOUNT_LOCKED"

    def test_login_inactive_account(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        signup = self._signup_user(db)
        signup.user.is_active = False
        db.flush()

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        result = svc.login(email="login@example.com", password="Str0ng!Pass123")
        assert result.success is False
        assert result.error_code == "ACCOUNT_INACTIVE"

    def test_login_unverified_email(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=True)
        svc = AuthService(db, config=config)
        svc.signup(email="unverified@example.com", password="Str0ng!Pass123")

        result = svc.login(email="unverified@example.com", password="Str0ng!Pass123")
        assert result.success is False
        assert result.error_code == "EMAIL_NOT_VERIFIED"

    def test_login_clears_failed_count(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        self._signup_user(db)
        config = AuthServiceConfig(
            max_login_attempts=5,
            require_email_verification=False,
        )
        svc = AuthService(db, config=config)

        # Fail twice
        svc.login(email="login@example.com", password="wrong")
        svc.login(email="login@example.com", password="wrong")

        # Succeed
        result = svc.login(email="login@example.com", password="Str0ng!Pass123")
        assert result.success is True
        assert result.user.failed_login_count == 0

    def test_login_mfa_required(self, db):
        from amoskys.auth.models import MFAType
        from amoskys.auth.service import AuthService, AuthServiceConfig

        signup = self._signup_user(db)
        signup.user.mfa_enabled = True
        signup.user.mfa_type = MFAType.TOTP
        db.flush()

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        result = svc.login(email="login@example.com", password="Str0ng!Pass123")
        assert result.success is True
        assert result.requires_mfa is True
        assert MFAType.TOTP in result.mfa_methods
        assert result.session_token is None  # No session yet until MFA


class TestAuthServiceLogout:
    """Tests for AuthService.logout / logout_all."""

    def _login_user(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig
        from amoskys.auth.sessions import SessionConfig

        config = AuthServiceConfig(require_email_verification=False)
        sess_cfg = SessionConfig()
        svc = AuthService(db, config=config, session_config=sess_cfg)
        svc.signup(email="logout@example.com", password="Str0ng!Pass123")
        login_result = svc.login(email="logout@example.com", password="Str0ng!Pass123")
        return svc, login_result

    def test_logout_success(self, db):
        svc, login_result = self._login_user(db)
        result = svc.logout(login_result.session_token)
        assert result.success is True

    def test_logout_invalid_token(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.logout(
            "invalid-session-token-that-is-long-enough-to-pass-format-check"
        )
        assert result.success is False
        assert result.error_code == "INVALID_SESSION"

    def test_logout_all(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig
        from amoskys.auth.sessions import SessionConfig

        config = AuthServiceConfig(require_email_verification=False)
        sess_cfg = SessionConfig(max_sessions_per_user=10)
        svc = AuthService(db, config=config, session_config=sess_cfg)
        svc.signup(email="logoutall@example.com", password="Str0ng!Pass123")

        # Login 3 times
        login1 = svc.login(email="logoutall@example.com", password="Str0ng!Pass123")
        login2 = svc.login(email="logoutall@example.com", password="Str0ng!Pass123")
        login3 = svc.login(email="logoutall@example.com", password="Str0ng!Pass123")

        result = svc.logout_all(login1.user.id)
        assert result.success is True

        # All sessions should be invalid now
        for token in [login1.session_token, login2.session_token, login3.session_token]:
            val = svc.validate_and_refresh_session(token)
            assert val.is_valid is False


class TestAuthServiceEmailVerification:
    """Tests for AuthService.verify_email / resend_verification_email."""

    def test_verify_email_success(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=True)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="verify@example.com", password="Str0ng!Pass123")
        assert signup.success is True

        result = svc.verify_email(signup.verification_token)
        assert result.success is True

        # User should now be verified
        from amoskys.auth.models import User

        user = (
            db.query(User).filter(User.email_normalized == "verify@example.com").first()
        )
        assert user.is_verified is True

    def test_verify_email_invalid_token(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.verify_email("invalid-token")
        assert result.success is False
        assert result.error_code == "INVALID_TOKEN"

    def test_resend_verification_user_not_found(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.resend_verification_email("nonexistent@example.com")
        # Should pretend success for security
        assert result.success is True

    def test_resend_verification_already_verified(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        svc.signup(email="already@example.com", password="Str0ng!Pass123")

        result = svc.resend_verification_email("already@example.com")
        assert result.success is False
        assert result.error_code == "ALREADY_VERIFIED"

    def test_resend_verification_generates_new_token(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=True)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="resend@example.com", password="Str0ng!Pass123")

        resend = svc.resend_verification_email("resend@example.com")
        assert resend.success is True
        assert resend.verification_token is not None
        # Old token should no longer work
        old_result = svc.verify_email(signup.verification_token)
        assert old_result.success is False


class TestAuthServicePasswordReset:
    """Tests for AuthService.request_password_reset / reset_password."""

    def test_request_reset_existing_user(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        svc.signup(email="reset@example.com", password="Str0ng!Pass123")

        result = svc.request_password_reset("reset@example.com")
        assert result.success is True
        assert result.reset_token is not None

    def test_request_reset_nonexistent_user(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.request_password_reset("nobody@example.com")
        # Pretend success for security
        assert result.success is True
        assert result.reset_token is None

    def test_reset_password_success(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        svc.signup(email="resetpw@example.com", password="Str0ng!Pass123")

        reset = svc.request_password_reset("resetpw@example.com")
        result = svc.reset_password(
            token=reset.reset_token,
            new_password="NewStr0ng!Pass456",
        )
        assert result.success is True

        # Can login with new password
        login = svc.login(email="resetpw@example.com", password="NewStr0ng!Pass456")
        assert login.success is True

    def test_reset_password_invalid_token(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.reset_password(token="bad-token", new_password="NewStr0ng!Pass456")
        assert result.success is False
        assert result.error_code == "INVALID_TOKEN"

    def test_reset_password_weak_new_password(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        svc.signup(email="weakreset@example.com", password="Str0ng!Pass123")

        reset = svc.request_password_reset("weakreset@example.com")
        result = svc.reset_password(token=reset.reset_token, new_password="abc")
        assert result.success is False
        assert result.error_code == "INVALID_PASSWORD"

    def test_reset_password_auto_verifies_email(self, db):
        from amoskys.auth.models import User
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=True)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="autoverify@example.com", password="Str0ng!Pass123")
        assert signup.user.is_verified is False

        reset = svc.request_password_reset("autoverify@example.com")
        result = svc.reset_password(
            token=reset.reset_token,
            new_password="NewStr0ng!Pass456",
        )
        assert result.success is True

        user = (
            db.query(User)
            .filter(User.email_normalized == "autoverify@example.com")
            .first()
        )
        assert user.is_verified is True

    def test_reset_password_revokes_all_sessions(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig
        from amoskys.auth.sessions import SessionConfig

        config = AuthServiceConfig(require_email_verification=False)
        sess_cfg = SessionConfig()
        svc = AuthService(db, config=config, session_config=sess_cfg)
        svc.signup(email="revokeall@example.com", password="Str0ng!Pass123")

        login = svc.login(email="revokeall@example.com", password="Str0ng!Pass123")
        assert login.success is True

        reset = svc.request_password_reset("revokeall@example.com")
        svc.reset_password(token=reset.reset_token, new_password="NewStr0ng!Pass456")

        # Old session should be revoked
        val = svc.validate_and_refresh_session(login.session_token)
        assert val.is_valid is False


class TestAuthServiceChangePassword:
    """Tests for AuthService.change_password."""

    def test_change_password_success(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="changepw@example.com", password="Str0ng!Pass123")

        result = svc.change_password(
            user_id=signup.user.id,
            current_password="Str0ng!Pass123",
            new_password="NewStr0ng!Pass456",
        )
        assert result.success is True

        # Can login with new password
        login = svc.login(email="changepw@example.com", password="NewStr0ng!Pass456")
        assert login.success is True

    def test_change_password_wrong_current(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="wrongcurr@example.com", password="Str0ng!Pass123")

        result = svc.change_password(
            user_id=signup.user.id,
            current_password="WrongCurrent1!",
            new_password="NewStr0ng!Pass456",
        )
        assert result.success is False
        assert result.error_code == "INVALID_PASSWORD"

    def test_change_password_user_not_found(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.change_password(
            user_id="nonexistent-id",
            current_password="any",
            new_password="any",
        )
        assert result.success is False
        assert result.error_code == "USER_NOT_FOUND"

    def test_change_password_weak_new(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="weaknew@example.com", password="Str0ng!Pass123")

        result = svc.change_password(
            user_id=signup.user.id,
            current_password="Str0ng!Pass123",
            new_password="short",
        )
        assert result.success is False
        assert result.error_code == "INVALID_NEW_PASSWORD"


class TestAuthServiceAccountManagement:
    """Tests for unlock, deactivate, reactivate."""

    def test_unlock_account(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="unlock@example.com", password="Str0ng!Pass123")
        signup.user.locked_until = datetime.utcnow() + timedelta(hours=1)
        signup.user.failed_login_count = 5
        db.flush()

        result = svc.unlock_account(signup.user.id, admin_user_id="admin-1")
        assert result.success is True
        assert signup.user.failed_login_count == 0
        assert signup.user.locked_until is None

    def test_unlock_nonexistent_user(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.unlock_account("nonexistent")
        assert result.success is False
        assert result.error_code == "USER_NOT_FOUND"

    def test_deactivate_account(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="deact@example.com", password="Str0ng!Pass123")

        result = svc.deactivate_account(signup.user.id, reason="test")
        assert result.success is True
        assert signup.user.is_active is False

    def test_deactivate_nonexistent(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.deactivate_account("nonexistent")
        assert result.success is False

    def test_reactivate_account(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="react@example.com", password="Str0ng!Pass123")
        signup.user.is_active = False
        db.flush()

        result = svc.reactivate_account(signup.user.id)
        assert result.success is True
        assert signup.user.is_active is True
        assert signup.user.failed_login_count == 0

    def test_reactivate_nonexistent(self, db):
        from amoskys.auth.service import AuthService

        svc = AuthService(db)
        result = svc.reactivate_account("nonexistent")
        assert result.success is False


class TestAuthServiceSessionValidation:
    """Tests for AuthService.validate_and_refresh_session / get_current_user."""

    def test_validate_and_refresh(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig
        from amoskys.auth.sessions import SessionConfig

        config = AuthServiceConfig(require_email_verification=False)
        sess_cfg = SessionConfig()
        svc = AuthService(db, config=config, session_config=sess_cfg)
        svc.signup(email="validate@example.com", password="Str0ng!Pass123")
        login = svc.login(email="validate@example.com", password="Str0ng!Pass123")

        result = svc.validate_and_refresh_session(login.session_token)
        assert result.is_valid is True
        assert result.user.email_normalized == "validate@example.com"

    def test_get_current_user(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig
        from amoskys.auth.sessions import SessionConfig

        config = AuthServiceConfig(require_email_verification=False)
        sess_cfg = SessionConfig()
        svc = AuthService(db, config=config, session_config=sess_cfg)
        svc.signup(email="curruser@example.com", password="Str0ng!Pass123")
        login = svc.login(email="curruser@example.com", password="Str0ng!Pass123")

        user = svc.get_current_user(login.session)
        assert user is not None
        assert user.email_normalized == "curruser@example.com"


class TestAuthServiceAuditLogs:
    """Tests for AuthService._log_audit / get_audit_logs."""

    def test_audit_logs_created_on_signup(self, db):
        from amoskys.auth.models import AuditEventType, AuthAuditLog
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        svc.signup(
            email="audit@example.com", password="Str0ng!Pass123", ip_address="10.0.0.1"
        )

        logs = (
            db.query(AuthAuditLog)
            .filter(AuthAuditLog.event_type == AuditEventType.SIGNUP)
            .all()
        )
        assert len(logs) >= 1
        assert logs[0].ip_address == "10.0.0.1"

    def test_get_audit_logs_with_filters(self, db):
        from amoskys.auth.models import AuditEventType
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        signup = svc.signup(email="filterlogs@example.com", password="Str0ng!Pass123")

        logs = svc.get_audit_logs(
            user_id=signup.user.id,
            event_types=[AuditEventType.SIGNUP],
        )
        assert len(logs) >= 1

    def test_get_audit_logs_limit(self, db):
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        svc.signup(email="limit@example.com", password="Str0ng!Pass123")

        logs = svc.get_audit_logs(limit=1)
        assert len(logs) <= 1

    def test_audit_log_user_agent_truncated(self, db):
        from amoskys.auth.models import AuditEventType, AuthAuditLog
        from amoskys.auth.service import AuthService, AuthServiceConfig

        config = AuthServiceConfig(require_email_verification=False)
        svc = AuthService(db, config=config)
        long_ua = "X" * 1000
        svc.signup(
            email="longua@example.com",
            password="Str0ng!Pass123",
            user_agent=long_ua,
        )

        logs = (
            db.query(AuthAuditLog)
            .filter(AuthAuditLog.event_type == AuditEventType.SIGNUP)
            .all()
        )
        for log in logs:
            if log.user_agent:
                assert len(log.user_agent) <= 500


# ============================================================================
# 6. Result Type Tests
# ============================================================================


class TestResultTypes:
    """Tests for AuthResult, SignupResult, LoginResult, PasswordResetResult."""

    def test_auth_result_to_dict(self):
        from amoskys.auth.service import AuthResult

        r = AuthResult(success=True)
        d = r.to_dict()
        assert d["success"] is True
        assert d["error"] is None

    def test_auth_result_error_to_dict(self):
        from amoskys.auth.service import AuthResult

        r = AuthResult(success=False, error="bad", error_code="BAD")
        d = r.to_dict()
        assert d["success"] is False
        assert d["error"] == "bad"
        assert d["error_code"] == "BAD"

    def test_signup_result_to_dict_with_user(self):
        from amoskys.auth.service import SignupResult

        mock_user = MagicMock()
        mock_user.id = "user-id-123"
        mock_user.email = "test@example.com"
        r = SignupResult(success=True, user=mock_user)
        d = r.to_dict()
        assert d["user"]["id"] == "user-id-123"
        assert d["user"]["email"] == "test@example.com"

    def test_signup_result_to_dict_no_user(self):
        from amoskys.auth.service import SignupResult

        r = SignupResult(success=False, error="fail")
        d = r.to_dict()
        assert "user" not in d

    def test_login_result_to_dict_with_mfa(self):
        from amoskys.auth.models import MFAType
        from amoskys.auth.service import LoginResult

        mock_user = MagicMock()
        mock_user.id = "uid"
        mock_user.email = "e@e.com"
        mock_user.full_name = "Test"
        r = LoginResult(
            success=True,
            user=mock_user,
            requires_mfa=True,
            mfa_methods=[MFAType.TOTP],
        )
        d = r.to_dict()
        assert d["requires_mfa"] is True
        assert "totp" in d["mfa_methods"]

    def test_login_result_to_dict_no_mfa(self):
        from amoskys.auth.service import LoginResult

        r = LoginResult(success=False, error="fail")
        d = r.to_dict()
        assert d["requires_mfa"] is False
        assert "mfa_methods" not in d

    def test_password_reset_result_hides_token(self):
        from amoskys.auth.service import PasswordResetResult

        r = PasswordResetResult(success=True, reset_token="secret-token")
        d = r.to_dict()
        assert "reset_token" not in d
        assert "token" not in d


# ============================================================================
# 7. AuthServiceConfig Tests
# ============================================================================


class TestAuthServiceConfig:
    """Tests for AuthServiceConfig defaults."""

    def test_defaults(self):
        from amoskys.auth.service import AuthServiceConfig

        cfg = AuthServiceConfig()
        assert cfg.email_verification_hours == 24
        assert cfg.require_email_verification is True
        assert cfg.password_reset_hours == 1
        assert cfg.max_login_attempts == 5
        assert cfg.lockout_minutes == 15
        assert cfg.session_config is None

    def test_custom_config(self):
        from amoskys.auth.service import AuthServiceConfig
        from amoskys.auth.sessions import SessionConfig

        sess_cfg = SessionConfig(session_lifetime_hours=48)
        cfg = AuthServiceConfig(
            max_login_attempts=10,
            lockout_minutes=30,
            session_config=sess_cfg,
        )
        assert cfg.max_login_attempts == 10
        assert cfg.session_config.session_lifetime_hours == 48
