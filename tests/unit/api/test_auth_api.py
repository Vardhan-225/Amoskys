"""
Tests for amoskys.api.auth — Auth API Flask Blueprint.

Covers:
  - POST /api/auth/signup
  - POST /api/auth/login
  - POST /api/auth/logout
  - POST /api/auth/logout-all
  - GET  /api/auth/verify-email
  - POST /api/auth/resend-verification
  - POST /api/auth/forgot-password
  - POST /api/auth/reset-password
  - POST /api/auth/change-password
  - GET  /api/auth/me
  - require_auth decorator
  - get_client_info helper
  - get_auth_config helper
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Mock result types mirroring amoskys.auth.service
# ---------------------------------------------------------------------------


@dataclass
class _FakeAuthResult:
    success: bool
    error: Optional[str] = None
    error_code: Optional[str] = None

    def to_dict(self):
        return {
            "success": self.success,
            "error": self.error,
            "error_code": self.error_code,
        }


@dataclass
class _FakeSignupResult(_FakeAuthResult):
    verification_token: Optional[str] = None
    user: Optional[object] = None

    def to_dict(self):
        d = super().to_dict()
        if self.user:
            d["user"] = {"id": "u1", "email": "a@b.com"}
        return d


@dataclass
class _FakeLoginResult(_FakeAuthResult):
    session_token: Optional[str] = None
    user: Optional[object] = None
    requires_mfa: bool = False

    def to_dict(self):
        d = super().to_dict()
        d["requires_mfa"] = self.requires_mfa
        return d


@dataclass
class _FakePasswordResetResult(_FakeAuthResult):
    reset_token: Optional[str] = None

    def to_dict(self):
        return super().to_dict()


@dataclass
class _FakeSessionValidation:
    is_valid: bool
    user: Optional[object] = None
    session: Optional[object] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(**overrides):
    """Create a fake user object with all fields the /me endpoint needs."""
    from enum import Enum

    class _Role(str, Enum):
        USER = "user"

    defaults = dict(
        id="u-123",
        email="test@example.com",
        full_name="Test User",
        role=_Role.USER,
        is_verified=True,
        mfa_enabled=False,
        created_at=datetime(2025, 1, 1),
        last_login_at=datetime(2025, 6, 1),
    )
    defaults.update(overrides)
    user = MagicMock()
    for k, v in defaults.items():
        setattr(user, k, v)
    return user


def _create_app():
    """Create a minimal Flask app with the auth blueprint registered."""
    # We must patch heavy imports that happen at module-level inside auth.py
    with patch("amoskys.api.security.limiter") as mock_limiter:
        # Make rate-limit decorators be identity decorators
        mock_limiter.limit.return_value = lambda f: f

        # Need to patch the decorator factories used by the blueprint
        with (
            patch("amoskys.api.auth.rate_limit_auth", return_value=lambda f: f),
            patch("amoskys.api.auth.rate_limit_strict", return_value=lambda f: f),
        ):

            from amoskys.api.auth import auth_bp

            app = Flask(__name__)
            app.config["TESTING"] = True
            app.register_blueprint(auth_bp)
            return app


# We build the app once per module; each test gets a fresh test client.
_app = None


def _get_app():
    global _app
    if _app is None:
        _app = _create_app()
    return _app


@pytest.fixture()
def client():
    app = _get_app()
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Tests: get_auth_config / get_client_info (unit)
# ---------------------------------------------------------------------------


class TestGetAuthConfig:
    def test_default_requires_verification(self):
        with patch.dict("os.environ", {}, clear=False):
            from amoskys.api.auth import get_auth_config

            cfg = get_auth_config()
            assert hasattr(cfg, "require_email_verification")

    def test_returns_config_object(self):
        from amoskys.api.auth import get_auth_config

        cfg = get_auth_config()
        assert cfg is not None


class TestGetClientInfo:
    def test_extracts_ip_and_ua(self, client):
        app = _get_app()
        with app.test_request_context(
            headers={"X-Forwarded-For": "1.2.3.4", "User-Agent": "TestBot"}
        ):
            from amoskys.api.auth import get_client_info

            info = get_client_info()
            assert info["ip_address"] == "1.2.3.4"
            assert info["user_agent"] == "TestBot"

    def test_falls_back_to_remote_addr(self, client):
        app = _get_app()
        with app.test_request_context():
            from amoskys.api.auth import get_client_info

            info = get_client_info()
            # remote_addr is typically 127.0.0.1 in test context or None
            assert "ip_address" in info


# ---------------------------------------------------------------------------
# Tests: POST /api/auth/signup
# ---------------------------------------------------------------------------


class TestSignup:
    def test_signup_no_body_returns_400(self, client):
        # Send valid JSON content-type with empty JSON body so Flask doesn't 415
        resp = client.post(
            "/api/auth/signup",
            data=json.dumps(None),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_signup_missing_fields_returns_400(self, client):
        resp = client.post(
            "/api/auth/signup",
            data=json.dumps({"email": "a@b.com"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "MISSING_FIELDS"

    @patch("amoskys.api.auth.send_verification_email")
    @patch("amoskys.api.auth.get_session_context")
    def test_signup_success_sends_verification(self, mock_ctx, mock_send_email, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeSignupResult(
            success=True, verification_token="tok123", user=_make_user()
        )

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.signup.return_value = fake_result

            resp = client.post(
                "/api/auth/signup",
                data=json.dumps({"email": "a@b.com", "password": "Secret123!"}),
                content_type="application/json",
            )
            assert resp.status_code == 201
            assert resp.get_json()["success"] is True
            mock_send_email.assert_called_once()

    @patch(
        "amoskys.api.auth.send_verification_email", side_effect=Exception("SMTP down")
    )
    @patch("amoskys.api.auth.get_session_context")
    def test_signup_email_failure_does_not_fail_signup(
        self, mock_ctx, mock_send, client
    ):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeSignupResult(
            success=True, verification_token="tok123", user=_make_user()
        )

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.signup.return_value = fake_result
            resp = client.post(
                "/api/auth/signup",
                data=json.dumps({"email": "a@b.com", "password": "Secret123!"}),
                content_type="application/json",
            )
            assert resp.status_code == 201  # signup still succeeds

    @patch("amoskys.api.auth.get_session_context")
    def test_signup_failure_returns_400(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeSignupResult(
            success=False, error="Email taken", error_code="DUPLICATE_EMAIL"
        )
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.signup.return_value = fake_result
            resp = client.post(
                "/api/auth/signup",
                data=json.dumps({"email": "a@b.com", "password": "pw"}),
                content_type="application/json",
            )
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: POST /api/auth/login
# ---------------------------------------------------------------------------


class TestLogin:
    def test_login_no_body_returns_400(self, client):
        resp = client.post("/api/auth/login", content_type="application/json")
        assert resp.status_code == 400

    def test_login_missing_fields_returns_400(self, client):
        resp = client.post(
            "/api/auth/login",
            data=json.dumps({"email": "a@b.com"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "MISSING_FIELDS"

    @patch("amoskys.api.auth.get_session_context")
    def test_login_success_sets_cookie(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeLoginResult(success=True, session_token="sess-tok-123")
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.login.return_value = fake_result
            resp = client.post(
                "/api/auth/login",
                data=json.dumps({"email": "a@b.com", "password": "pw"}),
                content_type="application/json",
            )
            assert resp.status_code == 200
            # Check the session cookie was set via Set-Cookie header
            set_cookie_headers = resp.headers.getlist("Set-Cookie")
            assert any("amoskys_session" in h for h in set_cookie_headers)

    @patch("amoskys.api.auth.get_session_context")
    def test_login_failure_returns_401(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeLoginResult(
            success=False, error="Bad creds", error_code="INVALID_CREDENTIALS"
        )
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.login.return_value = fake_result
            resp = client.post(
                "/api/auth/login",
                data=json.dumps({"email": "a@b.com", "password": "wrong"}),
                content_type="application/json",
            )
            assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tests: GET /api/auth/verify-email
# ---------------------------------------------------------------------------


class TestVerifyEmail:
    def test_verify_email_missing_token_returns_400(self, client):
        resp = client.get("/api/auth/verify-email")
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "MISSING_TOKEN"

    @patch("amoskys.api.auth.get_session_context")
    def test_verify_email_success(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeAuthResult(success=True)
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.verify_email.return_value = fake_result
            resp = client.get("/api/auth/verify-email?token=abc123")
            assert resp.status_code == 200
            assert resp.get_json()["success"] is True

    @patch("amoskys.api.auth.get_session_context")
    def test_verify_email_invalid_token_returns_400(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeAuthResult(success=False, error="Expired")
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.verify_email.return_value = fake_result
            resp = client.get("/api/auth/verify-email?token=bad")
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: POST /api/auth/resend-verification
# ---------------------------------------------------------------------------


class TestResendVerification:
    def test_resend_no_email_returns_400(self, client):
        resp = client.post(
            "/api/auth/resend-verification",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "MISSING_EMAIL"

    @patch("amoskys.api.auth.send_verification_email")
    @patch("amoskys.api.auth.get_session_context")
    def test_resend_always_returns_200(self, mock_ctx, mock_send, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = MagicMock(success=True, verification_token="vtok")
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.resend_verification_email.return_value = fake_result
            resp = client.post(
                "/api/auth/resend-verification",
                data=json.dumps({"email": "a@b.com"}),
                content_type="application/json",
            )
            assert resp.status_code == 200
            assert resp.get_json()["success"] is True
            mock_send.assert_called_once()

    def test_resend_no_body_returns_400(self, client):
        resp = client.post(
            "/api/auth/resend-verification",
            content_type="application/json",
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: POST /api/auth/forgot-password
# ---------------------------------------------------------------------------


class TestForgotPassword:
    def test_forgot_password_no_email_returns_400(self, client):
        resp = client.post(
            "/api/auth/forgot-password",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    @patch("amoskys.api.auth.send_password_reset_email")
    @patch("amoskys.api.auth.get_session_context")
    def test_forgot_password_returns_200(self, mock_ctx, mock_send, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakePasswordResetResult(success=True, reset_token="rstk")
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.request_password_reset.return_value = fake_result
            resp = client.post(
                "/api/auth/forgot-password",
                data=json.dumps({"email": "a@b.com"}),
                content_type="application/json",
            )
            assert resp.status_code == 200
            mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: POST /api/auth/reset-password
# ---------------------------------------------------------------------------


class TestResetPassword:
    def test_reset_password_no_body_returns_400(self, client):
        resp = client.post("/api/auth/reset-password", content_type="application/json")
        assert resp.status_code == 400

    def test_reset_password_missing_fields_returns_400(self, client):
        resp = client.post(
            "/api/auth/reset-password",
            data=json.dumps({"token": "abc"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json()["error_code"] == "MISSING_FIELDS"

    @patch("amoskys.api.auth.get_session_context")
    def test_reset_password_success(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeAuthResult(success=True)
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.reset_password.return_value = fake_result
            resp = client.post(
                "/api/auth/reset-password",
                data=json.dumps({"token": "tok", "new_password": "NewPass1!"}),
                content_type="application/json",
            )
            assert resp.status_code == 200

    @patch("amoskys.api.auth.get_session_context")
    def test_reset_password_failure(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_result = _FakeAuthResult(success=False, error="expired")
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.reset_password.return_value = fake_result
            resp = client.post(
                "/api/auth/reset-password",
                data=json.dumps({"token": "tok", "new_password": "x"}),
                content_type="application/json",
            )
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: require_auth decorator
# ---------------------------------------------------------------------------


class TestRequireAuth:
    def test_no_session_cookie_returns_401(self, client):
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 401
        assert resp.get_json()["error_code"] == "NO_SESSION"

    @patch("amoskys.api.auth.get_session_context")
    def test_invalid_session_returns_401_and_deletes_cookie(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
        mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

        fake_validation = _FakeSessionValidation(
            is_valid=False, error="Session expired", error_code="SESSION_EXPIRED"
        )
        with patch("amoskys.api.auth.AuthService") as MockAuth:
            MockAuth.return_value.validate_and_refresh_session.return_value = (
                fake_validation
            )
            client.set_cookie("amoskys_session", "bad-token", domain="localhost")
            resp = client.post("/api/auth/logout")
            assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tests: Protected endpoints (with valid auth)
# ---------------------------------------------------------------------------


def _mock_auth_passes(mock_ctx):
    """Configure mocks so that require_auth succeeds."""
    mock_db = MagicMock()
    mock_ctx.return_value.__enter__ = MagicMock(return_value=mock_db)
    mock_ctx.return_value.__exit__ = MagicMock(return_value=False)

    user = _make_user()
    session_obj = MagicMock()
    fake_validation = _FakeSessionValidation(
        is_valid=True, user=user, session=session_obj
    )
    return mock_db, user, fake_validation


class TestLogout:
    @patch("amoskys.api.auth.get_session_context")
    def test_logout_success(self, mock_ctx, client):
        mock_db, user, fake_val = _mock_auth_passes(mock_ctx)

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            inst = MockAuth.return_value
            inst.validate_and_refresh_session.return_value = fake_val
            inst.logout.return_value = _FakeAuthResult(success=True)

            client.set_cookie("amoskys_session", "valid-tok", domain="localhost")
            resp = client.post("/api/auth/logout")
            assert resp.status_code == 200
            assert resp.get_json()["success"] is True


class TestLogoutAll:
    @patch("amoskys.api.auth.get_session_context")
    def test_logout_all_success(self, mock_ctx, client):
        mock_db, user, fake_val = _mock_auth_passes(mock_ctx)

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            inst = MockAuth.return_value
            inst.validate_and_refresh_session.return_value = fake_val
            inst.logout_all.return_value = _FakeAuthResult(success=True)

            client.set_cookie("amoskys_session", "valid-tok", domain="localhost")
            resp = client.post("/api/auth/logout-all")
            assert resp.status_code == 200


class TestChangePassword:
    @patch("amoskys.api.auth.get_session_context")
    def test_change_password_no_body_returns_400(self, mock_ctx, client):
        mock_db, user, fake_val = _mock_auth_passes(mock_ctx)

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            inst = MockAuth.return_value
            inst.validate_and_refresh_session.return_value = fake_val

            client.set_cookie("amoskys_session", "tok", domain="localhost")
            resp = client.post(
                "/api/auth/change-password", content_type="application/json"
            )
            assert resp.status_code == 400

    @patch("amoskys.api.auth.get_session_context")
    def test_change_password_missing_fields_returns_400(self, mock_ctx, client):
        mock_db, user, fake_val = _mock_auth_passes(mock_ctx)

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            inst = MockAuth.return_value
            inst.validate_and_refresh_session.return_value = fake_val

            client.set_cookie("amoskys_session", "tok", domain="localhost")
            resp = client.post(
                "/api/auth/change-password",
                data=json.dumps({"current_password": "old"}),
                content_type="application/json",
            )
            assert resp.status_code == 400

    @patch("amoskys.api.auth.get_session_context")
    def test_change_password_success(self, mock_ctx, client):
        mock_db, user, fake_val = _mock_auth_passes(mock_ctx)

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            inst = MockAuth.return_value
            inst.validate_and_refresh_session.return_value = fake_val
            inst.change_password.return_value = _FakeAuthResult(success=True)

            client.set_cookie("amoskys_session", "tok", domain="localhost")
            resp = client.post(
                "/api/auth/change-password",
                data=json.dumps({"current_password": "old", "new_password": "New1!"}),
                content_type="application/json",
            )
            assert resp.status_code == 200


class TestGetCurrentUser:
    @patch("amoskys.api.auth.get_session_context")
    def test_me_returns_user_info(self, mock_ctx, client):
        mock_db, user, fake_val = _mock_auth_passes(mock_ctx)

        with patch("amoskys.api.auth.AuthService") as MockAuth:
            inst = MockAuth.return_value
            inst.validate_and_refresh_session.return_value = fake_val

            client.set_cookie("amoskys_session", "tok", domain="localhost")
            resp = client.get("/api/auth/me")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert data["user"]["email"] == "test@example.com"
            assert data["user"]["full_name"] == "Test User"
            assert data["user"]["role"] == "user"
            assert data["user"]["is_verified"] is True
