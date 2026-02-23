"""
Week 1 Security Hardening Tests (Sprint Phase A)

Tests for:
  A1.1 — Email password: env-only loading, no hardcoded secrets
  A1.2 — SECRET_KEY: startup validation, weak key rejection
  A1.3 — CSP: nonces enabled, unsafe-inline removed from script-src
  A1.4 — Health endpoints: auth required for /system and /agents, /ping minimal
"""

import importlib
import os
import secrets
import sys
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask


def _web_path():
    """Return path to web/ directory."""
    return os.path.join(os.path.dirname(__file__), "..", "..", "..", "web")


def _fresh_create_app():
    """Get a fresh create_app by reloading the module."""
    web_dir = _web_path()
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)
    # Force reimport to pick up new env vars
    if "app" in sys.modules:
        importlib.reload(sys.modules["app"])
    from app import create_app

    return create_app


# ---------------------------------------------------------------------------
# A1.2 — SECRET_KEY Validation
# ---------------------------------------------------------------------------


class TestSecretKeyValidation:
    """App must reject weak, short, or missing SECRET_KEYs in production."""

    def test_production_missing_key_raises(self):
        """Production mode without SECRET_KEY must raise ValueError."""
        env = {
            "FLASK_DEBUG": "false",
            "TESTING": "false",
            "FORCE_HTTPS": "false",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("SECRET_KEY", None)
            create_app = _fresh_create_app()
            with pytest.raises(ValueError, match="SECRET_KEY.*required"):
                create_app()

    def test_production_short_key_raises(self):
        """Production mode with key < 32 chars must raise ValueError."""
        env = {
            "FLASK_DEBUG": "false",
            "TESTING": "false",
            "FORCE_HTTPS": "false",
            "SECRET_KEY": "tooshort",
        }
        with patch.dict(os.environ, env, clear=False):
            create_app = _fresh_create_app()
            with pytest.raises(ValueError, match="too short"):
                create_app()

    def test_production_weak_pattern_dev_key_raises(self):
        """Production mode with dev-secret-key pattern must raise ValueError."""
        env = {
            "FLASK_DEBUG": "false",
            "TESTING": "false",
            "FORCE_HTTPS": "false",
            "SECRET_KEY": "my-dev-secret-key-for-testing-purposes-12345678",
        }
        with patch.dict(os.environ, env, clear=False):
            create_app = _fresh_create_app()
            with pytest.raises(ValueError, match="weak pattern"):
                create_app()

    def test_production_weak_pattern_changeme_raises(self):
        """Production mode with 'changeme' pattern must raise ValueError."""
        env = {
            "FLASK_DEBUG": "false",
            "TESTING": "false",
            "FORCE_HTTPS": "false",
            "SECRET_KEY": "please-changeme-this-is-a-long-placeholder-key1234",
        }
        with patch.dict(os.environ, env, clear=False):
            create_app = _fresh_create_app()
            with pytest.raises(ValueError, match="weak pattern"):
                create_app()

    def test_production_strong_key_accepted(self):
        """Production mode with strong key must succeed."""
        strong_key = secrets.token_hex(32)
        env = {
            "FLASK_DEBUG": "false",
            "TESTING": "false",
            "FORCE_HTTPS": "false",
            "SECRET_KEY": strong_key,
        }
        with patch.dict(os.environ, env, clear=False):
            create_app = _fresh_create_app()
            result = create_app()
            app = result[0] if isinstance(result, tuple) else result
            assert app.config["SECRET_KEY"] == strong_key

    def test_debug_mode_generates_ephemeral_key(self):
        """Debug mode without SECRET_KEY generates ephemeral key."""
        env = {
            "FLASK_DEBUG": "true",
            "TESTING": "false",
            "FORCE_HTTPS": "false",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("SECRET_KEY", None)
            create_app = _fresh_create_app()
            result = create_app()
            app = result[0] if isinstance(result, tuple) else result
            assert app.config["SECRET_KEY"] != "amoskys-neural-security-dev-key"
            assert len(app.config["SECRET_KEY"]) >= 32

    def test_testing_mode_generates_ephemeral_key(self):
        """Testing mode without SECRET_KEY generates ephemeral key."""
        env = {
            "FLASK_DEBUG": "false",
            "TESTING": "true",
            "FORCE_HTTPS": "false",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("SECRET_KEY", None)
            create_app = _fresh_create_app()
            result = create_app()
            app = result[0] if isinstance(result, tuple) else result
            assert len(app.config["SECRET_KEY"]) >= 32


# ---------------------------------------------------------------------------
# A1.3 — CSP Configuration
# ---------------------------------------------------------------------------


class TestCSPHardening:
    """CSP must use nonces and block unsafe-inline for scripts."""

    def test_unsafe_inline_not_in_script_src(self):
        """script-src must NOT contain unsafe-inline."""
        from amoskys.api.security import CSP

        assert "'unsafe-inline'" not in CSP["script-src"]

    def test_unsafe_inline_kept_in_style_src(self):
        """style-src may keep unsafe-inline temporarily (lower risk)."""
        from amoskys.api.security import CSP

        assert "'unsafe-inline'" in CSP["style-src"]

    def test_cdn_sources_present(self):
        """CDN sources for Chart.js and Socket.IO must be in script-src."""
        from amoskys.api.security import CSP

        assert "cdn.jsdelivr.net" in CSP["script-src"]
        assert "cdn.socket.io" in CSP["script-src"]

    def test_connect_src_allows_websocket(self):
        """connect-src must allow WebSocket for real-time updates."""
        from amoskys.api.security import CSP

        assert "ws:" in CSP["connect-src"]
        assert "wss:" in CSP["connect-src"]

    def test_self_in_script_src(self):
        """script-src must include 'self'."""
        from amoskys.api.security import CSP

        assert "'self'" in CSP["script-src"]

    def test_frame_ancestors_none(self):
        """frame-ancestors must be 'none' to prevent clickjacking."""
        from amoskys.api.security import CSP

        assert "'none'" in CSP["frame-ancestors"]


# ---------------------------------------------------------------------------
# A1.4 — Health Endpoint Authentication
# ---------------------------------------------------------------------------


class TestHealthEndpointAuth:
    """Health endpoints /system and /agents must require auth."""

    @pytest.fixture
    def client(self):
        """Create test Flask client with health blueprint registered."""
        env = {
            "FLASK_DEBUG": "true",
            "FORCE_HTTPS": "false",
            "SECRET_KEY": "test-only-key-not-for-production-use-abcdef12345",
            "TESTING": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            create_app = _fresh_create_app()
            result = create_app()
            app = result[0] if isinstance(result, tuple) else result
            app.config["TESTING"] = True
            return app.test_client()

    def test_ping_unauthenticated(self, client):
        """/api/v1/health/ping must work without any auth."""
        resp = client.get("/api/v1/health/ping")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_ping_minimal_response(self, client):
        """/api/v1/health/ping must return minimal data only."""
        resp = client.get("/api/v1/health/ping")
        data = resp.get_json()
        assert "agents" not in data
        assert "infrastructure" not in data
        assert "threat_level" not in data
        assert "platform" not in data
        assert "status" in data

    def test_system_requires_auth(self, client):
        """/api/v1/health/system must return 401 without auth."""
        resp = client.get("/api/v1/health/system")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error_code"] == "UNAUTHORIZED"

    def test_agents_requires_auth(self, client):
        """/api/v1/health/agents must return 401 without auth."""
        resp = client.get("/api/v1/health/agents")
        assert resp.status_code == 401

    def test_system_accepts_api_key(self, client):
        """/api/v1/health/system must accept valid API key."""
        with patch.dict(os.environ, {"AMOSKYS_API_KEY": "test-api-key-123"}):
            resp = client.get(
                "/api/v1/health/system",
                headers={"X-API-Key": "test-api-key-123"},
            )
            assert resp.status_code == 200

    def test_system_rejects_wrong_api_key(self, client):
        """/api/v1/health/system must reject invalid API key."""
        with patch.dict(os.environ, {"AMOSKYS_API_KEY": "correct-key"}):
            resp = client.get(
                "/api/v1/health/system",
                headers={"X-API-Key": "wrong-key"},
            )
            assert resp.status_code == 401

    def test_agents_accepts_api_key(self, client):
        """/api/v1/health/agents must accept valid API key."""
        with patch.dict(os.environ, {"AMOSKYS_API_KEY": "test-api-key-123"}):
            resp = client.get(
                "/api/v1/health/agents",
                headers={"X-API-Key": "test-api-key-123"},
            )
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# A1.1 — Email Security
# ---------------------------------------------------------------------------


class TestEmailSecurityConfig:
    """Email credentials must come from environment only."""

    def test_email_password_from_env_only(self):
        """Email config loads password from AMOSKYS_EMAIL_PASSWORD env var."""
        from amoskys.notifications.email import get_email_config, reset_email_config

        reset_email_config()
        test_pass = "test-smtp-password-from-env"
        with patch.dict(os.environ, {"AMOSKYS_EMAIL_PASSWORD": test_pass}):
            config = get_email_config()
            assert config.password == test_pass
        reset_email_config()

    def test_email_password_empty_when_not_set(self):
        """Email password defaults to empty string when env var not set."""
        from amoskys.notifications.email import get_email_config, reset_email_config

        reset_email_config()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AMOSKYS_EMAIL_PASSWORD", None)
            config = get_email_config()
            assert config.password == ""
        reset_email_config()

    def test_dev_mode_default_true(self):
        """Email dev mode defaults to True (safe default)."""
        from amoskys.notifications.email import EmailConfig

        config = EmailConfig()
        assert config.dev_mode is True

    def test_env_file_gitignored(self):
        """The .env file must be in .gitignore."""
        gitignore = os.path.join(
            os.path.dirname(__file__), "..", "..", "..", ".gitignore"
        )
        with open(gitignore) as f:
            content = f.read()
        assert ".env" in content

    def test_env_example_has_placeholder_password(self):
        """The .env.example must have placeholder, not real password."""
        env_example = os.path.join(
            os.path.dirname(__file__), "..", "..", "..", ".env.example"
        )
        with open(env_example) as f:
            content = f.read()
        assert "your-smtp-password" in content


# ---------------------------------------------------------------------------
# A1.4 — Rate Limit Exemption
# ---------------------------------------------------------------------------


class TestRateLimitExemptions:
    """Only /v1/health/ping and /health exempt among health endpoints."""

    def _check_exempt(self, path: str) -> bool:
        app = Flask(__name__)
        app.config["TESTING"] = True
        with app.test_request_context(path):
            from amoskys.api.security import rate_limit_exempt

            return rate_limit_exempt()

    def test_ping_exempt(self):
        assert self._check_exempt("/v1/health/ping") is True

    def test_health_fallback_exempt(self):
        assert self._check_exempt("/health") is True

    def test_system_not_exempt(self):
        assert self._check_exempt("/v1/health/system") is False

    def test_agents_not_exempt(self):
        assert self._check_exempt("/v1/health/agents") is False

    def test_old_api_health_not_exempt(self):
        """Old /api/health/* pattern should no longer be exempt."""
        assert self._check_exempt("/api/health/system") is False

    def test_dashboard_api_still_exempt(self):
        """Dashboard API endpoints remain exempt."""
        assert self._check_exempt("/dashboard/api/events") is True


# ---------------------------------------------------------------------------
# Pre-commit Configuration
# ---------------------------------------------------------------------------


class TestPreCommitConfig:
    """Pre-commit hooks must include secrets detection."""

    def test_detect_secrets_in_precommit(self):
        config = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            ".pre-commit-config.yaml",
        )
        with open(config) as f:
            content = f.read()
        assert "detect-secrets" in content

    def test_detect_private_key_in_precommit(self):
        config = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            ".pre-commit-config.yaml",
        )
        with open(config) as f:
            content = f.read()
        assert "detect-private-key" in content
