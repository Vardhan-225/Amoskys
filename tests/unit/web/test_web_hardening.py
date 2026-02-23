"""
Tests for web security hardening (P0-W1, P0-W2).

Covers:
  - SocketIO CORS configuration (not wildcard)
  - SECRET_KEY enforcement in production
"""

import os
from unittest.mock import patch

import pytest


class TestSocketIOCORS:
    """P0-W1: SocketIO CORS must not be wildcard."""

    def test_cors_not_wildcard(self):
        """CORS setting is never the string '*'."""
        from web.app.websocket import _get_cors_origins

        result = _get_cors_origins()
        assert result != "*"

    def test_cors_empty_returns_list(self):
        """No CORS_ALLOWED_ORIGINS env → empty list (same-origin only)."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CORS_ALLOWED_ORIGINS", None)
            from web.app.websocket import _get_cors_origins

            result = _get_cors_origins()
            assert result == []

    def test_cors_from_env(self):
        """CORS_ALLOWED_ORIGINS env → parsed list of origins."""
        with patch.dict(
            os.environ,
            {
                "CORS_ALLOWED_ORIGINS": "https://app.example.com, https://admin.example.com"
            },
        ):
            from web.app.websocket import _get_cors_origins

            result = _get_cors_origins()
            assert result == ["https://app.example.com", "https://admin.example.com"]

    def test_cors_strips_whitespace(self):
        """Origins are stripped of leading/trailing whitespace."""
        with patch.dict(
            os.environ,
            {"CORS_ALLOWED_ORIGINS": "  https://a.com ,  https://b.com  "},
        ):
            from web.app.websocket import _get_cors_origins

            result = _get_cors_origins()
            assert result == ["https://a.com", "https://b.com"]


class TestSecretKey:
    """P0-W2: SECRET_KEY must be enforced in production."""

    def test_secret_key_required_production(self):
        """No SECRET_KEY + no DEBUG/TESTING → ValueError."""
        env = {
            "FLASK_DEBUG": "false",
            "TESTING": "false",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("SECRET_KEY", None)
            from web.app import create_app

            with pytest.raises(ValueError, match="SECRET_KEY"):
                create_app()

    def test_secret_key_allowed_debug(self):
        """No SECRET_KEY + DEBUG=true → ephemeral key generated (no error)."""
        env = {
            "FLASK_DEBUG": "true",
            "TESTING": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("SECRET_KEY", None)
            from web.app import create_app

            app, _ = create_app()
            # Ephemeral key is generated (not the old hardcoded dev key)
            assert len(app.config["SECRET_KEY"]) >= 32
            assert app.config["SECRET_KEY"] != "amoskys-neural-security-dev-key"

    def test_secret_key_env_used(self):
        """SECRET_KEY from env → that exact key is used."""
        env = {
            "SECRET_KEY": "my-super-secret-production-key-abc123",
            "FLASK_DEBUG": "false",
            "TESTING": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            from web.app import create_app

            app, _ = create_app()
            assert app.config["SECRET_KEY"] == "my-super-secret-production-key-abc123"
