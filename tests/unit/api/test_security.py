"""
Tests for amoskys.api.security module.

Covers:
  - CSP configuration
  - Rate limiter configuration
  - require_api_key decorator
  - init_security function
"""

import os
from unittest.mock import patch

from flask import Flask

from amoskys.api.security import CSP, init_security, limiter, require_api_key


class TestCSPConfiguration:
    """Content Security Policy must block XSS vectors."""

    def test_default_src_self_only(self):
        assert "'self'" in CSP["default-src"]
        assert len(CSP["default-src"]) == 1

    def test_frame_ancestors_none(self):
        """Prevent clickjacking via frame-ancestors."""
        assert "'none'" in CSP["frame-ancestors"]

    def test_base_uri_restricted(self):
        assert "'self'" in CSP["base-uri"]

    def test_form_action_restricted(self):
        assert "'self'" in CSP["form-action"]


class TestRateLimiter:
    """Rate limiter must be properly configured."""

    def test_limiter_initialized(self):
        assert limiter is not None
        assert limiter._key_func is not None

    def test_health_ping_exempt(self):
        """Only /v1/health/ping is exempt from rate limiting."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        with app.test_request_context("/v1/health/ping"):
            from amoskys.api.security import rate_limit_exempt

            assert rate_limit_exempt() is True

    def test_health_system_not_exempt(self):
        """/v1/health/system is rate limited (requires auth, has sensitive data)."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        with app.test_request_context("/v1/health/system"):
            from amoskys.api.security import rate_limit_exempt

            assert rate_limit_exempt() is False

    def test_static_exempt(self):
        """Static assets must be exempt from rate limiting."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        with app.test_request_context("/static/js/app.js"):
            from amoskys.api.security import rate_limit_exempt

            assert rate_limit_exempt() is True

    def test_api_endpoint_not_exempt(self):
        """API endpoints should NOT be exempt."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        with app.test_request_context("/api/telemetry"):
            from amoskys.api.security import rate_limit_exempt

            assert rate_limit_exempt() is False


class TestRequireApiKey:
    """API key decorator must enforce authentication."""

    def test_missing_key_returns_401(self):
        app = Flask(__name__)
        app.config["TESTING"] = True

        @app.route("/test")
        @require_api_key
        def protected():
            return "ok"

        with patch.dict(os.environ, {"AMOSKYS_API_KEY": "secret123"}):
            with app.test_client() as client:
                resp = client.get("/test")
                assert resp.status_code == 401

    def test_wrong_key_returns_403(self):
        app = Flask(__name__)
        app.config["TESTING"] = True

        @app.route("/test")
        @require_api_key
        def protected():
            return "ok"

        with patch.dict(os.environ, {"AMOSKYS_API_KEY": "secret123"}):
            with app.test_client() as client:
                resp = client.get("/test", headers={"X-API-Key": "wrong"})
                assert resp.status_code == 403

    def test_correct_key_passes(self):
        app = Flask(__name__)
        app.config["TESTING"] = True

        @app.route("/test")
        @require_api_key
        def protected():
            return "ok"

        with patch.dict(os.environ, {"AMOSKYS_API_KEY": "secret123"}):
            with app.test_client() as client:
                resp = client.get("/test", headers={"X-API-Key": "secret123"})
                assert resp.status_code == 200

    def test_unconfigured_key_returns_500(self):
        app = Flask(__name__)
        app.config["TESTING"] = True

        @app.route("/test")
        @require_api_key
        def protected():
            return "ok"

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AMOSKYS_API_KEY", None)
            with app.test_client() as client:
                resp = client.get("/test", headers={"X-API-Key": "anything"})
                assert resp.status_code == 500


class TestInitSecurity:
    """init_security must set up all security features."""

    def test_init_security_dev_mode(self):
        """init_security runs without error in debug mode."""
        app = Flask(__name__)
        app.config["DEBUG"] = True
        app.config["TESTING"] = True
        init_security(app)
        # Should not raise

    def test_init_security_registers_error_handler(self):
        """429 error handler registered after init_security."""
        app = Flask(__name__)
        app.config["DEBUG"] = True
        app.config["TESTING"] = True
        init_security(app)
        assert 429 in app.error_handler_spec.get(None, {})
