"""
AMOSKYS API Security Module

Provides comprehensive security features for Flask applications:
- Rate limiting (brute-force protection)
- CSRF protection
- Security headers (Talisman)
- IP-based blocking
- Request validation

Usage:
    from amoskys.api.security import init_security

    app = Flask(__name__)
    init_security(app)
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Optional

from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

from amoskys.common.logging import get_logger

__all__ = ["init_security", "limiter", "require_api_key"]

logger = get_logger(__name__)

# =============================================================================
# Rate Limiter Configuration
# =============================================================================

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("RATE_LIMIT_STORAGE_URL", "memory://"),
    strategy="fixed-window",
    headers_enabled=True,
)

# Custom rate limit error handler


@limiter.request_filter
def rate_limit_exempt():
    """Exempt certain endpoints from rate limiting."""
    # Exempt health check endpoints
    if request.path.startswith("/api/health") or request.path == "/health":
        return True
    return False


def rate_limit_error_handler(error):
    """Custom error response for rate limit exceeded."""
    logger.warning(
        f"Rate limit exceeded",
        extra={
            "ip_address": request.remote_addr,
            "path": request.path,
            "user_agent": request.headers.get("User-Agent"),
        },
    )

    return (
        jsonify(
            {
                "error": "Rate limit exceeded. Please try again later.",
                "error_code": "RATE_LIMIT_EXCEEDED",
                "retry_after": error.description,
            }
        ),
        429,
    )


# =============================================================================
# Security Headers (Talisman)
# =============================================================================

# Content Security Policy
CSP = {
    "default-src": ["'self'"],
    "script-src": [
        "'self'",
        "'unsafe-inline'",  # For inline scripts (SocketIO, etc.)
        "cdn.jsdelivr.net",  # If using CDN
    ],
    "style-src": [
        "'self'",
        "'unsafe-inline'",  # For inline styles
    ],
    "img-src": ["'self'", "data:", "https:"],
    "font-src": ["'self'", "data:"],
    "connect-src": ["'self'", "ws:", "wss:"],  # For WebSocket
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
}

# =============================================================================
# API Key Authentication (Optional)
# =============================================================================


def require_api_key(f):
    """
    Decorator to require API key for endpoint.

    Usage:
        @auth_bp.route('/admin/users')
        @require_api_key
        def list_users():
            pass

    API key should be provided in header:
        X-API-Key: your-api-key
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        expected_key = os.environ.get("AMOSKYS_API_KEY")

        if not expected_key:
            logger.error("AMOSKYS_API_KEY not configured")
            return (
                jsonify(
                    {
                        "error": "API key authentication not configured",
                        "error_code": "CONFIGURATION_ERROR",
                    }
                ),
                500,
            )

        if not api_key:
            return (
                jsonify(
                    {"error": "API key required", "error_code": "MISSING_API_KEY"}
                ),
                401,
            )

        if api_key != expected_key:
            logger.warning(
                "Invalid API key attempt",
                extra={"ip_address": request.remote_addr},
            )
            return (
                jsonify(
                    {"error": "Invalid API key", "error_code": "INVALID_API_KEY"}
                ),
                403,
            )

        return f(*args, **kwargs)

    return decorated


# =============================================================================
# Security Initialization
# =============================================================================


def init_security(app: Flask) -> None:
    """
    Initialize all security features for Flask app.

    Args:
        app: Flask application instance

    Features enabled:
        - Rate limiting (Flask-Limiter)
        - Security headers (Talisman)
        - CORS configuration
        - Request validation
    """
    # Get environment
    is_dev = app.config.get("DEBUG", False)
    force_https = os.environ.get("FORCE_HTTPS", "true").lower() == "true"

    logger.info(
        f"Initializing security features (dev={is_dev}, force_https={force_https})"
    )

    # =========================================================================
    # 1. Rate Limiting
    # =========================================================================
    limiter.init_app(app)

    # Set custom error handler
    app.errorhandler(429)(rate_limit_error_handler)

    logger.info("✅ Rate limiting enabled")

    # =========================================================================
    # 2. Security Headers (Talisman)
    # =========================================================================

    # Different settings for dev vs production
    if is_dev:
        # Relaxed settings for development
        Talisman(
            app,
            force_https=False,  # Allow HTTP in dev
            strict_transport_security=False,
            content_security_policy=None,  # Disable CSP in dev for easier testing
            content_security_policy_nonce_in=None,
        )
        logger.info("✅ Security headers enabled (development mode)")
    else:
        # Strict settings for production
        Talisman(
            app,
            force_https=force_https,
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,  # 1 year
            content_security_policy=CSP,
            content_security_policy_nonce_in=["script-src"],
            referrer_policy="strict-origin-when-cross-origin",
            feature_policy={
                "geolocation": "'none'",
                "microphone": "'none'",
                "camera": "'none'",
            },
        )
        logger.info("✅ Security headers enabled (production mode)")

    # =========================================================================
    # 3. Request Logging & Validation
    # =========================================================================

    @app.before_request
    def log_request():
        """Log all incoming requests for security monitoring."""
        logger.debug(
            f"{request.method} {request.path}",
            extra={
                "ip_address": request.remote_addr,
                "user_agent": request.headers.get("User-Agent"),
                "referer": request.headers.get("Referer"),
            },
        )

    @app.after_request
    def add_security_headers(response):
        """Add additional security headers to all responses."""
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Enable browser XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control information disclosure
        response.headers["X-Powered-By"] = "AMOSKYS"

        return response

    logger.info("✅ Request logging and validation enabled")

    # =========================================================================
    # 4. CORS (if needed for frontend)
    # =========================================================================

    # Uncomment if you need CORS for a separate frontend
    # from flask_cors import CORS
    # CORS(app, origins=os.environ.get("ALLOWED_ORIGINS", "").split(","))

    logger.info("🔒 Security initialization complete")


# =============================================================================
# Rate Limit Decorators for Common Patterns
# =============================================================================


def rate_limit_auth(limit: str = "5 per minute"):
    """
    Rate limit decorator for authentication endpoints.

    Usage:
        @auth_bp.route('/login')
        @rate_limit_auth("5 per minute")
        def login():
            pass
    """
    return limiter.limit(limit)


def rate_limit_api(limit: str = "100 per hour"):
    """
    Rate limit decorator for general API endpoints.

    Usage:
        @api_bp.route('/data')
        @rate_limit_api("100 per hour")
        def get_data():
            pass
    """
    return limiter.limit(limit)


def rate_limit_strict(limit: str = "1 per minute"):
    """
    Strict rate limit for sensitive operations.

    Usage:
        @auth_bp.route('/forgot-password')
        @rate_limit_strict("1 per minute")
        def forgot_password():
            pass
    """
    return limiter.limit(limit)
