"""
AMOSKYS Neural Security Command Platform
Flask Application Factory
Phase 2.4 - Dashboard Integration
Phase 1.1 - Unified Error Handling & Structured Logging
"""

import logging
import os
import sys

from flask import Flask, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix


def create_app():
    """Application factory pattern for AMOSKYS web interface"""
    app = Flask(__name__)

    # Configure debug/testing FIRST (needed for SECRET_KEY gate)
    app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.config["TESTING"] = os.environ.get("TESTING", "False").lower() == "true"

    # Configure SECRET_KEY — required in all environments
    secret_key = os.environ.get("SECRET_KEY")
    is_dev = app.config["DEBUG"] or app.config["TESTING"]

    if not secret_key:
        if is_dev:
            import secrets as _secrets

            secret_key = _secrets.token_hex(32)
            logging.warning(
                "SECRET_KEY not set — generated ephemeral key for dev/test. "
                "Sessions will not persist across restarts."
            )
        else:
            raise ValueError(
                "SECRET_KEY environment variable is required. "
                "Generate one: python -c 'import secrets; print(secrets.token_hex(32))'"
            )

    # Reject known-weak / placeholder keys in production
    _WEAK_PATTERNS = {
        "dev-secret-key",
        "change-in-production",
        "your-secure-random",
        "amoskys-neural-security-dev-key",
        "changeme",
        "placeholder",
    }
    if not is_dev:
        if len(secret_key) < 32:
            raise ValueError(
                f"SECRET_KEY too short ({len(secret_key)} chars). "
                "Minimum 32 characters required."
            )
        lower_key = secret_key.lower()
        for weak in _WEAK_PATTERNS:
            if weak in lower_key:
                raise ValueError(
                    f"SECRET_KEY contains weak pattern '{weak}'. "
                    "Generate a cryptographic key: "
                    "python -c 'import secrets; print(secrets.token_hex(32))'"
                )

    app.config["SECRET_KEY"] = secret_key

    # Apply ProxyFix middleware for nginx/Cloudflare reverse proxy
    # This tells Flask to trust X-Forwarded-* headers for:
    # - x_for: Number of proxy servers (X-Forwarded-For)
    # - x_proto: HTTPS detection (X-Forwarded-Proto)
    # - x_host: Original host header (X-Forwarded-Host)
    # - x_prefix: URL prefix (X-Forwarded-Prefix)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Configure structured logging (P1-004)
    from amoskys.common.logging import configure_logging, init_flask_logging

    log_level = os.environ.get("LOG_LEVEL", "INFO")
    json_logs = os.environ.get("JSON_LOGS", "true").lower() == "true"

    # Persistent log file with rotation (50MB x 10 files)
    log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "logs",
    )
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "amoskys_web.log")

    configure_logging(
        level=log_level,
        json_format=json_logs and not app.config["DEBUG"],
        filter_sensitive=True,
        log_file=log_file,
    )

    # Initialize Flask request logging (correlation IDs, timing)
    init_flask_logging(app)

    # Lightweight schema migration (add any missing columns without heavy imports)
    from amoskys.db.web_db import _migrate_user_onboarding_columns, get_web_engine

    _migrate_user_onboarding_columns(get_web_engine())

    # Register blueprints
    from .routes import main_bp

    app.register_blueprint(main_bp)

    # Register Auth View routes (Phase 3.4 - UI)
    from .routes import auth_views_bp

    app.register_blueprint(auth_views_bp)

    # Register API blueprints (Phase 2.3)
    from .api import api_bp

    app.register_blueprint(api_bp)

    # Register Dashboard blueprints (Phase 2.4)
    from .dashboard import dashboard_bp

    app.register_blueprint(dashboard_bp)

    # Register Admin blueprint (Phase Pre-Deploy)
    from .admin import admin_bp

    app.register_blueprint(admin_bp)

    # Register User Auth API blueprint (Phase 3 - Web Auth)
    from .api.user_auth import user_auth_bp

    app.register_blueprint(user_auth_bp, url_prefix="/api")

    # Register Auth API blueprint (Phase 3)
    from amoskys.api.auth import auth_bp

    app.register_blueprint(auth_bp)

    # Register User Agent Management API blueprint (Phase 3 - Agent Distribution)
    from amoskys.api.agents_user import agents_user_bp

    app.register_blueprint(agents_user_bp)

    # Initialize security features (Phase 3)
    from amoskys.api.security import init_security

    init_security(app)

    # Initialize Prometheus metrics (Production monitoring)
    from .api.prometheus_metrics import (
        init_metrics_middleware,
        prometheus_bp,
        start_metrics_server,
    )

    app.register_blueprint(prometheus_bp)
    init_metrics_middleware(app)

    # Start dedicated metrics server on port 9102 (for Prometheus scraping)
    metrics_port = int(os.environ.get("PROMETHEUS_METRICS_PORT", "9102"))
    # Don't start metrics server during tests (port conflicts)
    is_testing = app.config["TESTING"] or "pytest" in sys.modules
    if not is_testing:
        try:
            start_metrics_server(port=metrics_port)
        except Exception as e:
            logging.warning(
                f"Could not start metrics server on port {metrics_port}: {e}"
            )

    # Initialize SocketIO for real-time updates
    from .websocket import init_socketio

    socketio = init_socketio(app)

    # Register unified error handlers (P1-002)
    from .errors import register_error_handlers

    register_error_handlers(app)

    # Keep HTML error handlers for non-API requests
    @app.errorhandler(404)
    def not_found_error(error):
        # Return JSON for API requests, HTML otherwise
        if request.path.startswith("/api/"):
            return  # Let unified handler deal with it
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        if request.path.startswith("/api/"):
            return  # Let unified handler deal with it
        # Generate error ID for tracking
        import uuid

        error_id = str(uuid.uuid4())[:8].upper()
        return render_template("500.html", error_id=error_id), 500

    return app, socketio
