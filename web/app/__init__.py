"""
AMOSKYS Neural Security Command Platform
Flask Application Factory
Phase 2.4 - Dashboard Integration
Phase 1.1 - Unified Error Handling & Structured Logging
"""

import logging
import os
import sys

from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix


def create_app():
    """Application factory pattern for AMOSKYS web interface"""
    app = Flask(__name__)

    # Configure debug/testing FIRST (needed for SECRET_KEY gate)
    app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.config["TESTING"] = os.environ.get("TESTING", "False").lower() == "true"

    # Bypass @require_login — opt-in via LOGIN_DISABLED=true env var
    # (Not auto-enabled in debug to allow testing real auth flows)
    is_dev = app.config["DEBUG"] or app.config["TESTING"]
    if os.environ.get("LOGIN_DISABLED", "").lower() == "true":
        app.config["LOGIN_DISABLED"] = True

    # Configure SECRET_KEY — required in all environments
    secret_key = os.environ.get("SECRET_KEY")

    if not secret_key:
        if is_dev:
            import secrets as _secrets

            # Persist dev key so sessions survive restarts
            _dev_key_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data",
                ".dev_secret_key",
            )
            try:
                os.makedirs(os.path.dirname(_dev_key_path), exist_ok=True)
                if os.path.exists(_dev_key_path):
                    with open(_dev_key_path) as f:
                        secret_key = f.read().strip()
                    if len(secret_key) >= 32:
                        logging.info(
                            "Loaded persistent dev SECRET_KEY from %s", _dev_key_path
                        )
                    else:
                        secret_key = None  # regenerate if corrupt
                if not secret_key:
                    secret_key = _secrets.token_hex(32)
                    with open(_dev_key_path, "w") as f:
                        f.write(secret_key)
                    logging.info(
                        "Generated persistent dev SECRET_KEY → %s", _dev_key_path
                    )
            except OSError:
                secret_key = _secrets.token_hex(32)
                logging.warning(
                    "Could not persist dev SECRET_KEY — sessions will not "
                    "survive restarts."
                )
        else:
            raise ValueError(
                "SECRET_KEY environment variable is required. "
                "Generate one: python -c 'import secrets; print(secrets.token_hex(32))'"
            )

    # Reject known-weak / placeholder keys in ALL environments
    _WEAK_PATTERNS = {
        "dev-secret-key",
        "change-in-production",
        "your-secure-random",
        "amoskys-neural-security-dev-key",
        "changeme",
        "placeholder",
        "change_me",
    }
    if secret_key:  # Only validate if not auto-generated
        _key_warnings = []
        if len(secret_key) < 32:
            _key_warnings.append(
                f"SECRET_KEY too short ({len(secret_key)} chars, minimum 32)."
            )
        lower_key = secret_key.lower()
        for weak in _WEAK_PATTERNS:
            if weak in lower_key:
                _key_warnings.append(f"SECRET_KEY contains weak pattern '{weak}'.")
        if _key_warnings:
            _msg = (
                " ".join(_key_warnings) + " Generate a strong key: "
                "python -c 'import secrets; print(secrets.token_hex(32))'"
            )
            if is_dev:
                logging.warning("INSECURE SECRET_KEY: %s", _msg)
            else:
                raise ValueError(_msg)

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

    # Ensure auth/web tables exist (idempotent) then run migrations
    from amoskys.db.web_db import (
        _migrate_user_onboarding_columns,
        get_web_engine,
        init_web_db,
    )

    init_web_db()
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

    # NOTE: user_auth_bp is already registered as a sub-blueprint of api_bp
    # (see web/app/api/__init__.py) — no duplicate registration needed here.

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

    # Start coordination bus bridge for cross-process health/alert signals
    if not is_testing:
        try:
            from .control_bus import init_control_bus

            init_control_bus()
            logging.info("Dashboard coordination bus initialized")
        except Exception as e:
            logging.warning("Dashboard coordination bus failed to start: %s", e)

    # Start EventBus gRPC server (infrastructure — must be up before agents)
    if not is_testing:
        try:
            import subprocess
            import socket

            def _eventbus_alive(port=50051):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect(("127.0.0.1", port))
                    s.close()
                    return True
                except (ConnectionRefusedError, OSError):
                    return False

            if not _eventbus_alive():
                _eb_proc = subprocess.Popen(
                    [sys.executable, "-m", "amoskys.eventbus.server"],
                    stdout=open("logs/eventbus.log", "a"),
                    stderr=open("logs/eventbus.err.log", "a"),
                    env={**os.environ, "PYTHONPATH": os.environ.get("PYTHONPATH", "")},
                )
                # Wait for it to come up
                for _ in range(30):
                    if _eventbus_alive():
                        break
                    import time
                    time.sleep(0.5)
                logging.info("EventBus auto-started (PID %d, port 50051)", _eb_proc.pid)
            else:
                logging.info("EventBus already running on port 50051")
        except Exception as e:
            logging.warning("EventBus auto-start failed: %s", e)

    # Start Agent Mesh + IGRIS orchestrator (singleton, idempotent)
    if not is_testing:
        try:
            from amoskys.mesh import MeshBus, ActionExecutor, MeshStore, MeshMixin
            from amoskys.igris.orchestrator import IGRISOrchestrator

            mesh_bus = MeshBus(db_path="data/mesh_events.db")
            MeshMixin.set_mesh_bus(mesh_bus)

            action_executor = ActionExecutor(mesh_bus=mesh_bus, dry_run=False)
            mesh_store = MeshStore(db_path="data/mesh_events.db")

            orchestrator = IGRISOrchestrator(
                mesh_bus=mesh_bus,
                action_executor=action_executor,
                mesh_store=mesh_store,
            )
            orchestrator.start()

            app.config["MESH_BUS"] = mesh_bus
            app.config["ACTION_EXECUTOR"] = action_executor
            app.config["MESH_STORE"] = mesh_store
            app.config["IGRIS_ORCHESTRATOR"] = orchestrator

            logging.info("Agent Mesh + IGRIS Orchestrator started (autonomous defense active)")
        except Exception as e:
            logging.warning("Agent Mesh failed to start: %s", e)

    # Start IGRIS supervisory daemon (singleton, idempotent)
    if not is_testing:
        try:
            from amoskys.igris import start_igris

            start_igris()
            logging.info("IGRIS supervisor daemon started")
        except Exception as e:
            logging.warning("IGRIS supervisor failed to start: %s", e)

    # Register unified error handlers (P1-002)
    from .errors import register_error_handlers

    register_error_handlers(app)

    # Keep HTML error handlers for non-API requests
    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found", "path": request.path}), 404
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        import uuid

        error_id = str(uuid.uuid4())[:8].upper()
        return render_template("500.html", error_id=error_id), 500

    # Top-level health alias for external monitoring (no /api prefix required)
    @app.route("/v1/health/ping", methods=["GET"])
    @app.route("/health", methods=["GET"])
    def health_ping_alias():
        return jsonify({"status": "ok"})

    return app, socketio


def main():
    """CLI entry point for amoskys-dashboard."""
    port = int(os.environ.get("FLASK_PORT", "5001"))
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app, socketio = create_app()
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=debug)
