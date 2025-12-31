"""
AMOSKYS Neural Security Command Platform
Flask Application Factory
Phase 2.4 - Dashboard Integration
Phase 1.1 - Unified Error Handling & Structured Logging
"""
from flask import Flask, render_template, request
from flask_socketio import SocketIO
import logging
import os


def create_app():
    """Application factory pattern for AMOSKYS web interface"""
    app = Flask(__name__)

    # Configure app
    # IMPORTANT: Set SECRET_KEY environment variable in production!
    # Default key is for development only and should NEVER be used in production
    secret_key = os.environ.get('SECRET_KEY', 'amoskys-neural-security-dev-key')
    if secret_key == 'amoskys-neural-security-dev-key' and not app.config.get('DEBUG'):
        import warnings
        warnings.warn(
            "Using default SECRET_KEY in production! "
            "Set the SECRET_KEY environment variable to a secure random value.",
            UserWarning,
            stacklevel=2
        )
    app.config['SECRET_KEY'] = secret_key
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Configure structured logging (P1-004)
    from amoskys.common.logging import configure_logging, init_flask_logging
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    json_logs = os.environ.get('JSON_LOGS', 'true').lower() == 'true'
    configure_logging(
        level=log_level,
        json_format=json_logs and not app.config['DEBUG'],
        filter_sensitive=True,
    )
    
    # Initialize Flask request logging (correlation IDs, timing)
    init_flask_logging(app)
    
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

    # Register Auth API blueprint (Phase 3)
    from amoskys.api.auth import auth_bp
    app.register_blueprint(auth_bp)

    # Register User Agent Management API blueprint (Phase 3 - Agent Distribution)
    from amoskys.api.agents_user import agents_user_bp
    app.register_blueprint(agents_user_bp)

    # Initialize security features (Phase 3)
    from amoskys.api.security import init_security
    init_security(app)

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
        if request.path.startswith('/api/'):
            return  # Let unified handler deal with it
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        if request.path.startswith('/api/'):
            return  # Let unified handler deal with it
        return render_template('404.html'), 500
    
    return app, socketio