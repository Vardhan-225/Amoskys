"""
AMOSKYS Neural Security Command Platform
Flask Application Factory
Phase 2.4 - Dashboard Integration
"""
from flask import Flask, render_template
from flask_socketio import SocketIO
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
    
    # Register blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)
    
    # Register API blueprints (Phase 2.3)
    from .api import api_bp
    app.register_blueprint(api_bp)
    
    # Register Dashboard blueprints (Phase 2.4)
    from .dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)
    
    # Initialize SocketIO for real-time updates
    from .websocket import init_socketio
    socketio = init_socketio(app)
    
    # Register error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('404.html'), 500
    
    return app, socketio