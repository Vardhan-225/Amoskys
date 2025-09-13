"""
AMOSKYS Neural Security Command Platform
API Gateway Module - Phase 2.3

This module implements the RESTful API gateway for AMOSKYS, providing
secure endpoints for agent communication, event ingestion, and system monitoring.
"""

from flask import Blueprint, jsonify

# API Blueprint registration
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Import API routes after blueprint creation
from .auth import auth_bp
from .agents import agents_bp  
from .events import events_bp
from .system import system_bp
from .integration import integration_bp
from .docs import generate_openapi_spec

# Register sub-blueprints
api_bp.register_blueprint(auth_bp)
api_bp.register_blueprint(agents_bp)
api_bp.register_blueprint(events_bp)
api_bp.register_blueprint(system_bp)
api_bp.register_blueprint(integration_bp)

# Add API documentation endpoint
@api_bp.route('/docs/openapi.json', methods=['GET'])
def openapi_spec():
    """OpenAPI 3.0 specification endpoint"""
    return jsonify(generate_openapi_spec())

@api_bp.route('/docs', methods=['GET'])
def api_docs():
    """API documentation landing page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AMOSKYS API Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css" />
        <style>
            body { margin: 0; background: #1a1a2e; }
            .swagger-ui .topbar { background: #16213e; }
            .swagger-ui .info .title { color: #00ff88; }
        </style>
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
        <script>
            SwaggerUIBundle({
                url: '/api/docs/openapi.json',
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.presets.standalone
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "BaseLayout"
            });
        </script>
    </body>
    </html>
    """
