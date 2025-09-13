"""
AMOSKYS Neural Security Command Platform
Flask Routes and Views
"""
from flask import Blueprint, render_template, jsonify
from datetime import datetime, timezone

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def landing():
    """AMOSKYS Public Landing Page"""
    return render_template('landing.html')


@main_bp.route('/command')
def command():
    """AMOSKYS Neural Security Command Interface"""
    return render_template('index.html')


@main_bp.route('/api-access')
def api_access():
    """API Access and Documentation Page"""
    return render_template('api_access.html')


@main_bp.route('/status')
def status():
    """System status endpoint for monitoring"""
    return jsonify({
        'status': 'OPERATIONAL',
        'platform': 'AMOSKYS Neural Security Command',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0-alpha',
        'components': {
            'web_interface': 'ACTIVE',
            'neural_core': 'STANDBY',
            'event_bus': 'READY'
        }
    })


@main_bp.route('/health')
def health():
    """Health check endpoint for load balancer"""
    return jsonify({'status': 'healthy'}), 200