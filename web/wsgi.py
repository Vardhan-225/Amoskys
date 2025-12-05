"""
AMOSKYS Neural Security Command Platform
WSGI Entry Point for Production Deployment
Phase 2.4 - Dashboard Integration with SocketIO

For production use with Gunicorn:
    gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:8000 wsgi:app

For development use:
    python wsgi.py --dev
"""
import os
import sys
from app import create_app

# Create the Flask application instance with SocketIO
app, socketio = create_app()

# Export the application for WSGI servers (Gunicorn, uWSGI, etc.)
application = app

if __name__ == '__main__':
    # Check if running in development mode
    is_dev = '--dev' in sys.argv or os.environ.get('FLASK_ENV') == 'development'
    port = int(os.environ.get('FLASK_PORT', 5001))

    if is_dev:
        # Development server with SocketIO support
        print("🧠⚡ AMOSKYS Development Server Starting...")
        print("⚠️  WARNING: Development mode - not suitable for production")
        socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)
    else:
        print("❌ Error: This script should not be run directly in production.")
        print("Use a production WSGI server like Gunicorn:")
        print("  gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:8000 wsgi:app")
        sys.exit(1)