"""
AMOSKYS Neural Security Command Platform
WSGI Entry Point for Production Deployment
Phase 2.4 - Dashboard Integration with SocketIO
"""
from app import create_app

# Create the Flask application instance with SocketIO
app, socketio = create_app()

if __name__ == '__main__':
    # Development server with SocketIO support
    socketio.run(app, host='0.0.0.0', port=8000, debug=False, allow_unsafe_werkzeug=True)