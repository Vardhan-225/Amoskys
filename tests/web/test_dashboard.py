#!/usr/bin/env python3
import os
import sys

# Add the web app to the path (go up from tests/web to project root, then into web)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "web"))

from app import create_app

result = create_app()
if isinstance(result, tuple):
    app, socketio = result
else:
    app = result
    socketio = None

if __name__ == "__main__":
    print("Starting AMOSKYS Dashboard on http://localhost:5001/dashboard/agents")
    if socketio:
        socketio.run(app, host="localhost", port=5001, debug=False, use_reloader=False)
    else:
        app.run(host="localhost", port=5001, debug=False)
