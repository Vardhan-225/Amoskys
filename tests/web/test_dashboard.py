#!/usr/bin/env python3
"""
AMOSKYS Dashboard - Smoke Tests

These tests verify the web dashboard can be initialized and basic endpoints work.
Used for VPS deployment smoke testing.
"""
import os
import sys

import pytest

# Add the web app to the path (go up from tests/web to project root, then into web)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "web"))

from app import create_app


@pytest.fixture
def app():
    """Create test application"""
    # Set environment variables BEFORE creating app to ensure proper test configuration
    os.environ["FLASK_DEBUG"] = "true"
    os.environ["FORCE_HTTPS"] = "false"
    os.environ["SECRET_KEY"] = "test-secret-key"
    
    result = create_app()
    if isinstance(result, tuple):
        app_instance, _ = result
    else:
        app_instance = result
    app_instance.config["TESTING"] = True
    return app_instance


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


class TestDashboardSmoke:
    """Smoke tests for dashboard - used in VPS deployment"""

    def test_app_creates_successfully(self, app):
        """Test that the Flask app initializes without errors"""
        assert app is not None
        assert app.config["TESTING"] is True

    def test_health_ping_endpoint(self, client):
        """Test the health ping endpoint responds"""
        response = client.get("/api/v1/health/ping")
        assert response.status_code == 200

    def test_system_health_endpoint(self, client):
        """Test system health endpoint responds"""
        response = client.get("/api/system/health")
        assert response.status_code == 200


if __name__ == "__main__":
    # When run directly, start the dashboard server
    result = create_app()
    if isinstance(result, tuple):
        app, socketio = result
    else:
        app = result
        socketio = None

    print("Starting AMOSKYS Dashboard on http://localhost:5001/dashboard/agents")
    if socketio:
        socketio.run(app, host="localhost", port=5001, debug=False, use_reloader=False)
    else:
        app.run(host="localhost", port=5001, debug=False)
