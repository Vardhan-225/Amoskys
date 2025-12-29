"""
AMOSKYS API Gateway - Test Suite
Phase 2.3 Integration Tests

This module contains comprehensive tests for the AMOSKYS API Gateway,
covering authentication, agent management, event ingestion, and system endpoints.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import jwt
import pytest

# Add the web app to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "web"))

try:
    from web.app import create_app
except ImportError:
    # Fallback import path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from web.app import create_app


@pytest.fixture
def app():
    """Create test application"""
    app_instance, _ = create_app()  # Unpack the tuple
    app_instance.config["TESTING"] = True
    app_instance.config["SECRET_KEY"] = "test-secret-key"
    return app_instance


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    """Get authentication headers for testing"""
    # Login as flowagent-001
    response = client.post(
        "/api/auth/login",
        json={
            "agent_id": "flowagent-001",
            "secret": "amoskys-neural-flow-secure-key-2025",
        },
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200
    data = json.loads(response.data)
    token = data["token"]

    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture
def admin_headers(client):
    """Get admin authentication headers for testing"""
    # Login as admin
    response = client.post(
        "/api/auth/login",
        json={"agent_id": "admin", "secret": "amoskys-neural-admin-secure-key-2025"},
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200
    data = json.loads(response.data)
    token = data["token"]

    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


class TestAuthentication:
    """Test authentication endpoints"""

    def test_login_success(self, client):
        """Test successful login"""
        response = client.post(
            "/api/auth/login",
            json={
                "agent_id": "flowagent-001",
                "secret": "amoskys-neural-flow-secure-key-2025",
            },
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "token" in data
        assert data["agent_id"] == "flowagent-001"
        assert data["role"] == "agent"

    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        response = client.post(
            "/api/auth/login",
            json={"agent_id": "invalid", "secret": "wrong-secret"},
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 401
        data = json.loads(response.data)
        assert "error" in data

    def test_login_missing_fields(self, client):
        """Test login with missing fields"""
        response = client.post(
            "/api/auth/login",
            json={"agent_id": "flowagent-001"},
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_verify_token(self, client, auth_headers):
        """Test token verification"""
        response = client.post("/api/auth/verify", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "authenticated"
        assert data["agent_id"] == "flowagent-001"

    def test_refresh_token(self, client, auth_headers):
        """Test token refresh"""
        response = client.post("/api/auth/refresh", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "token" in data


class TestAgents:
    """Test agent management endpoints"""

    def test_agent_ping(self, client, auth_headers):
        """Test agent ping endpoint"""
        response = client.post(
            "/api/agents/ping", json={"request_config": True}, headers=auth_headers
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "pong"
        assert data["agent_id"] == "flowagent-001"
        assert "system_metrics" in data
        assert "config_update" in data

    def test_agent_register(self, client, auth_headers):
        """Test agent registration"""
        agent_data = {
            "hostname": "test-host",
            "platform": "Linux-5.4.0",
            "version": "1.0.0",
            "capabilities": ["flow_monitoring", "packet_analysis"],
        }

        response = client.post(
            "/api/agents/register", json=agent_data, headers=auth_headers
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert data["agent_info"]["agent_id"] == "flowagent-001"
        assert data["agent_info"]["hostname"] == "test-host"

    def test_list_agents(self, client, auth_headers):
        """Test listing agents"""
        # First register an agent
        self.test_agent_register(client, auth_headers)

        response = client.get("/api/agents/list", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert data["agent_count"] >= 1
        assert len(data["agents"]) >= 1

    def test_agent_stats(self, client, auth_headers):
        """Test agent statistics"""
        response = client.get("/api/agents/stats", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "stats" in data
        assert "total_agents" in data["stats"]


class TestEvents:
    """Test event management endpoints"""

    def test_submit_event(self, client, auth_headers):
        """Test event submission"""
        event_data = {
            "event_type": "network_anomaly",
            "severity": "medium",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 443,
            "destination_port": 22,
            "protocol": "TCP",
            "description": "Unusual SSH connection attempt from HTTPS port",
            "metadata": {"bytes_transferred": 1024, "connection_duration": 30},
        }

        response = client.post(
            "/api/events/submit", json=event_data, headers=auth_headers
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "event_id" in data
        assert "timestamp" in data

    def test_submit_event_invalid_schema(self, client, auth_headers):
        """Test event submission with invalid schema"""
        event_data = {
            "event_type": "network_anomaly",
            "severity": "invalid_severity",  # Invalid severity
            "description": "Test event",
            # Missing required field: source_ip
        }

        response = client.post(
            "/api/events/submit", json=event_data, headers=auth_headers
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_list_events(self, client, auth_headers):
        """Test listing events"""
        # First submit an event
        self.test_submit_event(client, auth_headers)

        response = client.get("/api/events/list", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert data["event_count"] >= 1
        assert len(data["events"]) >= 1

    def test_event_stats(self, client, auth_headers):
        """Test event statistics"""
        response = client.get("/api/events/stats", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "stats" in data
        assert "total_events" in data["stats"]

    def test_event_schema(self, client):
        """Test event schema endpoint (no auth required)"""
        response = client.get("/api/events/schema")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "schema" in data
        assert "required_fields" in data["schema"]
        assert "example_event" in data["schema"]


class TestSystem:
    """Test system endpoints"""

    def test_system_health(self, client):
        """Test system health endpoint (no auth required)"""
        response = client.get("/api/system/health")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] in ["healthy", "degraded", "error"]
        assert "timestamp" in data
        assert "metrics" in data

    def test_system_status(self, client, auth_headers):
        """Test system status endpoint"""
        response = client.get("/api/system/status", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "operational"
        assert data["platform"] == "AMOSKYS Neural Security Command Platform"
        assert "components" in data
        assert "metrics" in data

    def test_system_info(self, client, auth_headers):
        """Test system info endpoint"""
        response = client.get("/api/system/info", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "system" in data
        assert "hardware" in data
        assert "process" in data

    def test_system_config(self, client, admin_headers):
        """Test system config endpoint (admin only)"""
        response = client.get("/api/system/config", headers=admin_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "config" in data
        assert data["config"]["api_version"] == "2.3.0"


class TestSecurity:
    """Test security features"""

    def test_unauthorized_access(self, client):
        """Test unauthorized access to protected endpoints"""
        response = client.get("/api/agents/list")
        assert response.status_code == 401

        response = client.post("/api/events/submit", json={})
        assert response.status_code == 401

        response = client.get("/api/system/status")
        assert response.status_code == 401

    def test_invalid_token(self, client):
        """Test access with invalid token"""
        headers = {
            "Authorization": "Bearer invalid-token",
            "Content-Type": "application/json",
        }

        response = client.get("/api/agents/list", headers=headers)
        assert response.status_code == 401

        response = client.post("/api/events/submit", json={}, headers=headers)
        assert response.status_code == 401

    def test_insufficient_permissions(self, client, auth_headers):
        """Test access with insufficient permissions"""
        # flowagent-001 should not have access to admin endpoints
        response = client.get("/api/system/config", headers=auth_headers)
        assert response.status_code == 403


if __name__ == "__main__":
    pytest.main([__file__])
