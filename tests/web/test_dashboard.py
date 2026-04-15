#!/usr/bin/env python3
"""
AMOSKYS Dashboard - Smoke Tests

These tests verify the web dashboard can be initialized and basic endpoints work.
Used for VPS deployment smoke testing.
"""
import os
import sqlite3
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
    app_instance.config["LOGIN_DISABLED"] = True
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


class TestThreatEndpoints:
    """Test rewired TelemetryStore-backed threat endpoints."""

    def test_live_threats_returns_empty_with_no_db(self, client):
        """GET /dashboard/api/live/threats returns empty list when no DB exists."""
        response = client.get("/dashboard/api/live/threats")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert isinstance(data["threats"], list)
        assert "count" in data

    def test_live_threat_score_returns_valid_response(self, client):
        """GET /dashboard/api/live/threat-score returns valid structure."""
        response = client.get("/dashboard/api/live/threat-score")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert isinstance(data["threat_score"], (int, float))
        assert data["threat_level"] in ("LOW", "NONE", "MEDIUM", "HIGH", "CRITICAL")

    def test_event_clustering_returns_empty_with_no_db(self, client):
        """GET /dashboard/api/live/event-clustering returns empty clusters."""
        response = client.get("/dashboard/api/live/event-clustering")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert "clusters" in data

    def test_correlate_unwraps_double_encoded_indicators(self, client, monkeypatch):
        """GET /dashboard/api/correlate handles double-encoded indicators JSON."""
        import json

        from app.dashboard import telemetry_bridge

        db = sqlite3.connect(":memory:")
        db.execute(
            """CREATE TABLE security_events (
                id INTEGER PRIMARY KEY,
                timestamp_ns INTEGER,
                timestamp_dt TEXT,
                device_id TEXT,
                collection_agent TEXT,
                event_category TEXT,
                event_action TEXT,
                risk_score REAL,
                confidence REAL,
                description TEXT,
                mitre_techniques TEXT,
                final_classification TEXT,
                indicators TEXT,
                requires_investigation INTEGER
            )"""
        )

        encoded_indicators = json.dumps(
            json.dumps(
                {
                    "source_ip": "192.168.1.100",
                    "agent": "flowagent-001",
                    "dst_ip": "10.0.0.1",
                }
            )
        )
        rows = [
            (
                37,
                1_700_000_000_000_000_000,
                "2026-03-14T09:28:44.143938+00:00",
                "flowagent-001",
                "flowagent-001",
                "network_anomaly",
                "detected",
                0.35,
                0.8,
                "Earlier anomaly",
                "[]",
                "suspicious",
                encoded_indicators,
                1,
            ),
            (
                38,
                1_700_000_000_500_000_000,
                "2026-03-14T09:28:44.207876+00:00",
                "flowagent-001",
                "flowagent-001",
                "network_anomaly",
                "detected",
                0.35,
                0.8,
                "Seed anomaly",
                "[]",
                "suspicious",
                encoded_indicators,
                1,
            ),
        ]
        db.executemany(
            "INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

        class FakeStore:
            def __init__(self, conn):
                self.db = conn

        monkeypatch.setattr(
            telemetry_bridge, "get_telemetry_store", lambda: FakeStore(db)
        )

        response = client.get("/dashboard/api/correlate?event_id=38&window_minutes=60")

        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert data["seed_event"]["indicators"]["source_ip"] == "192.168.1.100"
        assert data["total_correlated"] == 1
        assert data["correlated_events"][0]["id"] == 37

    def test_incident_timeline_prefers_linked_security_event_ids(
        self, client, monkeypatch
    ):
        """Incident timeline resolves linked security_events by string event_id."""
        import json

        from app.dashboard import telemetry_bridge

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.execute(
            """CREATE TABLE security_events (
                id INTEGER PRIMARY KEY,
                timestamp_ns INTEGER,
                timestamp_dt TEXT,
                device_id TEXT,
                event_category TEXT,
                event_action TEXT,
                risk_score REAL,
                confidence REAL,
                mitre_techniques TEXT,
                final_classification TEXT,
                description TEXT,
                indicators TEXT,
                collection_agent TEXT,
                event_id TEXT
            )"""
        )
        db.execute(
            """INSERT INTO security_events VALUES (
                101, 1700000000000000000, '2026-03-17T20:00:00+00:00',
                'Akashs-MacBook-Air.local', 'credential_access', 'detected',
                0.95, 0.9, '["T1555"]', 'malicious', 'Credential access detected',
                '{"source_ip":"198.51.100.10","process_name":"evil"}',
                'SECURITY', 'evt-credential-1'
            )"""
        )

        class FakeStore:
            def __init__(self, conn):
                self.db = conn

            def get_incident(self, incident_id):
                return {
                    "id": incident_id,
                    "source_event_ids": json.dumps(["evt-credential-1"]),
                    "signal_ids": None,
                    "title": "Incident on Akashs-MacBook-Air.local",
                    "description": "",
                    "created_at": "2026-03-17T20:05:00+00:00",
                }

            def build_incident_timeline(self, device_id, start_ns, end_ns):
                raise AssertionError("broad timeline fallback should not be used")

        monkeypatch.setattr(
            telemetry_bridge, "get_telemetry_store", lambda: FakeStore(db)
        )

        response = client.get("/dashboard/api/incidents/44/timeline")

        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["id"] == 101
        assert data[0]["event_id"] == "evt-credential-1"
        assert data[0]["event_category"] == "credential_access"
        assert data[0]["indicators"]["process_name"] == "evil"
        assert data[0]["source_ip"] == "198.51.100.10"
        assert "data" not in data[0]

    def test_incident_timeline_expands_linked_signals(self, client, monkeypatch):
        """Incident timeline expands signal IDs into contributing security events."""
        import json

        from app.dashboard import telemetry_bridge

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.execute(
            """CREATE TABLE security_events (
                id INTEGER PRIMARY KEY,
                timestamp_ns INTEGER,
                timestamp_dt TEXT,
                device_id TEXT,
                event_category TEXT,
                event_action TEXT,
                risk_score REAL,
                confidence REAL,
                mitre_techniques TEXT,
                final_classification TEXT,
                description TEXT,
                indicators TEXT,
                collection_agent TEXT,
                event_id TEXT
            )"""
        )
        db.execute(
            """CREATE TABLE signals (
                id INTEGER PRIMARY KEY,
                signal_id TEXT,
                contributing_event_ids TEXT
            )"""
        )
        db.execute(
            """INSERT INTO security_events VALUES (
                202, 1700000001000000000, '2026-03-17T20:01:00+00:00',
                'Akashs-MacBook-Air.local', 'kill_chain', 'detected',
                0.88, 0.8, '["TA0006"]', 'suspicious', 'Kill chain progression',
                '{}', 'SECURITY', 'evt-kill-chain-1'
            )"""
        )
        db.execute(
            "INSERT INTO signals VALUES (1, 'SIG-123', ?)",
            (json.dumps([202]),),
        )

        class FakeStore:
            def __init__(self, conn):
                self.db = conn

            def get_incident(self, incident_id):
                return {
                    "id": incident_id,
                    "source_event_ids": json.dumps([]),
                    "signal_ids": json.dumps(["SIG-123"]),
                    "title": "Signal-promoted incident",
                    "description": "",
                    "created_at": "2026-03-17T20:05:00+00:00",
                }

            def build_incident_timeline(self, device_id, start_ns, end_ns):
                raise AssertionError(
                    "signal-backed incident should resolve linked evidence"
                )

        monkeypatch.setattr(
            telemetry_bridge, "get_telemetry_store", lambda: FakeStore(db)
        )

        response = client.get("/dashboard/api/incidents/45/timeline")

        assert response.status_code == 200
        data = response.get_json()
        assert len(data) == 1
        assert data[0]["id"] == 202
        assert data[0]["event_category"] == "kill_chain"

    def test_list_incidents_normalizes_missing_severity_buckets(
        self, client, monkeypatch
    ):
        """Incidents API always returns all severity buckets."""
        from app.dashboard import telemetry_bridge

        class FakeStore:
            def get_incidents_count(self, status=None):
                return 1

            def get_incidents(self, status=None, limit=50, offset=0):
                return [
                    {"id": 1, "title": "test", "severity": "critical", "status": "open"}
                ]

            def get_incidents_status_counts(self):
                return {"open": 1}

            def get_incidents_severity_counts(self):
                return {"critical": 1, "high": 2}

        monkeypatch.setattr(
            telemetry_bridge, "get_telemetry_store", lambda: FakeStore()
        )

        response = client.get("/dashboard/api/incidents")

        assert response.status_code == 200
        data = response.get_json()
        assert data["severity_counts"]["critical"] == 1
        assert data["severity_counts"]["high"] == 2
        assert data["severity_counts"]["medium"] == 0
        assert data["severity_counts"]["low"] == 0


class TestProbeHealthEndpoint:
    """Test the probe health observability endpoint."""

    def test_probe_health_returns_valid_summary(self, client):
        """GET /dashboard/api/live/probe-health returns audit summary."""
        response = client.get("/dashboard/api/live/probe-health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        summary = data["summary"]
        assert summary["total"] > 0
        assert "real" in summary
        assert "degraded" in summary
        assert "by_agent" in summary


class TestDatabaseManagerPagination:
    """Test database manager pagination and export."""

    def test_view_table_accepts_pagination(self, client):
        """GET /database-manager/view-table with page params accepted."""
        response = client.get(
            "/api/database-manager/view-table/process_events?page=1&per_page=10"
        )
        # May 404 (no DB) or 200/500 — but shouldn't be 400
        assert response.status_code != 400

    def test_view_table_rejects_invalid_table(self, client):
        """GET /database-manager/view-table rejects unknown tables."""
        response = client.get("/api/database-manager/view-table/evil_table")
        # 400 when DB exists but table is invalid; 404 when DB file is absent
        assert response.status_code in (400, 404)

    def test_export_rejects_invalid_table(self, client):
        """GET /database-manager/export rejects unknown tables."""
        response = client.get("/api/database-manager/export/evil_table?format=csv")
        assert response.status_code in (400, 404)


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
