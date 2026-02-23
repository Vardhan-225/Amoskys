"""End-to-End Pipeline Test — WAL → TelemetryStore → Dashboard API.

Validates the critical data path:
    Agent SecurityEvent → WAL → WALProcessor → security_events table → Dashboard API

This test creates a realistic WAL database with protobuf-encoded SecurityEvents,
runs the WALProcessor to drain them, and verifies:
    1. Events land in security_events table
    2. TelemetryStore query methods return the right data
    3. Dashboard API endpoints serve correct JSON
"""

import json
import os
import sys
import time

import pytest

from amoskys.proto import universal_telemetry_pb2 as pb
from amoskys.storage.telemetry_store import TelemetryStore
from amoskys.storage.wal_processor import WALProcessor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _create_wal_db(path: str) -> None:
    """Create a minimal WAL SQLite database with the expected schema."""
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS wal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idem TEXT NOT NULL,
            ts_ns INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            checksum BLOB NOT NULL
        )"""
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS wal_idem ON wal(idem)")
    conn.commit()
    conn.close()


def _insert_wal_entry(wal_path: str, envelope: pb.UniversalEnvelope, idem: str) -> None:
    """Insert a serialized envelope into the WAL database."""
    import hashlib
    import sqlite3

    env_bytes = envelope.SerializeToString()
    checksum = hashlib.blake2b(env_bytes, digest_size=32).digest()
    ts_ns = envelope.ts_ns or int(time.time() * 1e9)

    conn = sqlite3.connect(wal_path)
    conn.execute(
        "INSERT INTO wal (idem, ts_ns, bytes, checksum) VALUES (?, ?, ?, ?)",
        (idem, ts_ns, env_bytes, checksum),
    )
    conn.commit()
    conn.close()


def _build_security_envelope(
    device_id: str,
    event_category: str,
    risk_score: float,
    probe_name: str,
    severity: str = "HIGH",
    mitre_techniques: list | None = None,
    confidence: float = 0.85,
    agent_name: str = "flow_agent_v2",
) -> pb.UniversalEnvelope:
    """Build a complete UniversalEnvelope with a SecurityEvent inside.

    Mirrors exactly what real agents produce:
        DeviceTelemetry → TelemetryEvent → SecurityEvent
    """
    ts_ns = int(time.time() * 1e9)

    security_event = pb.SecurityEvent(
        event_category=event_category,
        risk_score=risk_score,
        analyst_notes=f"Probe: {probe_name}, Severity: {severity}",
        requires_investigation=risk_score >= 0.7,
    )
    if mitre_techniques:
        security_event.mitre_techniques.extend(mitre_techniques)

    tel_event = pb.TelemetryEvent(
        event_id=f"{event_category}_{ts_ns}",
        event_type="SECURITY",
        severity=severity,
        event_timestamp_ns=ts_ns,
        source_component=probe_name,
        confidence_score=confidence,
        security_event=security_event,
    )
    tel_event.tags.extend([agent_name.split("_")[0], "threat"])

    device_telemetry = pb.DeviceTelemetry(
        device_id=device_id,
        device_type="HOST",
        protocol=agent_name.split("_")[0].upper(),
        timestamp_ns=ts_ns,
        collection_agent=agent_name,
        agent_version="2.0.0",
    )
    device_telemetry.events.append(tel_event)

    envelope = pb.UniversalEnvelope(
        version="v1",
        ts_ns=ts_ns,
        idempotency_key=f"{device_id}:{agent_name}:{ts_ns}",
        device_telemetry=device_telemetry,
    )
    return envelope


@pytest.fixture
def pipeline(tmp_path):
    """Create isolated WAL + TelemetryStore for testing."""
    wal_path = str(tmp_path / "test_wal.db")
    store_path = str(tmp_path / "test_telemetry.db")

    _create_wal_db(wal_path)

    processor = WALProcessor(wal_path=wal_path, store_path=store_path)
    return {
        "wal_path": wal_path,
        "store_path": store_path,
        "processor": processor,
        "store": processor.store,
    }


# ===================================================================
# 1. WAL → security_events table
# ===================================================================


class TestWALToSecurityEvents:
    """SecurityEvent in WAL → WALProcessor → security_events table."""

    def test_single_security_event_lands_in_db(self, pipeline):
        """One SecurityEvent envelope → 1 row in security_events."""
        env = _build_security_envelope(
            device_id="host-001",
            event_category="port_scan_detected",
            risk_score=0.8,
            probe_name="port_scan_sweep",
            mitre_techniques=["T1046"],
        )
        _insert_wal_entry(pipeline["wal_path"], env, "test-idem-001")

        processed = pipeline["processor"].process_batch(batch_size=10)
        assert processed == 1

        events = pipeline["store"].get_recent_security_events(limit=10, hours=1)
        assert len(events) == 1

        ev = events[0]
        assert ev["event_category"] == "port_scan_detected"
        assert ev["risk_score"] == pytest.approx(0.8, abs=0.01)
        assert ev["device_id"] == "host-001"
        assert "T1046" in ev["mitre_techniques"]
        assert ev["final_classification"] == "malicious"
        assert ev["requires_investigation"] == 1

    def test_multiple_agents_multiple_events(self, pipeline):
        """Events from flow, dns, auth agents all land in security_events."""
        agents = [
            (
                "flow_agent_v2",
                "lateral_movement_detected",
                0.9,
                "lateral_movement",
                ["T1021"],
            ),
            ("dns_agent_v2", "dns_c2_beaconing", 0.75, "dns_beaconing", ["T1071.004"]),
            (
                "auth_guard_agent_v2",
                "ssh_brute_force",
                0.85,
                "ssh_brute_force",
                ["T1110"],
            ),
            (
                "fim_agent_v2",
                "critical_file_modified",
                0.6,
                "critical_system_files",
                ["T1565"],
            ),
            (
                "persistence_agent_v2",
                "persistence_launch_agent",
                0.7,
                "launch_agent_detector",
                ["T1543.001"],
            ),
        ]

        for i, (agent, category, risk, probe, mitre) in enumerate(agents):
            env = _build_security_envelope(
                device_id="host-001",
                event_category=category,
                risk_score=risk,
                probe_name=probe,
                mitre_techniques=mitre,
                agent_name=agent,
            )
            _insert_wal_entry(pipeline["wal_path"], env, f"multi-agent-{i}")

        processed = pipeline["processor"].process_batch(batch_size=100)
        assert processed == 5

        events = pipeline["store"].get_recent_security_events(limit=50, hours=1)
        assert len(events) == 5

        categories = {ev["event_category"] for ev in events}
        assert "lateral_movement_detected" in categories
        assert "dns_c2_beaconing" in categories
        assert "ssh_brute_force" in categories

    def test_risk_score_classification_mapping(self, pipeline):
        """risk_score maps to correct final_classification."""
        test_cases = [
            (0.9, "malicious"),
            (0.75, "malicious"),
            (0.6, "suspicious"),
            (0.5, "suspicious"),
            (0.3, "legitimate"),
            (0.1, "legitimate"),
        ]

        for i, (risk, expected_class) in enumerate(test_cases):
            env = _build_security_envelope(
                device_id="host-class",
                event_category=f"test_event_{i}",
                risk_score=risk,
                probe_name="test_probe",
            )
            _insert_wal_entry(pipeline["wal_path"], env, f"class-test-{i}")

        pipeline["processor"].process_batch(batch_size=100)
        events = pipeline["store"].get_recent_security_events(limit=50, hours=1)

        for ev in events:
            idx = int(ev["event_category"].split("_")[-1])
            expected = test_cases[idx][1]
            assert (
                ev["final_classification"] == expected
            ), f"risk={test_cases[idx][0]} expected {expected}, got {ev['final_classification']}"

    def test_wal_entries_deleted_after_processing(self, pipeline):
        """WAL entries are removed after successful processing."""
        import sqlite3

        env = _build_security_envelope(
            device_id="host-001",
            event_category="test_cleanup",
            risk_score=0.5,
            probe_name="test_probe",
        )
        _insert_wal_entry(pipeline["wal_path"], env, "cleanup-test")

        # Verify WAL has entry
        conn = sqlite3.connect(pipeline["wal_path"])
        count = conn.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        conn.close()
        assert count == 1

        pipeline["processor"].process_batch(batch_size=10)

        # Verify WAL is empty
        conn = sqlite3.connect(pipeline["wal_path"])
        count = conn.execute("SELECT COUNT(*) FROM wal").fetchone()[0]
        conn.close()
        assert count == 0


# ===================================================================
# 2. TelemetryStore query methods
# ===================================================================


class TestTelemetryStoreQueries:
    """Verify dashboard query methods return correct data."""

    def _populate_events(self, pipeline, count=5):
        """Insert N security events into the pipeline."""
        for i in range(count):
            risk = 0.3 + (i * 0.15)  # 0.3, 0.45, 0.6, 0.75, 0.9
            env = _build_security_envelope(
                device_id="host-query",
                event_category=f"probe_finding_{i}",
                risk_score=min(risk, 1.0),
                probe_name=f"probe_{i}",
                mitre_techniques=[f"T{1000 + i}"],
            )
            _insert_wal_entry(pipeline["wal_path"], env, f"query-test-{i}")

        pipeline["processor"].process_batch(batch_size=100)

    def test_threat_score_reflects_real_events(self, pipeline):
        """get_threat_score_data() returns non-zero score with real events."""
        self._populate_events(pipeline, count=5)

        data = pipeline["store"].get_threat_score_data(hours=1)
        assert data["event_count"] == 5
        assert data["threat_score"] > 0
        assert data["threat_level"] != "none"
        assert data["avg_risk"] > 0
        assert data["max_risk"] >= 0.9

    def test_event_clustering_groups_correctly(self, pipeline):
        """get_security_event_clustering() groups by category/severity/hour."""
        self._populate_events(pipeline, count=5)

        data = pipeline["store"].get_security_event_clustering(hours=1)
        assert len(data["by_category"]) == 5
        assert sum(data["by_severity"].values()) == 5
        # At least one hour bucket should have events
        assert len(data["by_hour"]) >= 1

    def test_event_counts_by_classification(self, pipeline):
        """get_security_event_counts() returns by_category and by_classification."""
        self._populate_events(pipeline, count=5)

        data = pipeline["store"].get_security_event_counts(hours=1)
        assert data["total"] == 5
        assert len(data["by_category"]) == 5
        # Should have at least 2 classifications (legitimate, suspicious, malicious)
        assert len(data["by_classification"]) >= 2

    def test_empty_store_returns_safe_defaults(self, pipeline):
        """All query methods return safe defaults when table is empty."""
        data = pipeline["store"].get_threat_score_data(hours=1)
        assert data["threat_score"] == 0
        assert data["threat_level"] == "none"
        assert data["event_count"] == 0

        events = pipeline["store"].get_recent_security_events(limit=10, hours=1)
        assert events == []

        clusters = pipeline["store"].get_security_event_clustering(hours=1)
        assert clusters["by_category"] == {}


# ===================================================================
# 3. Dashboard API integration (Flask test client)
# ===================================================================


class TestDashboardAPIIntegration:
    """Verify dashboard endpoints serve data from TelemetryStore."""

    @pytest.fixture
    def client_with_data(self, tmp_path):
        """Create Flask test client with a pre-populated TelemetryStore."""
        store_path = str(tmp_path / "dashboard_test.db")
        store = TelemetryStore(store_path)

        # Insert test security events directly
        for i in range(3):
            store.insert_security_event(
                {
                    "timestamp_ns": int(time.time() * 1e9) - (i * 60_000_000_000),
                    "device_id": f"test-host-{i}",
                    "event_category": ["ssh_brute_force", "port_scan", "dns_tunneling"][
                        i
                    ],
                    "risk_score": [0.9, 0.6, 0.8][i],
                    "confidence": 0.85,
                    "mitre_techniques": [["T1110"], ["T1046"], ["T1048"]][i],
                    "final_classification": ["malicious", "suspicious", "malicious"][i],
                    "description": f"Test event {i}",
                    "requires_investigation": True,
                }
            )

        # Patch telemetry_bridge to use our test store
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "web"))
        os.environ["FLASK_DEBUG"] = "true"
        os.environ["FORCE_HTTPS"] = "false"
        os.environ["SECRET_KEY"] = "test-secret-key"

        from app import create_app

        result = create_app()
        app_instance = result[0] if isinstance(result, tuple) else result
        app_instance.config["TESTING"] = True

        # Monkey-patch the telemetry bridge to return our test store
        from app.dashboard import telemetry_bridge

        telemetry_bridge._telemetry_store = store

        return app_instance.test_client()

    def test_threats_endpoint_returns_real_events(self, client_with_data):
        """GET /dashboard/api/live/threats returns events from TelemetryStore."""
        response = client_with_data.get("/dashboard/api/live/threats")
        assert response.status_code == 200

        data = response.get_json()
        assert data["status"] == "success"
        assert data["count"] == 3
        assert len(data["threats"]) == 3

        # Verify event shape matches what cortex.html expects
        threat = data["threats"][0]
        assert "type" in threat
        assert "severity" in threat
        assert "description" in threat
        assert "timestamp" in threat

    def test_threat_score_endpoint_nonzero(self, client_with_data):
        """GET /dashboard/api/live/threat-score returns non-zero score."""
        response = client_with_data.get("/dashboard/api/live/threat-score")
        assert response.status_code == 200

        data = response.get_json()
        assert data["status"] == "success"
        assert data["threat_score"] > 0
        assert data["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_event_clustering_endpoint_has_data(self, client_with_data):
        """GET /dashboard/api/live/event-clustering returns grouped data."""
        response = client_with_data.get("/dashboard/api/live/event-clustering")
        assert response.status_code == 200

        data = response.get_json()
        assert data["status"] == "success"
        clusters = data["clusters"]
        assert len(clusters["by_type"]) >= 1
        assert sum(clusters["by_severity"].values()) >= 1
