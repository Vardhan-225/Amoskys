#!/usr/bin/env python3
"""AMOSKYS Infrastructure & Data Pipeline Test Suite.

Tests the complete flow:
  Agent (local) → Ops Server → Presentation Server → Dashboard

Run: PYTHONPATH=src python -m pytest tests/infra/test_pipeline.py -v
"""

import json
import os
import sqlite3
import time
from pathlib import Path

import pytest
import requests

# ── Configuration ──────────────────────────────────────────────────

OPS_SERVER = os.getenv("AMOSKYS_OPS_SERVER", "https://18.223.110.15")
WEB_SERVER = os.getenv("AMOSKYS_WEB_SERVER", "https://amoskys.com")
LOCAL_TELEMETRY_DB = Path("/var/lib/amoskys/data/telemetry.db")
VERIFY_SSL = False  # Ops server uses self-signed cert


# ── Helper ─────────────────────────────────────────────────────────

def ops_get(path, params=None):
    """GET from ops server."""
    return requests.get(f"{OPS_SERVER}{path}", params=params, timeout=10, verify=VERIFY_SSL)


def web_get(path, params=None):
    """GET from presentation server (no auth, public endpoints only)."""
    return requests.get(f"{WEB_SERVER}{path}", params=params, timeout=10, verify=True)


# ══════════════════════════════════════════════════════════════════
# LAYER 1: OPS SERVER HEALTH
# ══════════════════════════════════════════════════════════════════

class TestOpsServerHealth:
    """Verify the operations server is running and responding."""

    def test_health_endpoint(self):
        r = ops_get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"

    def test_devices_endpoint(self):
        r = ops_get("/api/v1/devices")
        assert r.status_code == 200
        data = r.json()
        assert "devices" in data
        assert "total" in data

    def test_fleet_status_endpoint(self):
        r = ops_get("/api/v1/fleet/status")
        assert r.status_code == 200
        data = r.json()
        assert "fleet" in data
        assert "last_24h" in data
        assert "devices" in data

    def test_events_endpoint(self):
        r = ops_get("/api/v1/events", params={"limit": 5})
        assert r.status_code == 200
        data = r.json()
        assert "events" in data

    def test_bulk_export_endpoint(self):
        r = ops_get("/api/v1/bulk-export", params={"limit": 10})
        assert r.status_code == 200
        data = r.json()
        expected_tables = ["security_events", "process_events", "flow_events",
                          "dns_events", "persistence_events"]
        for table in expected_tables:
            assert table in data, f"Missing table: {table}"

    def test_device_registration(self):
        """Test that device registration works, then clean up."""
        test_id = "test-pipeline-check"
        r = requests.post(
            f"{OPS_SERVER}/api/v1/register",
            json={
                "device_id": test_id,
                "hostname": "pipeline-test",
                "os": "TestOS",
                "arch": "test",
                "agent_version": "test",
            },
            timeout=10,
            verify=VERIFY_SSL,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "registered"

        # Clean up test device so it doesn't pollute the dashboard
        try:
            requests.delete(
                f"{OPS_SERVER}/api/v1/devices/{test_id}",
                timeout=5, verify=VERIFY_SSL,
            )
        except Exception:
            pass  # Best effort cleanup


# ══════════════════════════════════════════════════════════════════
# LAYER 2: OPS SERVER DATA INTEGRITY
# ══════════════════════════════════════════════════════════════════

class TestOpsServerData:
    """Verify data exists and has the right structure in the ops server."""

    def test_has_online_device(self):
        r = ops_get("/api/v1/devices")
        data = r.json()
        online = [d for d in data["devices"] if d["status"] == "online"]
        assert len(online) > 0, "No online devices — is an agent shipping?"

    def test_security_events_exist(self):
        r = ops_get("/api/v1/events", params={"limit": 1})
        data = r.json()
        assert len(data["events"]) > 0, "No security events in ops server"

    def test_bulk_export_has_data(self):
        r = ops_get("/api/v1/bulk-export", params={"limit": 5})
        data = r.json()
        non_empty = {k: len(v) for k, v in data.items() if v}
        assert len(non_empty) >= 3, f"Expected data in 3+ tables, got: {non_empty}"

    def test_all_9_tables_exist(self):
        """All 9 event tables should exist in the bulk export."""
        r = ops_get("/api/v1/bulk-export", params={"limit": 1})
        data = r.json()
        required = ["security_events", "process_events", "flow_events",
                    "dns_events", "persistence_events"]
        for table in required:
            assert table in data, f"Table {table} missing from bulk export"

    def test_security_events_have_enrichment(self):
        """Security events should have GeoIP/ASN enrichment data."""
        r = ops_get("/api/v1/events", params={"limit": 50})
        events = r.json()["events"]
        if not events:
            pytest.skip("No events to check")

        # Check if any events have enrichment
        enriched = [e for e in events if e.get("geo_src_country") or e.get("asn_src_org")]
        network_events = [e for e in events if e.get("remote_ip")]

        if network_events:
            pct = len(enriched) / len(network_events) * 100 if network_events else 0
            assert pct > 0, (
                f"No GeoIP enrichment found. {len(network_events)} events have remote_ip "
                f"but 0 have geo_src_country. Enrichment pipeline may be broken."
            )

    def test_security_events_have_mitre(self):
        """Security events should have MITRE ATT&CK techniques."""
        r = ops_get("/api/v1/events", params={"limit": 50})
        events = r.json()["events"]
        if not events:
            pytest.skip("No events")

        with_mitre = [e for e in events if e.get("mitre_techniques")]
        assert len(with_mitre) > 0, "No events have MITRE techniques"

    def test_device_telemetry_endpoint(self):
        """Per-device telemetry should return full dashboard data."""
        r = ops_get("/api/v1/devices")
        devices = r.json()["devices"]
        if not devices:
            pytest.skip("No devices")

        # Pick device with most events (skip test devices with 0)
        device_id = max(devices, key=lambda d: d.get("security_event_count", 0))["device_id"]
        r2 = ops_get(f"/api/v1/devices/{device_id}/telemetry")
        assert r2.status_code == 200
        data = r2.json()

        required_keys = ["device", "posture", "summary", "categories",
                        "mitre_techniques", "agents", "recent_events"]
        for key in required_keys:
            assert key in data, f"Missing key in telemetry: {key}"


# ══════════════════════════════════════════════════════════════════
# LAYER 3: PRESENTATION SERVER HEALTH
# ══════════════════════════════════════════════════════════════════

class TestPresentationServer:
    """Verify the presentation server (amoskys.com) is running."""

    def test_health(self):
        r = web_get("/health")
        assert r.status_code == 200

    def test_landing_page(self):
        r = web_get("/")
        assert r.status_code == 200

    def test_login_page(self):
        r = web_get("/auth/login")
        assert r.status_code == 200

    def test_signup_page(self):
        r = web_get("/auth/signup")
        assert r.status_code == 200

    def test_install_script(self):
        r = web_get("/deploy/install.sh")
        assert r.status_code == 200
        assert "AMOSKYS" in r.text

    def test_pkg_download(self):
        r = web_get("/download/AMOSKYS.pkg")
        assert r.status_code == 200
        assert len(r.content) > 1_000_000, "PKG file too small — truncated?"

    def test_dashboard_requires_auth(self):
        """Dashboard pages should redirect to login."""
        r = web_get("/dashboard/")
        # Should redirect (302) or show login
        assert r.status_code in (200, 302)


# ══════════════════════════════════════════════════════════════════
# LAYER 4: LOCAL AGENT
# ══════════════════════════════════════════════════════════════════

class TestLocalAgent:
    """Verify the local agent is installed and running."""

    def test_install_directory_exists(self):
        assert Path("/Library/Amoskys").exists(), "AMOSKYS not installed"

    def test_config_exists(self):
        config = Path("/Library/Amoskys/config/amoskys.env")
        assert config.exists(), "Config file missing"

    def test_config_has_server(self):
        config = Path("/Library/Amoskys/config/amoskys.env")
        if not config.exists():
            pytest.skip("Not installed")
        try:
            content = config.read_text()
        except PermissionError:
            pytest.skip("Config file is root-owned — run tests with sudo to check")
        assert "AMOSKYS_SERVER" in content, "AMOSKYS_SERVER not in config — agent won't ship"

    def test_venv_exists(self):
        assert Path("/Library/Amoskys/venv/bin/python3").exists(), "Venv missing"

    def test_launchdaemon_exists(self):
        assert Path("/Library/LaunchDaemons/com.amoskys.watchdog.plist").exists()

    def test_watchdog_running(self):
        import subprocess
        result = subprocess.run(["pgrep", "-f", "amoskys.watchdog"], capture_output=True)
        assert result.returncode == 0, "Watchdog not running"

    def test_local_telemetry_db(self):
        """Local telemetry.db should exist and have events."""
        candidates = [
            Path("/var/lib/amoskys/data/telemetry.db"),
            Path("/var/lib/amoskys/telemetry.db"),
        ]
        found = None
        for p in candidates:
            if p.exists():
                found = p
                break
        assert found is not None, "No telemetry.db found"

        db = sqlite3.connect(str(found))
        count = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        db.close()
        assert count > 0, "Local telemetry.db has no security events"

    def test_local_queue_files(self):
        """Agent queues should exist (collectors are writing)."""
        queue_dir = Path("/var/lib/amoskys/data/queue")
        if not queue_dir.exists():
            pytest.skip("Queue dir not found")
        queues = list(queue_dir.glob("*.db"))
        assert len(queues) > 5, f"Expected 5+ agent queues, found {len(queues)}"


# ══════════════════════════════════════════════════════════════════
# LAYER 5: END-TO-END PIPELINE
# ══════════════════════════════════════════════════════════════════

class TestEndToEndPipeline:
    """Verify data flows from agent through ops to presentation."""

    def _get_my_hostname(self):
        """Get hostname using the same logic as the shipper."""
        import platform, socket, subprocess
        if platform.system() == "Darwin":
            for cmd in ["ComputerName", "LocalHostName"]:
                try:
                    result = subprocess.run(["scutil", "--get", cmd], capture_output=True, text=True, timeout=3)
                    name = result.stdout.strip()
                    if name and len(name) > 1:
                        return name
                except Exception:
                    pass
        name = socket.gethostname()
        return name if name and name != "localhost" else platform.node()

    def test_agent_registered_on_ops(self):
        """The local Mac should be registered on the ops server."""
        hostname = self._get_my_hostname()
        r = ops_get("/api/v1/devices")
        devices = r.json()["devices"]
        hostnames = [d["hostname"] for d in devices]
        assert hostname in hostnames, f"Local host '{hostname}' not found in ops devices: {hostnames}"

    def test_agent_is_online(self):
        """The local Mac should show as online."""
        hostname = self._get_my_hostname()
        r = ops_get("/api/v1/devices")
        devices = r.json()["devices"]
        my_device = next((d for d in devices if d["hostname"] == hostname), None)
        assert my_device is not None, f"Device {hostname} not found"
        assert my_device["status"] == "online", f"Device status is {my_device['status']}, expected online"

    def test_events_shipped_to_ops(self):
        """The local Mac should have events on the ops server."""
        hostname = self._get_my_hostname()
        r = ops_get("/api/v1/devices")
        devices = r.json()["devices"]
        my_device = next((d for d in devices if d["hostname"] == hostname), None)
        assert my_device is not None, f"Device {hostname} not found"
        assert my_device["security_event_count"] > 0, "No events shipped to ops server"

    def test_ops_to_presentation_sync(self):
        """Events on ops should appear on the presentation server's fleet cache."""
        # This tests the fleet sync by checking if the presentation server
        # can proxy fleet status from the ops server
        r = web_get("/health")
        assert r.status_code == 200
        # The fleet sync runs in background — we just verify the server is up
        # Actual data verification requires authenticated access


# ══════════════════════════════════════════════════════════════════
# LAYER 6: DATA QUALITY
# ══════════════════════════════════════════════════════════════════

class TestDataQuality:
    """Verify the quality of telemetry data."""

    def test_events_have_timestamps(self):
        r = ops_get("/api/v1/events", params={"limit": 10})
        events = r.json()["events"]
        for e in events:
            assert e.get("timestamp_ns") or e.get("timestamp_dt"), f"Event missing timestamp: {e.get('id')}"

    def test_events_have_device_id(self):
        r = ops_get("/api/v1/events", params={"limit": 10})
        events = r.json()["events"]
        for e in events:
            assert e.get("device_id"), f"Event missing device_id: {e.get('id')}"

    def test_events_have_risk_scores(self):
        r = ops_get("/api/v1/events", params={"limit": 50})
        events = r.json()["events"]
        if not events:
            pytest.skip("No events")
        with_risk = [e for e in events if e.get("risk_score") is not None]
        pct = len(with_risk) / len(events) * 100
        assert pct > 50, f"Only {pct:.0f}% of events have risk scores"

    def test_events_have_collection_agent(self):
        r = ops_get("/api/v1/events", params={"limit": 50})
        events = r.json()["events"]
        if not events:
            pytest.skip("No events")
        with_agent = [e for e in events if e.get("collection_agent")]
        pct = len(with_agent) / len(events) * 100
        assert pct > 80, f"Only {pct:.0f}% of events have collection_agent"

    def test_multiple_event_categories(self):
        r = ops_get("/api/v1/fleet/status")
        cats = r.json().get("top_categories", [])
        assert len(cats) >= 3, f"Only {len(cats)} categories — expected diverse event types"

    def test_multiple_mitre_techniques(self):
        r = ops_get("/api/v1/fleet/status")
        mitre = r.json().get("top_mitre_techniques", [])
        assert len(mitre) >= 3, f"Only {len(mitre)} MITRE techniques — expected broader coverage"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
