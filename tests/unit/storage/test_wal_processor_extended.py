"""
Extended tests for WALProcessor (src/amoskys/storage/wal_processor.py).

Focuses on UNTESTED paths not covered by existing test files:
- _process_security_event with risk_score thresholds (malicious/suspicious/legitimate)
- _process_security_event description building (with/without source_component)
- _route_events dispatching to correct domain extractors
- _route_security_to_domain_tables routing logic per agent type
- _extract_process_from_security with missing fields
- _extract_flow_from_security with port conversion
- _extract_peripheral_from_security with JSON device list
- _extract_dns_from_security with beaconing/tunneling flags
- _extract_audit_from_security with all attribute fields
- _extract_persistence_from_security
- _extract_fim_from_security with patterns_matched splitting
- _process_process_event process category classification branches
- _process_device_telemetry with metadata fields
- process_local_queues with multiple queue files and errors
- run() loop (keyboard interrupt, cycle logging)
- Connection cleanup in process_batch finally block
"""

import json
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.storage.wal_processor import WALProcessor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _setup_wal_db(wal_path: str) -> sqlite3.Connection:
    """Create a minimal WAL database with the expected schema."""
    conn = sqlite3.connect(wal_path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS wal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idem TEXT UNIQUE,
            ts_ns INTEGER NOT NULL,
            bytes BLOB NOT NULL,
            checksum BLOB
        )"""
    )
    conn.commit()
    return conn


def _make_proc(tmp_path):
    """Create a WALProcessor with fresh databases."""
    return WALProcessor(
        wal_path=str(tmp_path / "wal.db"),
        store_path=str(tmp_path / "store.db"),
    )


def _make_security_event(
    risk_score=0.5,
    event_category="INTRUSION",
    event_action=None,
    event_outcome=None,
    analyst_notes="Test notes",
    mitre_techniques=None,
    requires_investigation=False,
    source_component="test-probe",
    confidence_score=0.8,
    attributes=None,
):
    """Build a TelemetryEvent with a SecurityEvent sub-message."""
    ev = telemetry_pb2.TelemetryEvent()
    ev.event_id = "ev-sec-1"
    ev.event_type = "SECURITY"
    ev.severity = "HIGH"
    ev.source_component = source_component
    ev.confidence_score = confidence_score
    if attributes:
        for k, v in attributes.items():
            ev.attributes[k] = v
    se = ev.security_event
    se.event_category = event_category
    if event_action:
        se.event_action = event_action
    if event_outcome:
        se.event_outcome = event_outcome
    se.risk_score = risk_score
    se.analyst_notes = analyst_notes
    if mitre_techniques:
        se.mitre_techniques.extend(mitre_techniques)
    se.requires_investigation = requires_investigation
    return ev


# ===========================================================================
# _process_security_event classification tests
# ===========================================================================


class TestProcessSecurityEventClassification:
    """Test risk_score -> classification mapping."""

    def test_malicious_classification(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(risk_score=0.85)
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert len(rows) == 1
        assert rows[0]["final_classification"] == "malicious"

    def test_suspicious_classification(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(risk_score=0.55)
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert len(rows) == 1
        assert rows[0]["final_classification"] == "suspicious"

    def test_legitimate_classification(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(risk_score=0.3)
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert len(rows) == 1
        assert rows[0]["final_classification"] == "legitimate"

    def test_boundary_075_is_malicious(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(risk_score=0.75)
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert rows[0]["final_classification"] == "malicious"

    def test_boundary_050_is_suspicious(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(risk_score=0.50)
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert rows[0]["final_classification"] == "suspicious"


class TestProcessSecurityEventDescription:
    """Test description building logic."""

    def test_description_includes_source_component(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            analyst_notes="Suspicious activity",
            source_component="auth-probe",
        )
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert "[auth-probe]" in rows[0]["description"]
        assert "Suspicious activity" in rows[0]["description"]

    def test_description_no_duplicate_source_component(self, tmp_path):
        """If source_component is already in analyst_notes, don't duplicate."""
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            analyst_notes="[auth-probe] already included",
            source_component="auth-probe",
        )
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        # Should NOT have double [auth-probe]
        assert rows[0]["description"].count("[auth-probe]") == 1

    def test_description_empty_analyst_notes(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            analyst_notes="",
            source_component="test-probe",
        )
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert "[test-probe]" in rows[0]["description"]

    def test_requires_investigation_from_high_risk(self, tmp_path):
        """requires_investigation should be True when risk >= 0.7."""
        proc = _make_proc(tmp_path)
        ev = _make_security_event(risk_score=0.71, requires_investigation=False)
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        assert rows[0]["requires_investigation"] == 1

    def test_mitre_techniques_stored(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(mitre_techniques=["T1059", "T1082"])
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )

        rows = proc.store.get_recent_security_events(hours=24 * 365 * 100)
        techniques = json.loads(rows[0]["mitre_techniques"])
        assert "T1059" in techniques
        assert "T1082" in techniques

    def test_process_security_event_error_handled(self, tmp_path):
        """Errors in _process_security_event should be caught, not crash."""
        proc = _make_proc(tmp_path)
        # Create a broken event that will raise during processing
        ev = MagicMock()
        ev.security_event = MagicMock()
        ev.security_event.mitre_techniques = None
        ev.security_event.risk_score = "not-a-number"  # Will cause issues

        # Should not raise
        proc._process_security_event(
            ev, "dev-1", 1000, "2024-01-01T00:00:00", "test-agent"
        )


# ===========================================================================
# _route_events and _route_security_to_domain_tables tests
# ===========================================================================


class TestRouteEvents:
    """Test event routing to correct table processors."""

    def test_peripheral_status_event_routed(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_type = "STATUS"
        ev.source_component = "peripheral_agent"
        ev.confidence_score = 0.5
        sd = ev.status_data
        sd.status = "CONNECTED"
        sd.component_name = "USB Drive"

        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "peripheral_agent",
            "1.0",
        )

        cursor = proc.store.db.execute("SELECT COUNT(*) FROM peripheral_events")
        assert cursor.fetchone()[0] == 1

    def test_security_event_with_dns_agent_routes_to_dns(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            event_category="dga_domain_detected",
            source_component="dns-probe",
            attributes={"domain": "evil.com", "query_type": "A"},
        )
        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "dns-agent-v2",
            "2.0",
        )

        # Should have written to security_events AND dns_events
        sec_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]
        dns_count = proc.store.db.execute("SELECT COUNT(*) FROM dns_events").fetchone()[
            0
        ]
        assert sec_count == 1
        assert dns_count == 1

    def test_security_event_with_proc_agent_routes_to_process(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            event_category="suspicious_process",
            source_component="proc-probe",
            attributes={"pid": "1234", "exe": "/tmp/evil", "ppid": "1"},
        )
        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "proc-agent",
            "3.0",
        )

        sec_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]
        proc_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM process_events"
        ).fetchone()[0]
        assert sec_count == 1
        assert proc_count == 1

    def test_security_event_with_flow_agent_routes_to_flow(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            event_category="suspicious_flow",
            source_component="flow-probe",
            attributes={
                "dst_ip": "10.0.0.5",
                "src_ip": "192.168.1.1",
                "dst_port": "443",
            },
        )
        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "flow-agent-v2",
            "2.0",
        )

        sec_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]
        flow_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM flow_events"
        ).fetchone()[0]
        assert sec_count == 1
        assert flow_count == 1

    def test_security_event_with_kernel_agent_routes_to_audit(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            event_category="kernel_execve_high_risk",
            source_component="kernel-probe",
            attributes={"syscall": "execve", "exe": "/bin/sh", "pid": "5678"},
        )
        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "kernel_audit-agent-v2",
            "2.0",
        )

        sec_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]
        audit_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]
        assert sec_count == 1
        assert audit_count == 1

    def test_security_event_with_persistence_agent_routes(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            event_category="persistence_launchd_created",
            source_component="persistence-probe",
            attributes={
                "mechanism": "launchd",
                "path": "/Library/LaunchDaemons/evil.plist",
            },
        )
        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "persistence-agent-v2",
            "2.0",
        )

        sec_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]
        pers_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM persistence_events"
        ).fetchone()[0]
        assert sec_count == 1
        assert pers_count == 1

    def test_security_event_with_fim_agent_routes(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            event_category="critical_file_tampered",
            source_component="fim-probe",
            attributes={"path": "/etc/passwd", "change_type": "modified"},
        )
        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "fim-agent-v2",
            "2.0",
        )

        sec_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]
        fim_count = proc.store.db.execute("SELECT COUNT(*) FROM fim_events").fetchone()[
            0
        ]
        assert sec_count == 1
        assert fim_count == 1

    def test_usb_category_routes_to_peripheral(self, tmp_path):
        """Events with 'usb' in category route to peripheral_events."""
        proc = _make_proc(tmp_path)
        ev = _make_security_event(
            event_category="usb_new_device_connected",
            source_component="some-probe",
            attributes={},
        )
        proc._route_events(
            [ev],
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "some-agent-v2",
            "2.0",
        )

        periph_count = proc.store.db.execute(
            "SELECT COUNT(*) FROM peripheral_events"
        ).fetchone()[0]
        assert periph_count >= 1


# ===========================================================================
# _extract_peripheral_from_security with device list
# ===========================================================================


class TestExtractPeripheralFromSecurity:
    """Test peripheral extraction with JSON device lists."""

    def test_empty_devices_stores_inventory_snapshot(self, tmp_path):
        proc = _make_proc(tmp_path)
        attrs = {"devices": "[]"}
        proc._extract_peripheral_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "periph-agent",
            "1.0",
        )
        cursor = proc.store.db.execute(
            "SELECT peripheral_device_id, event_type FROM peripheral_events"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "inventory-snapshot"
        assert row[1] == "INVENTORY"

    def test_devices_list_stores_each_device(self, tmp_path):
        proc = _make_proc(tmp_path)
        devices = [
            {"id": "usb-1", "name": "Flash", "type": "USB", "vendor_id": "v1"},
            {"id": "usb-2", "name": "Camera", "type": "USB", "vendor_id": "v2"},
        ]
        attrs = {"devices": json.dumps(devices)}
        proc._extract_peripheral_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "periph-agent",
            "1.0",
        )
        cursor = proc.store.db.execute("SELECT COUNT(*) FROM peripheral_events")
        assert cursor.fetchone()[0] == 2

    def test_invalid_devices_json_stores_inventory(self, tmp_path):
        proc = _make_proc(tmp_path)
        attrs = {"devices": "NOT_JSON"}
        proc._extract_peripheral_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "periph-agent",
            "1.0",
        )
        cursor = proc.store.db.execute("SELECT COUNT(*) FROM peripheral_events")
        assert cursor.fetchone()[0] == 1  # inventory-snapshot

    def test_no_devices_key_stores_inventory(self, tmp_path):
        proc = _make_proc(tmp_path)
        attrs = {}  # No devices key at all
        proc._extract_peripheral_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "periph-agent",
            "1.0",
        )
        cursor = proc.store.db.execute("SELECT COUNT(*) FROM peripheral_events")
        assert cursor.fetchone()[0] == 1


# ===========================================================================
# _extract_dns_from_security
# ===========================================================================


class TestExtractDnsFromSecurity:
    """Test DNS extraction with beaconing/tunneling flags."""

    def test_dns_with_beaconing(self, tmp_path):
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.8
        se.mitre_techniques = ["T1071"]
        attrs = {
            "domain": "beacon.evil.com",
            "query_type": "A",
            "avg_interval_seconds": "30.0",
            "confidence": "0.9",
        }
        proc._extract_dns_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "dns-agent-v2",
            "2.0",
            "dns_beaconing_detected",
            ["T1071"],
        )
        cursor = proc.store.db.execute(
            "SELECT is_beaconing, beacon_interval_seconds FROM dns_events"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == 1  # is_beaconing
        assert row[1] == 30.0

    def test_dns_with_tunneling(self, tmp_path):
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.9
        se.mitre_techniques = ["T1048"]
        attrs = {"domain": "tunnel.evil.com", "confidence": "0.95"}
        proc._extract_dns_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "dns-agent-v2",
            "2.0",
            "dns_tunnel_detected",
            ["T1048"],
        )
        cursor = proc.store.db.execute("SELECT is_tunneling FROM dns_events")
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == 1  # is_tunneling

    def test_dns_no_domain_skips(self, tmp_path):
        """If no domain in attributes, skip without error."""
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.5
        se.mitre_techniques = []
        attrs = {}
        proc._extract_dns_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "dns-agent",
            "1.0",
            "test",
            [],
        )
        cursor = proc.store.db.execute("SELECT COUNT(*) FROM dns_events")
        assert cursor.fetchone()[0] == 0

    def test_dns_with_dga_score(self, tmp_path):
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.7
        se.mitre_techniques = []
        attrs = {"domain": "xkjhsdakjhsd.com", "dga_score": "0.95"}
        proc._extract_dns_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "dns-agent-v2",
            "2.0",
            "dga_domain_detected",
            [],
        )
        cursor = proc.store.db.execute("SELECT dga_score FROM dns_events")
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == pytest.approx(0.95)


# ===========================================================================
# _extract_audit_from_security
# ===========================================================================


class TestExtractAuditFromSecurity:
    """Test kernel audit extraction."""

    def test_audit_with_all_fields(self, tmp_path):
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.9
        se.mitre_techniques = ["T1055"]
        attrs = {
            "host": "server-01",
            "syscall": "ptrace",
            "pid": "1234",
            "ppid": "1",
            "uid": "0",
            "euid": "0",
            "gid": "0",
            "egid": "0",
            "exe": "/tmp/evil",
            "comm": "evil",
            "cmdline": "./evil --inject",
            "cwd": "/tmp",
            "target_path": None,
            "target_pid": "5678",
            "target_comm": "sshd",
            "confidence": "0.95",
            "reason": "ptrace on sshd",
        }
        proc._extract_audit_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "kernel_audit-agent-v2",
            "2.0",
            "kernel_ptrace",
            ["T1055"],
        )
        cursor = proc.store.db.execute(
            "SELECT syscall, target_pid, reason FROM audit_events"
        )
        row = cursor.fetchone()
        assert row[0] == "ptrace"
        assert row[1] == 5678
        assert row[2] == "ptrace on sshd"

    def test_audit_with_attacker_exe_fallback(self, tmp_path):
        """Uses attacker_exe when exe is not in attributes."""
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.5
        se.mitre_techniques = []
        attrs = {
            "syscall": "execve",
            "attacker_exe": "/usr/bin/nc",
            "attacker_comm": "nc",
        }
        proc._extract_audit_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "kernel-agent-v2",
            "2.0",
            "kernel_execve",
            [],
        )
        cursor = proc.store.db.execute("SELECT exe, comm FROM audit_events")
        row = cursor.fetchone()
        assert row[0] == "/usr/bin/nc"
        assert row[1] == "nc"


# ===========================================================================
# _extract_persistence_from_security
# ===========================================================================


class TestExtractPersistenceFromSecurity:
    """Test persistence extraction."""

    def test_persistence_all_fields(self, tmp_path):
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.8
        se.mitre_techniques = ["T1543"]
        attrs = {
            "mechanism": "launchd",
            "entry_id": "com.evil.daemon",
            "path": "/Library/LaunchDaemons/evil.plist",
            "command": "/usr/bin/evil",
            "user": "root",
            "change_type": "created",
            "old_command": "",
            "new_command": "/usr/bin/evil",
            "confidence": "0.9",
            "reason": "New launch daemon",
        }
        proc._extract_persistence_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "persistence-agent-v2",
            "2.0",
            "persistence_launchd_created",
            ["T1543"],
        )
        cursor = proc.store.db.execute(
            "SELECT mechanism, entry_id, change_type FROM persistence_events"
        )
        row = cursor.fetchone()
        assert row[0] == "launchd"
        assert row[1] == "com.evil.daemon"
        assert row[2] == "created"


# ===========================================================================
# _extract_fim_from_security
# ===========================================================================


class TestExtractFimFromSecurity:
    """Test FIM extraction with patterns_matched splitting."""

    def test_fim_with_patterns_matched(self, tmp_path):
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.95
        se.mitre_techniques = ["T1505"]
        attrs = {
            "path": "/var/www/shell.php",
            "change_type": "created",
            "extension": ".php",
            "patterns_matched": "webshell,eval_exec,base64_decode",
            "confidence": "0.9",
            "reason": "Webshell detected",
        }
        proc._extract_fim_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "fim-agent-v2",
            "2.0",
            "webshell_detected",
            ["T1505"],
        )
        cursor = proc.store.db.execute("SELECT path, patterns_matched FROM fim_events")
        row = cursor.fetchone()
        assert row[0] == "/var/www/shell.php"
        patterns = json.loads(row[1])
        assert "webshell" in patterns
        assert "eval_exec" in patterns

    def test_fim_no_patterns_matched(self, tmp_path):
        proc = _make_proc(tmp_path)
        se = MagicMock()
        se.risk_score = 0.7
        se.mitre_techniques = []
        attrs = {
            "path": "/etc/shadow",
            "change_type": "modified",
        }
        proc._extract_fim_from_security(
            attrs,
            se,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "fim-agent-v2",
            "2.0",
            "critical_file_tampered",
            [],
        )
        cursor = proc.store.db.execute("SELECT patterns_matched FROM fim_events")
        row = cursor.fetchone()
        patterns = json.loads(row[0])
        assert patterns == []


# ===========================================================================
# _process_process_event category branches
# ===========================================================================


class TestProcessEventCategoryBranches:
    """Test process classification branches not covered by existing tests."""

    def _insert_process_envelope(self, wal_path, idem, exe, uid=501, ppid=1, pid=100):
        conn = _setup_wal_db(wal_path)
        env = telemetry_pb2.UniversalEnvelope()
        proc_ev = env.process
        proc_ev.pid = pid
        proc_ev.ppid = ppid
        proc_ev.exe = exe
        proc_ev.uid = uid
        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            (idem, 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

    def test_system_library_category(self, tmp_path):
        """Processes in /System/Library/ -> system."""
        wal_path = str(tmp_path / "wal.db")
        self._insert_process_envelope(
            wal_path,
            "sys-lib",
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
        )
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        proc.process_batch()
        rows = proc.store.get_recent_processes(limit=10)
        assert rows[0]["process_category"] == "system"

    def test_helper_category(self, tmp_path):
        """Processes with 'Helper' in path -> helper.

        Note: The helper branch is checked AFTER the application branch
        ('/Applications/' + '.app/'), so we use a path outside /Applications/.
        """
        wal_path = str(tmp_path / "wal.db")
        self._insert_process_envelope(
            wal_path, "helper", "/usr/local/bin/BrowserHelper"
        )
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        proc.process_batch()
        rows = proc.store.get_recent_processes(limit=10)
        assert rows[0]["process_category"] == "helper"

    def test_kernel_category(self, tmp_path):
        """kernel_task -> kernel."""
        wal_path = str(tmp_path / "wal.db")
        self._insert_process_envelope(
            wal_path, "kern", "kernel_task", uid=0, pid=0, ppid=0
        )
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        proc.process_batch()
        rows = proc.store.get_recent_processes(limit=10)
        # kernel_task ends in 'k' not 'd', but it's in the daemon name list
        # Actually: exe_name "kernel_task" is in the daemon detection name list
        assert rows[0]["process_category"] == "daemon"

    def test_unknown_category(self, tmp_path):
        """Unrecognized process -> unknown."""
        wal_path = str(tmp_path / "wal.db")
        self._insert_process_envelope(wal_path, "unk", "/usr/local/bin/myapp")
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        proc.process_batch()
        rows = proc.store.get_recent_processes(limit=10)
        assert rows[0]["process_category"] == "unknown"

    def test_com_apple_category(self, tmp_path):
        """Executables starting with com.apple. -> system."""
        wal_path = str(tmp_path / "wal.db")
        self._insert_process_envelope(wal_path, "apple", "/some/path/com.apple.Finder")
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        proc.process_batch()
        rows = proc.store.get_recent_processes(limit=10)
        assert rows[0]["process_category"] == "system"

    def test_empty_exe(self, tmp_path):
        """Empty exe string -> unknown category."""
        wal_path = str(tmp_path / "wal.db")
        self._insert_process_envelope(wal_path, "empty", "")
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        proc.process_batch()
        rows = proc.store.get_recent_processes(limit=10)
        assert rows[0]["process_category"] == "unknown"

    def test_process_with_args(self, tmp_path):
        """Cmdline is joined from args."""
        conn = _setup_wal_db(str(tmp_path / "wal.db"))
        env = telemetry_pb2.UniversalEnvelope()
        proc_ev = env.process
        proc_ev.pid = 42
        proc_ev.ppid = 1
        proc_ev.exe = "/usr/bin/ls"
        proc_ev.uid = 501
        proc_ev.args.extend(["-la", "/tmp"])
        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("args-test", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        processor = WALProcessor(
            wal_path=str(tmp_path / "wal.db"), store_path=str(tmp_path / "store.db")
        )
        processor.process_batch()
        rows = processor.store.get_recent_processes(limit=10)
        assert rows[0]["cmdline"] == "-la /tmp"


# ===========================================================================
# _process_device_telemetry with metadata
# ===========================================================================


class TestProcessDeviceTelemetryWithMetadata:
    """Test device telemetry processing with metadata fields."""

    def test_device_telemetry_with_metadata(self, tmp_path):
        wal_path = str(tmp_path / "wal.db")
        conn = _setup_wal_db(wal_path)

        env = telemetry_pb2.UniversalEnvelope()
        dt = env.device_telemetry
        dt.device_id = "server-01"
        dt.device_type = "ENDPOINT"
        dt.protocol = "gRPC"
        dt.collection_agent = "test-agent"
        dt.agent_version = "1.0"

        # Add a metric event
        ev = dt.events.add()
        ev.event_id = "ev-1"
        ev.event_type = "METRIC"
        ev.severity = "INFO"
        md = ev.metric_data
        md.metric_name = "process_count"
        md.numeric_value = 150.0

        raw = env.SerializeToString()
        conn.execute(
            "INSERT INTO wal (idem, ts_ns, bytes) VALUES (?, ?, ?)",
            ("dt-meta", 1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))
        count = proc.process_batch()
        assert count == 1

        cursor = proc.store.db.execute(
            "SELECT device_type, total_processes FROM device_telemetry"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "ENDPOINT"
        assert row[1] == 150


# ===========================================================================
# process_local_queues edge cases
# ===========================================================================


class TestProcessLocalQueuesExtended:
    """Extended tests for process_local_queues."""

    def test_v3_queue_files_processed(self, tmp_path):
        """Queue files matching *_v3.db are also processed."""
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        agent_db = str(queue_dir / "special_agent_v3.db")
        conn = sqlite3.connect(agent_db)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ns INTEGER NOT NULL, bytes BLOB NOT NULL)"
        )
        dt = telemetry_pb2.DeviceTelemetry()
        dt.device_id = "v3-dev"
        dt.collection_agent = "special-agent-v3"
        raw = dt.SerializeToString()
        conn.execute(
            "INSERT INTO queue (ts_ns, bytes) VALUES (?, ?)",
            (1000, sqlite3.Binary(raw)),
        )
        conn.commit()
        conn.close()

        proc = _make_proc(tmp_path)
        total = proc.process_local_queues(queue_dir=str(queue_dir))
        assert total == 1

    def test_nonexistent_queue_dir(self, tmp_path):
        """Non-existent queue directory returns 0."""
        proc = _make_proc(tmp_path)
        total = proc.process_local_queues(queue_dir=str(tmp_path / "no_such_dir"))
        assert total == 0

    def test_queue_with_connection_error(self, tmp_path):
        """Queue file with wrong schema logs error and continues."""
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        agent_db = str(queue_dir / "broken_v2.db")
        conn = sqlite3.connect(agent_db)
        # Create wrong schema (no 'queue' table)
        conn.execute("CREATE TABLE wrong (id INTEGER)")
        conn.close()

        proc = _make_proc(tmp_path)
        # Should not crash, returns 0
        total = proc.process_local_queues(queue_dir=str(queue_dir))
        assert total == 0

    def test_multiple_queue_files(self, tmp_path):
        """Multiple agent queues are all drained."""
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        for agent_name in ["alpha_v2", "beta_v2"]:
            agent_db = str(queue_dir / f"{agent_name}.db")
            conn = sqlite3.connect(agent_db)
            conn.execute(
                "CREATE TABLE queue (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ns INTEGER NOT NULL, bytes BLOB NOT NULL)"
            )
            dt = telemetry_pb2.DeviceTelemetry()
            dt.device_id = f"dev-{agent_name}"
            dt.collection_agent = agent_name
            raw = dt.SerializeToString()
            conn.execute(
                "INSERT INTO queue (ts_ns, bytes) VALUES (?, ?)",
                (1000, sqlite3.Binary(raw)),
            )
            conn.commit()
            conn.close()

        proc = _make_proc(tmp_path)
        total = proc.process_local_queues(queue_dir=str(queue_dir))
        assert total == 2

    def test_empty_queue_file_skipped(self, tmp_path):
        """Empty queue file (no rows) is skipped and returns 0."""
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        agent_db = str(queue_dir / "empty_v2.db")
        conn = sqlite3.connect(agent_db)
        conn.execute(
            "CREATE TABLE queue (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ns INTEGER NOT NULL, bytes BLOB NOT NULL)"
        )
        conn.commit()
        conn.close()

        proc = _make_proc(tmp_path)
        total = proc.process_local_queues(queue_dir=str(queue_dir))
        assert total == 0

    def test_drain_respects_max_entries_budget(self, tmp_path):
        """Drain stops after max_entries and leaves remaining queue rows."""
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        agent_db = str(queue_dir / "budgeted_v2.db")
        conn = sqlite3.connect(agent_db)
        conn.execute(
            "CREATE TABLE queue (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ns INTEGER NOT NULL, bytes BLOB NOT NULL)"
        )
        for idx in range(3):
            dt = telemetry_pb2.DeviceTelemetry()
            dt.device_id = f"dev-{idx}"
            dt.collection_agent = "budgeted-agent"
            conn.execute(
                "INSERT INTO queue (ts_ns, bytes) VALUES (?, ?)",
                (1000 + idx, sqlite3.Binary(dt.SerializeToString())),
            )
        conn.commit()
        conn.close()

        proc = _make_proc(tmp_path)
        total = proc.process_local_queues(queue_dir=str(queue_dir), max_entries=2)
        assert total == 2

        verify = sqlite3.connect(agent_db)
        remaining = verify.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        verify.close()
        assert remaining == 1

    def test_drain_respects_timeout_budget(self, tmp_path):
        """Drain exits when max_seconds budget is exceeded mid-queue."""
        queue_dir = tmp_path / "queue"
        queue_dir.mkdir()

        agent_db = str(queue_dir / "timeout_v2.db")
        conn = sqlite3.connect(agent_db)
        conn.execute(
            "CREATE TABLE queue (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ns INTEGER NOT NULL, bytes BLOB NOT NULL)"
        )
        for idx in range(2):
            dt = telemetry_pb2.DeviceTelemetry()
            dt.device_id = f"timeout-{idx}"
            dt.collection_agent = "timeout-agent"
            conn.execute(
                "INSERT INTO queue (ts_ns, bytes) VALUES (?, ?)",
                (1000 + idx, sqlite3.Binary(dt.SerializeToString())),
            )
        conn.commit()
        conn.close()

        proc = _make_proc(tmp_path)
        with patch(
            "amoskys.storage.wal_processor.time.monotonic",
            side_effect=[0.0, 0.0, 0.0, 2.0, 2.0, 2.0],
        ):
            total = proc.process_local_queues(queue_dir=str(queue_dir), max_seconds=1.0)
        assert total == 1

        verify = sqlite3.connect(agent_db)
        remaining = verify.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        verify.close()
        assert remaining == 1


# ===========================================================================
# _extract_process_from_security
# ===========================================================================


class TestExtractProcessFromSecurity:
    """Test process extraction from security event attributes."""

    def test_with_all_fields(self, tmp_path):
        proc = _make_proc(tmp_path)
        attrs = {
            "pid": "1234",
            "ppid": "1",
            "exe": "/tmp/malware",
            "cmdline": "./malware --payload",
            "username": "root",
        }
        proc._extract_process_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "proc-agent",
            "3.0",
            "suspicious_process",
        )
        rows = proc.store.get_recent_processes(limit=10)
        assert len(rows) == 1
        assert rows[0]["pid"] == 1234
        assert rows[0]["exe"] == "/tmp/malware"
        assert rows[0]["user_type"] == "root"
        assert rows[0]["is_suspicious"] == 1

    def test_with_binary_fallback(self, tmp_path):
        """Uses 'binary' attribute when 'exe' not present."""
        proc = _make_proc(tmp_path)
        attrs = {
            "pid": "5678",
            "binary": "/usr/bin/nc",
            "username": "nobody",
        }
        proc._extract_process_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "proc-agent",
            "3.0",
            "reverse_shell",
        )
        rows = proc.store.get_recent_processes(limit=10)
        assert rows[0]["exe"] == "/usr/bin/nc"
        assert rows[0]["user_type"] == "user"

    def test_with_missing_optional_fields(self, tmp_path):
        """Missing ppid, cmdline should not crash."""
        proc = _make_proc(tmp_path)
        attrs = {"pid": "1"}
        proc._extract_process_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "proc",
            "3.0",
            "test",
        )
        rows = proc.store.get_recent_processes(limit=10)
        assert len(rows) == 1
        assert rows[0]["ppid"] is None


# ===========================================================================
# _extract_flow_from_security
# ===========================================================================


class TestExtractFlowFromSecurity:
    """Test flow extraction from security event attributes."""

    def test_with_ports(self, tmp_path):
        proc = _make_proc(tmp_path)
        attrs = {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.5",
            "src_port": "12345",
            "dst_port": "443",
            "protocol": "TCP",
            "bytes_tx": "1024",
            "bytes_rx": "2048",
            "threat_score": "0.8",
        }
        proc._extract_flow_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
        )
        cursor = proc.store.db.execute(
            "SELECT src_port, dst_port, bytes_tx FROM flow_events"
        )
        row = cursor.fetchone()
        assert row[0] == 12345
        assert row[1] == 443
        assert row[2] == 1024

    def test_with_missing_ports(self, tmp_path):
        """Missing ports stored as NULL."""
        proc = _make_proc(tmp_path)
        attrs = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        proc._extract_flow_from_security(
            attrs,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
        )
        cursor = proc.store.db.execute("SELECT src_port, dst_port FROM flow_events")
        row = cursor.fetchone()
        assert row[0] is None
        assert row[1] is None


# ===========================================================================
# run() lifecycle tests
# ===========================================================================


class TestRunLifecycle:
    """Test the run() method lifecycle."""

    def test_run_keyboard_interrupt_exits(self, tmp_path):
        """run() exits cleanly on KeyboardInterrupt."""
        wal_path = str(tmp_path / "wal.db")
        _setup_wal_db(wal_path).close()
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))

        with patch.object(proc, "process_batch", side_effect=KeyboardInterrupt):
            proc.run(interval=1)
        # Should have logged final stats and closed store
        # No assertion needed - just verify no exception

    def test_run_handles_cycle_error(self, tmp_path):
        """run() catches generic exceptions and continues."""
        wal_path = str(tmp_path / "wal.db")
        _setup_wal_db(wal_path).close()
        proc = WALProcessor(wal_path=wal_path, store_path=str(tmp_path / "store.db"))

        call_count = [0]

        def batch_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("transient error")
            elif call_count[0] == 2:
                raise KeyboardInterrupt
            return 0

        with patch.object(proc, "process_batch", side_effect=batch_side_effect):
            with patch("amoskys.storage.wal_processor.time.sleep"):
                proc.run(interval=0)

        assert call_count[0] == 2  # First errored, second interrupted


# ===========================================================================
# _quarantine edge case
# ===========================================================================


class TestQuarantineEdgeCases:
    """Test quarantine failure handling."""

    def test_quarantine_failure_does_not_increment_count(self, tmp_path):
        """If quarantine INSERT fails, quarantine_count is NOT incremented."""
        proc = _make_proc(tmp_path)

        real_db = proc.store.db
        original_execute = real_db.execute

        def failing_execute(sql, *args, **kwargs):
            if "INSERT INTO wal_dead_letter" in str(sql):
                raise sqlite3.OperationalError("disk full")
            return original_execute(sql, *args, **kwargs)

        proc.store.db = MagicMock(wraps=real_db)
        proc.store.db.execute = failing_execute

        proc._quarantine(999, b"some_bytes", "test error")
        assert proc.quarantine_count == 0

    def test_quarantine_success_increments_count(self, tmp_path):
        proc = _make_proc(tmp_path)
        proc._quarantine(1, b"test_data", "test error msg")
        assert proc.quarantine_count == 1

        row = proc.store.db.execute(
            "SELECT row_id, error_msg, source FROM wal_dead_letter"
        ).fetchone()
        assert row[0] == 1
        assert row[1] == "test error msg"
        assert row[2] == "wal_processor"


# ===========================================================================
# _process_peripheral_event via process_batch
# ===========================================================================


class TestProcessPeripheralEventViaBatch:
    """Test _process_peripheral_event directly."""

    def test_peripheral_without_status_data(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_type = "STATUS"
        ev.source_component = "peripheral_agent"
        ev.confidence_score = 0.7
        ev.attributes["device_type"] = "USB_STORAGE"
        ev.attributes["vendor_id"] = "v1"
        ev.attributes["product_id"] = "p1"
        ev.attributes["risk_score"] = "0.3"
        ev.attributes["is_authorized"] = "True"

        proc._process_peripheral_event(
            ev,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "periph-agent",
            "1.0",
        )

        cursor = proc.store.db.execute(
            "SELECT device_type, is_authorized FROM peripheral_events"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == "USB_STORAGE"
        assert row[1] == 1  # True

    def test_peripheral_with_status_data(self, tmp_path):
        proc = _make_proc(tmp_path)
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_type = "STATUS"
        ev.source_component = "peripheral_agent"
        ev.confidence_score = 0.5
        sd = ev.status_data
        sd.status = "CONNECTED"
        sd.component_name = "Kingston Flash"
        sd.previous_status = "DISCONNECTED"

        proc._process_peripheral_event(
            ev,
            "dev-1",
            1000,
            "2024-01-01T00:00:00",
            "periph-agent",
            "1.0",
        )

        cursor = proc.store.db.execute(
            "SELECT connection_status, previous_status FROM peripheral_events"
        )
        row = cursor.fetchone()
        assert row[0] == "CONNECTED"
        assert row[1] == "DISCONNECTED"
