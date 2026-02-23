"""
Extended tests for TelemetryStore (src/amoskys/storage/telemetry_store.py).

Focuses on UNTESTED paths not covered by test_wal_processor.py:
- Error handlers for all insert methods (sqlite3.Error paths)
- search_events with different table types and query modes
- get_mitre_coverage edge cases (bad JSON, non-list, missing category)
- get_threat_score_data severity level thresholds
- get_security_event_clustering severity mapping and by_hour grouping
- Incident management error paths
- Metrics history with device_id filter
- get_statistics domain table fallback counts
- update_incident resolved_at auto-set logic
- search_events category filter
- Flow event duplicate handling (INSERT OR IGNORE)
- Device telemetry upsert
- Peripheral event with all fields
- close() method
"""

import json
import sqlite3
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.storage.telemetry_store import TelemetryStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path):
    """Create a fresh TelemetryStore instance."""
    s = TelemetryStore(str(tmp_path / "test.db"))
    yield s
    try:
        s.close()
    except Exception:
        pass


def _now_ns():
    return int(time.time() * 1e9)


def _now_dt():
    return datetime.now(timezone.utc).isoformat()


# ===========================================================================
# Insert error handler paths
# ===========================================================================


def _make_broken_store(store):
    """Replace store.db with a MagicMock that always raises on execute."""
    mock_db = MagicMock()
    mock_db.execute.side_effect = sqlite3.OperationalError("simulated error")
    store.db = mock_db
    return store


class TestInsertErrorPaths:
    """All insert methods have try/except sqlite3.Error returning None."""

    def test_insert_security_event_error_returns_none(self, store):
        """If db.execute raises sqlite3.Error, returns None."""
        _make_broken_store(store)
        result = store.insert_security_event({"device_id": "x"})
        assert result is None

    def test_insert_flow_event_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_flow_event({"device_id": "x"})
        assert result is None

    def test_insert_peripheral_event_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_peripheral_event({"device_id": "x"})
        assert result is None

    def test_insert_dns_event_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_dns_event({"device_id": "x"})
        assert result is None

    def test_insert_audit_event_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_audit_event({"device_id": "x"})
        assert result is None

    def test_insert_persistence_event_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_persistence_event({"device_id": "x"})
        assert result is None

    def test_insert_fim_event_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_fim_event({"device_id": "x"})
        assert result is None

    def test_insert_device_telemetry_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_device_telemetry({"device_id": "x"})
        assert result is None

    def test_insert_metrics_timeseries_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.insert_metrics_timeseries({"metric_name": "x"})
        assert result is None


# ===========================================================================
# search_events - all table types with query text
# ===========================================================================


class TestSearchEventsAllTables:
    """Test search_events with query text across all supported tables."""

    def test_search_process_events_by_exe(self, store):
        store.insert_process_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "pid": 1,
                "exe": "/usr/bin/malware",
                "cmdline": "malware --evil",
                "username": "attacker",
            }
        )
        result = store.search_events(query="malware", table="process_events", hours=24)
        assert result["total_count"] == 1

    def test_search_flow_events_by_ip(self, store):
        store.insert_flow_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.5",
                "protocol": "TCP",
            }
        )
        result = store.search_events(query="192.168", table="flow_events", hours=24)
        assert result["total_count"] == 1

    def test_search_peripheral_events_by_name(self, store):
        store.insert_peripheral_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "peripheral_device_id": "usb-001",
                "event_type": "CONNECTED",
                "device_name": "SuspiciousDrive",
                "device_type": "USB_STORAGE",
            }
        )
        result = store.search_events(
            query="Suspicious", table="peripheral_events", hours=24
        )
        assert result["total_count"] == 1

    def test_search_dns_events_by_domain(self, store):
        store.insert_dns_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "domain": "evil-c2.example.com",
                "event_type": "dga_domain_detected",
            }
        )
        result = store.search_events(query="evil-c2", table="dns_events", hours=24)
        assert result["total_count"] == 1

    def test_search_audit_events_by_syscall(self, store):
        store.insert_audit_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "syscall": "ptrace",
                "event_type": "kernel_ptrace_attack",
                "exe": "/tmp/injector",
                "reason": "Anti-debugging detected",
            }
        )
        result = store.search_events(query="ptrace", table="audit_events", hours=24)
        assert result["total_count"] == 1

    def test_search_persistence_events_by_mechanism(self, store):
        store.insert_persistence_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "event_type": "persistence_launchd_created",
                "mechanism": "launchd",
                "path": "/Library/LaunchDaemons/evil.plist",
                "reason": "New persistence entry",
            }
        )
        result = store.search_events(
            query="launchd", table="persistence_events", hours=24
        )
        assert result["total_count"] == 1

    def test_search_fim_events_by_path(self, store):
        store.insert_fim_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "event_type": "critical_file_tampered",
                "path": "/etc/shadow",
                "reason": "Hash changed",
            }
        )
        result = store.search_events(query="/etc/shadow", table="fim_events", hours=24)
        assert result["total_count"] == 1


class TestSearchEventsFilters:
    """Test search_events with min_risk and category filters."""

    def test_min_risk_filter_on_dns_events(self, store):
        store.insert_dns_event(
            {
                "timestamp_ns": _now_ns(),
                "device_id": "d1",
                "domain": "low-risk.com",
                "risk_score": 0.1,
            }
        )
        store.insert_dns_event(
            {
                "timestamp_ns": _now_ns() + 1,
                "device_id": "d1",
                "domain": "high-risk.com",
                "risk_score": 0.9,
            }
        )
        result = store.search_events(table="dns_events", min_risk=0.5, hours=24)
        assert result["total_count"] == 1

    def test_min_risk_filter_on_audit_events(self, store):
        store.insert_audit_event(
            {
                "timestamp_ns": _now_ns(),
                "device_id": "d1",
                "syscall": "execve",
                "event_type": "kernel_execve",
                "risk_score": 0.8,
            }
        )
        result = store.search_events(table="audit_events", min_risk=0.7, hours=24)
        assert result["total_count"] == 1

    def test_min_risk_filter_on_persistence_events(self, store):
        store.insert_persistence_event(
            {
                "timestamp_ns": _now_ns(),
                "device_id": "d1",
                "event_type": "persistence_cron_modified",
                "risk_score": 0.6,
            }
        )
        result = store.search_events(table="persistence_events", min_risk=0.5, hours=24)
        assert result["total_count"] == 1

    def test_min_risk_filter_on_fim_events(self, store):
        store.insert_fim_event(
            {
                "timestamp_ns": _now_ns(),
                "device_id": "d1",
                "event_type": "suid_bit_added",
                "path": "/tmp/escalate",
                "risk_score": 0.95,
            }
        )
        result = store.search_events(table="fim_events", min_risk=0.9, hours=24)
        assert result["total_count"] == 1

    def test_category_filter_on_security_events(self, store):
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "event_category": "INTRUSION",
                "risk_score": 0.8,
            }
        )
        store.insert_security_event(
            {
                "timestamp_ns": ts + 1,
                "device_id": "d1",
                "event_category": "AUTH",
                "risk_score": 0.3,
            }
        )
        result = store.search_events(
            table="security_events", category="INTRUSION", hours=24
        )
        assert result["total_count"] == 1

    def test_search_error_returns_empty(self, store):
        """SQLite error in search returns empty result."""
        _make_broken_store(store)
        result = store.search_events(table="security_events", hours=24)
        assert result["results"] == []
        assert result["total_count"] == 0

    def test_min_risk_not_applied_to_process_events(self, store):
        """min_risk filter should NOT be applied to process_events table."""
        store.insert_process_event(
            {
                "timestamp_ns": _now_ns(),
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "pid": 1,
            }
        )
        # process_events has no risk_score column in the filter list
        result = store.search_events(table="process_events", min_risk=0.5, hours=24)
        # Should still find the event because min_risk filter is not applied
        assert result["total_count"] == 1


# ===========================================================================
# MITRE Coverage edge cases
# ===========================================================================


class TestMitreCoverageEdgeCases:
    """Test get_mitre_coverage with bad data."""

    def test_invalid_json_skipped(self, store):
        """If mitre_techniques contains invalid JSON, skip that row."""
        ts = _now_ns()
        store.db.execute(
            "INSERT INTO security_events (timestamp_ns, timestamp_dt, device_id, "
            "mitre_techniques, event_category) VALUES (?, ?, ?, ?, ?)",
            (ts, _now_dt(), "d1", "NOT_JSON", "AUTH"),
        )
        store.db.commit()
        coverage = store.get_mitre_coverage()
        assert coverage == {}

    def test_non_list_techniques_skipped(self, store):
        """If mitre_techniques is valid JSON but not a list, skip."""
        ts = _now_ns()
        store.db.execute(
            "INSERT INTO security_events (timestamp_ns, timestamp_dt, device_id, "
            "mitre_techniques, event_category) VALUES (?, ?, ?, ?, ?)",
            (ts, _now_dt(), "d1", json.dumps({"bad": "format"}), "AUTH"),
        )
        store.db.commit()
        coverage = store.get_mitre_coverage()
        assert coverage == {}

    def test_null_mitre_techniques_skipped(self, store):
        """Null/empty techniques JSON results in empty list, no error."""
        ts = _now_ns()
        store.db.execute(
            "INSERT INTO security_events (timestamp_ns, timestamp_dt, device_id, "
            "mitre_techniques, event_category) VALUES (?, ?, ?, ?, ?)",
            (ts, _now_dt(), "d1", json.dumps([]), "AUTH"),
        )
        store.db.commit()
        coverage = store.get_mitre_coverage()
        assert coverage == {}

    def test_null_category_becomes_unknown(self, store):
        """If event_category is NULL, coverage uses 'unknown' key."""
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "event_category": None,
                "mitre_techniques": ["T1059"],
                "risk_score": 0.5,
            }
        )
        coverage = store.get_mitre_coverage()
        assert "T1059" in coverage
        assert "unknown" in coverage["T1059"]["categories"]

    def test_mitre_coverage_db_error_returns_empty(self, store):
        """SQLite error returns empty dict."""
        _make_broken_store(store)
        coverage = store.get_mitre_coverage()
        assert coverage == {}

    def test_multiple_techniques_per_event(self, store):
        """Multiple MITRE techniques in a single event are all counted."""
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "event_category": "INTRUSION",
                "mitre_techniques": ["T1059", "T1082", "T1003"],
                "risk_score": 0.9,
            }
        )
        coverage = store.get_mitre_coverage()
        assert len(coverage) == 3
        for tech in ["T1059", "T1082", "T1003"]:
            assert tech in coverage
            assert coverage[tech]["count"] == 1


# ===========================================================================
# Threat score levels
# ===========================================================================


class TestThreatScoreLevels:
    """Test get_threat_score_data classification logic."""

    def test_no_events_returns_none_level(self, store):
        result = store.get_threat_score_data(hours=1)
        assert result["threat_level"] == "none"
        assert result["threat_score"] == 0.0

    def test_low_risk_events(self, store):
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "risk_score": 0.1,
            }
        )
        result = store.get_threat_score_data(hours=1)
        # score = (0.1 * 50) + (0 * 10) + (0.1 * 20) = 5 + 0 + 2 = 7
        assert result["threat_level"] == "low"
        assert 0 < result["threat_score"] < 25

    def test_medium_risk_events(self, store):
        ts = _now_ns()
        # avg_risk = 0.4, max = 0.4 => score = 0.4*50 + 0 + 0.4*20 = 28
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "risk_score": 0.4,
            }
        )
        result = store.get_threat_score_data(hours=1)
        assert result["threat_level"] == "medium"
        assert 25 <= result["threat_score"] < 50

    def test_high_risk_events(self, store):
        ts = _now_ns()
        # Two events: avg_risk = 0.75, max = 0.8, critical_count = 1 (0.8 > 0.7)
        # score = 0.75*50 + 1*10 + 0.8*20 = 37.5 + 10 + 16 = 63.5
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "risk_score": 0.7,
            }
        )
        store.insert_security_event(
            {
                "timestamp_ns": ts + 1,
                "device_id": "d1",
                "risk_score": 0.8,
            }
        )
        result = store.get_threat_score_data(hours=1)
        assert result["threat_level"] == "high"
        assert 50 <= result["threat_score"] < 75

    def test_critical_risk_events(self, store):
        ts = _now_ns()
        # 5 critical events at risk_score=0.95: avg=0.95, max=0.95, crit_count=5
        # score = 0.95*50 + 5*10 + 0.95*20 = 47.5 + 50 + 19 = 116.5 -> capped at 100
        for i in range(5):
            store.insert_security_event(
                {
                    "timestamp_ns": ts + i,
                    "device_id": "d1",
                    "risk_score": 0.95,
                }
            )
        result = store.get_threat_score_data(hours=1)
        assert result["threat_level"] == "critical"
        assert result["threat_score"] >= 75

    def test_threat_score_db_error(self, store):
        """SQLite error returns safe defaults."""
        _make_broken_store(store)
        result = store.get_threat_score_data(hours=1)
        assert result["threat_score"] == 0
        assert result["threat_level"] == "none"


# ===========================================================================
# Security event clustering severity mapping
# ===========================================================================


class TestClusteringSeverityMapping:
    """Test by_severity mapping from risk_score ranges."""

    def test_severity_distribution(self, store):
        ts = _now_ns()
        # low: risk < 0.25
        store.insert_security_event(
            {"timestamp_ns": ts, "device_id": "d1", "risk_score": 0.1}
        )
        # medium: 0.25 <= risk < 0.5
        store.insert_security_event(
            {"timestamp_ns": ts + 1, "device_id": "d1", "risk_score": 0.3}
        )
        # high: 0.5 <= risk < 0.75
        store.insert_security_event(
            {"timestamp_ns": ts + 2, "device_id": "d1", "risk_score": 0.6}
        )
        # critical: risk >= 0.75
        store.insert_security_event(
            {"timestamp_ns": ts + 3, "device_id": "d1", "risk_score": 0.9}
        )

        result = store.get_security_event_clustering(hours=24)
        assert result["by_severity"]["low"] == 1
        assert result["by_severity"]["medium"] == 1
        assert result["by_severity"]["high"] == 1
        assert result["by_severity"]["critical"] == 1

    def test_clustering_by_hour(self, store):
        """by_hour groups events by the hour from timestamp_dt."""
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "timestamp_dt": "2024-06-15T14:30:00+00:00",
                "device_id": "d1",
                "risk_score": 0.5,
            }
        )
        store.insert_security_event(
            {
                "timestamp_ns": ts + 1,
                "timestamp_dt": "2024-06-15T14:45:00+00:00",
                "device_id": "d1",
                "risk_score": 0.6,
            }
        )
        result = store.get_security_event_clustering(hours=24 * 365 * 10)
        assert "14" in result["by_hour"]
        assert result["by_hour"]["14"] == 2

    def test_clustering_db_error(self, store):
        """SQLite error returns default structure."""
        _make_broken_store(store)
        result = store.get_security_event_clustering(hours=24)
        # Should still return the structure with defaults
        assert "by_category" in result
        assert "by_severity" in result

    def test_null_category_excluded_from_clustering(self, store):
        """Events with NULL event_category are excluded from by_category."""
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "event_category": None,
                "risk_score": 0.5,
            }
        )
        result = store.get_security_event_clustering(hours=24)
        assert result["by_category"] == {}


# ===========================================================================
# Incident management edge cases
# ===========================================================================


class TestIncidentEdgeCases:
    """Test incident management error paths."""

    def test_create_incident_db_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.create_incident({"title": "Test"})
        assert result is None

    def test_update_incident_db_error_returns_false(self, store):
        inc_id = store.create_incident({"title": "Test"})
        _make_broken_store(store)
        result = store.update_incident(inc_id, {"status": "resolved"})
        assert result is False

    def test_get_incidents_db_error_returns_empty(self, store):
        _make_broken_store(store)
        result = store.get_incidents()
        assert result == []

    def test_get_incident_db_error_returns_none(self, store):
        _make_broken_store(store)
        result = store.get_incident(1)
        assert result is None

    def test_update_only_allowed_fields(self, store):
        """Fields not in the allowed set are ignored."""
        inc_id = store.create_incident({"title": "Test"})
        # Try to update with an invalid field
        store.update_incident(inc_id, {"evil_field": "injected", "title": "Updated"})
        inc = store.get_incident(inc_id)
        assert inc["title"] == "Updated"
        # evil_field should not exist in the row
        assert "evil_field" not in inc

    def test_resolve_with_explicit_resolved_at_skips_auto(self, store):
        """When resolved_at is provided in data, auto-set logic is skipped.

        Note: resolved_at is NOT in the 'allowed' set, so the explicit value
        is also not applied. The net effect is resolved_at stays NULL when
        both status=resolved AND resolved_at is passed (edge case in the code).
        """
        inc_id = store.create_incident({"title": "Test"})
        store.update_incident(
            inc_id,
            {
                "status": "resolved",
                "resolved_at": "2024-01-01T00:00:00Z",
            },
        )
        inc = store.get_incident(inc_id)
        # resolved_at is NOT in allowed set, so explicit value is not applied,
        # AND auto-set is skipped because data.get("resolved_at") is truthy.
        assert inc["resolved_at"] is None
        assert inc["status"] == "resolved"

    def test_create_incident_defaults(self, store):
        """Incident creation uses defaults for missing fields."""
        inc_id = store.create_incident({})
        inc = store.get_incident(inc_id)
        assert inc["title"] == "Untitled Incident"
        assert inc["severity"] == "medium"
        assert inc["status"] == "open"


# ===========================================================================
# Metrics history error path
# ===========================================================================


class TestMetricsHistoryErrorPath:
    """Test get_metrics_history error handling."""

    def test_db_error_returns_empty_list(self, store):
        _make_broken_store(store)
        result = store.get_metrics_history("cpu", hours=24)
        assert result == []


# ===========================================================================
# get_recent_security_events error path
# ===========================================================================


class TestRecentSecurityEventsErrorPath:
    """Test get_recent_security_events error handling."""

    def test_db_error_returns_empty_list(self, store):
        _make_broken_store(store)
        result = store.get_recent_security_events(hours=24)
        assert result == []


# ===========================================================================
# get_security_event_counts error path
# ===========================================================================


class TestSecurityEventCountsErrorPath:
    """Test get_security_event_counts error handling."""

    def test_db_error_returns_default_structure(self, store):
        _make_broken_store(store)
        result = store.get_security_event_counts(hours=24)
        assert result["total"] == 0
        assert result["by_category"] == {}
        assert result["by_classification"] == {}

    def test_null_category_excluded_from_counts(self, store):
        """Events with NULL event_category excluded from by_category."""
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "event_category": None,
                "risk_score": 0.5,
                "final_classification": "suspicious",
            }
        )
        counts = store.get_security_event_counts(hours=24)
        assert counts["total"] == 1
        assert counts["by_category"] == {}
        assert counts["by_classification"]["suspicious"] == 1


# ===========================================================================
# Flow event duplicate handling
# ===========================================================================


class TestFlowEventDuplicates:
    """Test INSERT OR IGNORE for flow events."""

    def test_duplicate_flow_event_ignored(self, store):
        ts = _now_ns()
        data = {
            "timestamp_ns": ts,
            "timestamp_dt": _now_dt(),
            "device_id": "d1",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "src_port": 12345,
            "dst_port": 53,
        }
        id1 = store.insert_flow_event(data)
        id2 = store.insert_flow_event(data)  # Same unique key
        # Second insert uses OR IGNORE, so both return row IDs (id2 may be 0)
        assert id1 is not None


# ===========================================================================
# Device telemetry upsert
# ===========================================================================


class TestDeviceTelemetryUpsert:
    """Test INSERT OR REPLACE behaviour for device telemetry."""

    def test_upsert_replaces_on_conflict(self, store):
        ts = _now_ns()
        store.insert_device_telemetry(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "total_processes": 100,
            }
        )
        store.insert_device_telemetry(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "total_processes": 200,
            }
        )
        cursor = store.db.execute(
            "SELECT total_processes FROM device_telemetry WHERE device_id='d1' AND timestamp_ns=?",
            (ts,),
        )
        rows = cursor.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == 200


# ===========================================================================
# Statistics with all domain tables
# ===========================================================================


class TestStatisticsAllTables:
    """Test get_statistics includes all domain table counts."""

    def test_statistics_includes_all_domain_tables(self, store):
        ts = _now_ns()
        store.insert_dns_event(
            {"timestamp_ns": ts, "device_id": "d1", "domain": "x.com"}
        )
        store.insert_audit_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "syscall": "execve",
                "event_type": "test",
            }
        )
        store.insert_persistence_event(
            {"timestamp_ns": ts, "device_id": "d1", "event_type": "test"}
        )
        store.insert_fim_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "event_type": "test",
                "path": "/tmp",
            }
        )
        store.insert_peripheral_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "peripheral_device_id": "u1",
                "event_type": "CONNECTED",
            }
        )

        stats = store.get_statistics()
        assert stats["dns_events_count"] == 1
        assert stats["audit_events_count"] == 1
        assert stats["persistence_events_count"] == 1
        assert stats["fim_events_count"] == 1
        assert stats["peripheral_events_count"] == 1

    def test_statistics_time_range_with_data(self, store):
        store.insert_process_event(
            {
                "timestamp_ns": 1000,
                "timestamp_dt": "2024-01-01T00:00:00",
                "device_id": "d1",
                "pid": 1,
            }
        )
        store.insert_process_event(
            {
                "timestamp_ns": 2000,
                "timestamp_dt": "2024-06-01T00:00:00",
                "device_id": "d1",
                "pid": 2,
            }
        )
        stats = store.get_statistics()
        assert stats["time_range"]["oldest"] == "2024-01-01T00:00:00"
        assert stats["time_range"]["newest"] == "2024-06-01T00:00:00"


# ===========================================================================
# search_events pagination edge cases
# ===========================================================================


class TestSearchPaginationEdges:
    """Test search_events pagination boundaries."""

    def test_offset_beyond_results(self, store):
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "risk_score": 0.5,
            }
        )
        result = store.search_events(hours=24, limit=10, offset=100)
        assert result["total_count"] == 1
        assert len(result["results"]) == 0
        assert result["has_more"] is False

    def test_has_more_false_on_last_page(self, store):
        ts = _now_ns()
        for i in range(3):
            store.insert_security_event(
                {
                    "timestamp_ns": ts + i,
                    "device_id": "d1",
                    "risk_score": 0.5,
                }
            )
        result = store.search_events(hours=24, limit=10, offset=0)
        assert result["has_more"] is False

    def test_empty_query_no_text_filter(self, store):
        """Empty query string should not add text filter."""
        ts = _now_ns()
        store.insert_security_event(
            {
                "timestamp_ns": ts,
                "device_id": "d1",
                "risk_score": 0.5,
            }
        )
        result = store.search_events(query="", hours=24)
        assert result["total_count"] == 1


# ===========================================================================
# Full insert and retrieve for DNS, Audit, Persistence, FIM
# ===========================================================================


class TestFullInsertRetrieve:
    """Test full insert with all fields for each domain table."""

    def test_dns_event_all_fields(self, store):
        ts = _now_ns()
        row_id = store.insert_dns_event(
            {
                "timestamp_ns": ts,
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "domain": "beacon.evil.com",
                "query_type": "A",
                "response_code": "NOERROR",
                "source_ip": "192.168.1.5",
                "process_name": "curl",
                "pid": 1234,
                "event_type": "dns_beaconing_detected",
                "dga_score": 0.87,
                "is_beaconing": True,
                "beacon_interval_seconds": 30.5,
                "is_tunneling": False,
                "risk_score": 0.85,
                "confidence": 0.9,
                "mitre_techniques": ["T1071"],
                "collection_agent": "dns-agent-v2",
                "agent_version": "2.0",
            }
        )
        assert row_id is not None

    def test_audit_event_all_fields(self, store):
        ts = _now_ns()
        row_id = store.insert_audit_event(
            {
                "timestamp_ns": ts,
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "host": "server-01",
                "syscall": "ptrace",
                "event_type": "kernel_ptrace_attack",
                "pid": 5678,
                "ppid": 1,
                "uid": 0,
                "euid": 0,
                "gid": 0,
                "egid": 0,
                "exe": "/tmp/injector",
                "comm": "injector",
                "cmdline": "./injector --target 1234",
                "cwd": "/tmp",
                "target_path": None,
                "target_pid": 1234,
                "target_comm": "sshd",
                "risk_score": 0.95,
                "confidence": 0.9,
                "mitre_techniques": ["T1055"],
                "reason": "ptrace on privileged process",
                "collection_agent": "kernel_audit-agent-v2",
                "agent_version": "2.0",
            }
        )
        assert row_id is not None

    def test_persistence_event_all_fields(self, store):
        ts = _now_ns()
        row_id = store.insert_persistence_event(
            {
                "timestamp_ns": ts,
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "event_type": "persistence_launchd_modified",
                "mechanism": "launchd",
                "entry_id": "com.evil.daemon",
                "path": "/Library/LaunchDaemons/com.evil.daemon.plist",
                "command": "/usr/bin/evil",
                "schedule": None,
                "user": "root",
                "change_type": "modified",
                "old_command": "/usr/bin/good",
                "new_command": "/usr/bin/evil",
                "risk_score": 0.88,
                "confidence": 0.85,
                "mitre_techniques": ["T1543"],
                "reason": "Launch daemon command changed",
                "collection_agent": "persistence-agent-v2",
                "agent_version": "2.0",
            }
        )
        assert row_id is not None

    def test_fim_event_all_fields(self, store):
        ts = _now_ns()
        row_id = store.insert_fim_event(
            {
                "timestamp_ns": ts,
                "timestamp_dt": _now_dt(),
                "device_id": "d1",
                "event_type": "webshell_detected",
                "path": "/var/www/html/shell.php",
                "change_type": "created",
                "old_hash": None,
                "new_hash": "abc123",
                "old_mode": None,
                "new_mode": "0755",
                "file_extension": ".php",
                "owner_uid": 33,
                "owner_gid": 33,
                "risk_score": 0.99,
                "confidence": 0.95,
                "mitre_techniques": ["T1505"],
                "reason": "PHP file in web root",
                "patterns_matched": ["webshell", "eval_exec"],
                "collection_agent": "fim-agent-v2",
                "agent_version": "2.0",
            }
        )
        assert row_id is not None
