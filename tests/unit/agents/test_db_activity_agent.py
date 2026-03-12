"""Tests for DBActivityAgent and its 8 micro-probes.

Covers:
    - DBActivityAgent instantiation via mocked dependencies
    - Agent properties (agent_name)
    - 8 micro-probes:
        1. PrivilegeEscalationQueryProbe
        2. BulkDataExtractionProbe
        3. SchemaEnumerationProbe
        4. StoredProcAbuseProbe
        5. CredentialQueryProbe
        6. SQLInjectionPayloadProbe
        7. UnauthorizedDBAccessProbe
        8. DatabaseDDLChangeProbe
    - Probe scan() returns list of TelemetryEvent
    - Event field validation (event_type, severity, confidence, data, mitre_techniques)
"""

import pytest  # noqa: E402

pytest.skip(
    "macOS Observatory v2 uses different probe class names (no StoredProcAbuseProbe, DatabaseDDLChangeProbe, SQLInjectionPayloadProbe in new API)",
    allow_module_level=True,
)


from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.agents.os.macos.db_activity.agent_types import DatabaseQuery
from amoskys.agents.os.macos.db_activity.probes import (
    BulkDataExtractionProbe,
    CredentialQueryProbe,
    DatabaseDDLChangeProbe,
    PrivilegeEscalationQueryProbe,
    SchemaEnumerationProbe,
    SQLInjectionPayloadProbe,
    StoredProcAbuseProbe,
    UnauthorizedDBAccessProbe,
    create_db_activity_probes,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(queries=None):
    """Create a ProbeContext pre-populated with database_queries."""
    ctx = ProbeContext(
        device_id="test-host",
        agent_name="db_activity",
        collection_time=datetime.now(timezone.utc),
    )
    ctx.shared_data["database_queries"] = queries or []
    return ctx


def _make_query(**overrides):
    """Create a DatabaseQuery with sensible defaults, overridden by kwargs."""
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        db_type="postgresql",
        database_name="appdb",
        query_text="SELECT 1",
        query_type="SELECT",
        user="app_user",
        source_ip="10.0.0.5",
        rows_affected=None,
        execution_time_ms=None,
        process_name="postgres",
        file_path="/var/log/postgresql/postgresql.log",
    )
    defaults.update(overrides)
    return DatabaseQuery(**defaults)


# ---------------------------------------------------------------------------
# Agent Tests
# ---------------------------------------------------------------------------


def test_create_db_activity_probes_returns_eight():
    """create_db_activity_probes() returns exactly 8 probe instances."""
    probes = create_db_activity_probes()
    assert len(probes) == 8


def test_all_probes_have_unique_names():
    """Each probe in the registry has a unique name."""
    probes = create_db_activity_probes()
    names = [p.name for p in probes]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Probe 1: PrivilegeEscalationQueryProbe
# ---------------------------------------------------------------------------


def test_privesc_grant_all():
    """PrivilegeEscalationQueryProbe detects GRANT ALL queries."""
    probe = PrivilegeEscalationQueryProbe()
    query = _make_query(
        query_text="GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'",
        query_type="DCL",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "db_privilege_escalation"
    assert events[0].severity == Severity.CRITICAL
    assert events[0].data["pattern_type"] == "grant_all"


def test_privesc_create_role():
    """PrivilegeEscalationQueryProbe detects CREATE USER."""
    probe = PrivilegeEscalationQueryProbe()
    query = _make_query(
        query_text="CREATE USER 'backdoor'@'%' IDENTIFIED BY 'pass123'",
        query_type="DDL",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["pattern_type"] == "create_role"


# ---------------------------------------------------------------------------
# Probe 2: BulkDataExtractionProbe
# ---------------------------------------------------------------------------


def test_bulk_extraction_select_star_no_where():
    """BulkDataExtractionProbe detects SELECT * without WHERE."""
    probe = BulkDataExtractionProbe()
    query = _make_query(query_text="SELECT * FROM customers")
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "bulk_data_extraction"
    assert events[0].data["pattern_type"] == "select_star_no_where"


def test_bulk_extraction_with_where_no_alert():
    """BulkDataExtractionProbe does not fire on SELECT * with WHERE."""
    probe = BulkDataExtractionProbe()
    query = _make_query(query_text="SELECT * FROM customers WHERE id = 1")
    ctx = _make_context([query])
    events = probe.scan(ctx)

    # Should not match select_star_no_where because WHERE is present
    select_star_events = [
        e for e in events if e.data.get("pattern_type") == "select_star_no_where"
    ]
    assert len(select_star_events) == 0


def test_bulk_extraction_into_outfile():
    """BulkDataExtractionProbe detects INTO OUTFILE."""
    probe = BulkDataExtractionProbe()
    query = _make_query(query_text="SELECT * FROM users INTO OUTFILE '/tmp/dump.csv'")
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1


# ---------------------------------------------------------------------------
# Probe 3: SchemaEnumerationProbe
# ---------------------------------------------------------------------------


def test_schema_enumeration_burst():
    """SchemaEnumerationProbe fires on information_schema query bursts."""
    probe = SchemaEnumerationProbe()
    queries = [
        _make_query(
            query_text=f"SELECT * FROM information_schema.tables WHERE table_schema = 'db{i}'",
            user="attacker",
            source_ip="10.0.0.99",
        )
        for i in range(10)
    ]
    ctx = _make_context(queries)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "schema_enumeration_burst"
    assert events[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Probe 4: StoredProcAbuseProbe
# ---------------------------------------------------------------------------


def test_stored_proc_xp_cmdshell():
    """StoredProcAbuseProbe detects xp_cmdshell usage."""
    probe = StoredProcAbuseProbe()
    query = _make_query(
        query_text="EXEC xp_cmdshell 'whoami'",
        db_type="mssql",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "stored_proc_abuse"
    assert events[0].severity == Severity.CRITICAL
    assert events[0].data["pattern_type"] == "xp_cmdshell"


def test_stored_proc_load_data_infile():
    """StoredProcAbuseProbe detects LOAD DATA INFILE."""
    probe = StoredProcAbuseProbe()
    query = _make_query(
        query_text="LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE leaked",
        db_type="mysql",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["pattern_type"] == "load_data_infile"


# ---------------------------------------------------------------------------
# Probe 5: CredentialQueryProbe
# ---------------------------------------------------------------------------


def test_credential_query_users_table():
    """CredentialQueryProbe detects SELECT on users table."""
    probe = CredentialQueryProbe()
    query = _make_query(
        query_text="SELECT password, salt FROM users WHERE username = 'admin'",
        query_type="SELECT",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "credential_table_query"
    assert events[0].severity == Severity.HIGH


def test_credential_query_non_select_ignored():
    """CredentialQueryProbe ignores non-SELECT queries."""
    probe = CredentialQueryProbe()
    query = _make_query(
        query_text="INSERT INTO users (username, password) VALUES ('x', 'y')",
        query_type="INSERT",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 6: SQLInjectionPayloadProbe
# ---------------------------------------------------------------------------


def test_sqli_union_select():
    """SQLInjectionPayloadProbe detects UNION SELECT."""
    probe = SQLInjectionPayloadProbe()
    query = _make_query(
        query_text="SELECT * FROM products WHERE id=1 UNION SELECT username, password FROM users",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "sql_injection_detected"
    assert events[0].severity == Severity.CRITICAL
    assert events[0].data["pattern_type"] == "union_select"


def test_sqli_sleep_injection():
    """SQLInjectionPayloadProbe detects SLEEP() blind injection."""
    probe = SQLInjectionPayloadProbe()
    query = _make_query(
        query_text="SELECT * FROM users WHERE id=1 AND SLEEP(5)",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["pattern_type"] == "sleep_injection"


def test_sqli_or_always_true():
    """SQLInjectionPayloadProbe detects OR 1=1."""
    probe = SQLInjectionPayloadProbe()
    query = _make_query(
        query_text="SELECT * FROM users WHERE username='admin' OR 1=1",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["pattern_type"] == "or_always_true"


# ---------------------------------------------------------------------------
# Probe 7: UnauthorizedDBAccessProbe
# ---------------------------------------------------------------------------


def test_unauthorized_access_new_combo_after_warmup():
    """UnauthorizedDBAccessProbe detects new user+ip combos after warmup."""
    probe = UnauthorizedDBAccessProbe()

    # Build baseline during warmup (WARMUP_CYCLES = 3)
    baseline_queries = [
        _make_query(user=f"user{i}", source_ip=f"10.0.0.{i}") for i in range(10)
    ]
    for _ in range(3):
        ctx = _make_context(baseline_queries)
        probe.scan(ctx)

    # Now introduce an unknown combo
    new_query = _make_query(user="unknown_attacker", source_ip="192.168.1.100")
    ctx = _make_context([new_query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "unauthorized_db_access"
    assert events[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Probe 8: DatabaseDDLChangeProbe
# ---------------------------------------------------------------------------


def test_ddl_drop_database():
    """DatabaseDDLChangeProbe detects DROP DATABASE."""
    probe = DatabaseDDLChangeProbe()
    query = _make_query(
        query_text="DROP DATABASE production",
        query_type="DDL",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "database_ddl_change"
    assert events[0].severity == Severity.CRITICAL
    assert events[0].data["operation"] == "drop_database"


def test_ddl_truncate_table():
    """DatabaseDDLChangeProbe detects TRUNCATE TABLE."""
    probe = DatabaseDDLChangeProbe()
    query = _make_query(
        query_text="TRUNCATE TABLE audit_logs",
        query_type="DDL",
    )
    ctx = _make_context([query])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["operation"] == "truncate_table"


# ---------------------------------------------------------------------------
# Cross-cutting: all probes return TelemetryEvent with required fields
# ---------------------------------------------------------------------------


def test_all_probe_events_have_required_fields():
    """Every TelemetryEvent from all probes has required fields."""
    probes = create_db_activity_probes()
    trigger_queries = [
        _make_query(
            query_text="GRANT ALL ON *.* TO 'x'@'%'; UNION SELECT password FROM users; xp_cmdshell 'id'; DROP DATABASE prod",
            query_type="DCL",
            user="attacker",
            source_ip="10.0.0.99",
        ),
    ]
    ctx = _make_context(trigger_queries)

    for probe in probes:
        events = probe.scan(ctx)
        assert isinstance(events, list), f"Probe {probe.name} did not return a list"
        for event in events:
            assert isinstance(event, TelemetryEvent)
            assert event.event_type, f"Missing event_type from {probe.name}"
            assert event.severity is not None
            assert isinstance(event.data, dict)
            assert event.probe_name == probe.name
