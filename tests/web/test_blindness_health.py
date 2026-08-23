from __future__ import annotations

import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "web"))

from amoskys.observability.blindness import record_blindness_event
from amoskys.observability.esf_authorization import inspect_esf_authorization
from app import create_app
from app.dashboard import routes_observatory


class _Store:
    def __init__(self, db):
        self.db = db


def _write_tcc_db(path, *, auth_value):
    _write_tcc_rows(
        path,
        [
            {
                "client": "com.amoskys.agent",
                "client_type": 0,
                "auth_value": auth_value,
                "last_modified": 1000,
            }
        ],
    )


def _write_tcc_rows(path, rows):
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE access (
            service TEXT,
            client TEXT,
            client_type INTEGER,
            auth_value INTEGER,
            auth_reason INTEGER,
            auth_version INTEGER,
            flags INTEGER,
            last_modified INTEGER
        )
        """
    )
    for row in rows:
        conn.execute(
            """
            INSERT INTO access (
                service, client, client_type, auth_value, auth_reason,
                auth_version, flags, last_modified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "kTCCServiceEndpointSecurityClient",
                row["client"],
                row.get("client_type", 0),
                row["auth_value"],
                row.get("auth_reason", 2),
                row.get("auth_version", 1),
                row.get("flags", 0),
                row.get("last_modified", 1000),
            ),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def app():
    os.environ["FLASK_DEBUG"] = "true"
    os.environ["FORCE_HTTPS"] = "false"
    os.environ["SECRET_KEY"] = "test-secret-key"
    result = create_app()
    app_instance = result[0] if isinstance(result, tuple) else result
    app_instance.config["TESTING"] = True
    app_instance.config["LOGIN_DISABLED"] = True
    return app_instance


@pytest.fixture
def client(app):
    return app.test_client()


def test_blindness_health_is_healthy_without_events(monkeypatch):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    monkeypatch.setattr(routes_observatory, "_blindness_db_paths", lambda: [])
    monkeypatch.setattr(
        routes_observatory, "inspect_esf_authorization", lambda **_: None
    )

    health = routes_observatory._collect_blindness_health(_Store(conn), 24, None)

    assert health["status"] == "healthy"
    assert health["active_count"] == 0
    assert health["events"] == []


def test_blindness_health_treats_unauthorized_sensor_as_blind(monkeypatch):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    record_blindness_event(
        conn,
        device_id="dev-1",
        sensor="amoskys_sentinel",
        kind="endpoint_security_tcc",
        status="unauthorized",
        reason="Endpoint Security TCC denied",
        evidence={"tcc_service": "kTCCServiceEndpointSecurityClient"},
        source="macos_sentinel",
        event_key="sentinel:dev-1:es-tcc",
    )
    monkeypatch.setattr(routes_observatory, "_blindness_db_paths", lambda: [])
    monkeypatch.setattr(
        routes_observatory, "inspect_esf_authorization", lambda **_: None
    )

    health = routes_observatory._collect_blindness_health(_Store(conn), 24, "dev-1")

    assert health["status"] == "blind"
    assert health["active_count"] == 1
    assert health["events"][0]["sensor"] == "amoskys_sentinel"
    assert health["events"][0]["status"] == "unauthorized"
    assert health["events"][0]["evidence"]["tcc_service"] == (
        "kTCCServiceEndpointSecurityClient"
    )


def test_health_blindness_route_surfaces_active_events(client, monkeypatch):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    record_blindness_event(
        conn,
        device_id="dev-1",
        sensor="igris:RESTART_AGENT",
        kind="action_budget_suppressed",
        status="degraded",
        reason="Suppressed by budget",
        evidence={"policy_decision": "suppressed_by_budget"},
        source="igris_brain",
        event_key="budget:dev-1:restart",
    )
    monkeypatch.setattr(routes_observatory, "_get_store", lambda: _Store(conn))
    monkeypatch.setattr(routes_observatory, "_blindness_db_paths", lambda: [])
    monkeypatch.setattr(
        routes_observatory, "inspect_esf_authorization", lambda **_: None
    )

    response = client.get("/dashboard/api/health/blindness")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "degraded"
    assert data["active_count"] == 1
    assert data["events"][0]["kind"] == "action_budget_suppressed"


def test_esf_authorization_probe_reports_tcc_denial(tmp_path):
    """A DENIED Endpoint Security grant is a blindness event.

    Passes an explicit tcc_db_paths. Without it the probe falls back to
    _DEFAULT_TCC_DB_PATHS — the REAL system TCC.db — and this test passed only
    because the developer's machine happened to hold a denial. The moment that
    grant was fixed the test broke, having asserted nothing about the code for
    as long as it was green. Its sibling had the identical defect; both are now
    hermetic.
    """
    log_path = tmp_path / "sentinel.log"
    binary_path = tmp_path / "amoskys-sentinel"
    tcc_path = tmp_path / "TCC.db"
    binary_path.write_text("#!/bin/sh\n")
    log_path.write_text("amoskys-sentinel: needs Full Disk Access (TCC)\n")
    _write_tcc_db(tcc_path, auth_value=0)

    event = inspect_esf_authorization(
        log_paths=[log_path],
        binary_path=binary_path,
        tcc_db_paths=[tcc_path],
        device_id="dev-1",
        now=1000.0,
    )

    assert event["status"] == "unauthorized"
    assert event["kind"] == "endpoint_security_tcc"
    assert event["sensor"] == "amoskys_sentinel"
    assert event["evidence"]["tcc_service"] == "kTCCServiceEndpointSecurityClient"


def test_esf_authorization_probe_healthy_sentinel_is_not_blind(tmp_path):
    """A healthy Sentinel is not a blindness event.

    Must pass an explicit tcc_db_paths. Without it the probe falls back to
    _DEFAULT_TCC_DB_PATHS — the REAL system TCC.db — so the result depended on
    the developer's machine. On a host where Endpoint Security is denied (which
    is the normal state until the grant is made by hand) this test failed while
    the code under test was behaving correctly.
    """
    log_path = tmp_path / "sentinel.log"
    binary_path = tmp_path / "amoskys-sentinel"
    tcc_path = tmp_path / "TCC.db"
    binary_path.write_text("#!/bin/sh\n")
    log_path.write_text("amoskys-sentinel: guarding exec (mode=MONITOR, fail-open).\n")
    _write_tcc_db(tcc_path, auth_value=2)  # granted

    event = inspect_esf_authorization(
        log_paths=[log_path],
        binary_path=binary_path,
        tcc_db_paths=[tcc_path],
        device_id="dev-1",
        now=1000.0,
    )

    assert event is None


def test_esf_authorization_probe_tcc_denial_overrides_stale_healthy_log(tmp_path):
    log_path = tmp_path / "sentinel.log"
    binary_path = tmp_path / "amoskys-sentinel"
    tcc_path = tmp_path / "TCC.db"
    binary_path.write_text("#!/bin/sh\n")
    log_path.write_text("amoskys-sentinel: guarding exec (mode=MONITOR, fail-open).\n")
    _write_tcc_db(tcc_path, auth_value=0)

    event = inspect_esf_authorization(
        log_paths=[log_path],
        binary_path=binary_path,
        tcc_db_paths=[tcc_path],
        tcc_clients=["com.amoskys.agent"],
        device_id="dev-1",
        now=1000.0,
    )

    assert event["status"] == "unauthorized"
    assert event["kind"] == "endpoint_security_tcc"
    assert event["evidence"]["tcc"]["authority"] == "tcc_db"
    assert event["evidence"]["tcc"]["state"] == "denied"


def test_esf_authorization_probe_bundle_denial_beats_newer_path_allow(tmp_path):
    log_path = tmp_path / "sentinel.log"
    app_path = tmp_path / "AmoskysSentinel.app"
    binary_path = app_path / "Contents" / "MacOS" / "amoskys-sentinel"
    tcc_path = tmp_path / "TCC.db"
    binary_path.parent.mkdir(parents=True)
    binary_path.write_text("#!/bin/sh\n")
    log_path.write_text("amoskys-sentinel: guarding exec (mode=MONITOR, fail-open).\n")
    _write_tcc_rows(
        tcc_path,
        [
            {
                "client": "com.amoskys.agent",
                "client_type": 0,
                "auth_value": 0,
                "last_modified": 1000,
            },
            {
                "client": str(binary_path),
                "client_type": 1,
                "auth_value": 2,
                "last_modified": 2000,
            },
        ],
    )

    event = inspect_esf_authorization(
        log_paths=[log_path],
        binary_path=binary_path,
        tcc_db_paths=[tcc_path],
        tcc_clients=["com.amoskys.agent", str(binary_path), str(app_path)],
        device_id="dev-1",
        now=1000.0,
    )

    assert event["status"] == "unauthorized"
    assert event["kind"] == "endpoint_security_tcc"
    assert event["evidence"]["tcc"]["client"] == "com.amoskys.agent"
    assert event["evidence"]["tcc"]["state"] == "denied"
    assert event["evidence"]["tcc"]["conflict"] is True
    assert event["evidence"]["tcc"]["states_seen"] == ["allowed", "denied"]


def test_esf_authorization_probe_tcc_allow_does_not_swallow_runtime_denial_log(
    tmp_path,
):
    log_path = tmp_path / "sentinel.log"
    binary_path = tmp_path / "amoskys-sentinel"
    tcc_path = tmp_path / "TCC.db"
    binary_path.write_text("#!/bin/sh\n")
    log_path.write_text("amoskys-sentinel: needs Full Disk Access (TCC)\n")
    _write_tcc_db(tcc_path, auth_value=2)

    event = inspect_esf_authorization(
        log_paths=[log_path],
        binary_path=binary_path,
        tcc_db_paths=[tcc_path],
        tcc_clients=["com.amoskys.agent"],
        device_id="dev-1",
        now=1000.0,
    )

    assert event["status"] == "unauthorized"
    # kind is endpoint_security_FDA, not _tcc: the log line says "needs Full
    # Disk Access", and FDA is a different TCC service from the Endpoint
    # Security client grant. Reporting an ESF denial here sent anyone debugging
    # it at the wrong grant entirely — on the dev machine the ESF grant was
    # present and FDA was the actual blocker. The intent of this test is
    # unchanged and still enforced: a TCC allow must NOT swallow a runtime
    # denial log. Only the label is more precise.
    assert event["kind"] == "endpoint_security_not_permitted"
    assert event["evidence"]["tcc"]["state"] == "allowed"


def test_health_blindness_route_merges_live_esf_authorization_event(
    client, monkeypatch
):
    monkeypatch.setattr(routes_observatory, "_get_store", lambda: None)
    monkeypatch.setattr(routes_observatory, "_blindness_db_paths", lambda: [])
    monkeypatch.setattr(
        routes_observatory,
        "inspect_esf_authorization",
        lambda device_id=None: {
            "event_key": "sentinel:dev-1:es-tcc",
            "device_id": device_id or "dev-1",
            "sensor": "amoskys_sentinel",
            "kind": "endpoint_security_tcc",
            "status": "unauthorized",
            "reason": "Endpoint Security TCC denied",
            "since": 1000.0,
            "last_seen": 1000.0,
            "evidence": {"tcc_service": "kTCCServiceEndpointSecurityClient"},
            "source": "local_esf_authorization_probe",
            "active": True,
            "count": 1,
        },
    )

    response = client.get("/dashboard/api/health/blindness?device_id=dev-1")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "blind"
    assert data["active_count"] == 1
    assert data["events"][0]["sensor"] == "amoskys_sentinel"
    assert data["events"][0]["status"] == "unauthorized"
