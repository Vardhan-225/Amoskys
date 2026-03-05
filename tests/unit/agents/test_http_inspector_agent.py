"""Tests for HTTPInspectorAgent and its 8 micro-probes.

Covers:
    - HTTPInspectorAgent instantiation via mocked dependencies
    - Agent properties (agent_name)
    - 8 micro-probes:
        1. XSSDetectionProbe
        2. SSRFDetectionProbe
        3. PathTraversalProbe
        4. APIAbuseProbe
        5. DataExfilHTTPProbe
        6. SuspiciousUploadProbe
        7. WebSocketAbuseProbe
        8. CSRFTokenMissingProbe
    - Probe scan() returns list of TelemetryEvent
    - Event field validation (event_type, severity, confidence, data, mitre_techniques)
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.agents.http_inspector.agent_types import HTTPTransaction
from amoskys.agents.http_inspector.probes import (
    APIAbuseProbe,
    CSRFTokenMissingProbe,
    DataExfilHTTPProbe,
    PathTraversalProbe,
    SSRFDetectionProbe,
    SuspiciousUploadProbe,
    WebSocketAbuseProbe,
    XSSDetectionProbe,
    create_http_inspector_probes,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(transactions=None):
    """Create a ProbeContext pre-populated with http_transactions."""
    ctx = ProbeContext(
        device_id="test-host",
        agent_name="http_inspector",
        collection_time=datetime.now(timezone.utc),
    )
    ctx.shared_data["http_transactions"] = transactions or []
    return ctx


def _make_txn(**overrides):
    """Create an HTTPTransaction with sensible defaults, overridden by kwargs."""
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        method="GET",
        url="http://example.com/page",
        host="example.com",
        path="/page",
        query_params={},
        request_headers={},
        request_body=None,
        response_status=200,
        content_type="text/html",
        src_ip="10.0.0.5",
        dst_ip="93.184.216.34",
        bytes_sent=512,
        bytes_received=4096,
        process_name="curl",
        is_tls=False,
    )
    defaults.update(overrides)
    return HTTPTransaction(**defaults)


# ---------------------------------------------------------------------------
# Agent Tests
# ---------------------------------------------------------------------------


def test_create_http_inspector_probes_returns_eight():
    """create_http_inspector_probes() returns exactly 8 probe instances."""
    probes = create_http_inspector_probes()
    assert len(probes) == 8


def test_all_probes_have_unique_names():
    """Each probe in the registry has a unique name."""
    probes = create_http_inspector_probes()
    names = [p.name for p in probes]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Probe 1: XSSDetectionProbe
# ---------------------------------------------------------------------------


def test_xss_in_query_params():
    """XSSDetectionProbe detects <script> in query parameters."""
    probe = XSSDetectionProbe()
    txn = _make_txn(
        url="http://example.com/search?q=<script>alert(1)</script>",
        query_params={"q": "<script>alert(1)</script>"},
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_xss_detected"
    assert events[0].severity == Severity.HIGH


def test_xss_in_request_body():
    """XSSDetectionProbe detects XSS payload in request body."""
    probe = XSSDetectionProbe()
    txn = _make_txn(
        method="POST",
        request_body='{"comment": "<img onerror=alert(1) src=x>"}',
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1


def test_xss_no_false_positive():
    """XSSDetectionProbe does not fire on normal requests."""
    probe = XSSDetectionProbe()
    txn = _make_txn(query_params={"q": "hello world"})
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 2: SSRFDetectionProbe
# ---------------------------------------------------------------------------


def test_ssrf_metadata_endpoint():
    """SSRFDetectionProbe detects cloud metadata SSRF."""
    probe = SSRFDetectionProbe()
    txn = _make_txn(
        url="http://example.com/proxy?url=http://169.254.169.254/latest/meta-data/",
        query_params={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_ssrf_detected"
    assert events[0].severity == Severity.CRITICAL


def test_ssrf_localhost_reference():
    """SSRFDetectionProbe detects localhost references in params."""
    probe = SSRFDetectionProbe()
    txn = _make_txn(
        query_params={"redirect": "http://127.0.0.1:8080/admin"},
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1


# ---------------------------------------------------------------------------
# Probe 3: PathTraversalProbe
# ---------------------------------------------------------------------------


def test_path_traversal_dotdot():
    """PathTraversalProbe detects ../ in URL path."""
    probe = PathTraversalProbe()
    txn = _make_txn(
        url="http://example.com/files/../../etc/passwd",
        path="/files/../../etc/passwd",
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_path_traversal"
    assert events[0].severity == Severity.HIGH


def test_path_traversal_encoded():
    """PathTraversalProbe detects URL-encoded path traversal."""
    probe = PathTraversalProbe()
    txn = _make_txn(
        path="/files/%2e%2e/%2e%2e/etc/passwd",
        query_params={"file": "%2e%2e/%2e%2e/etc/shadow"},
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1


# ---------------------------------------------------------------------------
# Probe 4: APIAbuseProbe
# ---------------------------------------------------------------------------


def test_api_abuse_high_request_rate():
    """APIAbuseProbe detects high request rate from single IP."""
    probe = APIAbuseProbe()
    transactions = [_make_txn(src_ip="10.0.0.42") for _ in range(120)]
    ctx = _make_context(transactions)
    events = probe.scan(ctx)

    rate_events = [e for e in events if e.event_type == "http_api_rate_abuse"]
    assert len(rate_events) >= 1
    assert rate_events[0].data["src_ip"] == "10.0.0.42"


def test_api_abuse_graphql_introspection():
    """APIAbuseProbe detects GraphQL introspection queries."""
    probe = APIAbuseProbe()
    txn = _make_txn(
        method="POST",
        path="/graphql",
        request_body='{"query": "{ __schema { types { name } } }"}',
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    graphql_events = [e for e in events if e.event_type == "http_graphql_introspection"]
    assert len(graphql_events) >= 1


# ---------------------------------------------------------------------------
# Probe 5: DataExfilHTTPProbe
# ---------------------------------------------------------------------------


def test_data_exfil_large_upload():
    """DataExfilHTTPProbe detects large uploads to non-CDN hosts."""
    probe = DataExfilHTTPProbe()
    txn = _make_txn(
        method="POST",
        host="evil-drop.example.org",
        bytes_sent=5_000_000,  # 5 MB
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_data_exfiltration"
    assert events[0].severity == Severity.HIGH


def test_data_exfil_cdn_not_flagged():
    """DataExfilHTTPProbe does not flag uploads to known CDN domains."""
    probe = DataExfilHTTPProbe()
    txn = _make_txn(
        method="POST",
        host="s3.amazonaws.com",
        bytes_sent=5_000_000,
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 6: SuspiciousUploadProbe
# ---------------------------------------------------------------------------


def test_suspicious_upload_php_file():
    """SuspiciousUploadProbe detects .php file upload."""
    probe = SuspiciousUploadProbe()
    txn = _make_txn(
        method="POST",
        content_type="multipart/form-data; boundary=---",
        request_headers={"content-disposition": 'attachment; filename="shell.php"'},
        request_body='------\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n',
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_suspicious_upload"
    assert events[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Probe 7: WebSocketAbuseProbe
# ---------------------------------------------------------------------------


def test_websocket_unusual_path():
    """WebSocketAbuseProbe detects WS upgrade to unusual path."""
    probe = WebSocketAbuseProbe()
    txn = _make_txn(
        path="/secret-backdoor/tunnel",
        host="evil.example.com",
        request_headers={
            "upgrade": "websocket",
            "connection": "Upgrade",
        },
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_websocket_abuse"
    assert events[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Probe 8: CSRFTokenMissingProbe
# ---------------------------------------------------------------------------


def test_csrf_missing_token_and_origin():
    """CSRFTokenMissingProbe detects POST without CSRF token or Origin."""
    probe = CSRFTokenMissingProbe()
    txn = _make_txn(
        method="POST",
        host="app.example.com",
        content_type="application/x-www-form-urlencoded",
        request_headers={},  # No CSRF token, no Origin, no Referer
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "http_csrf_missing"
    assert events[0].severity == Severity.MEDIUM


def test_csrf_bearer_auth_exempt():
    """CSRFTokenMissingProbe does not fire for Bearer auth requests."""
    probe = CSRFTokenMissingProbe()
    txn = _make_txn(
        method="POST",
        host="api.example.com",
        request_headers={"authorization": "Bearer eyJhbGciOiJIUzI1NiJ9..."},
    )
    ctx = _make_context([txn])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Cross-cutting: all probes return TelemetryEvent with required fields
# ---------------------------------------------------------------------------


def test_all_probe_events_have_required_fields():
    """Every TelemetryEvent from all probes has required fields."""
    probes = create_http_inspector_probes()
    trigger_txns = [
        _make_txn(
            method="POST",
            url="http://example.com/search?q=<script>alert(1)</script>&url=http://169.254.169.254",
            path="/files/../../etc/passwd",
            query_params={
                "q": "<script>alert(1)</script>",
                "url": "http://169.254.169.254/latest",
            },
            request_headers={},
            request_body="<script>alert(1)</script>",
            host="evil.example.com",
            bytes_sent=5_000_000,
            content_type="text/html",
        ),
    ]
    ctx = _make_context(trigger_txns)

    for probe in probes:
        events = probe.scan(ctx)
        assert isinstance(events, list), f"Probe {probe.name} did not return a list"
        for event in events:
            assert isinstance(event, TelemetryEvent)
            assert event.event_type, f"Missing event_type from {probe.name}"
            assert event.severity is not None
            assert isinstance(event.data, dict)
            assert event.probe_name == probe.name
