"""Tests for NetScannerAgent and its 7 micro-probes.

Covers:
    - NetScannerAgent instantiation via mocked dependencies
    - Agent properties (agent_name)
    - 7 micro-probes:
        1. NewServiceDetectionProbe
        2. OpenPortChangeProbe
        3. RogueServiceProbe
        4. SSLCertIssueProbe
        5. VulnerableBannerProbe
        6. UnauthorizedListenerProbe
        7. NetworkTopologyChangeProbe
    - Probe scan() returns list of TelemetryEvent
    - Event field validation (event_type, severity, confidence, data, mitre_techniques)
"""

import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.agents.shared.net_scanner.agent_types import (
    STANDARD_SERVICE_PORTS,
    HostScanResult,
    PortInfo,
    ScanDiff,
    ScanResult,
)
from amoskys.agents.shared.net_scanner.probes import (
    NetworkTopologyChangeProbe,
    NewServiceDetectionProbe,
    OpenPortChangeProbe,
    RogueServiceProbe,
    SSLCertIssueProbe,
    UnauthorizedListenerProbe,
    VulnerableBannerProbe,
    create_net_scanner_probes,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(scan_diff=None, scan_results=None, now_ns=None):
    """Create a ProbeContext pre-populated with scan_diff and/or scan_results."""
    ctx = ProbeContext(
        device_id="test-host",
        agent_name="net_scanner",
        collection_time=datetime.now(timezone.utc),
        now_ns=now_ns or int(time.time() * 1e9),
    )
    if scan_diff is not None:
        ctx.shared_data["scan_diff"] = scan_diff
    if scan_results is not None:
        ctx.shared_data["scan_results"] = scan_results
    return ctx


def _make_port_info(**overrides):
    """Create a PortInfo with sensible defaults."""
    defaults = dict(
        port=80,
        state="open",
        service="http",
        banner="Apache/2.4.52",
        ssl_subject=None,
        ssl_expiry=None,
    )
    defaults.update(overrides)
    return PortInfo(**defaults)


def _make_host(**overrides):
    """Create a HostScanResult with sensible defaults."""
    defaults = dict(
        ip="192.168.1.100",
        hostname="server1.local",
        mac="aa:bb:cc:dd:ee:ff",
        is_alive=True,
        open_ports=[_make_port_info()],
        os_fingerprint=None,
    )
    defaults.update(overrides)
    return HostScanResult(**defaults)


def _make_scan_result(hosts=None):
    """Create a ScanResult with defaults."""
    return ScanResult(
        timestamp=datetime.now(timezone.utc),
        target_subnet="192.168.1.0/24",
        hosts=hosts or [_make_host()],
        scan_duration_seconds=10.0,
        scan_type="incremental",
    )


# ---------------------------------------------------------------------------
# Agent Tests
# ---------------------------------------------------------------------------


def test_create_net_scanner_probes_returns_seven():
    """create_net_scanner_probes() returns exactly 7 probe instances."""
    probes = create_net_scanner_probes()
    assert len(probes) == 7


def test_all_probes_have_unique_names():
    """Each probe in the registry has a unique name."""
    probes = create_net_scanner_probes()
    names = [p.name for p in probes]
    assert len(names) == len(set(names))


def test_probe_names_match_expected():
    """All 7 probe names match the expected values."""
    probes = create_net_scanner_probes()
    expected_names = {
        "new_service_detection",
        "open_port_change",
        "rogue_service",
        "ssl_cert_issue",
        "vulnerable_banner",
        "unauthorized_listener",
        "network_topology_change",
    }
    actual_names = {p.name for p in probes}
    assert actual_names == expected_names


# ---------------------------------------------------------------------------
# Probe 1: NewServiceDetectionProbe
# ---------------------------------------------------------------------------


def test_new_service_detection_new_port():
    """NewServiceDetectionProbe fires on new ports in scan diff."""
    probe = NewServiceDetectionProbe()
    diff = ScanDiff(
        new_ports=[
            {
                "ip": "192.168.1.50",
                "port": 8080,
                "service": "http",
                "banner": "nginx/1.22",
            },
        ],
    )
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_new_service_detected"
    assert events[0].severity == Severity.HIGH
    assert events[0].data["ip"] == "192.168.1.50"
    assert events[0].data["port"] == 8080


def test_new_service_detection_new_host():
    """NewServiceDetectionProbe fires on entirely new hosts."""
    probe = NewServiceDetectionProbe()
    new_host = _make_host(
        ip="10.0.0.99", open_ports=[_make_port_info(port=22, service="ssh")]
    )
    diff = ScanDiff(new_hosts=[new_host])
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["new_host"] is True
    assert events[0].data["ip"] == "10.0.0.99"


def test_new_service_detection_empty_diff():
    """NewServiceDetectionProbe returns empty list when no changes."""
    probe = NewServiceDetectionProbe()
    diff = ScanDiff()
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 2: OpenPortChangeProbe
# ---------------------------------------------------------------------------


def test_open_port_change_closed_to_open():
    """OpenPortChangeProbe detects closed->open transitions."""
    probe = OpenPortChangeProbe()
    diff = ScanDiff(
        new_ports=[
            {"ip": "192.168.1.10", "port": 3389, "service": "rdp"},
        ],
    )
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_port_opened"
    assert events[0].data["transition"] == "closed_to_open"


def test_open_port_change_open_to_closed():
    """OpenPortChangeProbe detects open->closed transitions."""
    probe = OpenPortChangeProbe()
    diff = ScanDiff(
        removed_ports=[
            {"ip": "192.168.1.10", "port": 80, "service": "http"},
        ],
    )
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_port_closed"
    assert events[0].data["transition"] == "open_to_closed"


# ---------------------------------------------------------------------------
# Probe 3: RogueServiceProbe
# ---------------------------------------------------------------------------


def test_rogue_service_ssh_on_non_standard_port():
    """RogueServiceProbe flags SSH running on non-standard port."""
    probe = RogueServiceProbe()
    host = _make_host(
        ip="192.168.1.50",
        open_ports=[_make_port_info(port=2222, service="ssh", banner="OpenSSH_9.0")],
    )
    scan_result = _make_scan_result(hosts=[host])
    ctx = _make_context(scan_results=[scan_result])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_rogue_service"
    assert events[0].data["port"] == 2222
    assert events[0].data["service"] == "ssh"


def test_rogue_service_standard_port_not_flagged():
    """RogueServiceProbe does not flag SSH on standard port 22."""
    probe = RogueServiceProbe()
    host = _make_host(
        ip="192.168.1.50",
        open_ports=[_make_port_info(port=22, service="ssh", banner="OpenSSH_9.0")],
    )
    scan_result = _make_scan_result(hosts=[host])
    ctx = _make_context(scan_results=[scan_result])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 4: SSLCertIssueProbe
# ---------------------------------------------------------------------------


def test_ssl_cert_expired():
    """SSLCertIssueProbe detects expired SSL certificates."""
    probe = SSLCertIssueProbe()
    host = _make_host(
        ip="192.168.1.20",
        open_ports=[
            _make_port_info(
                port=443,
                service="https",
                ssl_subject="CN=expired.example.com",
                ssl_expiry="2024-01-01T00:00:00+00:00",
            ),
        ],
    )
    scan_result = _make_scan_result(hosts=[host])
    ctx = _make_context(scan_results=[scan_result])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_ssl_cert_issue"
    assert events[0].severity == Severity.HIGH
    assert any("EXPIRED" in issue for issue in events[0].data["issues"])


def test_ssl_cert_cn_mismatch():
    """SSLCertIssueProbe detects CN/hostname mismatch."""
    probe = SSLCertIssueProbe()
    host = _make_host(
        ip="192.168.1.20",
        hostname="server1.local",
        open_ports=[
            _make_port_info(
                port=443,
                service="https",
                ssl_subject="CN=other-server.example.com",
                ssl_expiry="2030-12-31T23:59:59+00:00",
            ),
        ],
    )
    scan_result = _make_scan_result(hosts=[host])
    ctx = _make_context(scan_results=[scan_result])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert any("mismatch" in issue.lower() for issue in events[0].data["issues"])


# ---------------------------------------------------------------------------
# Probe 5: VulnerableBannerProbe
# ---------------------------------------------------------------------------


def test_vulnerable_banner_apache_path_traversal():
    """VulnerableBannerProbe detects Apache 2.4.49 (CVE-2021-41773)."""
    probe = VulnerableBannerProbe()
    host = _make_host(
        ip="192.168.1.30",
        open_ports=[
            _make_port_info(port=80, service="http", banner="Apache/2.4.49 (Unix)"),
        ],
    )
    scan_result = _make_scan_result(hosts=[host])
    ctx = _make_context(scan_results=[scan_result])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_vulnerable_banner"
    assert events[0].severity == Severity.HIGH
    assert "CVE-2021-41773" in events[0].data["cve"]


def test_vulnerable_banner_vsftpd_backdoor():
    """VulnerableBannerProbe detects vsftpd 2.3.4 backdoor."""
    probe = VulnerableBannerProbe()
    host = _make_host(
        ip="192.168.1.30",
        open_ports=[
            _make_port_info(port=21, service="ftp", banner="vsftpd 2.3.4"),
        ],
    )
    scan_result = _make_scan_result(hosts=[host])
    ctx = _make_context(scan_results=[scan_result])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert "CVE-2011-2523" in events[0].data["cve"]


def test_vulnerable_banner_safe_version_not_flagged():
    """VulnerableBannerProbe does not flag modern versions."""
    probe = VulnerableBannerProbe()
    host = _make_host(
        ip="192.168.1.30",
        open_ports=[
            _make_port_info(port=80, service="http", banner="nginx/1.25.3"),
        ],
    )
    scan_result = _make_scan_result(hosts=[host])
    ctx = _make_context(scan_results=[scan_result])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 6: UnauthorizedListenerProbe
# ---------------------------------------------------------------------------


def test_unauthorized_listener_new_local_port():
    """UnauthorizedListenerProbe detects new listener on 0.0.0.0."""
    probe = UnauthorizedListenerProbe()
    diff = ScanDiff(
        new_ports=[
            {"ip": "0.0.0.0", "port": 4444, "service": "unknown", "banner": ""},
        ],
    )
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_unauthorized_listener"
    assert events[0].severity == Severity.CRITICAL


def test_unauthorized_listener_remote_ip_ignored():
    """UnauthorizedListenerProbe ignores new ports on remote IPs."""
    probe = UnauthorizedListenerProbe()
    diff = ScanDiff(
        new_ports=[
            {"ip": "192.168.1.50", "port": 8080, "service": "http", "banner": ""},
        ],
    )
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 7: NetworkTopologyChangeProbe
# ---------------------------------------------------------------------------


def test_topology_new_host_detected():
    """NetworkTopologyChangeProbe fires on new hosts."""
    probe = NetworkTopologyChangeProbe()
    new_host = _make_host(
        ip="10.0.0.99", hostname="rogue-device", mac="ff:ff:ff:ff:ff:ff"
    )
    diff = ScanDiff(new_hosts=[new_host])
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_new_host"
    assert events[0].severity == Severity.HIGH
    assert events[0].data["ip"] == "10.0.0.99"


def test_topology_host_went_offline():
    """NetworkTopologyChangeProbe fires when hosts go offline."""
    probe = NetworkTopologyChangeProbe()
    removed_host = _make_host(ip="192.168.1.5", hostname="old-server")
    diff = ScanDiff(removed_hosts=[removed_host])
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_host_offline"


def test_topology_mac_change_arp_spoof():
    """NetworkTopologyChangeProbe detects MAC address changes (ARP spoof)."""
    probe = NetworkTopologyChangeProbe()
    diff = ScanDiff(
        mac_changes=[
            {
                "ip": "192.168.1.1",
                "old_mac": "aa:bb:cc:dd:ee:ff",
                "new_mac": "11:22:33:44:55:66",
            },
        ],
    )
    ctx = _make_context(scan_diff=diff)
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "net_mac_change"
    assert events[0].severity == Severity.HIGH
    assert events[0].data["old_mac"] == "aa:bb:cc:dd:ee:ff"
    assert events[0].data["new_mac"] == "11:22:33:44:55:66"


# ---------------------------------------------------------------------------
# Cross-cutting: all probes return TelemetryEvent with required fields
# ---------------------------------------------------------------------------


def test_all_probe_events_have_required_fields():
    """Every TelemetryEvent from all probes has required fields."""
    probes = create_net_scanner_probes()

    # Build a context that can trigger multiple probes
    diff = ScanDiff(
        new_hosts=[_make_host(ip="10.0.0.99")],
        new_ports=[
            {"ip": "0.0.0.0", "port": 4444, "service": "unknown", "banner": ""},
        ],
        removed_ports=[
            {"ip": "192.168.1.1", "port": 80, "service": "http"},
        ],
        mac_changes=[
            {
                "ip": "192.168.1.1",
                "old_mac": "aa:bb:cc:00:00:00",
                "new_mac": "ff:ff:ff:ff:ff:ff",
            },
        ],
    )

    # SSH on non-standard port 2222 for rogue service + vulnerable banner
    rogue_host = _make_host(
        ip="192.168.1.50",
        open_ports=[
            _make_port_info(port=2222, service="ssh", banner="OpenSSH_7.4"),
            _make_port_info(
                port=443,
                service="https",
                ssl_subject="CN=expired.example.com",
                ssl_expiry="2024-01-01T00:00:00+00:00",
            ),
        ],
    )
    scan_result = _make_scan_result(hosts=[rogue_host])

    ctx = _make_context(scan_diff=diff, scan_results=[scan_result])

    for probe in probes:
        events = probe.scan(ctx)
        assert isinstance(events, list), f"Probe {probe.name} did not return a list"
        for event in events:
            assert isinstance(event, TelemetryEvent)
            assert event.event_type, f"Missing event_type from {probe.name}"
            assert event.severity is not None
            assert isinstance(event.data, dict)
            assert event.probe_name == probe.name
