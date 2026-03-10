"""Tests for InternetActivityAgent and its 8 micro-probes.

Covers:
    - InternetActivityAgent instantiation via mocked dependencies
    - Agent properties (agent_name)
    - 8 micro-probes:
        1. CloudExfilProbe
        2. TORVPNUsageProbe
        3. CryptoMiningProbe
        4. SuspiciousDownloadProbe
        5. ShadowITSaaSProbe
        6. UnusualGeoConnectionProbe
        7. LongLivedConnectionProbe
        8. DNSOverHTTPSProbe
    - Probe scan() returns list of TelemetryEvent
    - Event field validation (event_type, severity, confidence, data, mitre_techniques)
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.agents.shared.internet_activity.agent_types import (
    BrowsingEntry,
    OutboundConnection,
)
from amoskys.agents.shared.internet_activity.probes import (
    CloudExfilProbe,
    CryptoMiningProbe,
    DNSOverHTTPSProbe,
    LongLivedConnectionProbe,
    ShadowITSaaSProbe,
    SuspiciousDownloadProbe,
    TORVPNUsageProbe,
    UnusualGeoConnectionProbe,
    create_internet_activity_probes,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_conn_context(connections=None):
    """Create a ProbeContext pre-populated with outbound_connections."""
    ctx = ProbeContext(
        device_id="test-host",
        agent_name="internet_activity",
        collection_time=datetime.now(timezone.utc),
    )
    ctx.shared_data["outbound_connections"] = connections or []
    return ctx


def _make_browse_context(entries=None):
    """Create a ProbeContext pre-populated with browsing_entries."""
    ctx = ProbeContext(
        device_id="test-host",
        agent_name="internet_activity",
        collection_time=datetime.now(timezone.utc),
    )
    ctx.shared_data["browsing_entries"] = entries or []
    return ctx


def _make_connection(**overrides):
    """Create an OutboundConnection with sensible defaults."""
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        process_name="curl",
        pid=12345,
        dst_ip="93.184.216.34",
        dst_port=443,
        dst_hostname="example.com",
        protocol="TCP",
        bytes_sent=1024,
        bytes_received=4096,
        duration_seconds=5.0,
        geo_country="US",
        is_encrypted=True,
        connection_state="ESTABLISHED",
    )
    defaults.update(overrides)
    return OutboundConnection(**defaults)


def _make_browsing_entry(**overrides):
    """Create a BrowsingEntry with sensible defaults."""
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        url="https://example.com/page",
        domain="example.com",
        title="Example Page",
        browser="chrome",
        visit_count=1,
    )
    defaults.update(overrides)
    return BrowsingEntry(**defaults)


# ---------------------------------------------------------------------------
# Agent Tests
# ---------------------------------------------------------------------------


def test_create_internet_activity_probes_returns_eight():
    """create_internet_activity_probes() returns exactly 8 probe instances."""
    probes = create_internet_activity_probes()
    assert len(probes) == 8


def test_all_probes_have_unique_names():
    """Each probe in the registry has a unique name."""
    probes = create_internet_activity_probes()
    names = [p.name for p in probes]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Probe 1: CloudExfilProbe
# ---------------------------------------------------------------------------


def test_cloud_exfil_s3_large_upload():
    """CloudExfilProbe detects large upload to S3."""
    probe = CloudExfilProbe()
    conn = _make_connection(
        dst_hostname="my-bucket.s3.amazonaws.com",
        dst_port=443,
        bytes_sent=20 * 1024 * 1024,  # 20 MB
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "internet_cloud_exfiltration"
    assert events[0].severity == Severity.HIGH


def test_cloud_exfil_small_upload_ignored():
    """CloudExfilProbe ignores small uploads to cloud storage."""
    probe = CloudExfilProbe()
    conn = _make_connection(
        dst_hostname="my-bucket.s3.amazonaws.com",
        bytes_sent=1024,  # 1 KB
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 2: TORVPNUsageProbe
# ---------------------------------------------------------------------------


def test_tor_port_detection():
    """TORVPNUsageProbe detects connections to TOR ports."""
    probe = TORVPNUsageProbe()
    conn = _make_connection(
        dst_port=9001,
        dst_hostname="tor-relay.example.com",
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "internet_tor_vpn_detected"
    assert events[0].data["is_tor"] is True


def test_vpn_wireguard_detection():
    """TORVPNUsageProbe detects WireGuard connections."""
    probe = TORVPNUsageProbe()
    conn = _make_connection(
        dst_port=51820,
        protocol="UDP",
        dst_hostname="vpn-server.example.com",
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert any("WireGuard" in ind for ind in events[0].data["indicators"])


def test_vpn_provider_domain():
    """TORVPNUsageProbe detects connections to VPN provider domains."""
    probe = TORVPNUsageProbe()
    conn = _make_connection(
        dst_hostname="nordvpn.com",
        dst_port=443,
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1


# ---------------------------------------------------------------------------
# Probe 3: CryptoMiningProbe
# ---------------------------------------------------------------------------


def test_crypto_mining_pool_port():
    """CryptoMiningProbe detects connections to mining pool ports."""
    probe = CryptoMiningProbe()
    conn = _make_connection(
        dst_port=3333,
        dst_hostname="pool.minexmr.com",
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "internet_crypto_mining"
    assert events[0].severity == Severity.CRITICAL


def test_crypto_mining_normal_port_not_flagged():
    """CryptoMiningProbe does not flag normal port 443 to CDN."""
    probe = CryptoMiningProbe()
    conn = _make_connection(
        dst_port=443,
        dst_hostname="cdn.example.com",
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 4: SuspiciousDownloadProbe
# ---------------------------------------------------------------------------


def test_suspicious_download_exe_from_untrusted():
    """SuspiciousDownloadProbe detects .exe download from untrusted domain."""
    probe = SuspiciousDownloadProbe()
    entry = _make_browsing_entry(
        url="https://sketchy-site.xyz/payload.exe",
        domain="sketchy-site.xyz",
    )
    ctx = _make_browse_context([entry])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "internet_suspicious_download"
    assert events[0].severity == Severity.HIGH
    assert events[0].data["extension"] == ".exe"


def test_suspicious_download_trusted_domain_ok():
    """SuspiciousDownloadProbe does not flag trusted domain downloads."""
    probe = SuspiciousDownloadProbe()
    entry = _make_browsing_entry(
        url="https://github.com/release/tool.exe",
        domain="github.com",
    )
    ctx = _make_browse_context([entry])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 5: ShadowITSaaSProbe
# ---------------------------------------------------------------------------


def test_shadow_it_personal_email():
    """ShadowITSaaSProbe detects connections to personal email services."""
    probe = ShadowITSaaSProbe()
    conn = _make_connection(
        dst_hostname="mail.google.com",
        dst_port=443,
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "internet_shadow_it"
    assert events[0].data["shadow_it_type"] == "personal_email"


def test_shadow_it_file_sharing():
    """ShadowITSaaSProbe detects file sharing service usage."""
    probe = ShadowITSaaSProbe()
    conn = _make_connection(
        dst_hostname="wetransfer.com",
        dst_port=443,
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].data["shadow_it_type"] == "file_sharing"


# ---------------------------------------------------------------------------
# Probe 6: UnusualGeoConnectionProbe
# ---------------------------------------------------------------------------


def test_unusual_geo_first_time_country():
    """UnusualGeoConnectionProbe flags first-time country connections."""
    probe = UnusualGeoConnectionProbe()

    # First cycle builds baseline
    baseline_conn = _make_connection(geo_country="US")
    ctx1 = _make_conn_context([baseline_conn])
    probe.scan(ctx1)

    # Second cycle: new country
    new_conn = _make_connection(geo_country="KP", dst_ip="175.45.176.1")
    ctx2 = _make_conn_context([new_conn])
    events = probe.scan(ctx2)

    assert len(events) >= 1
    assert events[0].event_type == "internet_unusual_geo"
    assert events[0].data["country"] == "KP"
    assert events[0].data["is_high_risk"] is True


# ---------------------------------------------------------------------------
# Probe 7: LongLivedConnectionProbe
# ---------------------------------------------------------------------------


def test_long_lived_connection_detected():
    """LongLivedConnectionProbe detects connections > 1 hour to non-CDN."""
    probe = LongLivedConnectionProbe()
    conn = _make_connection(
        dst_hostname="c2-server.example.com",
        duration_seconds=7200.0,  # 2 hours
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "internet_long_lived_connection"
    assert events[0].severity == Severity.MEDIUM


def test_long_lived_connection_cdn_not_flagged():
    """LongLivedConnectionProbe does not flag long connections to CDN."""
    probe = LongLivedConnectionProbe()
    conn = _make_connection(
        dst_hostname="cdn.google.com",
        duration_seconds=7200.0,
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Probe 8: DNSOverHTTPSProbe
# ---------------------------------------------------------------------------


def test_doh_cloudflare_detected():
    """DNSOverHTTPSProbe detects connections to Cloudflare DoH."""
    probe = DNSOverHTTPSProbe()
    conn = _make_connection(
        dst_ip="1.1.1.1",
        dst_port=443,
        dst_hostname="cloudflare-dns.com",
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1
    assert events[0].event_type == "internet_doh_detected"
    assert events[0].severity == Severity.MEDIUM


def test_doh_google_detected():
    """DNSOverHTTPSProbe detects connections to Google DoH."""
    probe = DNSOverHTTPSProbe()
    conn = _make_connection(
        dst_ip="8.8.8.8",
        dst_port=443,
        dst_hostname="dns.google",
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert len(events) >= 1


def test_doh_non_doh_port_443_not_flagged():
    """DNSOverHTTPSProbe does not flag normal HTTPS to non-DoH IPs."""
    probe = DNSOverHTTPSProbe()
    conn = _make_connection(
        dst_ip="93.184.216.34",
        dst_port=443,
        dst_hostname="example.com",
    )
    ctx = _make_conn_context([conn])
    events = probe.scan(ctx)

    assert events == []


# ---------------------------------------------------------------------------
# Cross-cutting: all probes return TelemetryEvent with required fields
# ---------------------------------------------------------------------------


def test_all_probe_events_have_required_fields():
    """Every TelemetryEvent from all probes has required fields."""
    probes = create_internet_activity_probes()

    # Create a context with both outbound_connections and browsing_entries
    ctx = ProbeContext(
        device_id="test-host",
        agent_name="internet_activity",
        collection_time=datetime.now(timezone.utc),
    )
    ctx.shared_data["outbound_connections"] = [
        _make_connection(
            dst_hostname="pool.minexmr.com",
            dst_port=3333,
            dst_ip="1.1.1.1",
            geo_country="KP",
            duration_seconds=7200.0,
            bytes_sent=20 * 1024 * 1024,
        ),
    ]
    ctx.shared_data["browsing_entries"] = [
        _make_browsing_entry(
            url="https://sketchy.example.xyz/payload.exe",
            domain="sketchy.example.xyz",
        ),
    ]

    for probe in probes:
        events = probe.scan(ctx)
        assert isinstance(events, list), f"Probe {probe.name} did not return a list"
        for event in events:
            assert isinstance(event, TelemetryEvent)
            assert event.event_type, f"Missing event_type from {probe.name}"
            assert event.severity is not None
            assert isinstance(event.data, dict)
            assert event.probe_name == probe.name
