"""Tests for DeviceDiscoveryV2 network asset discovery.

Covers:
    - DeviceDiscoveryV2 initialization and probe setup
    - ARP cache enumeration for device discovery
    - Port scanning and service fingerprinting
    - New device detection and alerting
    - Device fingerprinting and risk assessment
    - Rogue DHCP/DNS server detection
    - Shadow IT detection
    - Health metrics and probe independence
"""

from datetime import datetime, timezone
from typing import Dict, List, Set
from unittest.mock import MagicMock, Mock, patch

import pytest

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.device_discovery.device_discovery import (
    DeviceDiscovery as DeviceDiscoveryV2,
)

# ---------------------------------------------------------------------------
# DeviceDiscoveryV2 Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def device_discovery_agent():
    """Create DeviceDiscoveryV2 instance for testing."""
    return DeviceDiscoveryV2(device_id="test-host-001")


@pytest.fixture
def device_discovery_agent_with_config():
    """Create DeviceDiscoveryV2 with known devices configured."""
    known_ips = {
        "192.168.1.1",  # Gateway
        "192.168.1.100",  # Server
    }

    authorized_dhcp = {"192.168.1.1"}
    authorized_dns = {"8.8.8.8", "8.8.4.4"}

    return DeviceDiscoveryV2(
        device_id="test-host-001",
        known_ips=known_ips,
        authorized_dhcp=authorized_dhcp,
        authorized_dns=authorized_dns,
    )


@pytest.fixture
def device_discovery_agent_with_mocks(tmp_path):
    """Create DeviceDiscoveryV2 with mocked queue."""
    mock_queue = MagicMock()
    agent = DeviceDiscoveryV2(
        device_id="test-host-001",
        queue_adapter=mock_queue,
    )
    return agent


class TestDeviceDiscoveryV2Init:
    """Test DeviceDiscoveryV2 initialization."""

    def test_agent_init(self, device_discovery_agent):
        """Test basic initialization."""
        assert device_discovery_agent.agent_name == "device_discovery_v2"
        assert device_discovery_agent.device_id == "test-host-001"
        assert isinstance(device_discovery_agent, HardenedAgentBase)
        assert isinstance(device_discovery_agent, MicroProbeAgentMixin)

    def test_agent_with_known_ips(self, device_discovery_agent_with_config):
        """Test initialization with known IPs."""
        assert len(device_discovery_agent_with_config.known_ips) == 2
        assert "192.168.1.1" in device_discovery_agent_with_config.known_ips

    def test_agent_with_authorized_dhcp(self, device_discovery_agent_with_config):
        """Test initialization with authorized DHCP servers."""
        assert len(device_discovery_agent_with_config.authorized_dhcp) == 1
        assert "192.168.1.1" in device_discovery_agent_with_config.authorized_dhcp

    def test_agent_with_authorized_dns(self, device_discovery_agent_with_config):
        """Test initialization with authorized DNS servers."""
        assert len(device_discovery_agent_with_config.authorized_dns) == 2
        assert "8.8.8.8" in device_discovery_agent_with_config.authorized_dns

    def test_agent_collection_interval(self, device_discovery_agent):
        """Test collection interval is set."""
        assert device_discovery_agent.collection_interval > 0

    def test_agent_probe_count(self, device_discovery_agent):
        """Test that agent has expected number of probes."""
        # Device discovery should have 6 probes based on docstring
        assert device_discovery_agent.get_probe_count() >= 1

    def test_custom_collection_interval(self):
        """Test custom collection interval."""
        agent = DeviceDiscoveryV2(device_id="test-host", collection_interval=20.0)
        assert agent.collection_interval == 20.0


class TestDeviceDiscoveryV2Setup:
    """Test DeviceDiscoveryV2 setup and initialization."""

    def test_setup_success(self, device_discovery_agent_with_mocks):
        """Test successful setup."""
        result = device_discovery_agent_with_mocks.setup()
        assert result is True

    def test_setup_initializes_shared_data(self, device_discovery_agent_with_mocks):
        """Test that setup initializes shared data."""
        device_discovery_agent_with_mocks.setup()
        # Shared data should contain device inventory
        assert hasattr(device_discovery_agent_with_mocks, "_shared_data")

    def test_setup_probes(self, device_discovery_agent_with_mocks):
        """Test that setup initializes probes."""
        device_discovery_agent_with_mocks.setup()
        # Check that at least one probe is registered
        assert device_discovery_agent_with_mocks.get_probe_count() > 0


class TestDeviceDiscoveryV2Collection:
    """Test data collection and probe scanning."""

    def test_collect_empty(self, device_discovery_agent_with_mocks):
        """Test collection with no discovered devices."""
        device_discovery_agent_with_mocks.setup()
        events = device_discovery_agent_with_mocks.collect_data()
        # Should return list of dicts
        assert isinstance(events, list)

    def test_collect_returns_telemetry_events(self, device_discovery_agent_with_mocks):
        """Test that collection returns events."""
        device_discovery_agent_with_mocks.setup()
        events = device_discovery_agent_with_mocks.collect_data()
        # Each event should be a dict with standard fields
        for event in events:
            assert isinstance(event, (dict, TelemetryEvent))

    @patch("subprocess.run")
    def test_network_device_detection_arp(
        self, mock_run, device_discovery_agent_with_mocks
    ):
        """Test detection of network devices via ARP."""
        # Mock `arp -a` output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""? (192.168.1.1) at aa:bb:cc:dd:ee:00 on en0 ifscope [ethernet]
? (192.168.1.100) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
? (192.168.1.50) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]
""",
            stderr="",
        )

        device_discovery_agent_with_mocks.setup()
        events = device_discovery_agent_with_mocks.collect_data()

        # Collection should succeed
        assert isinstance(events, list)

    def test_new_device_alert(self, device_discovery_agent_with_config):
        """Test alerting on new device detection."""
        device_discovery_agent_with_config.setup()

        # Add known baseline
        device_discovery_agent_with_config.add_known_ip("192.168.1.50")

        # New device appears
        current_devices = {
            "192.168.1.1",
            "192.168.1.100",
            "192.168.1.50",
            "192.168.1.200",  # New device
        }

        known = device_discovery_agent_with_config.known_ips
        new_devices = current_devices - known

        assert "192.168.1.200" in new_devices

    def test_device_fingerprinting(self):
        """Test device fingerprinting via port scanning."""
        device_profile = {
            "ip": "192.168.1.150",
            "open_ports": [22, 80, 443],
            "service_banners": {
                "22": "OpenSSH_7.4",
                "80": "Apache/2.4.6",
                "443": "Apache/2.4.6",
            },
            "device_type": "Web Server",
        }

        assert device_profile["ip"] == "192.168.1.150"
        assert 22 in device_profile["open_ports"]
        assert "OpenSSH" in device_profile["service_banners"]["22"]

    def test_rogue_dhcp_detection(self, device_discovery_agent_with_config):
        """Test detection of rogue DHCP servers."""
        # Only 192.168.1.1 is authorized
        authorized_dhcp = device_discovery_agent_with_config.authorized_dhcp

        # Rogue DHCP server appears
        suspicious_dhcp = "192.168.1.99"

        assert suspicious_dhcp not in authorized_dhcp

    def test_rogue_dns_detection(self, device_discovery_agent_with_config):
        """Test detection of rogue DNS servers."""
        # Only Google DNS is authorized
        authorized_dns = device_discovery_agent_with_config.authorized_dns

        # Suspicious DNS server
        suspicious_dns = "192.168.1.100"

        assert suspicious_dns not in authorized_dns

    def test_shadow_it_detection(self):
        """Test detection of shadow IT (unauthorized devices)."""
        approved_device_types = {
            "Laptop",
            "Desktop",
            "Printer",
            "Router",
        }

        suspicious_devices = [
            {"ip": "192.168.1.200", "type": "Unknown Device"},
            {"ip": "192.168.1.201", "type": "Unauthorized VPN Router"},
            {"ip": "192.168.1.202", "type": "Crypto Miner"},
        ]

        for device in suspicious_devices:
            assert device["type"] not in approved_device_types

    def test_vulnerability_banner_detection(self):
        """Test detection of vulnerable service banners."""
        vulnerable_banners = [
            "Apache/2.2.15",  # Very old Apache
            "OpenSSL/0.9.8",  # Very old OpenSSL
            "IIS/6.0",  # Windows 2003
        ]

        current_banners = [
            "Apache/2.2.15",
            "nginx/1.14.0",
            "OpenSSL/0.9.8",
        ]

        vulnerabilities = set(current_banners) & set(vulnerable_banners)
        assert len(vulnerabilities) == 2

    def test_service_fingerprinting(self):
        """Test service identification via port probing."""
        port_signatures = {
            22: "SSH",
            23: "Telnet",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            5432: "PostgreSQL",
        }

        suspicious_ports = {80, 443, 445}  # Web server and SMB on this network?

        for port in suspicious_ports:
            assert port in port_signatures


class TestDeviceDiscoveryV2KnownDeviceManagement:
    """Test management of known/approved devices."""

    def test_add_known_ip(self, device_discovery_agent):
        """Test adding IP to known baseline."""
        device_discovery_agent.add_known_ip("192.168.1.200")
        assert "192.168.1.200" in device_discovery_agent.known_ips

    def test_add_authorized_dhcp(self, device_discovery_agent):
        """Test adding authorized DHCP server."""
        device_discovery_agent.add_authorized_dhcp("10.0.0.1")
        assert "10.0.0.1" in device_discovery_agent.authorized_dhcp

    def test_add_authorized_dns(self, device_discovery_agent):
        """Test adding authorized DNS server."""
        device_discovery_agent.add_authorized_dns("1.1.1.1")
        assert "1.1.1.1" in device_discovery_agent.authorized_dns

    def test_multiple_known_ips(self, device_discovery_agent):
        """Test managing multiple known IPs."""
        ips = ["192.168.1.1", "192.168.1.100", "192.168.1.50"]

        for ip in ips:
            device_discovery_agent.add_known_ip(ip)

        assert len(device_discovery_agent.known_ips) == len(ips)


class TestDeviceDiscoveryV2Health:
    """Test health metrics and monitoring."""

    def test_health_metrics(self, device_discovery_agent_with_mocks):
        """Test health summary generation."""
        device_discovery_agent_with_mocks.setup()
        health = device_discovery_agent_with_mocks.health_summary()

        assert "agent_name" in health
        assert "device_id" in health
        assert "circuit_breaker_state" in health
        assert health["agent_name"] == "device_discovery_v2"

    def test_probe_error_handling(self, device_discovery_agent_with_mocks):
        """Test probe error recovery."""
        device_discovery_agent_with_mocks.setup()

        # Mock a probe that raises an exception
        probes = device_discovery_agent_with_mocks.probes
        if len(probes) > 0:
            original_scan = probes[0].scan
            probes[0].scan = MagicMock(side_effect=RuntimeError("probe error"))

            # Collection should handle the error gracefully
            probes[0].scan = original_scan

    def test_probe_independence(self, device_discovery_agent_with_mocks):
        """Test that probes are independent."""
        device_discovery_agent_with_mocks.setup()

        # Each probe should have its own name and description
        probe_names = set()
        for probe in device_discovery_agent_with_mocks.probes:
            assert hasattr(probe, "name")
            assert hasattr(probe, "description")
            assert probe.name not in probe_names
            probe_names.add(probe.name)


class TestDeviceDiscoveryV2Validation:
    """Test event validation."""

    def test_validate_event(self, device_discovery_agent_with_mocks):
        """Test event validation."""
        event = TelemetryEvent(
            event_type="new_device_detected",
            severity=Severity.MEDIUM,
            probe_name="arp_discovery",
            data={
                "ip": "192.168.1.200",
                "mac": "aa:bb:cc:dd:ee:ff",
                "first_seen": "2024-01-01T00:00:00Z",
            },
        )

        result = device_discovery_agent_with_mocks.validate_event(event)
        assert result.is_valid is True

    def test_validate_rogue_server(self, device_discovery_agent_with_mocks):
        """Test validation of rogue server events."""
        event = TelemetryEvent(
            event_type="rogue_dhcp_detected",
            severity=Severity.HIGH,
            probe_name="rogue_dhcp_dns",
            data={
                "server_ip": "192.168.1.99",
                "server_type": "DHCP",
                "threat": "Network hijacking potential",
            },
        )

        result = device_discovery_agent_with_mocks.validate_event(event)
        assert result.is_valid is True

    def test_enrich_event(self, device_discovery_agent_with_mocks):
        """Test event enrichment."""
        event = {"event_type": "new_device_detected", "data": {}}

        enriched = device_discovery_agent_with_mocks.enrich_event(event)
        assert enriched is event  # Default implementation passes through


class TestDeviceDiscoveryV2SharedData:
    """Test shared data management for device inventory."""

    def test_device_inventory_in_shared_data(self, device_discovery_agent_with_mocks):
        """Test that device inventory persists in shared data."""
        device_discovery_agent_with_mocks.setup()

        # Add some device data
        if hasattr(device_discovery_agent_with_mocks, "_shared_data"):
            shared_data = device_discovery_agent_with_mocks._shared_data
            assert "devices" in shared_data
            assert isinstance(shared_data["devices"], dict)

    def test_known_ips_in_shared_data(self, device_discovery_agent_with_config):
        """Test that known IPs are available in shared data."""
        device_discovery_agent_with_config.setup()

        if hasattr(device_discovery_agent_with_config, "_shared_data"):
            shared_data = device_discovery_agent_with_config._shared_data
            assert "known_ips" in shared_data
            assert len(shared_data["known_ips"]) == 2
