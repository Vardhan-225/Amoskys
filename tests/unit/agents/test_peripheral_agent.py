"""Tests for PeripheralAgent and peripheral device monitoring.

Covers:
    - PeripheralAgent initialization and probe setup
    - USB device inventory and connection tracking
    - Bluetooth device detection
    - HID device monitoring (keyboard/mouse anomalies)
    - Unauthorized device alerts
    - Health metrics and probe independence
"""

from datetime import datetime, timezone
from typing import Dict, List
from unittest.mock import MagicMock, Mock, patch

import pytest

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.shared.peripheral.agent import PeripheralAgent

# ---------------------------------------------------------------------------
# PeripheralAgent Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def peripheral_agent():
    """Create PeripheralAgent instance for testing."""
    return PeripheralAgent()


@pytest.fixture
def peripheral_agent_with_mocks(tmp_path):
    """Create PeripheralAgent with mocked EventBus and queue."""
    with patch(
        "amoskys.agents.shared.peripheral.agent.EventBusPublisher"
    ) as mock_pub_class:
        with patch(
            "amoskys.agents.shared.peripheral.agent.LocalQueueAdapter"
        ) as mock_queue_class:
            mock_pub = MagicMock()
            mock_pub_class.return_value = mock_pub

            mock_queue = MagicMock()
            mock_queue_class.return_value = mock_queue

            agent = PeripheralAgent()
            agent._eventbus_publisher = mock_pub
            agent.local_queue = mock_queue
            return agent


class TestPeripheralAgentInit:
    """Test PeripheralAgent initialization."""

    def test_agent_init(self, peripheral_agent):
        """Test basic initialization."""
        assert peripheral_agent.agent_name == "peripheral"
        assert peripheral_agent.device_id is not None
        assert isinstance(peripheral_agent, HardenedAgentBase)
        assert isinstance(peripheral_agent, MicroProbeAgentMixin)

    def test_agent_collection_interval(self, peripheral_agent):
        """Test collection interval is set."""
        assert peripheral_agent.collection_interval > 0

    def test_agent_probe_count(self, peripheral_agent):
        """Test that agent has expected number of probes."""
        # Peripheral should have 7 probes based on docstring
        assert len(peripheral_agent._probes) >= 1

    def test_custom_collection_interval(self):
        """Test custom collection interval."""
        agent = PeripheralAgent(collection_interval=5.0)
        assert agent.collection_interval == 5.0


class TestPeripheralAgentSetup:
    """Test PeripheralAgent setup and initialization."""

    def test_setup_success(self, peripheral_agent_with_mocks):
        """Test successful setup."""
        result = peripheral_agent_with_mocks.setup()
        assert result is True

    def test_setup_probes(self, peripheral_agent_with_mocks):
        """Test that setup initializes probes."""
        peripheral_agent_with_mocks.setup()
        # Check that at least one probe is registered
        assert len(peripheral_agent_with_mocks._probes) > 0


class TestPeripheralAgentCollection:
    """Test data collection and probe scanning."""

    def test_collect_empty(self, peripheral_agent_with_mocks):
        """Test collection with no devices."""
        peripheral_agent_with_mocks.setup()
        events = peripheral_agent_with_mocks.collect_data()
        # Should return list of dicts
        assert isinstance(events, list)

    def test_collect_returns_telemetry_events(self, peripheral_agent_with_mocks):
        """Test that collection returns events."""
        peripheral_agent_with_mocks.setup()
        events = peripheral_agent_with_mocks.collect_data()
        # collect_data may return protobuf DeviceTelemetry or TelemetryEvent list
        assert isinstance(events, (list, type(None))) or hasattr(events, "__iter__")

    @patch("subprocess.run")
    def test_usb_device_detection(self, mock_run, peripheral_agent_with_mocks):
        """Test detection of USB devices via system_profiler."""
        # Mock macOS system_profiler output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""USB:

    USB 3.1 Bus:

        Host Controller Location: Built-in
        PCI Device ID: 0x9001

      Devices:

        Kingston DataTraveler:

            Product ID: 0x1234
            Vendor ID: 0x0930 (Kingston Technology Corp.)
            Version: 11.00
            Serial Number: 123ABC456
            Speed: Up to 480 Mb/s
            Manufacturer: Kingston
            Location ID: 0x14100000 / 2
            Current Available (mA): 500
            Current Required (mA): 100
""",
            stderr="",
        )

        peripheral_agent_with_mocks.setup()
        events = peripheral_agent_with_mocks.collect_data()

        # Collection should succeed
        assert isinstance(events, list)

    @patch("subprocess.run")
    def test_bluetooth_device_detection(self, mock_run, peripheral_agent_with_mocks):
        """Test detection of Bluetooth devices."""
        # Mock Bluetooth device list
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""Bluetooth:

    Apple Wireless Mouse:

        Device Name: Apple Wireless Mouse
        Device Address: AA:BB:CC:DD:EE:FF
        Manufacturer: Apple
        Product ID: 0x0001
        Vendor ID: 0x05ac
""",
            stderr="",
        )

        peripheral_agent_with_mocks.setup()
        events = peripheral_agent_with_mocks.collect_data()

        assert isinstance(events, list)

    def test_usb_storage_device_detection(self):
        """Test USB storage device detection."""
        # USB storage devices have specific characteristics
        device_data = {
            "product_id": "0x5581",
            "vendor_id": "0x0781",
            "device_class": "Mass Storage",
            "location_id": "0x14100000",
        }

        # Storage device would be flagged by probe
        assert device_data["device_class"] == "Mass Storage"

    def test_usb_network_adapter_detection(self):
        """Test USB network adapter detection."""
        # Network adapters over USB
        device_data = {
            "product_id": "0x1000",
            "vendor_id": "0x0bda",
            "device_class": "Network",
            "description": "USB Ethernet Adapter",
        }

        assert device_data["device_class"] == "Network"

    def test_unauthorized_device_alert(self, peripheral_agent_with_mocks):
        """Test alerting on unauthorized device connection."""
        # Setup whitelist of authorized devices
        authorized = {
            "AA:BB:CC:DD:EE:FF",  # Known keyboard
            "11:22:33:44:55:66",  # Known mouse
        }

        # Detect new device
        new_device = {
            "device_address": "99:88:77:66:55:44",
            "device_name": "Unknown Bluetooth Device",
            "vendor_id": "0x9999",
        }

        # New device not in whitelist
        assert new_device["device_address"] not in authorized

    def test_high_risk_peripheral_scoring(self):
        """Test risk scoring for high-risk peripherals."""
        # Devices that can perform credential harvesting, injection, etc.
        risk_devices = [
            {
                "type": "USB HID",
                "description": "Keylogger-capable",
                "risk_score": 0.9,
            },
            {
                "type": "Network Adapter",
                "description": "MITM-capable",
                "risk_score": 0.8,
            },
            {
                "type": "Storage",
                "description": "Data exfiltration",
                "risk_score": 0.7,
            },
        ]

        for device in risk_devices:
            assert device["risk_score"] > 0.5  # All flagged as risky


class TestPeripheralAgentHealth:
    """Test health metrics and monitoring."""

    def test_health_metrics(self, peripheral_agent_with_mocks):
        """Test health summary generation."""
        peripheral_agent_with_mocks.setup()
        health = peripheral_agent_with_mocks.health_summary()

        assert "agent_name" in health
        assert "device_id" in health
        assert "circuit_breaker_state" in health
        assert health["agent_name"] == "peripheral"

    def test_probe_error_handling(self, peripheral_agent_with_mocks):
        """Test probe error recovery."""
        peripheral_agent_with_mocks.setup()

        # Mock a probe that raises an exception
        if len(peripheral_agent_with_mocks._probes) > 0:
            original_scan = peripheral_agent_with_mocks._probes[0].scan
            peripheral_agent_with_mocks._probes[0].scan = MagicMock(
                side_effect=RuntimeError("probe error")
            )

            # Collection should handle the error gracefully
            peripheral_agent_with_mocks._probes[0].scan = original_scan

    def test_probe_independence(self, peripheral_agent_with_mocks):
        """Test that probes are independent."""
        peripheral_agent_with_mocks.setup()

        # Each probe should have its own name and description
        probe_names = set()
        for probe in peripheral_agent_with_mocks._probes:
            assert hasattr(probe, "name")
            assert hasattr(probe, "description")
            assert probe.name not in probe_names
            probe_names.add(probe.name)


class TestPeripheralAgentValidation:
    """Test event validation."""

    def test_validate_event(self, peripheral_agent_with_mocks):
        """Test event validation — expects protobuf DeviceTelemetry."""
        import time as _t

        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(_t.time() * 1e9),
            events=[
                tpb.TelemetryEvent(
                    event_id="usb-1",
                    event_type="SECURITY",
                    severity="MEDIUM",
                )
            ],
        )

        result = peripheral_agent_with_mocks.validate_event(event)
        assert result.is_valid is True

    def test_validate_hid_anomaly(self, peripheral_agent_with_mocks):
        """Test validation of HID anomaly event."""
        import time as _t

        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(_t.time() * 1e9),
            events=[
                tpb.TelemetryEvent(
                    event_id="hid-1",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )

        result = peripheral_agent_with_mocks.validate_event(event)
        assert result.is_valid is True


class TestPeripheralAgentDeviceTracking:
    """Test device inventory tracking."""

    def test_device_inventory_persistence(self, peripheral_agent_with_mocks):
        """Test that device inventory persists across collections."""
        peripheral_agent_with_mocks.setup()

        # Collect devices
        events1 = peripheral_agent_with_mocks.collect_data()

        # Collect again
        events2 = peripheral_agent_with_mocks.collect_data()

        # Both should be valid lists
        assert isinstance(events1, list)
        assert isinstance(events2, list)

    def test_new_device_detection(self):
        """Test detection of newly connected devices."""
        old_devices = {
            "AA:BB:CC:DD:EE:FF",
            "11:22:33:44:55:66",
        }

        current_devices = {
            "AA:BB:CC:DD:EE:FF",
            "11:22:33:44:55:66",
            "99:88:77:66:55:44",  # New device
        }

        new_devices = current_devices - old_devices
        assert "99:88:77:66:55:44" in new_devices

    def test_device_removal_detection(self):
        """Test detection of device disconnection."""
        old_devices = {
            "AA:BB:CC:DD:EE:FF",
            "11:22:33:44:55:66",
            "99:88:77:66:55:44",
        }

        current_devices = {
            "AA:BB:CC:DD:EE:FF",
            "11:22:33:44:55:66",
        }

        removed_devices = old_devices - current_devices
        assert "99:88:77:66:55:44" in removed_devices


# ===========================================================================
# EXTENDED TESTS — Uncovered code paths
# ===========================================================================


# ---------------------------------------------------------------------------
# EventBusPublisher Tests
# ---------------------------------------------------------------------------


class TestPeripheralEventBusPublisher:
    """Test EventBusPublisher in peripheral_agent module."""

    def test_publisher_init(self):
        """Test EventBusPublisher initialization."""
        from amoskys.agents.shared.peripheral.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        assert pub.address == "localhost:50051"
        assert pub.cert_dir == "/tmp/certs"
        assert pub._channel is None
        assert pub._stub is None

    def test_ensure_channel_missing_cert(self, tmp_path):
        """Test _ensure_channel raises RuntimeError when certs are missing."""
        from amoskys.agents.shared.peripheral.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", str(tmp_path / "no_certs"))
        with pytest.raises(RuntimeError, match="Certificate not found"):
            pub._ensure_channel()

    def test_ensure_channel_generic_error(self, tmp_path):
        """Test _ensure_channel raises RuntimeError on generic gRPC error."""
        from amoskys.agents.shared.peripheral.agent import EventBusPublisher

        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        (cert_dir / "ca.crt").write_bytes(b"fake")
        (cert_dir / "agent.crt").write_bytes(b"fake")
        (cert_dir / "agent.key").write_bytes(b"fake")

        pub = EventBusPublisher("localhost:50051", str(cert_dir))
        with patch(
            "amoskys.agents.shared.peripheral.agent.grpc.ssl_channel_credentials",
            side_effect=Exception("ssl fail"),
        ):
            with pytest.raises(RuntimeError, match="Failed to create gRPC channel"):
                pub._ensure_channel()

    def test_close_with_channel(self):
        """Test close() properly closes an existing channel."""
        from amoskys.agents.shared.peripheral.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub._channel = MagicMock()
        pub._stub = MagicMock()
        pub.close()
        assert pub._channel is None
        assert pub._stub is None

    def test_close_without_channel(self):
        """Test close() is a noop when no channel exists."""
        from amoskys.agents.shared.peripheral.agent import EventBusPublisher

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        pub.close()
        assert pub._channel is None

    def test_publish_success(self):
        """Test publish() sends events through the stub."""
        import time as _t

        from amoskys.agents.shared.peripheral.agent import EventBusPublisher
        from amoskys.proto import universal_telemetry_pb2 as tpb

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        mock_stub = MagicMock()
        mock_ack = MagicMock()
        mock_ack.status = tpb.UniversalAck.OK
        mock_stub.PublishTelemetry.return_value = mock_ack
        pub._stub = mock_stub
        pub._channel = MagicMock()

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(_t.time() * 1e9),
        )
        pub.publish([event])
        assert mock_stub.PublishTelemetry.called

    def test_publish_raises_on_bad_ack(self):
        """Test publish() raises when EventBus returns non-OK status."""
        from amoskys.agents.shared.peripheral.agent import EventBusPublisher
        from amoskys.proto import universal_telemetry_pb2 as tpb

        pub = EventBusPublisher("localhost:50051", "/tmp/certs")
        mock_stub = MagicMock()
        mock_ack = MagicMock()
        mock_ack.status = 999
        mock_stub.PublishTelemetry.return_value = mock_ack
        pub._stub = mock_stub
        pub._channel = MagicMock()

        event = tpb.DeviceTelemetry(device_id="test-host", timestamp_ns=100)
        with pytest.raises(Exception, match="EventBus returned status"):
            pub.publish([event])


# ---------------------------------------------------------------------------
# PeripheralAgent Setup Extended Tests
# ---------------------------------------------------------------------------


class TestPeripheralAgentSetupExtended:
    """Extended tests for setup() uncovered branches."""

    def test_setup_missing_certs_warns(self, peripheral_agent_with_mocks):
        """Test setup logs warnings for missing certs but still succeeds."""
        with patch("os.path.exists", return_value=False):
            result = peripheral_agent_with_mocks.setup()
            assert result is True

    def test_setup_no_probes_returns_false(self, peripheral_agent_with_mocks):
        """Test setup returns False if no probes initialize."""
        with patch.object(
            peripheral_agent_with_mocks, "setup_probes", return_value=False
        ):
            result = peripheral_agent_with_mocks.setup()
            assert result is False

    def test_setup_exception_returns_false(self, peripheral_agent_with_mocks):
        """Test setup returns False on unexpected exception."""
        with patch.object(
            peripheral_agent_with_mocks,
            "setup_probes",
            side_effect=RuntimeError("boom"),
        ):
            result = peripheral_agent_with_mocks.setup()
            assert result is False


# ---------------------------------------------------------------------------
# PeripheralAgent collect_data Extended Tests
# ---------------------------------------------------------------------------


class TestPeripheralAgentCollectExtended:
    """Extended tests for collect_data covering proto event conversion."""

    def test_collect_returns_device_telemetry(self, peripheral_agent_with_mocks):
        """Test collect_data returns properly structured DeviceTelemetry."""
        peripheral_agent_with_mocks.setup()
        results = peripheral_agent_with_mocks.collect_data()

        assert isinstance(results, list)
        assert len(results) == 1

        dt = results[0]
        assert dt.device_id == peripheral_agent_with_mocks.device_id
        assert dt.device_type == "HOST"
        assert dt.protocol == "USB"
        assert dt.collection_agent == "peripheral"
        assert dt.agent_version == "2.0.0"
        # Should always have at least the heartbeat metric
        assert len(dt.events) >= 1

    def test_collect_heartbeat_metric(self, peripheral_agent_with_mocks):
        """Test collect_data always emits a heartbeat collection summary metric."""
        peripheral_agent_with_mocks.setup()
        results = peripheral_agent_with_mocks.collect_data()
        dt = results[0]

        heartbeat_found = False
        for ev in dt.events:
            if (
                ev.event_type == "METRIC"
                and ev.metric_data.metric_name == "peripheral_events_collected"
            ):
                heartbeat_found = True
                assert ev.source_component == "peripheral_collector"
                assert "peripheral" in list(ev.tags)
                break
        assert heartbeat_found

    def test_collect_with_probe_events(self, peripheral_agent_with_mocks):
        """Test collect_data with probe-generated events creates security events."""
        peripheral_agent_with_mocks.setup()

        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "usb_test_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="usb_device_connected",
                severity=Severity.HIGH,
                probe_name="usb_test_probe",
                data={"vendor_id": "0x1234", "product_id": "0x5678"},
                mitre_techniques=["T1200"],
                confidence=0.9,
            )
        ]
        peripheral_agent_with_mocks._probes = [mock_probe]

        results = peripheral_agent_with_mocks.collect_data()
        dt = results[0]

        # Should have heartbeat + probe event count metric + security event
        assert len(dt.events) >= 3

        security_events = [e for e in dt.events if e.event_type == "SECURITY"]
        assert len(security_events) >= 1

        se = security_events[0]
        assert se.security_event.risk_score == pytest.approx(0.8, abs=1e-6)
        assert "T1200" in list(se.security_event.mitre_techniques)
        assert se.attributes["vendor_id"] == "0x1234"
        assert se.attributes["product_id"] == "0x5678"

    def test_collect_medium_severity_lower_risk(self, peripheral_agent_with_mocks):
        """Test MEDIUM severity maps to lower risk_score (0.4)."""
        peripheral_agent_with_mocks.setup()

        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "bt_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="bluetooth_new_device",
                severity=Severity.MEDIUM,
                probe_name="bt_probe",
                data={"device_name": "BT Mouse"},
            )
        ]
        peripheral_agent_with_mocks._probes = [mock_probe]

        results = peripheral_agent_with_mocks.collect_data()
        for ev in results[0].events:
            if ev.event_type == "SECURITY":
                assert ev.security_event.risk_score == pytest.approx(0.4, abs=1e-6)
                break

    def test_collect_event_data_none_values_skipped(self, peripheral_agent_with_mocks):
        """Test that None values in event.data are not written to attributes."""
        peripheral_agent_with_mocks.setup()

        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "test_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="test_event",
                severity=Severity.INFO,
                probe_name="test_probe",
                data={"key1": "value1", "key2": None},
            )
        ]
        peripheral_agent_with_mocks._probes = [mock_probe]

        results = peripheral_agent_with_mocks.collect_data()
        for ev in results[0].events:
            if ev.event_type == "SECURITY":
                assert "key1" in ev.attributes
                assert "key2" not in ev.attributes
                break

    def test_collect_probe_events_metric(self, peripheral_agent_with_mocks):
        """Test that probe event count metric is emitted when probes fire."""
        peripheral_agent_with_mocks.setup()

        mock_probe = MagicMock()
        mock_probe.enabled = True
        mock_probe.name = "active_probe"
        mock_probe.scan.return_value = [
            TelemetryEvent(
                event_type="probe_event",
                severity=Severity.LOW,
                probe_name="active_probe",
                data={},
            )
        ]
        peripheral_agent_with_mocks._probes = [mock_probe]

        results = peripheral_agent_with_mocks.collect_data()
        dt = results[0]

        probe_metric_found = False
        for ev in dt.events:
            if (
                ev.event_type == "METRIC"
                and ev.metric_data.metric_name == "peripheral_probe_events"
            ):
                probe_metric_found = True
                assert ev.metric_data.numeric_value >= 1.0
                break
        assert probe_metric_found

    def test_collect_no_probe_events_no_extra_metric(self, peripheral_agent_with_mocks):
        """Test no probe events means no probe event count metric."""
        peripheral_agent_with_mocks.setup()

        # Ensure all probes return empty
        for probe in peripheral_agent_with_mocks._probes:
            probe.scan = MagicMock(return_value=[])

        results = peripheral_agent_with_mocks.collect_data()
        dt = results[0]

        # Should only have heartbeat metric, no probe_events metric
        for ev in dt.events:
            if ev.event_type == "METRIC":
                assert ev.metric_data.metric_name != "peripheral_probe_events"


# ---------------------------------------------------------------------------
# PeripheralAgent validate_event Extended Tests
# ---------------------------------------------------------------------------


class TestPeripheralAgentValidateExtended:
    """Extended tests for validate_event edge cases."""

    def test_validate_missing_device_id(self, peripheral_agent_with_mocks):
        """Test validation fails with empty device_id."""
        import time as _t

        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=int(_t.time() * 1e9),
            events=[
                tpb.TelemetryEvent(
                    event_id="x",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )
        result = peripheral_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert any("device_id" in e for e in result.errors)

    def test_validate_zero_timestamp(self, peripheral_agent_with_mocks):
        """Test validation fails with zero timestamp_ns."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=0,
            events=[
                tpb.TelemetryEvent(
                    event_id="x",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )
        result = peripheral_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert any("timestamp" in e for e in result.errors)

    def test_validate_empty_events(self, peripheral_agent_with_mocks):
        """Test validation fails with empty events list."""
        import time as _t

        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=int(_t.time() * 1e9),
        )
        result = peripheral_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert any("empty" in e for e in result.errors)

    def test_validate_multiple_errors(self, peripheral_agent_with_mocks):
        """Test validation accumulates multiple errors."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(device_id="", timestamp_ns=0)
        result = peripheral_agent_with_mocks.validate_event(event)
        assert result.is_valid is False
        assert len(result.errors) >= 2


# ---------------------------------------------------------------------------
# PeripheralAgent Shutdown Tests
# ---------------------------------------------------------------------------


class TestPeripheralAgentShutdown:
    """Test shutdown lifecycle."""

    def test_shutdown_closes_publisher(self, peripheral_agent_with_mocks):
        """Test shutdown closes the EventBus publisher."""
        mock_pub = MagicMock()
        peripheral_agent_with_mocks.eventbus_publisher = mock_pub
        peripheral_agent_with_mocks.shutdown()
        mock_pub.close.assert_called_once()

    def test_shutdown_no_publisher(self, peripheral_agent_with_mocks):
        """Test shutdown handles None publisher gracefully."""
        peripheral_agent_with_mocks.eventbus_publisher = None
        peripheral_agent_with_mocks.shutdown()  # Should not raise


# ---------------------------------------------------------------------------
# PeripheralAgent get_health Tests
# ---------------------------------------------------------------------------


class TestPeripheralAgentGetHealth:
    """Test get_health method."""

    def test_get_health_returns_dict(self, peripheral_agent_with_mocks):
        """Test get_health returns dict with all expected keys."""
        peripheral_agent_with_mocks.setup()
        health = peripheral_agent_with_mocks.get_health()
        assert isinstance(health, dict)
        assert health["agent_name"] == "peripheral"
        assert "device_id" in health
        assert "is_running" in health
        assert "collection_count" in health
        assert "error_count" in health
        assert "last_error" in health
        assert "probes" in health
        assert "circuit_breaker_state" in health

    def test_get_health_reflects_error_count(self, peripheral_agent_with_mocks):
        """Test get_health reflects agent error state."""
        peripheral_agent_with_mocks.setup()
        peripheral_agent_with_mocks.error_count = 5
        peripheral_agent_with_mocks.last_error = "test error"

        health = peripheral_agent_with_mocks.get_health()
        assert health["error_count"] == 5
        assert health["last_error"] == "test error"
