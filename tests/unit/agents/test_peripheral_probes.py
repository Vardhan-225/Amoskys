"""Unit tests for peripheral/probes.py — all 7 micro-probes.

Covers uncovered scan() methods, USB/Bluetooth collectors, and risk scoring:
    1. USBInventoryProbe — inventory snapshot with mocked collector
    2. USBConnectionEdgeProbe — connect/disconnect edge detection
    3. USBStorageProbe — storage device classification
    4. USBNetworkAdapterProbe — network adapter detection
    5. HIDKeyboardMouseAnomalyProbe — BadUSB/Rubber Ducky detection
    6. BluetoothDeviceProbe — Bluetooth device tracking
    7. HighRiskPeripheralScoreProbe — composite risk score
    8. Collectors (MacOS, Linux, factory)
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, Mock, patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.agents.shared.peripheral.probes import (
    PERIPHERAL_PROBES,
    BluetoothDevice,
    BluetoothDeviceProbe,
    HIDKeyboardMouseAnomalyProbe,
    HighRiskPeripheralScoreProbe,
    LinuxUSBCollector,
    MacOSUSBCollector,
    USBCollector,
    USBConnectionEdgeProbe,
    USBDevice,
    USBInventoryProbe,
    USBNetworkAdapterProbe,
    USBStorageProbe,
    create_peripheral_probes,
    get_usb_collector,
)

# =============================================================================
# Helpers
# =============================================================================


def _ctx(**shared) -> ProbeContext:
    return ProbeContext(
        device_id="test-host",
        agent_name="peripheral_agent",
        shared_data=shared,
    )


def _usb(
    device_id: str = "dev001",
    name: str = "Generic Device",
    vendor_id: str = "1234",
    product_id: str = "5678",
    serial_number: str = "SN001",
    manufacturer: str = "TestCorp",
    location_id: str = "0x0",
    device_speed: str = "480",
    device_class: str = "",
) -> USBDevice:
    return USBDevice(
        device_id=device_id,
        name=name,
        vendor_id=vendor_id,
        product_id=product_id,
        serial_number=serial_number,
        manufacturer=manufacturer,
        location_id=location_id,
        device_speed=device_speed,
        device_class=device_class,
    )


# =============================================================================
# USB Collectors
# =============================================================================


class TestUSBCollectorBase:
    """Test USBCollector abstract base."""

    def test_collect_raises(self):
        collector = USBCollector()
        with pytest.raises(NotImplementedError):
            collector.collect()


class TestMacOSUSBCollector:
    """Test MacOSUSBCollector."""

    @patch("subprocess.run")
    def test_collect_parses_json(self, mock_run):
        """Parses system_profiler JSON output correctly."""
        data = {
            "SPUSBDataType": [
                {
                    "_name": "USB Bus",
                    "_items": [
                        {
                            "_name": "Kingston DataTraveler",
                            "vendor_id": "0x0930",
                            "product_id": "0x6545",
                            "serial_num": "ABC123",
                            "manufacturer": "Kingston",
                            "location_id": "0x14100000",
                            "device_speed": "super_speed",
                        }
                    ],
                }
            ]
        }
        mock_run.return_value = Mock(returncode=0, stdout=json.dumps(data), stderr="")

        collector = MacOSUSBCollector()
        devices = collector.collect()

        assert len(devices) == 1
        assert devices[0].name == "Kingston DataTraveler"
        assert devices[0].vendor_id == "0x0930"

    @patch("subprocess.run")
    def test_collect_nonzero_returncode(self, mock_run):
        """Non-zero returncode returns empty list."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")
        collector = MacOSUSBCollector()
        devices = collector.collect()
        assert devices == []

    @patch("subprocess.run")
    def test_collect_timeout(self, mock_run):
        """Timeout returns empty list."""
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)
        collector = MacOSUSBCollector()
        devices = collector.collect()
        assert devices == []

    @patch("subprocess.run")
    def test_collect_json_error(self, mock_run):
        """Invalid JSON returns empty list."""
        mock_run.return_value = Mock(returncode=0, stdout="not json", stderr="")
        collector = MacOSUSBCollector()
        devices = collector.collect()
        assert devices == []

    @patch("subprocess.run")
    def test_collect_general_exception(self, mock_run):
        """General exception returns empty list."""
        mock_run.side_effect = RuntimeError("boom")
        collector = MacOSUSBCollector()
        devices = collector.collect()
        assert devices == []

    @patch("subprocess.run")
    def test_collect_nested_items(self, mock_run):
        """Nested _items (USB hubs with children) are parsed."""
        data = {
            "SPUSBDataType": [
                {
                    "_name": "USB Bus",
                    "_items": [
                        {
                            "_name": "Hub",
                            "_items": [
                                {
                                    "_name": "Mouse",
                                    "vendor_id": "046d",
                                    "product_id": "c077",
                                    "serial_num": "",
                                    "manufacturer": "Logitech",
                                    "location_id": "0x01",
                                    "device_speed": "full_speed",
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        mock_run.return_value = Mock(returncode=0, stdout=json.dumps(data), stderr="")
        collector = MacOSUSBCollector()
        devices = collector.collect()
        # Hub itself (if _name != "USB") + Mouse
        assert len(devices) >= 1

    @patch("subprocess.run")
    def test_collect_skips_usb_root(self, mock_run):
        """Items named 'USB' (root bus) are skipped."""
        data = {
            "SPUSBDataType": [
                {
                    "_name": "USB",
                    "_items": [
                        {
                            "_name": "RealDevice",
                            "vendor_id": "1234",
                            "product_id": "5678",
                        }
                    ],
                }
            ]
        }
        mock_run.return_value = Mock(returncode=0, stdout=json.dumps(data), stderr="")
        collector = MacOSUSBCollector()
        devices = collector.collect()
        # "USB" item is skipped, but its child "RealDevice" should be found
        assert any(d.name == "RealDevice" for d in devices)


class TestLinuxUSBCollector:
    """Test LinuxUSBCollector."""

    @patch("subprocess.run")
    def test_collect_parses_lsusb(self, mock_run):
        """Parses standard lsusb output."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Bus 001 Device 002: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
            "Bus 002 Device 003: ID 0930:6545 Kingston DataTraveler\n",
            stderr="",
        )
        collector = LinuxUSBCollector()
        devices = collector.collect()

        assert len(devices) == 2
        assert devices[1].name == "Kingston DataTraveler"
        assert devices[1].vendor_id == "0930"

    @patch("subprocess.run")
    def test_collect_lsusb_v_failure_falls_back(self, mock_run):
        """lsusb -v failure falls back to lsusb (simple)."""
        calls = []

        def side_effect(*args, **kwargs):
            cmd = args[0]
            calls.append(cmd)
            if "-v" in cmd:
                return Mock(returncode=1, stdout="", stderr="error")
            return Mock(
                returncode=0,
                stdout="Bus 001 Device 001: ID 1d6b:0002 Linux Foundation Hub\n",
                stderr="",
            )

        mock_run.side_effect = side_effect
        collector = LinuxUSBCollector()
        devices = collector.collect()

        assert len(calls) == 2
        assert len(devices) == 1

    @patch("subprocess.run")
    def test_collect_timeout(self, mock_run):
        """Timeout returns empty list."""
        mock_run.side_effect = subprocess.TimeoutExpired("lsusb", 10)
        collector = LinuxUSBCollector()
        devices = collector.collect()
        assert devices == []

    @patch("subprocess.run")
    def test_collect_general_exception(self, mock_run):
        """General exception returns empty list."""
        mock_run.side_effect = OSError("no lsusb")
        collector = LinuxUSBCollector()
        devices = collector.collect()
        assert devices == []


class TestGetUSBCollector:
    """Test platform-specific collector factory."""

    @patch("amoskys.agents.shared.peripheral.probes.platform")
    def test_darwin(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        assert isinstance(get_usb_collector(), MacOSUSBCollector)

    @patch("amoskys.agents.shared.peripheral.probes.platform")
    def test_linux(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        assert isinstance(get_usb_collector(), LinuxUSBCollector)

    @patch("amoskys.agents.shared.peripheral.probes.platform")
    def test_unsupported(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        # Falls back to MacOSUSBCollector
        assert isinstance(get_usb_collector(), MacOSUSBCollector)


# =============================================================================
# 1. USBInventoryProbe
# =============================================================================


class TestUSBInventoryProbe:
    """Tests for USBInventoryProbe."""

    def test_inventory_snapshot(self):
        """Probe returns inventory event and stores devices in shared_data."""
        probe = USBInventoryProbe()
        probe.collector = MagicMock()
        probe.collector.collect.return_value = [
            _usb("d1", "Mouse"),
            _usb("d2", "Keyboard"),
        ]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].event_type == "usb_inventory_snapshot"
        assert events[0].data["device_count"] == 2
        assert len(ctx.shared_data["usb_devices"]) == 2

    def test_empty_inventory(self):
        """No devices returns inventory event with count 0."""
        probe = USBInventoryProbe()
        probe.collector = MagicMock()
        probe.collector.collect.return_value = []
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].data["device_count"] == 0


# =============================================================================
# 2. USBConnectionEdgeProbe
# =============================================================================


class TestUSBConnectionEdgeProbe:
    """Tests for USBConnectionEdgeProbe."""

    def test_first_run_baseline(self):
        """First run establishes baseline, no events."""
        probe = USBConnectionEdgeProbe()
        probe.collector = MagicMock()
        probe.collector.collect.return_value = [_usb("d1", "Mouse")]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert events == []
        assert probe.first_run is False
        assert "d1" in probe.known_devices

    def test_new_device_connected(self):
        """New device after baseline triggers connect event."""
        probe = USBConnectionEdgeProbe()
        probe.collector = MagicMock()
        probe.first_run = False
        probe.known_devices = {"d1": _usb("d1", "Mouse")}

        probe.collector.collect.return_value = [
            _usb("d1", "Mouse"),
            _usb("d2", "USB Flash Drive"),
        ]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].event_type == "usb_device_connected"
        assert events[0].data["device_id"] == "d2"
        assert events[0].severity == Severity.MEDIUM

    def test_device_disconnected(self):
        """Device removal triggers disconnect event."""
        probe = USBConnectionEdgeProbe()
        probe.collector = MagicMock()
        probe.first_run = False
        probe.known_devices = {
            "d1": _usb("d1", "Mouse"),
            "d2": _usb("d2", "Keyboard"),
        }

        probe.collector.collect.return_value = [_usb("d1", "Mouse")]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].event_type == "usb_device_disconnected"
        assert events[0].data["device_id"] == "d2"

    def test_simultaneous_connect_disconnect(self):
        """Connect and disconnect at the same time."""
        probe = USBConnectionEdgeProbe()
        probe.collector = MagicMock()
        probe.first_run = False
        probe.known_devices = {"d1": _usb("d1", "Old")}

        probe.collector.collect.return_value = [_usb("d2", "New")]
        ctx = _ctx()

        events = probe.scan(ctx)

        types = {e.event_type for e in events}
        assert "usb_device_connected" in types
        assert "usb_device_disconnected" in types


# =============================================================================
# 3. USBStorageProbe
# =============================================================================


class TestUSBStorageProbe:
    """Tests for USBStorageProbe."""

    def test_storage_class_code_detected(self):
        """Device with class code '08' is detected as storage."""
        probe = USBStorageProbe()
        probe.collector = MagicMock()
        device = _usb("d1", "Generic", device_class="08")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].event_type == "usb_storage_detected"

    def test_storage_vendor_pattern_detected(self):
        """Device with storage vendor name is detected."""
        probe = USBStorageProbe()
        probe.collector = MagicMock()
        device = _usb("d2", "SanDisk Cruzer")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 1

    def test_storage_keyword_detected(self):
        """Device with 'flash' in name is detected as storage."""
        probe = USBStorageProbe()
        probe.collector = MagicMock()
        device = _usb("d3", "USB Flash Drive")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 1

    def test_non_storage_device(self):
        """Non-storage device does not trigger event."""
        probe = USBStorageProbe()
        probe.collector = MagicMock()
        device = _usb("d4", "Logitech Mouse", vendor_id="046d")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 0

    def test_known_storage_not_re_alerted(self):
        """Already-seen storage device does not trigger again."""
        probe = USBStorageProbe()
        probe.collector = MagicMock()
        probe.known_storage = {"d1"}
        device = _usb("d1", "Kingston Flash", device_class="08")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 0

    def test_falls_back_to_collector(self):
        """When usb_devices not in shared_data, uses collector."""
        probe = USBStorageProbe()
        probe.collector = MagicMock()
        probe.collector.collect.return_value = [_usb("d5", "Samsung Drive")]
        ctx = _ctx()  # No usb_devices in shared_data

        events = probe.scan(ctx)

        probe.collector.collect.assert_called_once()
        assert len(events) == 1


# =============================================================================
# 4. USBNetworkAdapterProbe
# =============================================================================


class TestUSBNetworkAdapterProbe:
    """Tests for USBNetworkAdapterProbe."""

    def test_network_vendor_detected(self):
        """Known network vendor ID triggers event."""
        probe = USBNetworkAdapterProbe()
        probe.collector = MagicMock()
        device = _usb("net1", "USB Adapter", vendor_id="0b95")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].event_type == "usb_network_adapter_detected"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["mitm_risk"] is True

    def test_network_name_pattern_detected(self):
        """Device with 'ethernet' in name triggers event."""
        probe = USBNetworkAdapterProbe()
        probe.collector = MagicMock()
        device = _usb("net2", "USB Ethernet Adapter")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 1

    def test_wifi_pattern_detected(self):
        """Device with 'wifi' in name triggers event."""
        probe = USBNetworkAdapterProbe()
        probe.collector = MagicMock()
        device = _usb("net3", "TP-Link WiFi Adapter")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 1

    def test_non_network_device(self):
        """Non-network device does not trigger event."""
        probe = USBNetworkAdapterProbe()
        probe.collector = MagicMock()
        device = _usb("other", "Logitech Webcam")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 0

    def test_known_network_not_re_alerted(self):
        """Already-seen network adapter not re-alerted."""
        probe = USBNetworkAdapterProbe()
        probe.collector = MagicMock()
        probe.known_network = {"net1"}
        device = _usb("net1", "USB Ethernet", vendor_id="0b95")
        ctx = _ctx(usb_devices=[device])

        events = probe.scan(ctx)

        assert len(events) == 0


# =============================================================================
# 5. HIDKeyboardMouseAnomalyProbe
# =============================================================================


class TestHIDKeyboardMouseAnomalyProbe:
    """Tests for HIDKeyboardMouseAnomalyProbe."""

    def test_first_run_baseline(self):
        """First run establishes keyboard count baseline."""
        probe = HIDKeyboardMouseAnomalyProbe()
        probe.collector = MagicMock()
        probe.collector.collect.return_value = [_usb("kb1", "Apple Keyboard")]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert events == []
        assert probe.keyboard_count_baseline == 1

    def test_new_keyboard_detected(self):
        """New keyboard above baseline triggers HIGH event."""
        probe = HIDKeyboardMouseAnomalyProbe()
        probe.collector = MagicMock()
        probe.keyboard_count_baseline = 1

        probe.collector.collect.return_value = [
            _usb("kb1", "Apple Keyboard"),
            _usb("kb2", "Unknown HID Device"),
        ]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) >= 1
        assert events[0].event_type == "new_keyboard_detected"
        assert events[0].data["badusb_risk"] is True

    def test_known_attack_device_critical(self):
        """Known attack device vendor/product triggers CRITICAL."""
        probe = HIDKeyboardMouseAnomalyProbe()
        probe.collector = MagicMock()
        probe.keyboard_count_baseline = 0

        # Arduino Leonardo (2341:8036) with "HID" in name to pass _is_keyboard
        device = _usb(
            "atk1",
            "Arduino HID Device",
            vendor_id="2341",
            product_id="8036",
        )
        probe.collector.collect.return_value = [device]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) >= 1
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["known_attack_device"] is True

    def test_no_extra_keyboards_no_event(self):
        """Same number of keyboards as baseline => no event."""
        probe = HIDKeyboardMouseAnomalyProbe()
        probe.collector = MagicMock()
        probe.keyboard_count_baseline = 1

        probe.collector.collect.return_value = [_usb("kb1", "Apple Keyboard")]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) == 0

    def test_already_alerted_device_skipped(self):
        """Previously alerted device is not re-alerted."""
        probe = HIDKeyboardMouseAnomalyProbe()
        probe.collector = MagicMock()
        probe.keyboard_count_baseline = 0
        probe.alerted_devices = {"kb1"}

        probe.collector.collect.return_value = [_usb("kb1", "HID Keyboard")]
        ctx = _ctx()

        events = probe.scan(ctx)

        assert len(events) == 0

    def test_is_keyboard_detection(self):
        """_is_keyboard detects keyboards by name keywords."""
        probe = HIDKeyboardMouseAnomalyProbe()
        assert probe._is_keyboard(_usb("x", "Apple Keyboard")) is True
        assert probe._is_keyboard(_usb("x", "Generic HID Device")) is True
        assert probe._is_keyboard(_usb("x", "USB Input Controller")) is True
        assert probe._is_keyboard(_usb("x", "Logitech Mouse")) is False

    def test_uses_shared_data_devices(self):
        """When usb_devices in shared_data, uses those instead of collector."""
        probe = HIDKeyboardMouseAnomalyProbe()
        probe.collector = MagicMock()
        probe.keyboard_count_baseline = 0

        devices = [_usb("kb1", "HID Keyboard")]
        ctx = _ctx(usb_devices=devices)

        events = probe.scan(ctx)

        probe.collector.collect.assert_not_called()
        assert len(events) >= 1


# =============================================================================
# 6. BluetoothDeviceProbe
# =============================================================================


class TestBluetoothDeviceProbe:
    """Tests for BluetoothDeviceProbe."""

    def test_new_bluetooth_device_detected(self):
        """New Bluetooth device triggers event."""
        probe = BluetoothDeviceProbe()
        bt_device = BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="JBL Speaker",
            device_type="audio",
            connected=True,
            paired=True,
        )
        with patch.object(
            probe, "_collect_bluetooth_devices", return_value=[bt_device]
        ):
            events = probe.scan(_ctx())

        assert len(events) == 1
        assert events[0].event_type == "bluetooth_device_detected"
        assert events[0].data["address"] == "AA:BB:CC:DD:EE:FF"

    def test_known_bluetooth_device_no_event(self):
        """Already-known Bluetooth device does not trigger."""
        probe = BluetoothDeviceProbe()
        bt_device = BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Known",
            device_type="audio",
            connected=True,
            paired=True,
        )
        probe.known_devices["AA:BB:CC:DD:EE:FF"] = bt_device

        with patch.object(
            probe, "_collect_bluetooth_devices", return_value=[bt_device]
        ):
            events = probe.scan(_ctx())

        assert len(events) == 0

    @patch("amoskys.agents.shared.peripheral.probes.platform")
    @patch("subprocess.run")
    def test_linux_bluetooth_collector(self, mock_run, mock_platform):
        """Linux bluetoothctl output is parsed."""
        mock_platform.system.return_value = "Linux"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Device AA:BB:CC:DD:EE:FF JBL Flip\nDevice 11:22:33:44:55:66 AirPods\n",
        )

        probe = BluetoothDeviceProbe()
        devices = probe._collect_bluetooth_devices()

        assert len(devices) == 2
        assert devices[0].address == "AA:BB:CC:DD:EE:FF"
        assert devices[1].name == "AirPods"

    @patch("amoskys.agents.shared.peripheral.probes.platform")
    @patch("subprocess.run")
    def test_linux_bluetooth_failure(self, mock_run, mock_platform):
        """Linux bluetoothctl failure returns empty list."""
        mock_platform.system.return_value = "Linux"
        mock_run.side_effect = FileNotFoundError("bluetoothctl not found")

        probe = BluetoothDeviceProbe()
        devices = probe._collect_bluetooth_devices()

        assert devices == []

    @patch("amoskys.agents.shared.peripheral.probes.platform")
    @patch("subprocess.run")
    def test_darwin_bluetooth_collector(self, mock_run, mock_platform):
        """macOS system_profiler Bluetooth is called."""
        mock_platform.system.return_value = "Darwin"
        mock_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps({"SPBluetoothDataType": []}),
        )

        probe = BluetoothDeviceProbe()
        devices = probe._collect_bluetooth_devices()

        # macOS parsing is simplified; just verify it doesn't crash
        assert isinstance(devices, list)

    @patch("amoskys.agents.shared.peripheral.probes.platform")
    def test_unsupported_platform(self, mock_platform):
        """Unsupported platform returns empty list."""
        mock_platform.system.return_value = "Windows"

        probe = BluetoothDeviceProbe()
        devices = probe._collect_bluetooth_devices()

        assert devices == []


# =============================================================================
# 7. HighRiskPeripheralScoreProbe
# =============================================================================


class TestHighRiskPeripheralScoreProbe:
    """Tests for HighRiskPeripheralScoreProbe."""

    def test_high_risk_score(self):
        """Multiple risk factors produce HIGH severity event."""
        probe = HighRiskPeripheralScoreProbe()
        probe.collector = MagicMock()

        devices = [
            _usb("s1", "USB storage device", manufacturer=""),
            _usb("n1", "USB network adapter", manufacturer=""),
            _usb("k1", "keyboard device", manufacturer=""),
            _usb("k2", "keyboard device #2", manufacturer=""),
        ]
        ctx = _ctx(usb_devices=devices)

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].event_type == "peripheral_risk_assessment"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["risk_score"] > 0.6

    def test_medium_risk_score(self):
        """Two storage devices produce MEDIUM severity (0.4 > 0.2 threshold)."""
        probe = HighRiskPeripheralScoreProbe()
        probe.collector = MagicMock()

        devices = [
            _usb("s1", "USB storage device"),
            _usb("s2", "USB storage stick"),
            _usb("m1", "Mouse"),
        ]
        ctx = _ctx(usb_devices=devices)

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].severity == Severity.MEDIUM

    def test_low_risk_no_event(self):
        """Normal devices with no risk factors produce no event."""
        probe = HighRiskPeripheralScoreProbe()
        probe.collector = MagicMock()

        devices = [_usb("m1", "Mouse", manufacturer="Logitech")]
        ctx = _ctx(usb_devices=devices)

        events = probe.scan(ctx)

        assert len(events) == 0

    def test_empty_devices_no_event(self):
        """No devices means no risk."""
        probe = HighRiskPeripheralScoreProbe()
        probe.collector = MagicMock()
        ctx = _ctx(usb_devices=[])

        events = probe.scan(ctx)

        assert len(events) == 0

    def test_risk_capped_at_one(self):
        """Risk score is capped at 1.0."""
        probe = HighRiskPeripheralScoreProbe()
        probe.collector = MagicMock()

        # Many risky devices
        devices = [
            _usb(f"s{i}", "USB storage device", manufacturer="") for i in range(10)
        ] + [_usb(f"n{i}", "USB network adapter", manufacturer="") for i in range(5)]
        ctx = _ctx(usb_devices=devices)

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].data["risk_score"] <= 1.0

    def test_unknown_manufacturer_risk(self):
        """Devices with empty manufacturer add risk."""
        probe = HighRiskPeripheralScoreProbe()
        probe.collector = MagicMock()

        devices = [
            _usb("u1", "Unknown1", manufacturer=""),
            _usb("u2", "Unknown2", manufacturer=""),
        ]
        ctx = _ctx(usb_devices=devices)

        events = probe.scan(ctx)

        assert len(events) == 1
        assert events[0].data["unknown_count"] == 2

    def test_falls_back_to_collector(self):
        """Without shared_data usb_devices, uses collector."""
        probe = HighRiskPeripheralScoreProbe()
        probe.collector = MagicMock()
        probe.collector.collect.return_value = [
            _usb("s1", "USB storage", manufacturer="")
        ]
        ctx = _ctx()  # No usb_devices

        events = probe.scan(ctx)

        probe.collector.collect.assert_called_once()


# =============================================================================
# Factory
# =============================================================================


class TestPeripheralProbesFactory:
    """Test factory function."""

    def test_creates_seven_probes(self):
        probes = create_peripheral_probes()
        assert len(probes) == 7

    def test_probe_names_unique(self):
        names = [p.name for p in create_peripheral_probes()]
        assert len(names) == len(set(names))

    def test_peripheral_probes_list(self):
        assert len(PERIPHERAL_PROBES) == 7
