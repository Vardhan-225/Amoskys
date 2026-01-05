"""Peripheral Agent Micro-Probes - 7 Eyes Watching Physical Device Activity.

Each probe monitors ONE specific peripheral threat vector:

    1. USBInventoryProbe - Complete USB device inventory
    2. USBConnectionEdgeProbe - New device connect/disconnect events
    3. USBStorageProbe - USB storage device monitoring
    4. USBNetworkAdapterProbe - USB network adapter detection
    5. HIDKeyboardMouseAnomalyProbe - Keystroke injection detection
    6. BluetoothDeviceProbe - Bluetooth device monitoring
    7. HighRiskPeripheralScoreProbe - Overall peripheral risk scoring

MITRE ATT&CK Coverage:
    - T1200: Hardware Additions
    - T1091: Replication Through Removable Media
    - T1052: Exfiltration Over Physical Medium
    - T1056.001: Input Capture: Keylogging
    - T1557: Adversary-in-the-Middle (USB network)
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Shared Data Structures
# =============================================================================


@dataclass
class USBDevice:
    """Represents a USB device."""

    device_id: str  # Unique identifier
    name: str
    vendor_id: str
    product_id: str
    serial_number: str
    manufacturer: str
    location_id: str
    device_speed: str
    device_class: str = ""  # Mass Storage, HID, Network, etc.
    is_authorized: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class BluetoothDevice:
    """Represents a Bluetooth device."""

    address: str
    name: str
    device_type: str  # keyboard, mouse, headset, etc.
    connected: bool
    paired: bool
    rssi: int = 0


# =============================================================================
# Platform-Specific USB Collectors
# =============================================================================


class USBCollector:
    """Base class for platform-specific USB collection."""

    def collect(self) -> List[USBDevice]:
        """Collect USB devices from system."""
        raise NotImplementedError


class MacOSUSBCollector(USBCollector):
    """Collects USB devices on macOS using system_profiler."""

    def collect(self) -> List[USBDevice]:
        """Collect USB devices via system_profiler."""
        devices = []

        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                logger.error(f"system_profiler failed: {result.stderr}")
                return devices

            data = json.loads(result.stdout)

            def parse_usb_tree(items: List[Dict], devices_list: List[USBDevice]):
                for item in items:
                    if "_name" in item and item.get("_name") != "USB":
                        vendor_id = item.get("vendor_id", "")
                        product_id = item.get("product_id", "")
                        serial = item.get("serial_num", "")

                        # Create unique device ID
                        id_str = f"{vendor_id}:{product_id}:{serial}"
                        device_id = hashlib.md5(id_str.encode()).hexdigest()[:16]

                        device = USBDevice(
                            device_id=device_id,
                            name=item.get("_name", "Unknown"),
                            vendor_id=vendor_id,
                            product_id=product_id,
                            serial_number=serial,
                            manufacturer=item.get("manufacturer", ""),
                            location_id=item.get("location_id", ""),
                            device_speed=item.get("device_speed", ""),
                        )
                        devices_list.append(device)

                    # Recursively parse children
                    if "_items" in item:
                        parse_usb_tree(item["_items"], devices_list)

            if "SPUSBDataType" in data:
                for bus in data["SPUSBDataType"]:
                    if "_items" in bus:
                        parse_usb_tree(bus["_items"], devices)

        except subprocess.TimeoutExpired:
            logger.error("USB scan timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse USB JSON: {e}")
        except Exception as e:
            logger.error(f"Failed to collect USB devices: {e}")

        return devices


class LinuxUSBCollector(USBCollector):
    """Collects USB devices on Linux using lsusb."""

    def collect(self) -> List[USBDevice]:
        """Collect USB devices via lsusb."""
        devices = []

        try:
            result = subprocess.run(
                ["lsusb", "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                # Try simpler lsusb
                result = subprocess.run(
                    ["lsusb"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

            if result.returncode == 0:
                # Parse lsusb output
                # Format: Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
                for line in result.stdout.splitlines():
                    match = re.match(
                        r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]+):([0-9a-fA-F]+)\s+(.*)",
                        line,
                    )
                    if match:
                        bus, dev, vendor_id, product_id, name = match.groups()

                        device_id = hashlib.md5(
                            f"{vendor_id}:{product_id}:{bus}:{dev}".encode()
                        ).hexdigest()[:16]

                        device = USBDevice(
                            device_id=device_id,
                            name=name.strip(),
                            vendor_id=vendor_id,
                            product_id=product_id,
                            serial_number="",
                            manufacturer="",
                            location_id=f"Bus {bus} Device {dev}",
                            device_speed="",
                        )
                        devices.append(device)

        except subprocess.TimeoutExpired:
            logger.error("USB scan timed out")
        except Exception as e:
            logger.error(f"Failed to collect USB devices: {e}")

        return devices


def get_usb_collector() -> USBCollector:
    """Get platform-appropriate USB collector."""
    system = platform.system()
    if system == "Darwin":
        return MacOSUSBCollector()
    elif system == "Linux":
        return LinuxUSBCollector()
    else:
        logger.warning(f"Unsupported platform for USB: {system}")
        return MacOSUSBCollector()


# =============================================================================
# 1. USBInventoryProbe
# =============================================================================


class USBInventoryProbe(MicroProbe):
    """Maintains complete USB device inventory.

    Produces a snapshot of all connected USB devices for baseline tracking.

    MITRE: T1200 (Hardware Additions)
    """

    name = "usb_inventory"
    description = "Maintains complete USB device inventory"
    mitre_techniques = ["T1200"]
    mitre_tactics = ["initial_access"]
    scan_interval = 60.0  # Full inventory every minute

    def __init__(self) -> None:
        super().__init__()
        self.collector = get_usb_collector()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Generate USB inventory snapshot."""
        events = []

        devices = self.collector.collect()

        # Store devices in shared data for other probes
        context.shared_data["usb_devices"] = devices

        # Generate inventory event
        events.append(
            self._create_event(
                event_type="usb_inventory_snapshot",
                severity=Severity.DEBUG,
                data={
                    "device_count": len(devices),
                    "devices": [
                        {
                            "device_id": d.device_id,
                            "name": d.name,
                            "vendor_id": d.vendor_id,
                            "product_id": d.product_id,
                            "manufacturer": d.manufacturer,
                        }
                        for d in devices
                    ],
                },
                confidence=1.0,
            )
        )

        return events


# =============================================================================
# 2. USBConnectionEdgeProbe
# =============================================================================


class USBConnectionEdgeProbe(MicroProbe):
    """Detects USB device connect/disconnect events.

    Tracks changes in USB device inventory to detect when devices are
    plugged in or removed.

    MITRE: T1200 (Hardware Additions), T1091 (Removable Media)
    """

    name = "usb_connection_edge"
    description = "Detects USB device connect/disconnect events"
    mitre_techniques = ["T1200", "T1091"]
    mitre_tactics = ["initial_access", "lateral_movement"]
    scan_interval = 5.0

    def __init__(self) -> None:
        super().__init__()
        self.known_devices: Dict[str, USBDevice] = {}
        self.collector = get_usb_collector()
        self.first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect USB connect/disconnect events."""
        events = []

        current_devices = self.collector.collect()
        current_ids = {d.device_id: d for d in current_devices}

        # Skip first run (establish baseline)
        if self.first_run:
            self.known_devices = current_ids
            self.first_run = False
            return events

        # Detect new connections
        for device_id, device in current_ids.items():
            if device_id not in self.known_devices:
                events.append(
                    self._create_event(
                        event_type="usb_device_connected",
                        severity=Severity.MEDIUM,
                        data={
                            "device_id": device_id,
                            "name": device.name,
                            "vendor_id": device.vendor_id,
                            "product_id": device.product_id,
                            "manufacturer": device.manufacturer,
                            "serial_number": device.serial_number,
                        },
                        confidence=1.0,
                    )
                )

        # Detect disconnections
        for device_id, device in self.known_devices.items():
            if device_id not in current_ids:
                events.append(
                    self._create_event(
                        event_type="usb_device_disconnected",
                        severity=Severity.INFO,
                        data={
                            "device_id": device_id,
                            "name": device.name,
                            "vendor_id": device.vendor_id,
                            "product_id": device.product_id,
                        },
                        confidence=1.0,
                    )
                )

        # Update known devices
        self.known_devices = current_ids

        return events


# =============================================================================
# 3. USBStorageProbe
# =============================================================================


class USBStorageProbe(MicroProbe):
    """Monitors USB storage devices.

    Tracks USB mass storage for potential data exfiltration.

    MITRE: T1052 (Exfiltration Over Physical Medium), T1091 (Removable Media)
    """

    name = "usb_storage"
    description = "Monitors USB storage devices for exfiltration risk"
    mitre_techniques = ["T1052", "T1091"]
    mitre_tactics = ["exfiltration", "lateral_movement"]
    scan_interval = 10.0

    # USB Mass Storage class code
    STORAGE_CLASS_CODES = {"08", "8"}  # Mass Storage

    # Known storage vendor IDs (common USB drives)
    STORAGE_VENDOR_PATTERNS = [
        r"sandisk",
        r"kingston",
        r"lexar",
        r"samsung",
        r"seagate",
        r"western.*digital",
        r"toshiba",
        r"pny",
        r"corsair",
    ]

    def __init__(self) -> None:
        super().__init__()
        self.collector = get_usb_collector()
        self.known_storage: Set[str] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Monitor USB storage devices."""
        events = []

        devices = context.shared_data.get("usb_devices") or self.collector.collect()

        for device in devices:
            is_storage = self._is_storage_device(device)

            if is_storage and device.device_id not in self.known_storage:
                self.known_storage.add(device.device_id)

                events.append(
                    self._create_event(
                        event_type="usb_storage_detected",
                        severity=Severity.MEDIUM,
                        data={
                            "device_id": device.device_id,
                            "name": device.name,
                            "vendor_id": device.vendor_id,
                            "product_id": device.product_id,
                            "manufacturer": device.manufacturer,
                            "exfiltration_risk": True,
                        },
                        confidence=0.9,
                    )
                )

        return events

    def _is_storage_device(self, device: USBDevice) -> bool:
        """Check if device is a storage device."""
        # Check class code
        if device.device_class in self.STORAGE_CLASS_CODES:
            return True

        # Check name patterns
        name_lower = device.name.lower()
        for pattern in self.STORAGE_VENDOR_PATTERNS:
            if re.search(pattern, name_lower):
                return True

        # Check for common storage keywords
        storage_keywords = ["flash", "disk", "drive", "storage", "thumb", "memory"]
        if any(kw in name_lower for kw in storage_keywords):
            return True

        return False


# =============================================================================
# 4. USBNetworkAdapterProbe
# =============================================================================


class USBNetworkAdapterProbe(MicroProbe):
    """Detects USB network adapters.

    USB network adapters can be used for MITM attacks or to bypass
    network security controls.

    MITRE: T1557 (Adversary-in-the-Middle), T1200 (Hardware Additions)
    """

    name = "usb_network_adapter"
    description = "Detects USB network adapters (potential MITM)"
    mitre_techniques = ["T1557", "T1200"]
    mitre_tactics = ["credential_access", "initial_access"]
    scan_interval = 30.0

    # Known network adapter vendor IDs (partial list)
    NETWORK_PATTERNS = [
        r"ethernet",
        r"network",
        r"wifi",
        r"wireless",
        r"lan.*adapter",
        r"usb.*nic",
        r"rndis",  # USB network protocol
        r"802\.11",
    ]

    # Known USB network adapter vendors
    NETWORK_VENDORS = {
        "0b95",  # ASIX Electronics (Ethernet)
        "2357",  # TP-Link
        "0bda",  # Realtek (many WiFi adapters)
        "148f",  # Ralink
        "0cf3",  # Qualcomm Atheros
        "7392",  # Edimax
        "050d",  # Belkin
    }

    def __init__(self) -> None:
        super().__init__()
        self.collector = get_usb_collector()
        self.known_network: Set[str] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect USB network adapters."""
        events = []

        devices = context.shared_data.get("usb_devices") or self.collector.collect()

        for device in devices:
            is_network = self._is_network_adapter(device)

            if is_network and device.device_id not in self.known_network:
                self.known_network.add(device.device_id)

                events.append(
                    self._create_event(
                        event_type="usb_network_adapter_detected",
                        severity=Severity.HIGH,
                        data={
                            "device_id": device.device_id,
                            "name": device.name,
                            "vendor_id": device.vendor_id,
                            "product_id": device.product_id,
                            "manufacturer": device.manufacturer,
                            "mitm_risk": True,
                        },
                        confidence=0.85,
                    )
                )

        return events

    def _is_network_adapter(self, device: USBDevice) -> bool:
        """Check if device is a network adapter."""
        # Check vendor ID
        if device.vendor_id.lower() in self.NETWORK_VENDORS:
            return True

        # Check name patterns
        name_lower = device.name.lower()
        for pattern in self.NETWORK_PATTERNS:
            if re.search(pattern, name_lower):
                return True

        return False


# =============================================================================
# 5. HIDKeyboardMouseAnomalyProbe
# =============================================================================


class HIDKeyboardMouseAnomalyProbe(MicroProbe):
    """Detects suspicious HID devices (keystroke injection).

    BadUSB and Rubber Ducky attacks use HID devices to inject keystrokes.
    This probe detects multiple keyboards or suspicious HID behavior.

    MITRE: T1200 (Hardware Additions), T1056.001 (Keylogging)
    """

    name = "hid_anomaly"
    description = "Detects suspicious HID devices (keystroke injection)"
    mitre_techniques = ["T1200", "T1056.001"]
    mitre_tactics = ["initial_access", "collection"]
    scan_interval = 10.0

    # Known attack device vendor/product IDs
    KNOWN_ATTACK_DEVICES = {
        ("05ac", "0227"),  # Fake Apple keyboard (common clone)
        ("1d6b", "0001"),  # Generic USB keyboard
        ("feed", "6969"),  # Rubber Ducky (joke ID)
        ("1b4f", "9206"),  # SparkFun (often used for DIY HID)
        ("2341", "8036"),  # Arduino Leonardo (HID capable)
        ("16c0", "0486"),  # Teensy (HID capable)
    }

    def __init__(self) -> None:
        super().__init__()
        self.collector = get_usb_collector()
        self.keyboard_count_baseline: Optional[int] = None
        self.alerted_devices: Set[str] = set()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Detect HID anomalies."""
        events = []

        devices = context.shared_data.get("usb_devices") or self.collector.collect()

        # Count keyboards
        keyboards = [d for d in devices if self._is_keyboard(d)]

        # Establish baseline
        if self.keyboard_count_baseline is None:
            self.keyboard_count_baseline = len(keyboards)
            return events

        # Detect new keyboard (potential BadUSB)
        if len(keyboards) > self.keyboard_count_baseline:
            for kb in keyboards:
                if kb.device_id not in self.alerted_devices:
                    self.alerted_devices.add(kb.device_id)

                    # Check if it's a known attack device
                    is_known_attack = (
                        kb.vendor_id.lower(),
                        kb.product_id.lower(),
                    ) in self.KNOWN_ATTACK_DEVICES

                    severity = Severity.CRITICAL if is_known_attack else Severity.HIGH

                    events.append(
                        self._create_event(
                            event_type="new_keyboard_detected",
                            severity=severity,
                            data={
                                "device_id": kb.device_id,
                                "name": kb.name,
                                "vendor_id": kb.vendor_id,
                                "product_id": kb.product_id,
                                "manufacturer": kb.manufacturer,
                                "known_attack_device": is_known_attack,
                                "keyboard_count": len(keyboards),
                                "baseline_count": self.keyboard_count_baseline,
                                "badusb_risk": True,
                            },
                            confidence=0.9 if is_known_attack else 0.7,
                        )
                    )

        return events

    def _is_keyboard(self, device: USBDevice) -> bool:
        """Check if device is a keyboard."""
        name_lower = device.name.lower()
        return any(kw in name_lower for kw in ["keyboard", "hid", "input"])


# =============================================================================
# 6. BluetoothDeviceProbe
# =============================================================================


class BluetoothDeviceProbe(MicroProbe):
    """Monitors Bluetooth devices.

    Tracks Bluetooth connections for potential unauthorized access.

    MITRE: T1200 (Hardware Additions)
    """

    name = "bluetooth_device"
    description = "Monitors Bluetooth device connections"
    mitre_techniques = ["T1200"]
    mitre_tactics = ["initial_access"]
    scan_interval = 30.0
    platforms = ["darwin", "linux"]  # Windows needs different approach

    def __init__(self) -> None:
        super().__init__()
        self.known_devices: Dict[str, BluetoothDevice] = {}

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Monitor Bluetooth devices."""
        events = []

        devices = self._collect_bluetooth_devices()

        for device in devices:
            if device.address not in self.known_devices:
                self.known_devices[device.address] = device

                events.append(
                    self._create_event(
                        event_type="bluetooth_device_detected",
                        severity=Severity.LOW,
                        data={
                            "address": device.address,
                            "name": device.name,
                            "device_type": device.device_type,
                            "connected": device.connected,
                            "paired": device.paired,
                        },
                        confidence=0.9,
                    )
                )

        return events

    def _collect_bluetooth_devices(self) -> List[BluetoothDevice]:
        """Collect Bluetooth devices from system."""
        devices = []
        system = platform.system()

        if system == "Darwin":
            try:
                # Use system_profiler on macOS
                result = subprocess.run(
                    ["system_profiler", "SPBluetoothDataType", "-json"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    # Parse Bluetooth data...
                    # (Simplified - full implementation would parse the JSON)

            except Exception as e:
                logger.debug(f"Failed to collect Bluetooth devices: {e}")

        elif system == "Linux":
            try:
                # Use bluetoothctl on Linux
                result = subprocess.run(
                    ["bluetoothctl", "devices"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        match = re.match(r"Device\s+([0-9A-Fa-f:]+)\s+(.*)", line)
                        if match:
                            address, name = match.groups()
                            devices.append(
                                BluetoothDevice(
                                    address=address,
                                    name=name,
                                    device_type="unknown",
                                    connected=False,
                                    paired=True,
                                )
                            )

            except Exception as e:
                logger.debug(f"Failed to collect Bluetooth devices: {e}")

        return devices


# =============================================================================
# 7. HighRiskPeripheralScoreProbe
# =============================================================================


class HighRiskPeripheralScoreProbe(MicroProbe):
    """Calculates overall peripheral risk score.

    Aggregates signals from other probes to produce a composite risk score.

    MITRE: T1200 (Hardware Additions)
    """

    name = "peripheral_risk_score"
    description = "Calculates overall peripheral risk score"
    mitre_techniques = ["T1200", "T1091", "T1052"]
    mitre_tactics = ["initial_access", "exfiltration"]
    scan_interval = 60.0

    def __init__(self) -> None:
        super().__init__()
        self.collector = get_usb_collector()

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Calculate peripheral risk score."""
        events = []

        devices = context.shared_data.get("usb_devices") or self.collector.collect()

        # Calculate risk factors
        risk_factors = []
        total_risk = 0.0

        # Count device types
        storage_count = sum(1 for d in devices if "storage" in d.name.lower())
        network_count = sum(
            1
            for d in devices
            if any(x in d.name.lower() for x in ["network", "ethernet", "wifi"])
        )
        keyboard_count = sum(1 for d in devices if "keyboard" in d.name.lower())
        unknown_count = sum(1 for d in devices if not d.manufacturer)

        # Score each risk
        if storage_count > 0:
            risk_factors.append(f"USB storage devices: {storage_count}")
            total_risk += 0.2 * storage_count

        if network_count > 0:
            risk_factors.append(f"USB network adapters: {network_count}")
            total_risk += 0.3 * network_count

        if keyboard_count > 1:
            risk_factors.append(f"Multiple keyboards: {keyboard_count}")
            total_risk += 0.4 * (keyboard_count - 1)

        if unknown_count > 0:
            risk_factors.append(f"Unknown manufacturer devices: {unknown_count}")
            total_risk += 0.15 * unknown_count

        # Normalize to 0-1
        total_risk = min(total_risk, 1.0)

        # Only report if risk is notable
        if total_risk > 0.2:
            severity = Severity.HIGH if total_risk > 0.6 else Severity.MEDIUM

            events.append(
                self._create_event(
                    event_type="peripheral_risk_assessment",
                    severity=severity,
                    data={
                        "risk_score": round(total_risk, 2),
                        "risk_factors": risk_factors,
                        "device_count": len(devices),
                        "storage_count": storage_count,
                        "network_count": network_count,
                        "keyboard_count": keyboard_count,
                        "unknown_count": unknown_count,
                    },
                    confidence=0.8,
                )
            )

        return events


# =============================================================================
# Probe Registry
# =============================================================================

PERIPHERAL_PROBES = [
    USBInventoryProbe,
    USBConnectionEdgeProbe,
    USBStorageProbe,
    USBNetworkAdapterProbe,
    HIDKeyboardMouseAnomalyProbe,
    BluetoothDeviceProbe,
    HighRiskPeripheralScoreProbe,
]


def create_peripheral_probes() -> List[MicroProbe]:
    """Create instances of all peripheral probes.

    Returns:
        List of initialized peripheral probe instances
    """
    return [probe_class() for probe_class in PERIPHERAL_PROBES]


__all__ = [
    "BluetoothDevice",
    "BluetoothDeviceProbe",
    "create_peripheral_probes",
    "HighRiskPeripheralScoreProbe",
    "HIDKeyboardMouseAnomalyProbe",
    "PERIPHERAL_PROBES",
    "USBCollector",
    "USBConnectionEdgeProbe",
    "USBDevice",
    "USBInventoryProbe",
    "USBNetworkAdapterProbe",
    "USBStorageProbe",
]
