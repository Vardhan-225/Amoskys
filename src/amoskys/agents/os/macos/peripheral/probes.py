"""macOS Peripheral Probes -- 5 detection probes for hardware peripherals.

Each probe consumes PeripheralDevice data from MacOSPeripheralCollector via
shared_data["usb_devices"], shared_data["bluetooth_devices"], and
shared_data["volumes"]. All probes are macOS-only (platforms=["darwin"]).

Probes:
    1. USBInventoryProbe -- baseline-diff for USB device changes (T1200)
    2. BluetoothInventoryProbe -- baseline-diff for BT device changes (T1200)
    3. NewPeripheralProbe -- alerts on any new peripheral device (T1200)
    4. RemovableMediaProbe -- new volume mounts in /Volumes/ (T1200, T1052.001)
    5. ThunderboltDMAProbe -- baseline-diff for Thunderbolt/DMA devices (T1200, T1052)

Detection pattern: baseline-diff
    First scan establishes the baseline of known devices. Subsequent scans
    compare against the baseline and report additions/removals. This avoids
    false alerts on first run and handles device churn gracefully.

MITRE Coverage:
    - T1200: Hardware Additions (rogue USB/BT devices, Thunderbolt DMA)
    - T1052: Exfiltration Over Physical Medium
    - T1052.001: Exfiltration Over USB (data theft via removable media)
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Dict, List, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)

logger = logging.getLogger(__name__)


def _device_fingerprint(dev: Any) -> str:
    """Create a stable fingerprint for a peripheral device.

    Uses device_type + name + vendor_id + product_id + serial to create
    a unique key that survives reconnection (same physical device).
    Falls back to name-only if IDs are missing (Bluetooth devices).
    """
    parts = [
        dev.device_type,
        dev.name,
        dev.vendor_id or "",
        dev.product_id or "",
        dev.serial or "",
    ]
    return "|".join(parts)


# =============================================================================
# 1. USBInventoryProbe
# =============================================================================


class USBInventoryProbe(MicroProbe):
    """Baseline-diff probe for USB device inventory.

    Tracks known USB devices by fingerprint (vendor_id + product_id + serial).
    Reports new USB devices (additions) and removed USB devices (departures).
    First scan silently establishes the baseline.

    MITRE: T1200 (Hardware Additions)
    """

    name = "macos_usb_inventory"
    description = "Tracks USB device inventory changes on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1200"]
    mitre_tactics = ["initial_access"]
    scan_interval = 30.0
    requires_fields = ["usb_devices", "bluetooth_devices"]

    def __init__(self) -> None:
        super().__init__()
        self._known: Dict[str, Any] = {}  # fingerprint -> device snapshot
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        usb_devices = context.shared_data.get("usb_devices", [])

        current: Dict[str, Any] = {}
        for dev in usb_devices:
            fp = _device_fingerprint(dev)
            current[fp] = dev

            if self._first_run:
                continue

            # New USB device detected
            if fp not in self._known:
                severity = Severity.HIGH if dev.is_storage else Severity.MEDIUM
                events.append(
                    self._create_event(
                        event_type="usb_device_added",
                        severity=severity,
                        data={
                            "probe_name": self.name,
                            "detection_source": "system_profiler",
                            "name": dev.name,
                            "vendor_id": dev.vendor_id,
                            "product_id": dev.product_id,
                            "serial": dev.serial,
                            "manufacturer": dev.manufacturer,
                            "is_storage": dev.is_storage,
                            "mount_point": dev.mount_point,
                            "address": dev.address,
                            "fingerprint": fp,
                        },
                        confidence=0.9,
                        correlation_id=fp,
                    )
                )

        # Detect removed USB devices
        if not self._first_run:
            for fp, dev in self._known.items():
                if fp not in current:
                    events.append(
                        self._create_event(
                            event_type="usb_device_removed",
                            severity=Severity.INFO,
                            data={
                                "probe_name": self.name,
                                "detection_source": "system_profiler",
                                "name": dev.name,
                                "vendor_id": dev.vendor_id,
                                "product_id": dev.product_id,
                                "serial": dev.serial,
                                "fingerprint": fp,
                            },
                            confidence=0.95,
                            correlation_id=fp,
                        )
                    )

        self._known = current
        self._first_run = False
        return events


# =============================================================================
# 2. BluetoothInventoryProbe
# =============================================================================


class BluetoothInventoryProbe(MicroProbe):
    """Baseline-diff probe for Bluetooth device inventory.

    Tracks known Bluetooth devices by fingerprint (name + address).
    Reports new BT pairings/connections and disconnected devices.
    First scan silently establishes the baseline.

    MITRE: T1200 (Hardware Additions)
    """

    name = "macos_bluetooth_inventory"
    description = "Tracks Bluetooth device inventory changes on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1200"]
    mitre_tactics = ["initial_access"]
    scan_interval = 30.0
    requires_fields = ["usb_devices", "bluetooth_devices"]

    def __init__(self) -> None:
        super().__init__()
        self._known: Dict[str, Any] = {}  # fingerprint -> device snapshot
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        bt_devices = context.shared_data.get("bluetooth_devices", [])

        current: Dict[str, Any] = {}
        for dev in bt_devices:
            fp = _device_fingerprint(dev)
            current[fp] = dev

            if self._first_run:
                continue

            # New Bluetooth device detected
            if fp not in self._known:
                events.append(
                    self._create_event(
                        event_type="bluetooth_device_added",
                        severity=Severity.MEDIUM,
                        data={
                            "probe_name": self.name,
                            "detection_source": "system_profiler",
                            "name": dev.name,
                            "address": dev.address,
                            "vendor_id": dev.vendor_id,
                            "product_id": dev.product_id,
                            "manufacturer": dev.manufacturer,
                            "connected": dev.connected,
                            "fingerprint": fp,
                        },
                        confidence=0.85,
                        correlation_id=fp,
                    )
                )

        # Detect removed Bluetooth devices
        if not self._first_run:
            for fp, dev in self._known.items():
                if fp not in current:
                    events.append(
                        self._create_event(
                            event_type="bluetooth_device_removed",
                            severity=Severity.INFO,
                            data={
                                "probe_name": self.name,
                                "detection_source": "system_profiler",
                                "name": dev.name,
                                "address": dev.address,
                                "fingerprint": fp,
                            },
                            confidence=0.9,
                            correlation_id=fp,
                        )
                    )

        self._known = current
        self._first_run = False
        return events


# =============================================================================
# 3. NewPeripheralProbe
# =============================================================================


class NewPeripheralProbe(MicroProbe):
    """Alerts on any new peripheral device (USB or Bluetooth).

    Unified detection probe that fires on ANY new peripheral, regardless of
    type. Uses a combined baseline across USB and Bluetooth devices.
    Higher severity for storage devices (potential data exfil/malware vector).

    MITRE: T1200 (Hardware Additions)
    """

    name = "macos_new_peripheral"
    description = "Alerts on any new peripheral device on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1200"]
    mitre_tactics = ["initial_access"]
    scan_interval = 30.0
    requires_fields = ["usb_devices", "bluetooth_devices"]

    def __init__(self) -> None:
        super().__init__()
        self._known_fingerprints: Set[str] = set()
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []

        usb_devices = context.shared_data.get("usb_devices", [])
        bt_devices = context.shared_data.get("bluetooth_devices", [])
        all_devices = list(usb_devices) + list(bt_devices)

        current_fingerprints: Set[str] = set()

        for dev in all_devices:
            fp = _device_fingerprint(dev)
            current_fingerprints.add(fp)

            if self._first_run:
                continue

            if fp not in self._known_fingerprints:
                # Storage USB devices get HIGH, everything else MEDIUM
                if dev.device_type == "usb" and dev.is_storage:
                    severity = Severity.HIGH
                    confidence = 0.9
                else:
                    severity = Severity.MEDIUM
                    confidence = 0.8

                events.append(
                    self._create_event(
                        event_type="new_peripheral_detected",
                        severity=severity,
                        data={
                            "probe_name": self.name,
                            "detection_source": "system_profiler",
                            "device_type": dev.device_type,
                            "name": dev.name,
                            "vendor_id": dev.vendor_id,
                            "product_id": dev.product_id,
                            "serial": dev.serial,
                            "manufacturer": dev.manufacturer,
                            "is_storage": dev.is_storage,
                            "mount_point": dev.mount_point,
                            "address": dev.address,
                            "fingerprint": fp,
                        },
                        confidence=confidence,
                        correlation_id=fp,
                    )
                )

        self._known_fingerprints = current_fingerprints
        self._first_run = False
        return events


# =============================================================================
# 4. RemovableMediaProbe
# =============================================================================


class RemovableMediaProbe(MicroProbe):
    """Detects new volume mounts in /Volumes/ (removable media).

    Monitors for new volumes appearing in /Volumes/ that are not system
    volumes (Macintosh HD, Recovery, etc.). Removable media mounts indicate
    USB drives, external SSDs, mounted DMGs, or network shares.

    Security concern: USB drives are the primary vector for hardware attacks
    (BadUSB, rubber ducky, data exfiltration via removable media).

    MITRE: T1200 (Hardware Additions) + T1052.001 (Exfiltration Over USB)
    Note: T1091 (Replication Through Removable Media) is Windows-only in ATT&CK.
    macOS removable media maps to T1200 (hardware vector) and T1052.001 (exfil).
    """

    name = "macos_removable_media"
    description = "Detects new removable media mounts on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1200", "T1052.001"]
    mitre_tactics = ["initial_access", "exfiltration"]
    scan_interval = 15.0
    requires_fields = ["volumes"]

    def __init__(self) -> None:
        super().__init__()
        self._known_volumes: Set[str] = set()  # volume name set
        self._first_run = True

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []
        volumes = context.shared_data.get("volumes", [])

        current_volumes: Set[str] = set()

        for vol in volumes:
            vol_key = f"{vol.name}:{vol.mount_point}"
            current_volumes.add(vol_key)

            if self._first_run:
                continue

            if vol_key not in self._known_volumes:
                events.append(
                    self._create_event(
                        event_type="removable_media_mounted",
                        severity=Severity.HIGH,
                        data={
                            "probe_name": self.name,
                            "detection_source": "system_profiler",
                            "volume_name": vol.name,
                            "mount_point": vol.mount_point,
                        },
                        confidence=0.9,
                        correlation_id=vol_key,
                    )
                )

        # Detect unmounted volumes
        if not self._first_run:
            for vol_key in self._known_volumes:
                if vol_key not in current_volumes:
                    vol_name = vol_key.split(":")[0]
                    events.append(
                        self._create_event(
                            event_type="removable_media_unmounted",
                            severity=Severity.INFO,
                            data={
                                "probe_name": self.name,
                                "detection_source": "system_profiler",
                                "volume_name": vol_name,
                            },
                            confidence=0.95,
                            correlation_id=vol_key,
                        )
                    )

        self._known_volumes = current_volumes
        self._first_run = False
        return events


# =============================================================================
# 5. ThunderboltDMAProbe
# =============================================================================


# DMA capability keywords found in system_profiler Thunderbolt data
_DMA_CAPABILITY_FLAGS = frozenset(
    {
        "DMA",
        "PCIe",
        "Thunderbolt 3",
        "Thunderbolt 4",
        "USB4",
    }
)


def _thunderbolt_fingerprint(dev: Dict[str, Any]) -> str:
    """Create a stable fingerprint for a Thunderbolt device.

    Uses device_name + vendor_id + device_id + route_string to create
    a unique key that survives reconnection (same physical device).
    """
    parts = [
        dev.get("device_name", ""),
        dev.get("vendor_id", ""),
        dev.get("device_id", ""),
        dev.get("route_string", ""),
    ]
    return "|".join(parts)


def _has_dma_capability(dev: Dict[str, Any]) -> bool:
    """Check if a Thunderbolt device has DMA capability flags."""
    raw = json.dumps(dev).lower()
    return any(flag.lower() in raw for flag in _DMA_CAPABILITY_FLAGS)


class ThunderboltDMAProbe(MicroProbe):
    """Baseline-diff probe for Thunderbolt/DMA device inventory.

    Thunderbolt devices have Direct Memory Access (DMA) capability,
    making them high-risk attack vectors. A malicious Thunderbolt device
    can read/write system memory directly, bypassing OS protections
    (Thunderclap, DMA attacks). This probe tracks known Thunderbolt
    devices by fingerprint and alerts on new connections.

    Uses system_profiler SPThunderboltDataType for device enumeration.
    First scan silently establishes the baseline.

    MITRE: T1200 (Hardware Additions), T1052 (Exfiltration Over Physical Medium)
    """

    name = "macos_thunderbolt_dma"
    description = "Tracks Thunderbolt/DMA device inventory changes on macOS"
    platforms = ["darwin"]
    mitre_techniques = ["T1200", "T1052"]
    mitre_tactics = ["initial_access", "exfiltration"]
    scan_interval = 30.0
    requires_fields = ["usb_devices"]  # runs alongside peripheral collector

    def __init__(self) -> None:
        super().__init__()
        self._known: Dict[str, Dict[str, Any]] = {}  # fingerprint -> device dict
        self._first_run = True

    @staticmethod
    def _enumerate_thunderbolt_devices() -> List[Dict[str, Any]]:
        """Run system_profiler SPThunderboltDataType and parse JSON output.

        Returns a flat list of device dicts. Each dict contains device_name,
        vendor_id, device_id, route_string, link_speed, and receptacle fields.
        """
        devices: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPThunderboltDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return devices

            data = json.loads(result.stdout)
            tb_items = data.get("SPThunderboltDataType", [])

            for bus in tb_items:
                # Each bus may contain device entries
                bus_devices = bus.get("device_name_key", [])
                if isinstance(bus_devices, list):
                    for dev in bus_devices:
                        devices.append(dev)
                # Also check for inline device attributes on the bus itself
                if bus.get("vendor_id_key") or bus.get("device_id_key"):
                    devices.append(bus)

        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("system_profiler Thunderbolt enumeration failed: %s", e)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.debug("Thunderbolt JSON parse error: %s", e)

        return devices

    def _make_added_event(self, dev: Dict[str, Any], fp: str) -> TelemetryEvent:
        """Create event for a newly connected Thunderbolt device."""
        dma_capable = _has_dma_capability(dev)
        severity = Severity.CRITICAL if dma_capable else Severity.HIGH
        confidence = 0.95 if dma_capable else 0.85

        return self._create_event(
            event_type="thunderbolt_device_added",
            severity=severity,
            data={
                "probe_name": self.name,
                "detection_source": "system_profiler",
                "device_name": dev.get("device_name", "Unknown"),
                "vendor_id": dev.get("vendor_id_key", ""),
                "device_id": dev.get("device_id_key", ""),
                "route_string": dev.get("route_string", ""),
                "link_speed": dev.get("link_speed", ""),
                "receptacle": dev.get("receptacle", ""),
                "dma_capable": dma_capable,
                "fingerprint": fp,
            },
            confidence=confidence,
            correlation_id=fp,
        )

    def _make_removed_event(self, dev: Dict[str, Any], fp: str) -> TelemetryEvent:
        """Create event for a disconnected Thunderbolt device."""
        return self._create_event(
            event_type="thunderbolt_device_removed",
            severity=Severity.INFO,
            data={
                "probe_name": self.name,
                "detection_source": "system_profiler",
                "device_name": dev.get("device_name", "Unknown"),
                "vendor_id": dev.get("vendor_id_key", ""),
                "device_id": dev.get("device_id_key", ""),
                "fingerprint": fp,
            },
            confidence=0.95,
            correlation_id=fp,
        )

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        events: List[TelemetryEvent] = []

        tb_devices = self._enumerate_thunderbolt_devices()

        current: Dict[str, Dict[str, Any]] = {}
        for dev in tb_devices:
            fp = _thunderbolt_fingerprint(dev)
            if not fp.replace("|", ""):
                continue  # skip empty fingerprints
            current[fp] = dev

            if not self._first_run and fp not in self._known:
                events.append(self._make_added_event(dev, fp))

        # Detect removed Thunderbolt devices
        if not self._first_run:
            for fp, dev in self._known.items():
                if fp not in current:
                    events.append(self._make_removed_event(dev, fp))

        self._known = current
        self._first_run = False
        return events


# =============================================================================
# Factory
# =============================================================================


def create_peripheral_probes() -> List[MicroProbe]:
    """Create all macOS peripheral probes."""
    return [
        USBInventoryProbe(),
        BluetoothInventoryProbe(),
        NewPeripheralProbe(),
        RemovableMediaProbe(),
        ThunderboltDMAProbe(),
    ]
