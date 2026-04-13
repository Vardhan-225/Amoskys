"""macOS Peripheral Collector — system_profiler based hardware enumeration.

Collects USB devices, Bluetooth peripherals, and mounted volumes on macOS.
Uses system_profiler JSON output for structured hardware data and /Volumes/
listing for removable media detection.

Data sources:
    - system_profiler SPUSBDataType -json: USB device tree (vendor, product, serial)
    - system_profiler SPBluetoothDataType -json: Bluetooth paired/connected devices
    - /Volumes/ directory listing: mounted volumes (removable media)

No root required. system_profiler runs as current user and returns all visible
hardware. /Volumes/ is world-readable.

Ground truth (macOS 26.0, uid=501):
    - USB enumeration: ~200ms via system_profiler
    - Bluetooth enumeration: ~300ms via system_profiler
    - /Volumes/ listing: <1ms
    - Internal drives (Macintosh HD) excluded from volume alerts
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PeripheralDevice:
    """A single peripheral device at collection time."""

    device_type: str  # "usb", "bluetooth", "volume"
    name: str  # Device name / volume name
    vendor_id: str  # USB vendor ID (hex) or "" for BT/volumes
    product_id: str  # USB product ID (hex) or "" for BT/volumes
    serial: str  # Serial number if available
    is_storage: bool  # True if mass storage device
    mount_point: str  # Mount path for volumes, "" otherwise
    # Additional metadata
    manufacturer: str = ""  # Manufacturer string
    address: str = ""  # Bluetooth address or USB location
    connected: bool = True  # Currently connected/mounted


# macOS system volumes to exclude from removable media alerts
_SYSTEM_VOLUMES = frozenset(
    {
        "Macintosh HD",
        "Macintosh HD - Data",
        "Recovery",
        "Preboot",
        "VM",
        "Update",
        "com.apple.TimeMachine.localsnapshots",
    }
)

# Volume mount paths that are always system-internal
_SYSTEM_MOUNT_PREFIXES = (
    "/System/",
    "/private/",
)


class MacOSPeripheralCollector:
    """Collects peripheral device data from macOS.

    Returns shared_data dict with keys:
        usb_devices: List[PeripheralDevice] - USB peripherals
        bluetooth_devices: List[PeripheralDevice] - Bluetooth peripherals
        volumes: List[PeripheralDevice] - mounted volumes (non-system)
        volume_activity: Dict - per-volume activity stats (plug count, duration)
        collection_time_ms: float - total collection time
    """

    def __init__(self) -> None:
        self._volumes_path = Path("/Volumes")
        # Track volume plug/unplug history across collections
        self._volume_history: Dict[str, Dict[str, Any]] = {}
        # {name: {"first_seen": float, "last_seen": float, "plug_count": int, "total_seconds": float}}

    def collect(self) -> Dict[str, Any]:
        """Collect full peripheral snapshot.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()

        usb_devices = self._collect_usb()
        bluetooth_devices = self._collect_bluetooth()
        volumes = self._collect_volumes()

        # Enrich volumes with diskutil metadata (vendor, serial, filesystem)
        for vol in volumes:
            self._enrich_volume(vol)

        # Track volume plug/unplug activity
        volume_activity = self._track_volume_activity(volumes)

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "usb_devices": usb_devices,
            "bluetooth_devices": bluetooth_devices,
            "volumes": volumes,
            "volume_activity": volume_activity,
            "collection_time_ms": round(elapsed_ms, 2),
        }

    # -------------------------------------------------------------------------
    # USB Collection
    # -------------------------------------------------------------------------

    def _collect_usb(self) -> List[PeripheralDevice]:
        """Enumerate USB devices via system_profiler SPUSBDataType -json."""
        devices: List[PeripheralDevice] = []

        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning(
                    "system_profiler SPUSBDataType returned %d", result.returncode
                )
                return devices

            data = json.loads(result.stdout)
            usb_items = data.get("SPUSBDataType", [])

            # USB data is a tree — recursively walk it
            for bus in usb_items:
                self._walk_usb_tree(bus, devices)

        except subprocess.TimeoutExpired:
            logger.warning("system_profiler SPUSBDataType timed out")
        except json.JSONDecodeError as e:
            logger.error("Failed to parse USB JSON: %s", e)
        except FileNotFoundError:
            logger.error("system_profiler not found")
        except Exception as e:
            logger.error("USB collection failed: %s", e)

        return devices

    def _walk_usb_tree(
        self, node: Dict[str, Any], devices: List[PeripheralDevice]
    ) -> None:
        """Recursively walk the USB device tree from system_profiler.

        system_profiler outputs a tree where USB hubs contain child devices
        under _items. Each device node has _name, vendor_id, product_id, etc.
        """
        name = node.get("_name", "")
        vendor_id = node.get("vendor_id", "")
        product_id = node.get("product_id", "")

        # Only add leaf devices that have vendor/product IDs (skip hub headers)
        if vendor_id or product_id:
            serial = node.get("serial_num", "")
            manufacturer = node.get("manufacturer", "")

            # Determine if this is a storage device
            # system_profiler marks media with "Media" key or bsd_name
            is_storage = bool(
                node.get("Media")
                or node.get("bsd_name")
                or "storage" in name.lower()
                or "disk" in name.lower()
            )

            # Determine mount point from Media entries
            mount_point = ""
            media = node.get("Media")
            if media and isinstance(media, list):
                for m in media:
                    volumes = m.get("volumes", [])
                    for vol in volumes:
                        mp = vol.get("mount_point", "")
                        if mp:
                            mount_point = mp
                            break
                    if mount_point:
                        break

            location_id = node.get("location_id", "")

            devices.append(
                PeripheralDevice(
                    device_type="usb",
                    name=name,
                    vendor_id=str(vendor_id),
                    product_id=str(product_id),
                    serial=str(serial),
                    is_storage=is_storage,
                    mount_point=mount_point,
                    manufacturer=str(manufacturer),
                    address=str(location_id),
                    connected=True,
                )
            )

        # Recurse into child items (USB hubs contain _items)
        children = node.get("_items", [])
        for child in children:
            self._walk_usb_tree(child, devices)

    # -------------------------------------------------------------------------
    # Bluetooth Collection
    # -------------------------------------------------------------------------

    def _collect_bluetooth(self) -> List[PeripheralDevice]:
        """Enumerate Bluetooth devices via system_profiler SPBluetoothDataType -json."""
        devices: List[PeripheralDevice] = []

        try:
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning(
                    "system_profiler SPBluetoothDataType returned %d",
                    result.returncode,
                )
                return devices

            data = json.loads(result.stdout)
            bt_items = data.get("SPBluetoothDataType", [])

            for controller in bt_items:
                # Connected devices
                connected = controller.get("device_connected", [])
                for dev_group in connected:
                    if isinstance(dev_group, dict):
                        for dev_name, dev_info in dev_group.items():
                            devices.append(
                                self._parse_bt_device(
                                    dev_name, dev_info, connected=True
                                )
                            )

                # Paired but not connected devices
                paired = controller.get("device_title", [])
                if not paired:
                    paired = controller.get("devices_paired", [])
                for dev_group in paired:
                    if isinstance(dev_group, dict):
                        for dev_name, dev_info in dev_group.items():
                            # Skip if already in connected list
                            if not any(d.name == dev_name for d in devices):
                                devices.append(
                                    self._parse_bt_device(
                                        dev_name, dev_info, connected=False
                                    )
                                )

        except subprocess.TimeoutExpired:
            logger.warning("system_profiler SPBluetoothDataType timed out")
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Bluetooth JSON: %s", e)
        except FileNotFoundError:
            logger.error("system_profiler not found")
        except Exception as e:
            logger.error("Bluetooth collection failed: %s", e)

        return devices

    @staticmethod
    def _parse_bt_device(
        name: str, info: Dict[str, Any], connected: bool
    ) -> PeripheralDevice:
        """Parse a single Bluetooth device entry from system_profiler."""
        address = info.get("device_address", "")
        # Bluetooth devices don't have vendor_id/product_id in the same sense
        # but some expose them via minor/major type
        vendor_id = info.get("device_vendorID", "")
        product_id = info.get("device_productID", "")
        serial = info.get("device_serialNumber", "")

        return PeripheralDevice(
            device_type="bluetooth",
            name=name,
            vendor_id=str(vendor_id),
            product_id=str(product_id),
            serial=str(serial),
            is_storage=False,  # BT storage devices are rare
            mount_point="",
            manufacturer=info.get("device_manufacturer", ""),
            address=str(address),
            connected=connected,
        )

    # -------------------------------------------------------------------------
    # Volume Enrichment & Activity Tracking
    # -------------------------------------------------------------------------

    @staticmethod
    def _enrich_volume(vol: PeripheralDevice) -> None:
        """Enrich a volume with diskutil info for real hardware metadata.

        Extracts: device vendor, media name, serial (disk identifier),
        filesystem type, total size, and protocol (USB/SATA/NVMe).
        """
        if not vol.mount_point:
            return
        try:
            result = subprocess.run(
                ["diskutil", "info", vol.mount_point],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return
            info: Dict[str, str] = {}
            for line in result.stdout.split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    info[key.strip()] = value.strip()

            vol.manufacturer = (
                info.get("Media Name", "")
                or info.get("Device / Media Name", "")
            )
            vol.vendor_id = info.get("Disk / Partition UUID", "")[:16]
            vol.serial = (
                info.get("Volume UUID", "")
                or info.get("Disk / Partition UUID", "")
            )
            # Store extra metadata in the address field (protocol + filesystem)
            protocol = info.get("Protocol", "")
            fs_type = info.get("Type (Bundle)", "") or info.get("File System Personality", "")
            total_size = info.get("Disk Size", "") or info.get("Container Total Space", "")
            vol.address = f"{protocol}|{fs_type}|{total_size}"
        except Exception as e:
            logger.debug("diskutil enrich failed for %s: %s", vol.mount_point, e)

    def _track_volume_activity(
        self, current_volumes: List[PeripheralDevice]
    ) -> Dict[str, Dict[str, Any]]:
        """Track plug/unplug events and connection duration per volume.

        Compares current snapshot with previous snapshot to detect:
        - New volumes (plug event) → increment plug_count
        - Missing volumes (unplug event) → record duration
        - Persistent volumes → update last_seen, accumulate duration
        """
        now = time.time()
        current_names = {v.name for v in current_volumes}
        prev_names = set(self._volume_history.keys())

        # New volumes (plugged in since last collection)
        for name in current_names - prev_names:
            self._volume_history[name] = {
                "first_seen": now,
                "last_seen": now,
                "plug_count": 1,
                "total_seconds": 0.0,
            }

        # Still present volumes (update last_seen)
        for name in current_names & prev_names:
            h = self._volume_history[name]
            h["last_seen"] = now
            h["total_seconds"] = now - h["first_seen"]

        # Removed volumes (unplugged since last collection)
        for name in prev_names - current_names:
            h = self._volume_history[name]
            h["total_seconds"] = h["last_seen"] - h["first_seen"]
            # Keep history for a while (re-plug detection)

        # Re-plugged volumes (was gone, now back)
        for name in current_names & prev_names:
            h = self._volume_history[name]
            # If last_seen was far from now (gap > 2 collection cycles), it's a re-plug
            gap = now - h.get("_prev_last_seen", h["last_seen"])
            if gap > 120:  # >2 min gap = re-plug
                h["plug_count"] = h.get("plug_count", 1) + 1
                h["first_seen"] = now
            h["_prev_last_seen"] = now

        # Build activity report
        activity: Dict[str, Dict[str, Any]] = {}
        for name, h in self._volume_history.items():
            activity[name] = {
                "plug_count": h.get("plug_count", 1),
                "total_seconds": round(h.get("total_seconds", 0), 1),
                "first_seen": h.get("first_seen", 0),
                "last_seen": h.get("last_seen", 0),
                "currently_mounted": name in current_names,
            }

        return activity

    # -------------------------------------------------------------------------
    # Volume Collection
    # -------------------------------------------------------------------------

    def _collect_volumes(self) -> List[PeripheralDevice]:
        """Enumerate mounted volumes from /Volumes/.

        Excludes system volumes (Macintosh HD, Recovery, etc.) to focus on
        removable media: USB drives, external SSDs, mounted DMGs, network shares.
        """
        devices: List[PeripheralDevice] = []

        try:
            if not self._volumes_path.exists():
                return devices

            for entry in self._volumes_path.iterdir():
                vol_name = entry.name

                # Skip system volumes
                if vol_name in _SYSTEM_VOLUMES:
                    continue

                # Skip hidden volumes
                if vol_name.startswith("."):
                    continue

                mount_point = str(entry.resolve())

                # Skip system mount prefixes
                if any(mount_point.startswith(p) for p in _SYSTEM_MOUNT_PREFIXES):
                    continue

                devices.append(
                    PeripheralDevice(
                        device_type="volume",
                        name=vol_name,
                        vendor_id="",
                        product_id="",
                        serial="",
                        is_storage=True,
                        mount_point=mount_point,
                        connected=True,
                    )
                )

        except PermissionError:
            logger.warning("Permission denied reading /Volumes/")
        except Exception as e:
            logger.error("Volume collection failed: %s", e)

        return devices
