#!/usr/bin/env python3
"""
AMOSKYS Peripheral Monitoring Agent

Monitors physical devices connected to the endpoint:
- USB devices (flash drives, keyboards, mice, webcams)
- Bluetooth devices
- External storage (file transfer detection)
- Unauthorized device detection

This agent is critical for detecting USB-based attacks:
- BadUSB / Rubber Ducky attacks
- USB keyloggers
- Unauthorized data exfiltration
- Malicious charging cables
"""

import hashlib
import json
import logging
import os
import platform
import socket
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Set

import grpc

from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PeripheralAgent")

# Load configuration
config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir


class PeripheralAgent:
    """Monitors peripheral devices for security threats"""

    def __init__(self):
        """Initialize peripheral agent"""
        self.known_devices = {}  # device_id -> device_info
        self.previous_devices = set()  # Set of device IDs from last scan
        self.authorized_devices = self._load_authorized_devices()
        self.platform = platform.system()

        logger.info(f"Peripheral Agent initialized for {self.platform}")

    def _load_authorized_devices(self) -> Set[str]:
        """Load list of authorized device IDs from config"""
        # TODO: Load from config file or database
        # For now, return empty set (all devices flagged as unauthorized)
        return set()

    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus with mTLS"""
        try:
            # Load client certificates for mTLS
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            with open(f"{CERT_DIR}/agent.crt", "rb") as f:
                client_cert = f.read()
            with open(f"{CERT_DIR}/agent.key", "rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            logger.info("Created secure gRPC channel with mTLS")
            return channel
        except FileNotFoundError as e:
            logger.error("Certificate not found: %s", e)
            return None
        except Exception as e:
            logger.error("Failed to create gRPC channel: %s", str(e))
            return None

    def _scan_usb_devices_macos(self) -> List[Dict]:
        """Scan USB devices on macOS using system_profiler"""
        devices = []

        try:
            # Get USB device tree
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                logger.error("system_profiler failed: %s", result.stderr)
                return devices

            data = json.loads(result.stdout)

            # Parse USB device tree
            def parse_usb_tree(items, devices_list):
                for item in items:
                    # Check if this is a USB device (not a controller)
                    if "_name" in item and item.get("_name") != "USB":
                        device = {
                            "name": item.get("_name", "Unknown"),
                            "vendor_id": item.get("vendor_id", ""),
                            "product_id": item.get("product_id", ""),
                            "serial_num": item.get("serial_num", ""),
                            "manufacturer": item.get("manufacturer", ""),
                            "location_id": item.get("location_id", ""),
                            "device_speed": item.get("device_speed", ""),
                            "bcd_device": item.get("bcd_device", ""),
                        }

                        # Create unique device ID
                        device_id = f"{device['vendor_id']}:{device['product_id']}:{device['serial_num']}"
                        device["device_id"] = hashlib.md5(
                            device_id.encode()
                        ).hexdigest()[:16]

                        devices_list.append(device)

                    # Recursively parse children
                    if "_items" in item:
                        parse_usb_tree(item["_items"], devices_list)

            # Start parsing from root
            if "SPUSBDataType" in data:
                for bus in data["SPUSBDataType"]:
                    if "_items" in bus:
                        parse_usb_tree(bus["_items"], devices)

        except subprocess.TimeoutExpired:
            logger.error("USB scan timed out")
        except Exception as e:
            logger.error("Failed to scan USB devices: %s", e)

        return devices

    def _scan_usb_devices_linux(self) -> List[Dict]:
        """Scan USB devices on Linux using lsusb"""
        devices = []

        try:
            result = subprocess.run(
                ["lsusb", "-v"], capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                logger.error("lsusb failed")
                return devices

            # Parse lsusb output (simplified)
            for line in result.stdout.split("\n"):
                if line.startswith("Bus "):
                    parts = line.split()
                    if len(parts) >= 6:
                        device = {
                            "name": " ".join(parts[6:]),
                            "vendor_id": parts[5].split(":")[0],
                            "product_id": (
                                parts[5].split(":")[1] if ":" in parts[5] else ""
                            ),
                            "device_id": hashlib.md5(line.encode()).hexdigest()[:16],
                        }
                        devices.append(device)

        except Exception as e:
            logger.error("Failed to scan USB devices on Linux: %s", e)

        return devices

    def _scan_usb_devices(self) -> List[Dict]:
        """Scan USB devices (platform-aware)"""
        if self.platform == "Darwin":
            return self._scan_usb_devices_macos()
        elif self.platform == "Linux":
            return self._scan_usb_devices_linux()
        else:
            logger.warning(f"USB scanning not implemented for {self.platform}")
            return []

    def _scan_mounted_volumes(self) -> List[Dict]:
        """Scan mounted volumes to detect USB storage"""
        volumes = []

        try:
            if self.platform == "Darwin":
                # Get mounted volumes
                result = subprocess.run(["df", "-h"], capture_output=True, text=True)

                for line in result.stdout.split("\n")[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 6:
                        mount_point = parts[5]
                        # Check if it's a removable volume (under /Volumes)
                        if mount_point.startswith("/Volumes/"):
                            volumes.append(
                                {
                                    "mount_point": mount_point,
                                    "filesystem": parts[0],
                                    "size": parts[1],
                                    "used": parts[2],
                                    "available": parts[3],
                                    "capacity": parts[4],
                                    "volume_name": mount_point.split("/")[-1],
                                }
                            )

            elif self.platform == "Linux":
                # Check /media and /mnt for mounted USB drives
                for base_path in ["/media", "/mnt"]:
                    if os.path.exists(base_path):
                        for item in os.listdir(base_path):
                            mount_point = os.path.join(base_path, item)
                            if os.path.ismount(mount_point):
                                volumes.append(
                                    {"mount_point": mount_point, "volume_name": item}
                                )

        except Exception as e:
            logger.error("Failed to scan mounted volumes: %s", e)

        return volumes

    def _detect_device_events(self, current_devices: List[Dict]) -> Dict:
        """Detect connection/disconnection events"""
        current_ids = {d["device_id"] for d in current_devices}

        events = {"connected": [], "disconnected": [], "persistent": []}

        # New devices (connected)
        for device in current_devices:
            if device["device_id"] not in self.previous_devices:
                events["connected"].append(device)
            else:
                events["persistent"].append(device)

        # Removed devices (disconnected)
        disconnected_ids = self.previous_devices - current_ids
        for device_id in disconnected_ids:
            if device_id in self.known_devices:
                events["disconnected"].append(self.known_devices[device_id])

        # Update state
        self.previous_devices = current_ids
        for device in current_devices:
            self.known_devices[device["device_id"]] = device

        return events

    def _classify_device_type(self, device: Dict) -> str:
        """Classify device type based on attributes"""
        name = device.get("name", "").lower()
        vendor = device.get("manufacturer", "").lower()

        if "keyboard" in name or "kbd" in name:
            return "KEYBOARD"
        elif "mouse" in name or "pointing" in name:
            return "MOUSE"
        elif "storage" in name or "disk" in name or "flash" in name:
            return "USB_STORAGE"
        elif "camera" in name or "webcam" in name:
            return "CAMERA"
        elif "audio" in name or "microphone" in name:
            return "AUDIO"
        elif "bluetooth" in name or "bt" in vendor:
            return "BLUETOOTH"
        elif "hub" in name:
            return "USB_HUB"
        else:
            return "UNKNOWN"

    def _calculate_risk_score(self, device: Dict, event_type: str) -> float:
        """Calculate risk score for device"""
        risk = 0.0

        # Unauthorized device = high risk
        if device["device_id"] not in self.authorized_devices:
            risk += 0.5

        # New connection = moderate risk
        if event_type == "CONNECTED":
            risk += 0.2

        # High-risk device types
        device_type = self._classify_device_type(device)
        if device_type in ["KEYBOARD", "USB_STORAGE"]:
            risk += 0.3  # Keyloggers, BadUSB, data exfiltration

        # No serial number = suspicious
        if not device.get("serial_num"):
            risk += 0.2

        return min(risk, 1.0)

    def _create_telemetry(
        self, devices: List[Dict], events: Dict
    ) -> telemetry_pb2.DeviceTelemetry:
        """Create DeviceTelemetry protobuf"""
        timestamp_ns = int(time.time() * 1e9)
        telemetry_events = []

        # Create events for each connection/disconnection
        for device in events["connected"]:
            device_type = self._classify_device_type(device)
            risk_score = self._calculate_risk_score(device, "CONNECTED")

            event = telemetry_pb2.TelemetryEvent(
                event_id=f"peripheral_connected_{device['device_id']}_{timestamp_ns}",
                event_type="STATUS",
                severity="WARN" if risk_score > 0.5 else "INFO",
                event_timestamp_ns=timestamp_ns,
                status_data=telemetry_pb2.StatusData(
                    component_name=device.get("name", "Unknown Device"),
                    status="CONNECTED",
                    previous_status="OFFLINE",
                    status_change_time_ns=timestamp_ns,
                ),
                source_component="peripheral_agent",
                tags=["peripheral", "usb", device_type.lower()],
                confidence_score=1.0 - risk_score,
                attributes={
                    "device_id": device["device_id"],
                    "vendor_id": device.get("vendor_id", ""),
                    "product_id": device.get("product_id", ""),
                    "manufacturer": device.get("manufacturer", ""),
                    "device_type": device_type,
                    "is_authorized": str(
                        device["device_id"] in self.authorized_devices
                    ),
                    "risk_score": str(risk_score),
                },
            )
            telemetry_events.append(event)

        for device in events["disconnected"]:
            event = telemetry_pb2.TelemetryEvent(
                event_id=f"peripheral_disconnected_{device['device_id']}_{timestamp_ns}",
                event_type="STATUS",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                status_data=telemetry_pb2.StatusData(
                    component_name=device.get("name", "Unknown Device"),
                    status="DISCONNECTED",
                    previous_status="CONNECTED",
                    status_change_time_ns=timestamp_ns,
                ),
                source_component="peripheral_agent",
                tags=["peripheral", "usb", "disconnection"],
                attributes={
                    "device_id": device["device_id"],
                    "device_type": self._classify_device_type(device),
                },
            )
            telemetry_events.append(event)

        # Add summary metric
        summary_event = telemetry_pb2.TelemetryEvent(
            event_id=f"peripheral_summary_{timestamp_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=timestamp_ns,
            metric_data=telemetry_pb2.MetricData(
                metric_name="connected_peripherals_count",
                metric_type="GAUGE",
                numeric_value=float(len(devices)),
                unit="devices",
            ),
            source_component="peripheral_agent",
            tags=["peripheral", "metric"],
        )
        telemetry_events.append(summary_event)

        # Device metadata
        try:
            ip_addr = socket.gethostbyname(socket.gethostname())
        except:
            ip_addr = "127.0.0.1"

        metadata = telemetry_pb2.DeviceMetadata(
            manufacturer="Apple" if self.platform == "Darwin" else "Unknown",
            model=socket.gethostname(),
            ip_address=ip_addr,
            protocols=["USB", "PERIPHERAL"],
        )

        # DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=socket.gethostname(),
            device_type="ENDPOINT",
            protocol="PERIPHERAL",
            metadata=metadata,
            events=telemetry_events,
            timestamp_ns=timestamp_ns,
            collection_agent="peripheral-agent",
            agent_version="1.0.0",
        )

        return device_telemetry

    def _publish_telemetry(
        self, device_telemetry: telemetry_pb2.DeviceTelemetry
    ) -> bool:
        """Publish telemetry to EventBus"""
        try:
            channel = self._get_grpc_channel()
            if not channel:
                logger.error("No gRPC channel")
                return False

            # Create UniversalEnvelope
            timestamp_ns = int(time.time() * 1e9)
            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=timestamp_ns,
                idempotency_key=f"{device_telemetry.device_id}_peripheral_{timestamp_ns}",
                device_telemetry=device_telemetry,
                signing_algorithm="Ed25519",
                priority="NORMAL",
                requires_acknowledgment=True,
            )

            # Publish via UniversalEventBus.PublishTelemetry
            stub = universal_pbrpc.UniversalEventBusStub(channel)
            ack = stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status == telemetry_pb2.UniversalAck.OK:
                logger.info(
                    f"Published peripheral telemetry ({len(device_telemetry.events)} events)"
                )
                return True
            else:
                logger.warning("Publish status: %s", ack.status)
                return False
        except Exception as e:
            logger.error("Publish failed: %s", str(e))
            return False

    def collect(self) -> bool:
        """Collect and publish peripheral telemetry once"""
        try:
            logger.info("Scanning peripheral devices...")

            # Scan USB devices
            devices = self._scan_usb_devices()
            logger.info(f"Found {len(devices)} USB devices")

            # Scan mounted volumes
            volumes = self._scan_mounted_volumes()
            if volumes:
                logger.info(f"Found {len(volumes)} mounted volumes")

            # Detect connection/disconnection events
            events = self._detect_device_events(devices)

            if events["connected"]:
                logger.info(f"🔌 {len(events['connected'])} device(s) connected")
                for dev in events["connected"]:
                    logger.info(
                        f"  → {dev['name']} ({self._classify_device_type(dev)})"
                    )

            if events["disconnected"]:
                logger.info(f"🔌 {len(events['disconnected'])} device(s) disconnected")

            # Create and publish telemetry
            device_telemetry = self._create_telemetry(devices, events)
            success = self._publish_telemetry(device_telemetry)

            if success:
                logger.info(f"Collection complete ({len(devices)} devices tracked)")
            else:
                logger.warning("Collection failed")

            return success

        except Exception as e:
            logger.error("Collection error: %s", str(e), exc_info=True)
            return False

    def run(self, interval: int = 30):
        """Main collection loop"""
        logger.info("=" * 70)
        logger.info("AMOSKYS Peripheral Monitoring Agent")
        logger.info("=" * 70)
        logger.info(f"Platform: {self.platform}")
        logger.info(f"EventBus: {EVENTBUS_ADDRESS}")
        logger.info(f"Collection interval: {interval}s")
        logger.info("=" * 70)

        cycle = 0
        while True:
            cycle += 1
            logger.info("")
            logger.info("=" * 70)
            logger.info(f"Cycle #{cycle} - {datetime.now().isoformat()}")
            logger.info("=" * 70)

            self.collect()

            logger.info(f"Next collection in {interval}s...")
            time.sleep(interval)


def main():
    """Entry point"""
    agent = PeripheralAgent()
    agent.run(interval=30)


if __name__ == "__main__":
    main()
