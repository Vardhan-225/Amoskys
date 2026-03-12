"""macOS Peripheral Agent -- Peripheral Observatory for Darwin.

Monitors USB devices, Bluetooth peripherals, and removable media mounts on
macOS. Uses the AMOSKYS canonical agent pattern (MicroProbeAgentMixin +
HardenedAgentBase) with a macOS-specific collector and 4 detection probes.

Data flow:
    1. MacOSPeripheralCollector.collect() -> USB/BT/volume snapshots
    2. Probes.scan(context) -> TelemetryEvents (detections)
    3. Agent converts events -> DeviceTelemetry protobuf
    4. LocalQueueAdapter -> WAL -> EventBus

Probes:
    1. macos_usb_inventory -- USB device baseline-diff (T1200)
    2. macos_bluetooth_inventory -- Bluetooth device baseline-diff (T1200)
    3. macos_new_peripheral -- any new peripheral alert (T1200)
    4. macos_removable_media -- /Volumes/ mount detection (T1091)

Usage:
    agent = MacOSPeripheralAgent()
    agent.run()  # Enters main loop
"""

from __future__ import annotations

import logging
import platform
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.peripheral.collector import MacOSPeripheralCollector
from amoskys.agents.os.macos.peripheral.probes import create_peripheral_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/macos_peripheral.db"


class MacOSPeripheralAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Peripheral Observatory agent.

    Monitors USB, Bluetooth, and removable media on macOS via system_profiler
    and /Volumes/ with 4 detection probes.

    Probes:
        1. macos_usb_inventory -- USB device baseline-diff
        2. macos_bluetooth_inventory -- Bluetooth device baseline-diff
        3. macos_new_peripheral -- any new peripheral alert
        4. macos_removable_media -- /Volumes/ mount detection
    """

    def __init__(self, collection_interval: float = 30.0) -> None:
        device_id = socket.gethostname()

        # Local queue for offline resilience
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="macos_peripheral",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name="macos_peripheral",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )

        self.collector = MacOSPeripheralCollector()
        self.register_probes(create_peripheral_probes())

        logger.info(
            "MacOSPeripheralAgent initialized: %d probes, device=%s",
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        """Verify macOS platform and initialize probes."""
        if platform.system() != "Darwin":
            logger.error("MacOSPeripheralAgent requires macOS (Darwin)")
            return False

        # Verify system_profiler is available
        try:
            import subprocess

            result = subprocess.run(
                ["system_profiler", "-listDataTypes"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                logger.error("system_profiler not available")
                return False
            logger.info("system_profiler OK")
        except Exception as e:
            logger.error("system_profiler verification failed: %s", e)
            return False

        # Setup probes with collector's shared_data keys
        if not self.setup_probes(
            collector_shared_data_keys=[
                "usb_devices",
                "bluetooth_devices",
                "volumes",
                "collection_time_ms",
            ]
        ):
            logger.error("No probes initialized")
            return False

        logger.info("MacOSPeripheralAgent setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Run collector + probes, emit raw observations + detections."""
        snapshot = self.collector.collect()

        # Build OBSERVATION events for all peripheral devices
        all_devices = (
            snapshot.get("usb_devices", [])
            + snapshot.get("bluetooth_devices", [])
            + snapshot.get("volumes", [])
        )
        obs_events = self._make_observation_events(
            all_devices,
            domain="peripheral",
            field_mapper=self._peripheral_to_obs,
        )

        # Run probes (detection events)
        context = self._create_probe_context()
        context.shared_data = snapshot
        probe_events = self.run_probes(context)

        usb_count = len(snapshot["usb_devices"])
        bt_count = len(snapshot["bluetooth_devices"])
        vol_count = len(snapshot["volumes"])

        all_events = obs_events + probe_events
        all_events.append(
            TelemetryEvent(
                event_type="collection_metadata",
                severity=Severity.DEBUG,
                probe_name="macos_peripheral_collector",
                data={
                    "usb_devices": usb_count,
                    "bluetooth_devices": bt_count,
                    "volumes": vol_count,
                    "collection_time_ms": snapshot["collection_time_ms"],
                    "observation_events": len(obs_events),
                    "probe_events": len(probe_events),
                },
            )
        )

        logger.info(
            "Peripheral collected in %.1fms: %d USB, %d BT, %d volumes, "
            "%d observations, %d probe events",
            snapshot["collection_time_ms"],
            usb_count,
            bt_count,
            vol_count,
            len(obs_events),
            len(probe_events),
        )

        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    @staticmethod
    def _peripheral_to_obs(device) -> Dict[str, Any]:
        """Map a PeripheralDevice to observation data dict."""
        return {
            "device_type": device.device_type,
            "name": device.name,
            "vendor_id": device.vendor_id,
            "product_id": device.product_id,
            "serial": device.serial,
            "is_storage": str(device.is_storage),
            "mount_point": device.mount_point,
            "manufacturer": device.manufacturer,
            "address": device.address,
            "connected": str(device.connected),
        }

    def _events_to_telemetry(self, events: List[TelemetryEvent]) -> Any:
        """Convert TelemetryEvents to protobuf DeviceTelemetry."""
        from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

        timestamp_ns = int(time.time() * 1e9)
        proto_events = []

        for idx, event in enumerate(events):
            if event.event_type == "collection_metadata":
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_peripheral_meta_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="macos_peripheral_collector",
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="peripheral_collection",
                        metric_type="GAUGE",
                        numeric_value=float(
                            event.data.get("usb_devices", 0)
                            + event.data.get("bluetooth_devices", 0)
                            + event.data.get("volumes", 0)
                        ),
                        unit="devices",
                    ),
                )
            elif event.event_type.startswith("obs_"):
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"macos_peripheral_obs_{idx}_{timestamp_ns}",
                    event_type="OBSERVATION",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="peripheral_collector",
                    confidence_score=0.0,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)
            else:
                security_event = telemetry_pb2.SecurityEvent(
                    event_category=event.event_type,
                    risk_score=event.confidence,
                    analyst_notes=str(event.data),
                )
                if event.mitre_techniques:
                    security_event.mitre_techniques.extend(event.mitre_techniques)

                source_ip = event.data.get("source_ip")
                if source_ip:
                    security_event.source_ip = str(source_ip)

                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"{event.probe_name}_{event.event_type}_{timestamp_ns}",
                    event_type="SECURITY",
                    severity=event.severity.value,
                    event_timestamp_ns=timestamp_ns,
                    source_component=event.probe_name,
                    security_event=security_event,
                    confidence_score=event.confidence,
                    tags=event.tags,
                )
                for k, v in event.data.items():
                    proto_event.attributes[k] = str(v)

            proto_events.append(proto_event)

        return telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="MACOS_PERIPHERAL",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="macos_peripheral",
            agent_version="2.0.0",
        )

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate DeviceTelemetry before publishing."""
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns == 0:
            errors.append("Missing timestamp_ns")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("MacOSPeripheralAgent shutting down")
