#!/usr/bin/env python3
"""AMOSKYS Peripheral Agent v2 - Micro-Probe Architecture.

This is the modernized Peripheral agent using the "swarm of eyes" pattern.
7 micro-probes each watch one specific peripheral threat vector.

Probes:
    1. USBInventoryProbe - Complete device inventory
    2. USBConnectionEdgeProbe - Connect/disconnect events
    3. USBStorageProbe - Storage device monitoring
    4. USBNetworkAdapterProbe - Network adapter detection
    5. HIDKeyboardMouseAnomalyProbe - Keystroke injection detection
    6. BluetoothDeviceProbe - Bluetooth monitoring
    7. HighRiskPeripheralScoreProbe - Composite risk scoring

MITRE ATT&CK Coverage:
    - T1200: Hardware Additions
    - T1091: Replication Through Removable Media
    - T1052: Exfiltration Over Physical Medium
    - T1056.001: Input Capture: Keylogging
    - T1557: Adversary-in-the-Middle

Usage:
    >>> agent = PeripheralAgentV2()
    >>> agent.run_forever()
"""

from __future__ import annotations

import logging
import platform
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

import grpc

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.peripheral.probes import create_peripheral_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("PeripheralAgentV2")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent, "peripheral_queue_path", "data/queue/peripheral_agent_v2.db"
)


# =============================================================================
# EventBus Publisher
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
        """Create gRPC channel if needed."""
        if self._channel is None:
            try:
                with open(f"{self.cert_dir}/ca.crt", "rb") as f:
                    ca_cert = f.read()
                with open(f"{self.cert_dir}/agent.crt", "rb") as f:
                    client_cert = f.read()
                with open(f"{self.cert_dir}/agent.key", "rb") as f:
                    client_key = f.read()

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=ca_cert,
                    private_key=client_key,
                    certificate_chain=client_cert,
                )
                self._channel = grpc.secure_channel(self.address, credentials)
                self._stub = universal_pbrpc.UniversalEventBusStub(self._channel)
                logger.info("Created secure gRPC channel with mTLS")
            except FileNotFoundError as e:
                raise RuntimeError(f"Certificate not found: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to create gRPC channel: {e}")

    def publish(self, events: list) -> None:
        """Publish events to EventBus."""
        self._ensure_channel()

        for device_telemetry in events:
            timestamp_ns = int(time.time() * 1e9)
            idempotency_key = f"{device_telemetry.device_id}_{timestamp_ns}"
            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=timestamp_ns,
                idempotency_key=idempotency_key,
                device_telemetry=device_telemetry,
                signing_algorithm="Ed25519",
                priority="NORMAL",
                requires_acknowledgment=True,
            )

            ack = self._stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status != telemetry_pb2.UniversalAck.OK:
                raise Exception(f"EventBus returned status: {ack.status}")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# Peripheral Agent V2
# =============================================================================


class PeripheralAgentV2(MicroProbeAgentMixin, HardenedAgentBase):
    """Peripheral Agent with micro-probe architecture.

    This agent hosts 7 micro-probes that each monitor a specific peripheral
    threat vector. The agent handles:
        - Probe lifecycle management
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    def __init__(self, collection_interval: float = 10.0):
        """Initialize Peripheral Agent v2.

        Args:
            collection_interval: Seconds between collection cycles
        """
        device_id = socket.gethostname()

        # Create EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Create local queue
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="peripheral_agent_v2",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
        )

        # Initialize base classes
        super().__init__(
            agent_name="peripheral_agent_v2",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Register all peripheral probes
        self.register_probes(create_peripheral_probes())

        logger.info(f"PeripheralAgentV2 initialized with {len(self._probes)} probes")

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist (warns if missing — dev mode tolerant)
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates (warn but don't fail — dev mode may lack certs)
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.warning(f"Certificate not found: {cert_path} (EventBus publishing will fail)")

            # Setup probes
            if not self.setup_probes():
                logger.error("No probes initialized successfully")
                return False

            logger.info("PeripheralAgentV2 setup complete")
            return True

        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def collect_data(self) -> Sequence[Any]:
        """Run all probes and collect events.

        Returns:
            List of DeviceTelemetry protobuf messages (always at least one)
        """
        timestamp_ns = int(time.time() * 1e9)

        # Run all probes
        events = self.scan_all_probes()

        logger.info(f"Probes generated {len(events)} events")

        # Build proto events
        proto_events = []

        # Always emit a collection summary metric (heartbeat)
        proto_events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"peripheral_collection_summary_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                source_component="peripheral_collector",
                tags=["peripheral", "metric"],
                metric_data=telemetry_pb2.MetricData(
                    metric_name="peripheral_events_collected",
                    metric_type="GAUGE",
                    numeric_value=float(len(events)),
                    unit="events",
                ),
            )
        )

        # Probe event count metric (when probes fire)
        if events:
            proto_events.append(
                telemetry_pb2.TelemetryEvent(
                    event_id=f"peripheral_probe_events_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    source_component="peripheral_agent",
                    tags=["peripheral", "metric"],
                    metric_data=telemetry_pb2.MetricData(
                        metric_name="peripheral_probe_events",
                        metric_type="GAUGE",
                        numeric_value=float(len(events)),
                        unit="events",
                    ),
                )
            )

        # Convert probe events to SecurityEvent-based telemetry
        severity_map = {
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }

        for event in events:
            # Build SecurityEvent sub-message
            security_event = telemetry_pb2.SecurityEvent(
                event_category=event.event_type,
                risk_score=0.8 if event.severity.value in ("HIGH", "CRITICAL") else 0.4,
                analyst_notes=f"Probe: {event.probe_name}, "
                              f"Severity: {event.severity.value}",
            )
            security_event.mitre_techniques.extend(event.mitre_techniques)

            tel_event = telemetry_pb2.TelemetryEvent(
                event_id=f"{event.event_type}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(event.severity.value, "INFO"),
                event_timestamp_ns=timestamp_ns,
                source_component=event.probe_name or "peripheral_agent",
                tags=["peripheral", "threat"],
                security_event=security_event,
                confidence_score=event.confidence if hasattr(event, 'confidence') else 0.7,
            )

            # Populate attributes map with evidence
            if event.data:
                for key, value in event.data.items():
                    if value is not None:
                        tel_event.attributes[key] = str(value)

            proto_events.append(tel_event)

        # Create DeviceTelemetry
        telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="USB",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="peripheral_agent_v2",
            agent_version="2.0.0",
        )

        return [telemetry]

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing.

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult
        """
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns <= 0:
            errors.append("Missing or invalid timestamp_ns")
        if not event.events:
            errors.append("events list is empty")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("PeripheralAgentV2 shutting down...")

        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("PeripheralAgentV2 shutdown complete")

    def get_health(self) -> Dict[str, Any]:
        """Get agent health status.

        Returns:
            Dict with health metrics
        """
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "probes": self.get_probe_health(),
            "circuit_breaker_state": self.circuit_breaker.state,
        }


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """Run Peripheral Agent v2."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS Peripheral Agent v2")
    parser.add_argument(
        "--interval",
        type=float,
        default=10.0,
        help="Collection interval in seconds",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )

    args = parser.parse_args()

    if args.debug or args.log_level == "DEBUG":
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(getattr(logging, args.log_level))

    agent = PeripheralAgentV2(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
