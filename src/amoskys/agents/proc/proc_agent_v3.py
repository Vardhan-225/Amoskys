#!/usr/bin/env python3
"""AMOSKYS Process Agent v3 - Micro-Probe Architecture.

This is the modernized Process agent using the "swarm of eyes" pattern.
8 micro-probes each watch one specific process threat vector.

Probes:
    1. ProcessSpawnProbe - New process creation
    2. LOLBinExecutionProbe - Living-off-the-land binary abuse
    3. ProcessTreeAnomalyProbe - Unusual parent-child relationships
    4. HighCPUAndMemoryProbe - Resource abuse detection
    5. LongLivedProcessProbe - Persistent suspicious processes
    6. SuspiciousUserProcessProbe - Wrong user for process type
    7. BinaryFromTempProbe - Execution from temp directories
    8. ScriptInterpreterProbe - Suspicious script execution

MITRE ATT&CK Coverage:
    - T1059: Command and Scripting Interpreter
    - T1218: System Binary Proxy Execution
    - T1055: Process Injection
    - T1496: Resource Hijacking
    - T1036: Masquerading
    - T1204: User Execution
    - T1078: Valid Accounts

Usage:
    >>> agent = ProcAgentV3()
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
import psutil

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin, Severity, TelemetryEvent
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.proc.probes import create_proc_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ProcAgentV3")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "proc_queue_path", "data/queue/proc_agent_v3.db")


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
# System Metrics Collector
# =============================================================================


class SystemMetricsCollector:
    """Collects system-level metrics (CPU, memory, process count)."""

    def collect(self) -> Dict[str, Any]:
        """Collect system metrics.

        Returns:
            Dict with system metrics
        """
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "process_count": len(list(psutil.process_iter())),
            "boot_time": psutil.boot_time(),
        }


# =============================================================================
# Process Agent V3
# =============================================================================


class ProcAgentV3(MicroProbeAgentMixin, HardenedAgentBase):
    """Process Agent with micro-probe architecture.

    This agent hosts 8 micro-probes that each monitor a specific process
    threat vector. The agent handles:
        - Probe lifecycle management
        - System metrics collection
        - Event aggregation and publishing
        - Circuit breaker and retry logic
        - Offline queue management

    Probes are responsible only for detection - no networking or state
    management.
    """

    def __init__(self, collection_interval: float = 10.0):
        """Initialize Process Agent v3.

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
            agent_name="proc_agent_v3",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
        )

        # Initialize base classes
        super().__init__(
            agent_name="proc_agent_v3",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # System metrics collector
        self.metrics_collector = SystemMetricsCollector()

        # Register all process probes
        self.register_probes(create_proc_probes())

        logger.info(f"ProcAgentV3 initialized with {len(self._probes)} probes")

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - psutil is working
            - Probes initialize successfully

        Returns:
            True if setup succeeded
        """
        try:
            import os

            # Verify certificates
            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.error(f"Certificate not found: {cert_path}")
                    return False

            # Test psutil
            try:
                _ = psutil.cpu_percent(interval=0)
                logger.info("psutil verification passed")
            except Exception as e:
                logger.error(f"psutil verification failed: {e}")
                return False

            # Setup probes
            if not self.setup_probes():
                logger.error("No probes initialized successfully")
                return False

            logger.info("ProcAgentV3 setup complete")
            return True

        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def collect_data(self) -> Sequence[Any]:
        """Run all probes and collect events.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        all_events: List[TelemetryEvent] = []

        # Collect system metrics
        try:
            metrics = self.metrics_collector.collect()
            all_events.extend(self._create_metric_events(metrics))
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")

        # Run all probes
        probe_events = self.scan_all_probes()
        all_events.extend(probe_events)

        logger.info(
            f"Collected {len(all_events)} events "
            f"(metrics: {len(all_events) - len(probe_events)}, "
            f"probes: {len(probe_events)})"
        )

        # Convert to protobuf
        if all_events:
            return [self._events_to_telemetry(all_events)]
        return []

    def _create_metric_events(self, metrics: Dict[str, Any]) -> List[TelemetryEvent]:
        """Create TelemetryEvents for system metrics.

        Args:
            metrics: Dict from SystemMetricsCollector

        Returns:
            List of TelemetryEvents
        """
        events = []

        # CPU metric
        events.append(
            TelemetryEvent(
                event_type="system_metric",
                severity=Severity.DEBUG,
                probe_name="system_metrics",
                data={
                    "metric_name": "cpu_percent",
                    "value": metrics["cpu_percent"],
                    "unit": "percent",
                },
            )
        )

        # Memory metric
        events.append(
            TelemetryEvent(
                event_type="system_metric",
                severity=Severity.DEBUG,
                probe_name="system_metrics",
                data={
                    "metric_name": "memory_percent",
                    "value": metrics["memory_percent"],
                    "unit": "percent",
                },
            )
        )

        # Process count metric
        events.append(
            TelemetryEvent(
                event_type="system_metric",
                severity=Severity.DEBUG,
                probe_name="system_metrics",
                data={
                    "metric_name": "process_count",
                    "value": metrics["process_count"],
                    "unit": "processes",
                },
            )
        )

        return events

    def _events_to_telemetry(
        self, events: List[TelemetryEvent]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Convert TelemetryEvents to protobuf DeviceTelemetry.

        Args:
            events: List of TelemetryEvent objects

        Returns:
            DeviceTelemetry protobuf message
        """
        timestamp_ns = int(time.time() * 1e9)

        # Create telemetry events
        proto_events = []

        for event in events:
            if event.event_type == "system_metric":
                # Metric event
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"{event.probe_name}_{timestamp_ns}",
                    event_type="METRIC",
                    severity="INFO",
                    event_timestamp_ns=timestamp_ns,
                    metric_data=telemetry_pb2.MetricData(
                        metric_name=event.data.get("metric_name", ""),
                        metric_type="GAUGE",
                        numeric_value=float(event.data.get("value", 0)),
                        unit=event.data.get("unit", ""),
                    ),
                    source_component=event.probe_name,
                    tags=["process", "metric"],
                )
            else:
                # Security event
                proto_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"{event.probe_name}_{event.event_type}_{timestamp_ns}",
                    event_type="SECURITY",
                    severity=event.severity.value,
                    event_timestamp_ns=timestamp_ns,
                    source_component=event.probe_name,
                    tags=event.mitre_techniques + event.tags,
                )
                # Add security data
                if event.mitre_techniques:
                    proto_event.mitre_techniques.extend(event.mitre_techniques)

            proto_events.append(proto_event)

        # Create DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="PROC",
            events=proto_events,
            timestamp_ns=timestamp_ns,
            collection_agent="proc-agent-v3",
            agent_version="3.0.0",
        )

        # Add alert data for high-severity events
        for event in events:
            if event.severity.value in ("HIGH", "CRITICAL"):
                alert = telemetry_pb2.AlertData(
                    alert_type=event.event_type,
                    severity=event.severity.value,
                    description=str(event.data),
                    mitre_techniques=event.mitre_techniques,
                )
                device_telemetry.alerts.append(alert)

        return device_telemetry

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

        if not hasattr(event, "timestamp_ns") or event.timestamp_ns == 0:
            errors.append("Missing timestamp_ns")

        # Validate timestamp is reasonable
        now = time.time() * 1e9
        if hasattr(event, "timestamp_ns") and event.timestamp_ns > 0:
            if abs(event.timestamp_ns - now) > 3600 * 1e9:  # 1 hour tolerance
                errors.append("timestamp_ns too far from current time")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("ProcAgentV3 shutting down...")

        if self.eventbus_publisher:
            self.eventbus_publisher.close()

        logger.info("ProcAgentV3 shutdown complete")

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
    """Run Process Agent v3."""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS Process Agent v3")
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

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("AMOSKYS Process Agent v3 (Micro-Probe Architecture)")
    logger.info("=" * 70)

    agent = ProcAgentV3(collection_interval=args.interval)

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        agent.shutdown()


if __name__ == "__main__":
    main()
