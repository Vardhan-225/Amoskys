#!/usr/bin/env python3
"""AMOSKYS Process Agent (ProcAgent) - Refactored with HardenedAgentBase.

This is the reference implementation showing how to migrate existing agents
to the new unbreakable architecture. Compare with proc_agent.py to see the
simplification and improvements.

Key Changes:
    - Inherits from HardenedAgentBase (consistent behavior)
    - Separates concerns: collect, validate, enrich, publish
    - Circuit breaker and retry logic handled by base class
    - Local queue integration simplified
    - Better error handling and logging
    - Health tracking built-in
"""

import logging
import socket
import time

import grpc
import psutil

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ProcAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "queue_path", "data/queue/proc_agent.db")


# ----------------- EventBus Publisher Wrapper ------------------------------


class EventBusPublisher:
    """Wrapper for EventBus gRPC client.

    Provides a simple publish(events) interface that the HardenedAgentBase
    can use. Handles mTLS connection and UniversalEnvelope creation.
    """

    def __init__(self, address: str, cert_dir: str):
        """Initialize EventBus publisher.

        Args:
            address: EventBus gRPC address (host:port)
            cert_dir: Directory containing mTLS certificates
        """
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
        """Create gRPC channel if needed."""
        if self._channel is None:
            try:
                # Load client certificates for mTLS
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
        """Publish events to EventBus.

        Args:
            events: List of DeviceTelemetry protobuf messages

        Raises:
            Exception: On publish failure (handled by base class retry logic)
        """
        self._ensure_channel()

        for device_telemetry in events:
            # Create UniversalEnvelope
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

            # Publish via UniversalEventBus
            ack = self._stub.PublishTelemetry(envelope, timeout=5.0)

            if ack.status != telemetry_pb2.UniversalAck.OK:
                raise Exception(f"EventBus returned status: {ack.status}")

    def close(self):
        """Close gRPC channel."""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# ----------------- ProcAgent Implementation --------------------------------


class ProcAgent(HardenedAgentBase):
    """Process monitoring agent with unbreakable architecture.

    Collects system process telemetry and publishes to EventBus:
        - Process count
        - System CPU usage
        - System memory usage
        - Per-process metrics (future enhancement)

    Inherits robust error handling, circuit breaker, and queue management
    from HardenedAgentBase.
    """

    def __init__(self, collection_interval: float = 30.0):
        """Initialize process agent.

        Args:
            collection_interval: Seconds between collections (default: 30)
        """
        # Get device ID
        device_id = socket.gethostname()

        # Create EventBus publisher
        publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Create local queue adapter
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="proc_agent",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,  # 50MB
            max_retries=10,
        )

        # Initialize base class
        super().__init__(
            agent_name="proc_agent",
            device_id=device_id,
            collection_interval=collection_interval,
            eventbus_publisher=publisher,
            local_queue=queue_adapter,
        )

        # Agent-specific state
        self.last_pids = set()

    # ----------------- Lifecycle Hooks -------------------------------------

    def setup(self) -> bool:
        """Initialize agent resources.

        Verifies:
            - Certificates exist
            - EventBus is reachable (optional check)
            - psutil is available

        Returns:
            True if setup succeeded
        """
        try:
            # Verify certificates exist
            import os

            required_certs = ["ca.crt", "agent.crt", "agent.key"]
            for cert in required_certs:
                cert_path = f"{CERT_DIR}/{cert}"
                if not os.path.exists(cert_path):
                    logger.error(f"Certificate not found: {cert_path}")
                    return False

            # Verify psutil works
            _ = psutil.cpu_percent(interval=0)

            logger.info("ProcAgent setup complete")
            logger.info(f"EventBus: {EVENTBUS_ADDRESS}")
            logger.info(f"Queue: {QUEUE_PATH}")
            logger.info(f"Device: {self.device_id}")

            return True

        except Exception as e:
            logger.error(f"Setup failed: {e}", exc_info=True)
            return False

    def collect_data(self) -> list:
        """Collect process telemetry.

        Returns:
            List containing single DeviceTelemetry protobuf message

        Note:
            This returns raw telemetry. Validation and enrichment
            happen in separate stages (see validate_event, enrich_event).
        """
        timestamp_ns = int(time.time() * 1e9)

        # Scan processes
        processes = self._scan_processes()

        # Create telemetry events
        events = []

        # Process count metric
        events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"proc_count_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                metric_data=telemetry_pb2.MetricData(
                    metric_name="process_count",
                    metric_type="GAUGE",
                    numeric_value=float(len(processes)),
                    unit="processes",
                ),
                source_component="proc_agent",
                tags=["process", "metric"],
            )
        )

        # System CPU metric
        cpu_percent = psutil.cpu_percent(interval=0.1)
        events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"system_cpu_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                metric_data=telemetry_pb2.MetricData(
                    metric_name="system_cpu_percent",
                    metric_type="GAUGE",
                    numeric_value=cpu_percent,
                    unit="percent",
                ),
                source_component="proc_agent",
                tags=["system", "metric"],
            )
        )

        # System memory metric
        mem = psutil.virtual_memory()
        events.append(
            telemetry_pb2.TelemetryEvent(
                event_id=f"system_mem_{timestamp_ns}",
                event_type="METRIC",
                severity="INFO",
                event_timestamp_ns=timestamp_ns,
                metric_data=telemetry_pb2.MetricData(
                    metric_name="system_memory_percent",
                    metric_type="GAUGE",
                    numeric_value=mem.percent,
                    unit="percent",
                ),
                source_component="proc_agent",
                tags=["system", "metric"],
            )
        )

        # Create DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="PROC",
            events=events,
            timestamp_ns=timestamp_ns,
            collection_agent="proc-agent",
            agent_version="2.0.0",  # v2 = refactored version
        )

        return [device_telemetry]

    def validate_event(self, event: telemetry_pb2.DeviceTelemetry) -> ValidationResult:
        """Validate DeviceTelemetry message.

        Checks:
            - device_id is present and non-empty
            - timestamp_ns is reasonable (not too far in past/future)
            - events list is not empty
            - each event has required fields

        Args:
            event: DeviceTelemetry protobuf message

        Returns:
            ValidationResult with errors if invalid
        """
        errors = []

        # Check device_id
        if not event.device_id:
            errors.append("device_id is required")

        # Check timestamp
        now = time.time() * 1e9
        if event.timestamp_ns <= 0:
            errors.append("timestamp_ns must be positive")
        elif abs(event.timestamp_ns - now) > 3600 * 1e9:  # 1 hour tolerance
            errors.append(
                f"timestamp_ns too far from current time: {event.timestamp_ns}"
            )

        # Check events
        if not event.events:
            errors.append("events list is empty")
        else:
            for idx, tel_event in enumerate(event.events):
                if not tel_event.event_id:
                    errors.append(f"event[{idx}].event_id is required")
                if not tel_event.event_type:
                    errors.append(f"event[{idx}].event_type is required")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def enrich_event(
        self, event: telemetry_pb2.DeviceTelemetry
    ) -> telemetry_pb2.DeviceTelemetry:
        """Add metadata to telemetry.

        Adds:
            - IP address
            - Device metadata (manufacturer, model, protocols)

        Args:
            event: Validated DeviceTelemetry

        Returns:
            Enriched DeviceTelemetry
        """
        try:
            # Add IP address
            ip_addr = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip_addr = "127.0.0.1"

        # Add metadata if not present
        if not event.HasField("metadata"):
            event.metadata.CopyFrom(
                telemetry_pb2.DeviceMetadata(
                    manufacturer="Unknown",
                    model=socket.gethostname(),
                    ip_address=ip_addr,
                    protocols=["PROC"],
                )
            )

        return event

    def shutdown(self) -> None:
        """Cleanup on agent shutdown.

        Closes EventBus connection.
        """
        logger.info("ProcAgent shutting down")
        if self.eventbus_publisher:
            self.eventbus_publisher.close()

    # ----------------- Helper Methods --------------------------------------

    def _scan_processes(self) -> dict:
        """Scan all running processes.

        Returns:
            Dict mapping PID to process info
        """
        processes = {}
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                processes[proc.pid] = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "username": proc.username(),
                    "cpu_percent": proc.cpu_percent(interval=0),
                    "memory_percent": proc.memory_percent(),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes


# ----------------- Main Entry Point ----------------------------------------


def main():
    """Start process agent.

    Creates and runs agent indefinitely until SIGTERM/SIGINT.
    """
    logger.info("=" * 70)
    logger.info("AMOSKYS Process Agent v2 (Refactored)")
    logger.info("=" * 70)

    agent = ProcAgent(collection_interval=30.0)
    agent.run_forever()


if __name__ == "__main__":
    main()
