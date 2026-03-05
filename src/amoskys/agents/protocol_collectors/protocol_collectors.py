#!/usr/bin/env python3
"""ProtocolCollectors Agent - Micro-Probe Based Protocol Monitoring.

This is the implementation using the micro-probe architecture.
Each probe focuses on a specific protocol-level threat vector:

    1. HTTPSuspiciousHeadersProbe - Suspicious HTTP headers (T1071.001)
    2. TLSSSLAnomalyProbe - TLS/SSL anomalies (T1573.002)
    3. SSHBruteForceProbe - SSH brute force (T1110, T1021.004)
    4. DNSTunnelingProbe - DNS exfiltration (T1048.003)
    5. SQLInjectionProbe - SQL injection (T1190)
    6. RDPSuspiciousProbe - RDP suspicious activity (T1021.001)
    7. FTPCleartextCredsProbe - FTP credential exposure (T1552.001)
    8. SMTPSpamPhishProbe - SMTP spam/phishing (T1566.001)
    9. IRCP2PC2Probe - IRC/P2P C2 (T1071.001)
    10. ProtocolAnomalyProbe - Protocol anomalies (T1205)

Architecture:
    - Uses ProtocolCollector to gather protocol events
    - Events passed to probes via context.shared_data["protocol_events"]
    - Each probe returns TelemetryEvents for detected threats
    - Inherits metrics/observability from HardenedAgentBase

Usage:
    >>> from amoskys.agents.protocol_collectors import ProtocolCollectors
    >>> agent = ProtocolCollectors(device_id="host-001")
    >>> agent.run_forever()
"""

from __future__ import annotations

import logging
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import grpc

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

from .agent_types import ProtocolEvent

# Use relative imports to avoid triggering amoskys.agents.__init__
from .collector import BaseProtocolCollector, create_protocol_collector
from .probes import PROTOCOL_PROBES

logger = logging.getLogger(__name__)

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = os.environ.get(
    "AMOSKYS_PROTOCOL_COLLECTORS_QUEUE_PATH",
    getattr(
        config.agent,
        "protocol_collectors_queue_path",
        "data/queue/protocol_collectors.db",
    ),
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

        for event in events:
            # Already-wrapped envelopes (e.g. from drain path) go directly
            if isinstance(event, telemetry_pb2.UniversalEnvelope):
                envelope = event
            else:
                timestamp_ns = int(time.time() * 1e9)
                idempotency_key = f"{event.device_id}_{timestamp_ns}"
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=timestamp_ns,
                    idempotency_key=idempotency_key,
                    device_telemetry=event,
                    priority="NORMAL",
                    requires_acknowledgment=True,
                    schema_version=1,
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


class ProtocolCollectors(MicroProbeAgentMixin, HardenedAgentBase):
    """Protocol plane threat detection using micro-probe architecture.

    Monitors network protocol traffic for security threats across
    multiple protocol types (HTTP, DNS, SSH, etc.).

    Attributes:
        collector: Protocol event collector instance
        log_path: Path to network/protocol log file
        use_stub: Use stub collector for testing
    """

    def __init__(
        self,
        collection_interval: float = 5.0,
        *,
        device_id: Optional[str] = None,
        agent_name: str = "protocol_collectors",
        log_path: str = "/var/log/syslog",
        collector: Optional[BaseProtocolCollector] = None,
        use_stub: bool = False,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
        probes: Optional[Sequence[MicroProbe]] = None,
    ):
        """Initialize ProtocolCollectors agent.

        Args:
            collection_interval: Seconds between collection cycles
            device_id: Unique device identifier (defaults to hostname)
            agent_name: Agent name for logging/metrics
            log_path: Path to network log file
            collector: Custom collector (overrides log_path)
            use_stub: Use stub collector for testing
            queue_adapter: Queue adapter for event persistence
            metrics_interval: Seconds between metrics emissions
            probes: Custom probes (overrides defaults)
        """
        # Auto-create infra when called via cli.run_agent() (zero-args path)
        _auto_infra = device_id is None
        device_id = device_id or socket.gethostname()

        if _auto_infra and queue_adapter is None:
            Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
            queue_adapter = LocalQueueAdapter(
                queue_path=QUEUE_PATH,
                agent_name=agent_name,
                device_id=device_id,
                max_bytes=50 * 1024 * 1024,
                max_retries=10,
                signing_key_path=f"{CERT_DIR}/agent.ed25519",
            )

        eventbus_publisher = None
        if _auto_infra:
            eventbus_publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

        # Initialize using super() for proper MRO handling
        super().__init__(
            agent_name=agent_name,
            device_id=device_id,
            collection_interval=collection_interval,
            probes=probes,
            eventbus_publisher=eventbus_publisher,
            local_queue=queue_adapter,
            queue_adapter=queue_adapter,
            metrics_interval=metrics_interval,
        )

        self.log_path = log_path
        self.use_stub = use_stub
        self._collector = collector

    def setup(self) -> bool:
        """Initialize collector and register probes.

        Returns:
            True if setup succeeded, False otherwise
        """
        logger.info(f"Setting up {self.agent_name} for device {self.device_id}")

        # Initialize collector
        if self._collector is None:
            self._collector = create_protocol_collector(
                use_stub=self.use_stub,
                log_path=self.log_path,
            )
        logger.info(f"Initialized collector: {type(self._collector).__name__}")

        # Register default probes if none were provided
        if not self.probes:
            self._register_default_probes()

        logger.info(
            f"{self.agent_name} setup complete: {len(self.probes)} probes active"
        )
        return True

    def _register_default_probes(self) -> None:
        """Register all default protocol collector probes."""
        for probe_class in PROTOCOL_PROBES:
            probe = probe_class()
            self.register_probe(probe)
        logger.info(
            f"Registered {len(PROTOCOL_PROBES)} default protocol_collectors probes"
        )

    def collect_data(self) -> List[Dict[str, Any]]:
        """Collect protocol events and run through probes.

        This implements the abstract method from HardenedAgentBase.

        Returns:
            List of telemetry dictionaries from probe analysis
        """
        results: List[Dict[str, Any]] = []

        # Collect raw protocol events
        try:
            protocol_events = self._collector.collect()
            logger.debug(f"Collected {len(protocol_events)} protocol events")
        except Exception as e:
            logger.error(f"Error collecting protocol events: {e}")
            return results

        # Create probe context with events
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.agent_name,
            shared_data={"protocol_events": protocol_events},
        )

        # Run all probes
        telemetry_events = self.run_probes(context)

        # Convert to dictionaries
        # NOTE: Do not enqueue here — base class run() handles queue_adapter.enqueue()
        for event in telemetry_events:
            event_dict = event.to_dict()
            event_dict["device_id"] = self.device_id
            event_dict["agent"] = self.agent_name
            results.append(event_dict)

        return results

    def cleanup(self) -> None:
        """Clean up resources."""
        logger.info(f"Cleaning up {self.agent_name}")
        # Collector cleanup if needed
        if hasattr(self._collector, "cleanup"):
            self._collector.cleanup()


# Convenience factory function
def create_protocol_collectors(
    device_id: str,
    **kwargs,
) -> "ProtocolCollectors":
    """Create and configure a ProtocolCollectors agent.

    Args:
        device_id: Unique device identifier
        **kwargs: Additional configuration options

    Returns:
        Configured ProtocolCollectors instance
    """
    return ProtocolCollectors(device_id=device_id, **kwargs)
