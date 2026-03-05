"""macOS Security Monitor Agent.

Monitors the macOS security framework layer via the Unified Logging system.
This is the macOS counterpart to the Linux KernelAuditAgent — same probe
architecture and event schema, different sensor and detection surface.

What this agent monitors (macOS security framework layer):
    - Certificate trust evaluation and PKI anomalies (trustd)
    - Gatekeeper and code signing enforcement (syspolicyd)
    - Security daemon health and availability
    - Unusual security framework event volumes per process

What this agent does NOT monitor (requires Endpoint Security Framework):
    - Kernel syscalls (execve, ptrace, setuid, etc.)
    - Process injection
    - Privilege escalation primitives
    - File permission changes at syscall level

See docs/Engineering/kernel_audit/macos_reality_matrix.md for the full
sensor truth analysis of what this agent can and cannot detect.

Usage:
    >>> from amoskys.agents.macos.security_monitor import MacOSSecurityMonitorAgent
    >>> agent = MacOSSecurityMonitorAgent(device_id="host-001")
    >>> agent.run_forever()

MITRE ATT&CK Coverage:
    - T1553.001: Code Signing (Gatekeeper bypass detection)
    - T1557:     Adversary-in-the-Middle (cert anomaly detection)
    - T1562:     Impair Defenses (security framework silence canary)
    - T1592:     Gather Victim Host Information (security framework flood)
"""

from __future__ import annotations

import logging
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
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.linux.kernel_audit.agent_types import KernelAuditEvent
from amoskys.agents.macos.security_monitor.collector import (
    BaseKernelAuditCollector,
    create_macos_security_collector,
)
from amoskys.agents.macos.security_monitor.probes import create_macos_security_probes
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logger = logging.getLogger(__name__)

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent,
    "macos_security_queue_path",
    "data/queue/macos_security.db",
)


# =============================================================================
# EventBus Publisher (shared pattern with other agents)
# =============================================================================


class EventBusPublisher:
    """Wrapper for EventBus gRPC client."""

    def __init__(self, address: str, cert_dir: str):
        self.address = address
        self.cert_dir = cert_dir
        self._channel = None
        self._stub = None

    def _ensure_channel(self):
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
            except FileNotFoundError as e:
                raise RuntimeError(f"Certificate not found: {e}")
            except Exception as e:
                raise RuntimeError(f"Failed to create gRPC channel: {e}")

    def publish(self, events: list) -> None:
        self._ensure_channel()
        for event in events:
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
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None


# =============================================================================
# MacOS Security Monitor Agent
# =============================================================================


class MacOSSecurityMonitorAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """macOS Security Framework Monitor with micro-probe architecture.

    Monitors Apple's security framework layer via Unified Logging.
    Uses the same probe architecture as KernelAuditAgent but targets
    macOS-specific detection vectors.

    Attributes:
        collector: MacOSUnifiedLogCollector for gathering security events
    """

    def __init__(
        self,
        collection_interval: float = 10.0,
        *,
        device_id: Optional[str] = None,
        agent_name: str = "macos_security_monitor",
        collector: Optional[BaseKernelAuditCollector] = None,
        probes: Optional[List[MicroProbe]] = None,
        eventbus_publisher: Optional[Any] = None,
        local_queue: Optional[Any] = None,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
    ) -> None:
        _auto_infra = device_id is None
        device_id = device_id or socket.gethostname()

        if _auto_infra and eventbus_publisher is None:
            eventbus_publisher = EventBusPublisher(EVENTBUS_ADDRESS, CERT_DIR)

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

        super().__init__(
            agent_name=agent_name,
            device_id=device_id,
            collection_interval=collection_interval,
            probes=probes,
            eventbus_publisher=eventbus_publisher,
            local_queue=local_queue or queue_adapter,
            queue_adapter=queue_adapter,
            metrics_interval=metrics_interval,
        )

        self._collector = collector
        self._total_security_events: int = 0
        self._total_threats_detected: int = 0

    def setup(self) -> bool:
        logger.info("Setting up %s for device %s", self.agent_name, self.device_id)

        if self._collector is None:
            self._collector = create_macos_security_collector()
        logger.info("Initialized collector: %s", type(self._collector).__name__)

        if not self._probes:
            default_probes = create_macos_security_probes()
            self.register_probes(default_probes)
            logger.info(
                "Registered %d macOS security probes", len(default_probes)
            )

        if not self.setup_probes(collector_shared_data_keys=["kernel_events"]):
            logger.error("Failed to initialize any probes")
            return False

        logger.info(
            "%s setup complete: %d probes active",
            self.agent_name,
            len([p for p in self._probes if p.enabled]),
        )
        return True

    def collect_data(self) -> Sequence[TelemetryEvent]:
        security_events: List[KernelAuditEvent] = []
        if self._collector:
            try:
                security_events = self._collector.collect_batch()
                self._total_security_events += len(security_events)
            except Exception as e:
                logger.error("Error collecting security events: %s", e)

        logger.debug(
            "Collected %d macOS security framework events", len(security_events)
        )

        now_ns = int(time.time() * 1e9)
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.agent_name,
            now_ns=now_ns,
            shared_data={"kernel_events": security_events},
        )

        events = self.run_probes(context)

        if events:
            self._total_threats_detected += len(events)
            logger.info(
                "Detected %d security anomalies from %d framework events",
                len(events),
                len(security_events),
            )

        return list(events)

    def get_health(self) -> Dict[str, Any]:
        base_health = {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "is_running": self.is_running,
            "uptime_seconds": time.time() - self.start_time,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "circuit_breaker_state": self.circuit_breaker.state,
        }
        base_health.update(
            {
                "collector_type": (
                    type(self._collector).__name__ if self._collector else None
                ),
                "total_security_events": self._total_security_events,
                "total_threats_detected": self._total_threats_detected,
                "probes": self.get_probe_health(),
            }
        )
        return base_health

    @property
    def collector(self) -> Optional[BaseKernelAuditCollector]:
        return self._collector

    def inject_events(self, events: List[KernelAuditEvent]) -> None:
        if not hasattr(self._collector, "inject"):
            raise RuntimeError("Collector does not support event injection")
        self._collector.inject(events)  # type: ignore


__all__ = ["MacOSSecurityMonitorAgent"]
