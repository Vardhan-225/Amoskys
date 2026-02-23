#!/usr/bin/env python3
"""KernelAudit Agent v2 - Micro-Probe Based Kernel Audit Monitoring.

This is the v2 implementation of the Kernel Audit Agent using the micro-probe
architecture. Each probe focuses on a specific kernel-level threat vector:

    1. ExecveHighRiskProbe - Execution from /tmp, /dev/shm, etc.
    2. PrivEscSyscallProbe - setuid/setgid privilege escalation
    3. KernelModuleLoadProbe - Rootkit/driver loading
    4. PtraceAbuseProbe - Process injection via ptrace
    5. FilePermissionTamperProbe - chmod/chown on /etc/shadow, etc.
    6. AuditTamperProbe - Attempts to blind audit subsystem
    7. SyscallFloodProbe - Brute force/enumeration patterns

Architecture:
    - Uses KernelAuditCollector to gather normalized audit events
    - Events passed to probes via context.shared_data["kernel_events"]
    - Each probe returns TelemetryEvents for detected threats
    - Inherits metrics/observability from HardenedAgentBase

Usage:
    >>> from amoskys.agents.kernel_audit import KernelAuditAgentV2
    >>> agent = KernelAuditAgentV2(device_id="host-001")
    >>> agent.run_forever()

MITRE ATT&CK Coverage:
    - T1068: Exploitation for Privilege Escalation
    - T1055: Process Injection
    - T1014: Rootkit
    - T1547: Boot or Logon Autostart Execution
    - T1222: File and Directory Permissions Modification
    - T1562: Impair Defenses
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Sequence

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    TelemetryEvent,
)
from amoskys.agents.kernel_audit.collector import (
    BaseKernelAuditCollector,
    create_kernel_audit_collector,
)
from amoskys.agents.kernel_audit.probes import create_kernel_audit_probes
from amoskys.agents.kernel_audit.types import KernelAuditEvent

logger = logging.getLogger(__name__)


class KernelAuditAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """Kernel Audit Agent v2 with micro-probe architecture.

    Monitors kernel-level events (syscalls, privilege changes, module loads)
    using pluggable collectors and specialized micro-probes.

    Attributes:
        collector: KernelAuditCollector for gathering audit events
        audit_log_path: Path to audit log (Linux)
    """

    def __init__(
        self,
        device_id: str,
        agent_name: str = "kernel_audit_v2",
        collection_interval: float = 5.0,
        audit_log_path: str = "/var/log/audit/audit.log",
        *,
        collector: Optional[BaseKernelAuditCollector] = None,
        probes: Optional[List[MicroProbe]] = None,
        eventbus_publisher: Optional[Any] = None,
        local_queue: Optional[Any] = None,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
    ) -> None:
        """Initialize KernelAudit Agent v2.

        Args:
            device_id: Unique device identifier
            agent_name: Agent name for logging/metrics
            collection_interval: Seconds between collection cycles
            audit_log_path: Path to audit log file
            collector: Optional custom collector (uses AuditdLogCollector if None)
            probes: Optional custom probes (uses default probes if None)
            eventbus_publisher: EventBus client for publishing
            local_queue: LocalQueue for offline resilience
            queue_adapter: LocalQueueAdapter for simplified queue interface
            metrics_interval: Seconds between metrics emissions
        """
        # Initialize MicroProbeAgentMixin first (handles probes)
        super().__init__(
            agent_name=agent_name,
            device_id=device_id,
            collection_interval=collection_interval,
            probes=probes,
            eventbus_publisher=eventbus_publisher,
            local_queue=local_queue,
            queue_adapter=queue_adapter,
            metrics_interval=metrics_interval,
        )

        self.audit_log_path = audit_log_path
        self._collector = collector

        # Stats
        self._total_audit_events: int = 0
        self._total_threats_detected: int = 0

    def setup(self) -> bool:
        """Initialize kernel audit collector and probes.

        Returns:
            True if setup succeeded, False otherwise
        """
        logger.info("Setting up %s for device %s", self.agent_name, self.device_id)

        # Initialize collector
        if self._collector is None:
            self._collector = create_kernel_audit_collector(
                source=self.audit_log_path,
                use_stub=False,
            )
        logger.info("Initialized collector: %s", type(self._collector).__name__)

        # Register default probes if none provided
        if not self._probes:
            default_probes = create_kernel_audit_probes()
            self.register_probes(default_probes)
            logger.info(
                "Registered %d default kernel audit probes", len(default_probes)
            )

        # Initialize all probes
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
        """Collect kernel audit events and run through probes.

        Returns:
            List of TelemetryEvents from all probes
        """
        # Collect batch of audit events
        kernel_events: List[KernelAuditEvent] = []
        if self._collector:
            try:
                kernel_events = self._collector.collect_batch()
                self._total_audit_events += len(kernel_events)
            except Exception as e:
                logger.error("Error collecting audit events: %s", e)

        if not kernel_events:
            return []

        logger.debug("Collected %d kernel audit events", len(kernel_events))

        # Build probe context with shared kernel events
        now_ns = int(time.time() * 1e9)
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.agent_name,
            now_ns=now_ns,
            shared_data={"kernel_events": kernel_events},
        )

        # Run all probes
        events = self.run_probes(context)

        if events:
            self._total_threats_detected += len(events)
            logger.info(
                "Detected %d threats from %d audit events",
                len(events),
                len(kernel_events),
            )

        return events

    def get_health(self) -> Dict[str, Any]:
        """Get agent health status.

        Returns:
            Dict with health metrics
        """
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

        # Add kernel-specific stats
        base_health.update(
            {
                "collector_type": (
                    type(self._collector).__name__ if self._collector else None
                ),
                "audit_log_path": self.audit_log_path,
                "total_audit_events": self._total_audit_events,
                "total_threats_detected": self._total_threats_detected,
                "probes": self.get_probe_health(),
            }
        )

        return base_health

    @property
    def collector(self) -> Optional[BaseKernelAuditCollector]:
        """Get the audit collector instance."""
        return self._collector

    def inject_events(self, events: List[KernelAuditEvent]) -> None:
        """Inject events for testing (only works with StubCollector).

        Args:
            events: Events to inject

        Raises:
            RuntimeError: If collector doesn't support injection
        """
        if not hasattr(self._collector, "inject"):
            raise RuntimeError("Collector does not support event injection")
        self._collector.inject(events)  # type: ignore


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "KernelAuditAgentV2",
]


# B5.1: Deprecated alias — will be removed in v1.0
KernelAuditAgentV2 = KernelAuditAgent
