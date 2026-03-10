"""Agent Heartbeat v2 — structured liveness and health reporting.

Extracted from base.py to be a standalone, importable model. The heartbeat
captures everything needed to assess agent health at a glance:
    - Liveness: is the agent running, how long, last cycle timing
    - Health: circuit breaker state, queue depth, error rate
    - Probes: coverage breakdown (REAL/DEGRADED/BROKEN)
    - Capabilities: what the collector can see
    - Cross-agent: AgentBus connectivity, peer visibility
    - Detection: events emitted, detections, FP feedback count

Usage:
    heartbeat = AgentHeartbeat.create(
        agent_name="macos_process",
        device_id="macbook-pro",
        metrics=self._metrics,
        capabilities=self.collector.get_capabilities(),
        agent_bus=self.agent_bus,
    )
    # Serialize for EventBus or heartbeat file
    hb_dict = heartbeat.to_dict()
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from amoskys.agents.common.agent_bus import AgentBus
    from amoskys.agents.common.collector import CapabilityBadge
    from amoskys.agents.common.metrics import AgentMetrics


@dataclass
class AgentHeartbeat:
    """Complete agent health snapshot — emitted every collection cycle.

    Designed to be serialized to JSON (heartbeat file) or protobuf
    (AgentMetrics DeviceTelemetry event).
    """

    # Identity
    agent_name: str
    device_id: str
    timestamp_ns: int
    agent_version: str = "v2"

    # Liveness
    uptime_seconds: float = 0.0
    cycle_count: int = 0
    last_cycle_duration_ms: float = 0.0

    # Health
    circuit_breaker_state: str = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
    queue_depth: int = 0
    queue_bytes: int = 0
    error_rate: float = 0.0  # Fraction of failed cycles (last 100)

    # Probe health
    probes_total: int = 0
    probes_real: int = 0
    probes_degraded: int = 0
    probes_broken: int = 0
    probes_disabled: int = 0

    # Capabilities (from collector)
    capabilities: Dict[str, str] = field(default_factory=dict)  # name → badge string

    # Cross-agent
    agent_bus_connected: bool = False
    peer_agents_visible: int = 0

    # Detection metrics
    events_emitted_last_cycle: int = 0
    detections_last_hour: int = 0
    false_positives_reported: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON/protobuf conversion."""
        return asdict(self)

    @classmethod
    def create(
        cls,
        agent_name: str,
        device_id: str,
        metrics: Optional[AgentMetrics] = None,
        capabilities: Optional[Dict[str, Any]] = None,
        agent_bus: Optional[AgentBus] = None,
        start_time_ns: Optional[int] = None,
    ) -> AgentHeartbeat:
        """Factory: build heartbeat from agent components.

        Args:
            agent_name: Agent identifier.
            device_id: Device/host identifier.
            metrics: AgentMetrics instance for health data.
            capabilities: Collector capability badges.
            agent_bus: AgentBus for peer visibility.
            start_time_ns: Agent start timestamp for uptime calc.

        Returns:
            Populated AgentHeartbeat.
        """
        now_ns = time.time_ns()
        hb = cls(
            agent_name=agent_name,
            device_id=device_id,
            timestamp_ns=now_ns,
        )

        if start_time_ns:
            hb.uptime_seconds = (now_ns - start_time_ns) / 1e9

        if metrics is not None:
            hb.cycle_count = metrics.loops_started
            hb.circuit_breaker_state = metrics.circuit_breaker_state.value
            hb.queue_depth = metrics.queue_current_depth
            hb.queue_bytes = metrics.queue_current_bytes
            hb.probes_total = metrics.probes_total
            hb.probes_real = metrics.probes_real
            hb.probes_degraded = metrics.probes_degraded
            hb.probes_broken = metrics.probes_broken
            hb.probes_disabled = getattr(metrics, "probes_disabled", 0)
            hb.events_emitted_last_cycle = metrics.probe_events_emitted

            # Error rate: fraction of failed cycles
            total = metrics.loops_succeeded + metrics.loops_failed
            if total > 0:
                hb.error_rate = metrics.loops_failed / total

        if capabilities:
            hb.capabilities = {
                name: (badge.value if hasattr(badge, "value") else str(badge))
                for name, badge in capabilities.items()
            }

        if agent_bus is not None:
            hb.agent_bus_connected = True
            try:
                hb.peer_agents_visible = len(agent_bus.get_active_agents())
            except Exception:
                hb.peer_agents_visible = 0

        return hb
