"""AgentBus — local shared context between co-located AMOSKYS agents.

NOT a message queue. A shared blackboard where agents post threat signals
that other agents can read. Updated every collection cycle.

Design decisions:
    1. Thread-safe (agents run in separate threads/processes).
    2. Volatile — no persistence. This is real-time context, not telemetry.
    3. TTL-based expiry — stale contexts and alerts auto-expire.
    4. Zero external dependencies — pure Python threading primitives.

Why this exists:
    - ProcessAgent detects LOLBin → NetworkAgent checks that PID's connections
    - PersistenceAgent finds new LaunchAgent → ProcessAgent watches for execution
    - CorrelationAgent reads all contexts instead of re-running 7 collectors
    - Any agent can post an urgent PeerAlert visible to all others

Usage:
    # In agent's collect_data():
    bus = self.agent_bus
    bus.post_context("process_agent", ThreatContext(
        agent_name="process_agent",
        timestamp_ns=time.time_ns(),
        active_pids={1234, 5678},
        suspicious_ips=set(),
        persistence_paths=set(),
        active_techniques={"T1059", "T1218"},
        risk_indicators={"lolbin_count": 0.7},
    ))

    # In another agent's scan_with_context():
    proc_ctx = bus.get_context("process_agent")
    if proc_ctx and pid in proc_ctx.active_pids:
        # Cross-agent correlation!

    # Urgent alerts:
    bus.post_alert(PeerAlert(
        source_agent="network_agent",
        alert_type="c2_beacon_detected",
        timestamp_ns=time.time_ns(),
        data={"pid": 1234, "remote_ip": "198.51.100.1", "port": 443},
    ))
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)

# Default TTLs
CONTEXT_TTL_SECONDS = 120  # Agent context expires after 2 minutes (4x typical cycle)
ALERT_TTL_SECONDS = 300  # Peer alerts expire after 5 minutes
MAX_ALERTS = 1000  # Max alerts stored before oldest evicted


@dataclass(frozen=True)
class ThreatContext:
    """What an agent knows about current threats — shared with peers.

    Frozen (immutable) to prevent race conditions. Agents post a new
    ThreatContext each cycle; readers never modify it.

    Fields are designed for fast cross-agent lookups:
        active_pids: PIDs currently under suspicion
        suspicious_ips: IPs flagged by this agent
        persistence_paths: Paths where persistence was detected
        active_techniques: MITRE technique IDs currently firing
        risk_indicators: Named scores (0.0-1.0) for risk dimensions
        shared_data_summary: Compact summary of collector data (not full data)
    """

    agent_name: str
    timestamp_ns: int
    active_pids: FrozenSet[int] = field(default_factory=frozenset)
    suspicious_ips: FrozenSet[str] = field(default_factory=frozenset)
    persistence_paths: FrozenSet[str] = field(default_factory=frozenset)
    active_techniques: FrozenSet[str] = field(default_factory=frozenset)
    risk_indicators: Dict[str, float] = field(default_factory=dict)
    shared_data_summary: Dict[str, Any] = field(default_factory=dict)

    @property
    def age_seconds(self) -> float:
        """Seconds since this context was created."""
        return (time.time_ns() - self.timestamp_ns) / 1e9

    @property
    def is_expired(self) -> bool:
        """True if context is older than TTL."""
        return self.age_seconds > CONTEXT_TTL_SECONDS


@dataclass(frozen=True)
class PeerAlert:
    """Urgent signal from one agent to all others.

    Posted when an agent detects something that other agents should
    immediately act on (e.g., C2 beacon detected, new persistence installed).

    Frozen (immutable) for thread safety. TTL-based auto-expiry.
    """

    source_agent: str
    alert_type: str  # "c2_detected", "new_persistence", etc.
    timestamp_ns: int
    data: Dict[str, Any] = field(default_factory=dict)
    ttl_seconds: int = ALERT_TTL_SECONDS
    severity: str = "HIGH"  # INFO, MEDIUM, HIGH, CRITICAL

    @property
    def age_seconds(self) -> float:
        """Seconds since this alert was posted."""
        return (time.time_ns() - self.timestamp_ns) / 1e9

    @property
    def is_expired(self) -> bool:
        """True if alert has exceeded its TTL."""
        return self.age_seconds > self.ttl_seconds


class AgentBus:
    """Local shared context between co-located agents.

    Thread-safe shared blackboard. Agents post ThreatContext each cycle
    and read other agents' contexts for cross-domain correlation.

    The bus is volatile — it exists only in memory while agents run.
    On restart, agents rebuild context from their first collection cycle.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._contexts: Dict[str, ThreatContext] = {}
        self._alerts: List[PeerAlert] = []
        self._stats = _BusStats()

    # ── Context API ──

    def post_context(self, agent_name: str, context: ThreatContext) -> None:
        """Post threat context from an agent's latest cycle.

        Replaces any previous context from the same agent.
        Thread-safe — can be called from any agent thread.

        Args:
            agent_name: The posting agent's name.
            context: Immutable ThreatContext snapshot.
        """
        with self._lock:
            self._contexts[agent_name] = context
            self._stats.contexts_posted += 1

    def get_context(self, agent_name: str) -> Optional[ThreatContext]:
        """Read another agent's latest context.

        Returns None if the agent hasn't posted yet or its context expired.
        Does NOT remove the context (read is non-destructive).

        Args:
            agent_name: The agent whose context to read.

        Returns:
            ThreatContext if available and not expired, else None.
        """
        with self._lock:
            ctx = self._contexts.get(agent_name)
            if ctx is None:
                return None
            if ctx.is_expired:
                del self._contexts[agent_name]
                self._stats.contexts_expired += 1
                return None
            self._stats.contexts_read += 1
            return ctx

    def get_all_contexts(self) -> Dict[str, ThreatContext]:
        """Read all agent contexts (non-expired).

        Used by the Correlation agent to get the full picture without
        re-running all collectors.

        Returns:
            Dict of agent_name → ThreatContext for all non-expired contexts.
        """
        with self._lock:
            self._evict_expired_contexts()
            self._stats.contexts_read += len(self._contexts)
            return dict(self._contexts)

    def get_active_agents(self) -> List[str]:
        """List agent names with active (non-expired) contexts."""
        with self._lock:
            self._evict_expired_contexts()
            return list(self._contexts.keys())

    # ── Alert API ──

    def post_alert(self, alert: PeerAlert) -> None:
        """Post urgent alert visible to all agents immediately.

        Alerts auto-expire after their TTL. The bus keeps at most
        MAX_ALERTS alerts; oldest are evicted when limit is reached.

        Args:
            alert: Immutable PeerAlert to broadcast.
        """
        with self._lock:
            self._alerts.append(alert)
            self._stats.alerts_posted += 1

            # Evict oldest if over limit
            if len(self._alerts) > MAX_ALERTS:
                evicted = len(self._alerts) - MAX_ALERTS
                self._alerts = self._alerts[evicted:]
                self._stats.alerts_evicted += evicted

    def get_alerts(self, since_ns: int = 0) -> List[PeerAlert]:
        """Get alerts posted since a timestamp.

        Filters out expired alerts automatically.

        Args:
            since_ns: Only return alerts posted after this timestamp.
                      Use 0 to get all non-expired alerts.

        Returns:
            List of non-expired PeerAlert objects, ordered by timestamp.
        """
        with self._lock:
            self._evict_expired_alerts()
            result = [a for a in self._alerts if a.timestamp_ns > since_ns]
            self._stats.alerts_read += len(result)
            return result

    def get_alerts_by_type(self, alert_type: str) -> List[PeerAlert]:
        """Get all non-expired alerts of a specific type.

        Args:
            alert_type: Alert type to filter (e.g., "c2_detected").

        Returns:
            List of matching non-expired PeerAlert objects.
        """
        with self._lock:
            self._evict_expired_alerts()
            return [a for a in self._alerts if a.alert_type == alert_type]

    # ── Cross-Agent Queries ──

    def get_all_suspicious_pids(self) -> Set[int]:
        """Union of all active_pids from all non-expired agent contexts.

        Quick check: "Is this PID suspicious according to ANY agent?"
        """
        with self._lock:
            self._evict_expired_contexts()
            pids: Set[int] = set()
            for ctx in self._contexts.values():
                pids.update(ctx.active_pids)
            return pids

    def get_all_suspicious_ips(self) -> Set[str]:
        """Union of all suspicious_ips from all non-expired agent contexts."""
        with self._lock:
            self._evict_expired_contexts()
            ips: Set[str] = set()
            for ctx in self._contexts.values():
                ips.update(ctx.suspicious_ips)
            return ips

    def get_all_active_techniques(self) -> Set[str]:
        """Union of all MITRE techniques currently detected by any agent."""
        with self._lock:
            self._evict_expired_contexts()
            techniques: Set[str] = set()
            for ctx in self._contexts.values():
                techniques.update(ctx.active_techniques)
            return techniques

    # ── Observability ──

    def get_stats(self) -> Dict[str, int]:
        """Bus usage statistics for metrics/heartbeat."""
        with self._lock:
            return {
                "active_agents": len(self._contexts),
                "pending_alerts": len(self._alerts),
                "contexts_posted": self._stats.contexts_posted,
                "contexts_read": self._stats.contexts_read,
                "contexts_expired": self._stats.contexts_expired,
                "alerts_posted": self._stats.alerts_posted,
                "alerts_read": self._stats.alerts_read,
                "alerts_evicted": self._stats.alerts_evicted,
            }

    def clear(self) -> None:
        """Clear all contexts and alerts. Used in tests."""
        with self._lock:
            self._contexts.clear()
            self._alerts.clear()

    # ── Internal ──

    def _evict_expired_contexts(self) -> None:
        """Remove expired contexts. Must hold self._lock."""
        expired = [name for name, ctx in self._contexts.items() if ctx.is_expired]
        for name in expired:
            del self._contexts[name]
            self._stats.contexts_expired += 1

    def _evict_expired_alerts(self) -> None:
        """Remove expired alerts. Must hold self._lock."""
        before = len(self._alerts)
        self._alerts = [a for a in self._alerts if not a.is_expired]
        evicted = before - len(self._alerts)
        if evicted:
            self._stats.alerts_evicted += evicted


class _BusStats:
    """Internal counters for AgentBus observability."""

    def __init__(self) -> None:
        self.contexts_posted: int = 0
        self.contexts_read: int = 0
        self.contexts_expired: int = 0
        self.alerts_posted: int = 0
        self.alerts_read: int = 0
        self.alerts_evicted: int = 0


# ── Singleton for co-located agents ──

_global_bus: Optional[AgentBus] = None
_global_bus_lock = threading.Lock()


def get_agent_bus() -> AgentBus:
    """Get or create the global AgentBus singleton.

    All co-located agents share the same bus instance. Thread-safe.
    """
    global _global_bus
    if _global_bus is None:
        with _global_bus_lock:
            if _global_bus is None:
                _global_bus = AgentBus()
                logger.info("AgentBus initialized (singleton)")
    return _global_bus


def reset_agent_bus() -> None:
    """Reset the global bus. Used in tests only."""
    global _global_bus
    with _global_bus_lock:
        _global_bus = None
