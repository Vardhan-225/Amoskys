"""
MeshMixin — Drop-in mixin that adds mesh capabilities to any BaseAgent.

Usage:
    class MyAgent(BaseAgent, MeshMixin):
        def collect(self):
            data = self._poll_something()
            if data.is_suspicious:
                self.publish(SecurityEvent(
                    event_type=EventType.SUSPICIOUS_PROCESS,
                    source_agent=self.agent_id,
                    severity=Severity.MEDIUM,
                    payload=data.to_dict(),
                    related_pid=data.pid,
                ))

        def on_event(self, event: SecurityEvent):
            # React to events from other agents
            if event.event_type == EventType.DIRECTED_WATCH:
                target = event.payload.get("target_value")
                self._add_to_watch_list(target)

Design:
  - Backward compatible: agents work without mesh (publish becomes no-op)
  - Thread-safe: publish/on_event can be called from any thread
  - Zero overhead when mesh is not connected
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional, Set

from .events import EventType, SecurityEvent, Severity

logger = logging.getLogger("amoskys.mesh.mixin")


class MeshMixin:
    """Drop-in mixin that adds mesh pub/sub to any agent.

    Agents that inherit this mixin gain:
      - publish(event): send an event to the mesh
      - on_event(event): receive events from other agents (override)
      - watch_list: set of IOCs this agent is directed to watch
      - adaptive_interval: current polling interval based on mesh mode
    """

    # Class-level mesh bus reference (set by orchestrator at startup)
    _mesh_bus = None

    # Adaptive polling modes
    CALM_INTERVAL = 60
    ALERT_INTERVAL = 15
    HUNT_INTERVAL = 5
    RESPONSE_INTERVAL = 2

    def __init_mesh__(self) -> None:
        """Initialize mesh state. Call from agent __init__."""
        self._watch_list: Dict[str, Set[str]] = {
            "pid": set(),
            "ip": set(),
            "domain": set(),
            "path": set(),
        }
        self._watch_expiry: Dict[str, float] = {}
        self._adaptive_interval = self.CALM_INTERVAL
        self._mesh_event_buffer: List[SecurityEvent] = []
        self._mesh_lock = threading.Lock()

    @classmethod
    def set_mesh_bus(cls, bus) -> None:
        """Set the shared mesh bus instance. Called once at startup."""
        cls._mesh_bus = bus

    def publish(self, event: SecurityEvent) -> None:
        """Publish an event to the mesh bus.

        Safe to call even if mesh is not connected (becomes no-op).
        """
        if self._mesh_bus is None:
            # No mesh connected — buffer for later or just log
            logger.debug("Mesh not connected, buffering: %s", event)
            return

        self._mesh_bus.publish(event)

    def on_event(self, event: SecurityEvent) -> None:
        """Handle an event from the mesh. Override in subclasses.

        Default implementation handles DIRECTED_WATCH events to update
        the agent's watch list.
        """
        if event.event_type == EventType.DIRECTED_WATCH:
            payload = event.payload
            target_agent = payload.get("target_agent", "")

            # Only handle directives addressed to this agent
            agent_id = getattr(self, "agent_id", "")
            if target_agent and target_agent != agent_id:
                return

            target_type = payload.get("target_type", "")
            target_value = payload.get("target_value", "")
            duration_s = payload.get("duration_s", 300)

            if target_type in self._watch_list:
                self._watch_list[target_type].add(target_value)
                self._watch_expiry[f"{target_type}:{target_value}"] = (
                    time.time() + duration_s
                )
                logger.info(
                    "[%s] Added to watch list: %s=%s for %ds",
                    agent_id,
                    target_type,
                    target_value,
                    duration_s,
                )

        elif event.event_type == EventType.ADAPTIVE_MODE_CHANGE:
            mode = event.payload.get("mode", "calm")
            intervals = {
                "calm": self.CALM_INTERVAL,
                "alert": self.ALERT_INTERVAL,
                "hunt": self.HUNT_INTERVAL,
                "response": self.RESPONSE_INTERVAL,
            }
            self._adaptive_interval = intervals.get(mode, self.CALM_INTERVAL)
            logger.info(
                "[%s] Adaptive mode: %s (interval=%ds)",
                getattr(self, "agent_id", "?"),
                mode,
                self._adaptive_interval,
            )

    def is_watched(self, target_type: str, value: str) -> bool:
        """Check if a value is in this agent's directed watch list.

        Also prunes expired watches.
        """
        key = f"{target_type}:{value}"
        expiry = self._watch_expiry.get(key)
        if expiry and time.time() > expiry:
            self._watch_list.get(target_type, set()).discard(value)
            del self._watch_expiry[key]
            return False
        return value in self._watch_list.get(target_type, set())

    @property
    def adaptive_interval(self) -> float:
        """Current polling interval based on mesh adaptive mode."""
        return getattr(self, "_adaptive_interval", self.CALM_INTERVAL)

    def prune_expired_watches(self) -> int:
        """Remove expired watch entries. Returns count removed."""
        now = time.time()
        expired = [k for k, v in self._watch_expiry.items() if now > v]
        for key in expired:
            target_type, _, value = key.partition(":")
            self._watch_list.get(target_type, set()).discard(value)
            del self._watch_expiry[key]
        return len(expired)
