"""
AMOSKYS Agent Mesh — Distributed Security Nervous System.

Agents publish SecurityEvents to the MeshBus. Other agents subscribe
and react. IGRIS orchestrates autonomous defense via ActionExecutor.

Usage:
    from amoskys.mesh import SecurityEvent, EventType, MeshBus, ActionExecutor

    bus = MeshBus()
    bus.subscribe(EventType.CREDENTIAL_FILE_ACCESS, my_handler)
    bus.publish(SecurityEvent(
        event_type=EventType.SUSPICIOUS_PROCESS,
        source_agent="process_monitor",
        severity=Severity.MEDIUM,
        payload={"pid": 8842, "binary": "/usr/bin/curl"},
    ))
"""

from .events import SecurityEvent, EventType, Severity
from .bus import MeshBus
from .actions import ActionExecutor
from .mixin import MeshMixin
from .store import MeshStore

__all__ = [
    "SecurityEvent",
    "EventType",
    "Severity",
    "MeshBus",
    "ActionExecutor",
    "MeshMixin",
    "MeshStore",
]
