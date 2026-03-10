"""Shared filesystem integrity monitoring implementation.

Platform-agnostic FIM agent, probes, and data models.
No platform-routing logic — callers choose which agent class to use.

Usage:
    from amoskys.agents.shared.filesystem import FIMAgent, BaselineEngine
    from amoskys.agents.shared.filesystem.probes import CriticalSystemFileChangeProbe
"""

from amoskys.agents.shared.filesystem.agent import (
    BaselineEngine,
    EventBusPublisher,
    FIMAgent,
)
from amoskys.agents.shared.filesystem.probes import (
    BootloaderTamperProbe,
    ChangeType,
    ConfigBackdoorProbe,
    CriticalSystemFileChangeProbe,
    FileChange,
    FileState,
    LibraryHijackProbe,
    ServiceCreationProbe,
    SUIDBitChangeProbe,
    WebShellDropProbe,
    WorldWritableSensitiveProbe,
    create_fim_probes,
)


def __getattr__(name: str):
    """Lazy import for MacOSFSEventsCollector (requires watchdog)."""
    if name == "MacOSFSEventsCollector":
        from amoskys.agents.shared.filesystem.fsevents_collector import (
            MacOSFSEventsCollector,
        )

        return MacOSFSEventsCollector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Agent & engine
    "FIMAgent",
    "BaselineEngine",
    "EventBusPublisher",
    # Real-time collector (lazy — requires watchdog)
    "MacOSFSEventsCollector",
    # Data models
    "FileState",
    "FileChange",
    "ChangeType",
    # Probes
    "create_fim_probes",
    "CriticalSystemFileChangeProbe",
    "SUIDBitChangeProbe",
    "ServiceCreationProbe",
    "WebShellDropProbe",
    "ConfigBackdoorProbe",
    "LibraryHijackProbe",
    "BootloaderTamperProbe",
    "WorldWritableSensitiveProbe",
]
