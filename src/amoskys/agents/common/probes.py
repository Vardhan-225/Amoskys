"""MicroProbe Base Class - Foundation for the "Swarm of Eyes" Architecture.

Each macro-agent (ProcAgent, DNSAgent, PeripheralAgent, etc.) hosts multiple
micro-probes. Each probe watches ONE specific "door" or perspective:

    - Probe = lightweight, single-responsibility detector
    - Agent = orchestrator that manages probes, queue, circuit breaker
    - "If you breathe, we see it" - 77+ probes across 11 agents

Design Principles:
    1. Probes are DUMB - they only observe and return TelemetryEvents
    2. Probes do NOT handle networking, retries, or queuing
    3. Probes are stateless where possible (parent agent manages state)
    4. Probes declare their capabilities via class attributes
    5. Probes can be enabled/disabled individually

Example Usage:
    >>> class HighCPUProbe(MicroProbe):
    ...     name = "high_cpu"
    ...     description = "Detects processes consuming excessive CPU"
    ...     mitre_techniques = ["T1496"]  # Resource Hijacking
    ...
    ...     def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
    ...         events = []
    ...         for proc in psutil.process_iter(['pid', 'cpu_percent']):
    ...             if proc.info['cpu_percent'] > 80:
    ...                 events.append(TelemetryEvent(
    ...                     event_type="high_cpu_process",
    ...                     severity="WARN",
    ...                     data={"pid": proc.info['pid'], "cpu": proc.info['cpu_percent']}
    ...                 ))
    ...         return events
"""

from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Set, Type

if TYPE_CHECKING:
    from amoskys.agents.common.base import HardenedAgentBase

logger = logging.getLogger(__name__)


# =============================================================================
# Severity Levels
# =============================================================================


class Severity(str, Enum):
    """Event severity levels aligned with SIEM conventions."""

    DEBUG = "DEBUG"  # Development/troubleshooting only
    INFO = "INFO"  # Normal operational events
    LOW = "LOW"  # Minor anomalies
    MEDIUM = "MEDIUM"  # Notable security events
    HIGH = "HIGH"  # Significant threats
    CRITICAL = "CRITICAL"  # Active attacks, immediate action needed


# =============================================================================
# Telemetry Event
# =============================================================================


@dataclass
class TelemetryEvent:
    """Standard telemetry event emitted by micro-probes.

    This is the canonical output format for all probes. The parent agent
    converts these to protobuf messages for EventBus transmission.

    Attributes:
        event_type: Unique event identifier (e.g., "usb_device_connected")
        severity: Event severity level
        probe_name: Name of the probe that generated this event
        timestamp: UTC timestamp of event creation
        data: Probe-specific event data
        mitre_techniques: MITRE ATT&CK technique IDs
        mitre_tactics: MITRE ATT&CK tactic IDs
        confidence: Detection confidence (0.0 to 1.0)
        device_id: Device identifier (set by parent agent)
        correlation_id: Optional correlation ID for related events
        tags: Additional classification tags
    """

    event_type: str
    severity: Severity
    probe_name: str
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    confidence: float = 0.8
    device_id: str = ""
    correlation_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_type": self.event_type,
            "severity": self.severity.value,
            "probe_name": self.probe_name,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "confidence": self.confidence,
            "device_id": self.device_id,
            "correlation_id": self.correlation_id,
            "tags": self.tags,
        }


# =============================================================================
# Probe Context
# =============================================================================


@dataclass
class ProbeContext:
    """Context passed to probes during scanning.

    Contains shared state and resources that probes may need.
    Parent agent populates this before each collection cycle.

    Attributes:
        device_id: Unique device identifier
        agent_name: Name of parent agent
        collection_time: When this collection cycle started
        previous_state: State from last collection (agent-managed)
        shared_data: Data shared between probes in same agent
        config: Probe-specific configuration overrides
    """

    device_id: str
    agent_name: str
    collection_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    previous_state: Dict[str, Any] = field(default_factory=dict)
    shared_data: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# MicroProbe Base Class
# =============================================================================


class MicroProbe(abc.ABC):
    """Base class for all micro-probes.

    Each probe is a lightweight detector focused on ONE specific perspective.
    Probes are designed to be:
        - Single-responsibility: One probe, one detection focus
        - Stateless: State managed by parent agent
        - Fast: Sub-second execution for real-time monitoring
        - Declarative: Capabilities declared via class attributes

    Class Attributes (override in subclasses):
        name: Unique probe identifier (e.g., "usb_inventory")
        description: Human-readable probe purpose
        mitre_techniques: MITRE ATT&CK techniques this probe detects
        mitre_tactics: MITRE ATT&CK tactics this probe addresses
        default_enabled: Whether probe is enabled by default
        scan_interval: Recommended seconds between scans
        requires_root: Whether probe requires elevated privileges
        platforms: Supported platforms ("linux", "darwin", "windows")

    Methods to Override:
        scan(): Perform detection and return TelemetryEvents
        setup() (optional): One-time initialization
        get_health(): Return probe health status
    """

    # --- Class Attributes (override in subclasses) ---

    name: str = "base_probe"
    description: str = "Base probe class - do not use directly"
    mitre_techniques: List[str] = []
    mitre_tactics: List[str] = []
    default_enabled: bool = True
    scan_interval: float = 10.0  # seconds
    requires_root: bool = False
    platforms: List[str] = ["linux", "darwin", "windows"]

    # --- Instance State ---

    def __init__(self) -> None:
        """Initialize probe instance."""
        self.enabled: bool = self.default_enabled
        self.last_scan: Optional[datetime] = None
        self.scan_count: int = 0
        self.error_count: int = 0
        self.last_error: Optional[str] = None
        self._logger = logging.getLogger(f"probe.{self.name}")

    # --- Abstract Methods ---

    @abc.abstractmethod
    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Perform detection scan and return events.

        This is the core detection logic. Called by parent agent on each
        collection cycle. Must be fast (sub-second for most probes).

        Args:
            context: ProbeContext with shared state and config

        Returns:
            List of TelemetryEvents (empty if nothing to report)

        Raises:
            Exception: Caught by parent agent, logged as error
        """
        raise NotImplementedError

    # --- Optional Hooks ---

    def setup(self) -> bool:
        """One-time probe initialization.

        Called by parent agent before first scan. Use for:
            - Loading static data (blocklists, baselines)
            - Verifying dependencies (tools, permissions)
            - Initializing expensive resources

        Returns:
            True if setup succeeded, False to disable probe
        """
        return True

    def get_health(self) -> Dict[str, Any]:
        """Return probe health status.

        Returns:
            Dict with health metrics
        """
        return {
            "name": self.name,
            "enabled": self.enabled,
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
            "scan_count": self.scan_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
        }

    # --- Utility Methods ---

    def _create_event(
        self,
        event_type: str,
        severity: Severity,
        data: Dict[str, Any],
        confidence: float = 0.8,
        correlation_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> TelemetryEvent:
        """Helper to create TelemetryEvent with probe defaults.

        Args:
            event_type: Unique event identifier
            severity: Event severity
            data: Event-specific data
            confidence: Detection confidence (0.0-1.0)
            correlation_id: Optional correlation ID
            tags: Additional tags

        Returns:
            TelemetryEvent populated with probe metadata
        """
        return TelemetryEvent(
            event_type=event_type,
            severity=severity,
            probe_name=self.name,
            data=data,
            mitre_techniques=self.mitre_techniques.copy(),
            mitre_tactics=self.mitre_tactics.copy(),
            confidence=confidence,
            correlation_id=correlation_id,
            tags=tags or [],
        )

    def __repr__(self) -> str:
        """Return string representation."""
        return f"<{self.__class__.__name__}(name={self.name}, enabled={self.enabled})>"


# =============================================================================
# Probe Registry
# =============================================================================


class ProbeRegistry:
    """Registry for discovering and instantiating probes.

    Provides a central place to register probe classes and create instances.
    Parent agents use this to discover available probes.

    Usage:
        >>> registry = ProbeRegistry()
        >>> registry.register(USBInventoryProbe)
        >>> registry.register(USBConnectionProbe)
        >>> probes = registry.create_all()
    """

    def __init__(self) -> None:
        """Initialize empty registry."""
        self._probes: Dict[str, Type[MicroProbe]] = {}

    def register(self, probe_class: Type[MicroProbe]) -> None:
        """Register a probe class.

        Args:
            probe_class: MicroProbe subclass to register
        """
        if not issubclass(probe_class, MicroProbe):
            raise TypeError(f"{probe_class} is not a MicroProbe subclass")
        self._probes[probe_class.name] = probe_class
        logger.debug(f"Registered probe: {probe_class.name}")

    def unregister(self, name: str) -> None:
        """Unregister a probe by name.

        Args:
            name: Probe name to unregister
        """
        if name in self._probes:
            del self._probes[name]

    def get(self, name: str) -> Optional[Type[MicroProbe]]:
        """Get probe class by name.

        Args:
            name: Probe name

        Returns:
            Probe class or None if not found
        """
        return self._probes.get(name)

    def list_probes(self) -> List[str]:
        """List all registered probe names.

        Returns:
            List of probe names
        """
        return list(self._probes.keys())

    def create_all(
        self, enabled_only: bool = True, platform: Optional[str] = None
    ) -> List[MicroProbe]:
        """Create instances of all registered probes.

        Args:
            enabled_only: Only create probes that are default_enabled
            platform: Filter by platform support

        Returns:
            List of probe instances
        """
        probes = []
        for name, probe_class in self._probes.items():
            if enabled_only and not probe_class.default_enabled:
                continue
            if platform and platform not in probe_class.platforms:
                continue
            try:
                probe = probe_class()
                probes.append(probe)
            except Exception as e:
                logger.error(f"Failed to create probe {name}: {e}")
        return probes

    def create(self, name: str) -> Optional[MicroProbe]:
        """Create a single probe instance by name.

        Args:
            name: Probe name

        Returns:
            Probe instance or None if not found
        """
        probe_class = self._probes.get(name)
        if probe_class:
            return probe_class()
        return None


# =============================================================================
# Agent Mixin for Micro-Probe Support
# =============================================================================


class MicroProbeAgentMixin:
    """Mixin that adds micro-probe support to HardenedAgentBase.

    Provides:
        - Probe registration and lifecycle management
        - Aggregated scan across all probes
        - Probe health tracking
        - Per-probe enable/disable

    Usage:
        >>> class ProcAgent(MicroProbeAgentMixin, HardenedAgentBase):
        ...     def setup(self):
        ...         self.register_probe(ProcessSpawnProbe())
        ...         self.register_probe(HighCPUProbe())
        ...         return self.setup_probes()
        ...
        ...     def collect_data(self):
        ...         return self.scan_all_probes()
    """

    def __init__(self, *args, **kwargs) -> None:
        """Initialize mixin state."""
        super().__init__(*args, **kwargs)
        self._probes: List[MicroProbe] = []
        self._probe_state: Dict[str, Dict[str, Any]] = {}  # Persistent state per probe

    def register_probe(self, probe: MicroProbe) -> None:
        """Register a micro-probe with this agent.

        Args:
            probe: MicroProbe instance to register
        """
        self._probes.append(probe)
        self._probe_state[probe.name] = {}
        logger.info(f"Registered probe: {probe.name}")

    def register_probes(self, probes: Sequence[MicroProbe]) -> None:
        """Register multiple probes at once.

        Args:
            probes: List of MicroProbe instances
        """
        for probe in probes:
            self.register_probe(probe)

    def setup_probes(self) -> bool:
        """Initialize all registered probes.

        Calls setup() on each probe. Probes that fail setup are disabled.

        Returns:
            True if at least one probe initialized successfully
        """
        success_count = 0
        for probe in self._probes:
            try:
                if probe.setup():
                    success_count += 1
                    logger.info(f"Probe {probe.name} initialized")
                else:
                    probe.enabled = False
                    logger.warning(f"Probe {probe.name} setup returned False, disabled")
            except Exception as e:
                probe.enabled = False
                probe.last_error = str(e)
                logger.error(f"Probe {probe.name} setup failed: {e}")

        logger.info(f"Initialized {success_count}/{len(self._probes)} probes")
        return success_count > 0

    def scan_all_probes(self) -> List[TelemetryEvent]:
        """Execute all enabled probes and collect events.

        Returns:
            Aggregated list of TelemetryEvents from all probes
        """
        all_events: List[TelemetryEvent] = []
        context = self._create_probe_context()

        for probe in self._probes:
            if not probe.enabled:
                continue

            try:
                # Update context with probe-specific state
                context.previous_state = self._probe_state.get(probe.name, {})

                # Run probe scan
                start_time = time.time()
                events = probe.scan(context)
                scan_duration = time.time() - start_time

                # Update probe metrics
                probe.last_scan = datetime.now(timezone.utc)
                probe.scan_count += 1

                # Enrich events with device_id
                for event in events:
                    event.device_id = context.device_id

                all_events.extend(events)

                logger.debug(
                    f"Probe {probe.name} returned {len(events)} events "
                    f"in {scan_duration:.3f}s"
                )

            except Exception as e:
                probe.error_count += 1
                probe.last_error = str(e)
                logger.error(f"Probe {probe.name} scan failed: {e}")

        return all_events

    def _create_probe_context(self) -> ProbeContext:
        """Create context for probe scans.

        Returns:
            ProbeContext with agent info
        """
        return ProbeContext(
            device_id=getattr(self, "device_id", "unknown"),
            agent_name=getattr(self, "agent_name", "unknown"),
            collection_time=datetime.now(timezone.utc),
        )

    def get_probe_health(self) -> List[Dict[str, Any]]:
        """Get health status of all probes.

        Returns:
            List of probe health dictionaries
        """
        return [probe.get_health() for probe in self._probes]

    def enable_probe(self, name: str) -> bool:
        """Enable a probe by name.

        Args:
            name: Probe name

        Returns:
            True if probe was found and enabled
        """
        for probe in self._probes:
            if probe.name == name:
                probe.enabled = True
                return True
        return False

    def disable_probe(self, name: str) -> bool:
        """Disable a probe by name.

        Args:
            name: Probe name

        Returns:
            True if probe was found and disabled
        """
        for probe in self._probes:
            if probe.name == name:
                probe.enabled = False
                return True
        return False

    def list_probes(self) -> List[str]:
        """List all registered probe names.

        Returns:
            List of probe names
        """
        return [probe.name for probe in self._probes]


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "MicroProbe",
    "MicroProbeAgentMixin",
    "ProbeContext",
    "ProbeRegistry",
    "Severity",
    "TelemetryEvent",
]
