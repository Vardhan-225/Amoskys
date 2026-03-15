"""MicroProbe Base Class - Foundation for the "Swarm of Eyes" Architecture.

Each macro-agent (ProcAgent, DNSAgent, PeripheralAgent, etc.) hosts multiple
micro-probes. Each probe watches ONE specific "door" or perspective:

    - Probe = lightweight, single-responsibility detector
    - Agent = orchestrator that manages probes, queue, circuit breaker
    - "If you breathe, we see it" - 62+ probes across 8 agents

Design Principles:
    1. Probes are DUMB - they only observe and return TelemetryEvents
    2. Probes do NOT handle networking, retries, or queuing
    3. Probes are stateless where possible (parent agent manages state)
    4. Probes declare their capabilities via class attributes
    5. Probes can be enabled/disabled individually

Observability Contract:
    Every probe declares an Observability Contract — the fields it requires,
    the event types it filters on, and the semantic guarantees it expects.
    The system enforces contracts at runtime and refuses to run probes whose
    dependencies are unmet. This ensures:
        - No phantom fields (hardcoded/stubbed data)
        - No false confidence (BROKEN probes never fire)
        - No silent degradation (DEGRADED probes tag their output)
        - No trust-burners (false-positive factories are blocked)

    Contract attributes (override in subclasses):
        requires_fields: shared_data keys this probe reads
        requires_event_types: event types this probe filters on
        field_semantics: expected semantic guarantees per field
        degraded_without: fields that cause DEGRADED (not BROKEN) if missing

Example Usage:
    >>> class NXDOMAINBurstProbe(MicroProbe):
    ...     name = "nxdomain_burst"
    ...     description = "Detects NXDOMAIN storms indicating DGA or scanning"
    ...     mitre_techniques = ["T1568.002"]
    ...     requires_fields = ["dns_queries"]
    ...     field_semantics = {"response_code": "dns_rcode"}
    ...     degraded_without = []  # response_code is critical
    ...
    ...     def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
    ...         ...
"""

from __future__ import annotations

import abc
import logging
import platform as _platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
)

from amoskys.observability.probe_registry import get_probe_contract_registry

if TYPE_CHECKING:
    from amoskys.agents.common.agent_bus import AgentBus
    from amoskys.agents.common.base import HardenedAgentBase
    from amoskys.agents.common.metrics import AgentMetrics


class _HasMetrics(Protocol):
    """Protocol for type checking: classes with an AgentMetrics attribute."""

    metrics: "AgentMetrics"


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
        timestamp_ns: Optional nanosecond timestamp (converts to timestamp if set)
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
    timestamp_ns: Optional[int] = None  # If provided, overrides timestamp
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    confidence: float = 0.8
    device_id: str = ""
    correlation_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Convert timestamp_ns to timestamp if provided."""
        if self.timestamp_ns is not None:
            # Convert nanoseconds to datetime
            seconds = self.timestamp_ns / 1e9
            self.timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc)

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
        now_ns: Current timestamp in nanoseconds (optional, for v2 agents)
        previous_state: State from last collection (agent-managed)
        shared_data: Data shared between probes in same agent
        config: Probe-specific configuration overrides
    """

    device_id: str
    agent_name: str
    collection_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    now_ns: Optional[int] = None  # Nanosecond timestamp for v2 agents
    previous_state: Dict[str, Any] = field(default_factory=dict)
    shared_data: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Probe Readiness (Observability Contract Result)
# =============================================================================


_VALID_PROBE_STATUSES = frozenset({"REAL", "DEGRADED", "BROKEN", "DISABLED"})


@dataclass
class ProbeReadiness:
    """Result of validating a probe's Observability Contract.

    Produced by MicroProbe.validate_contract() to indicate whether the
    probe's field dependencies are satisfied by the current shared_data.

    Attributes:
        probe_name: Name of the probe
        status: REAL, DEGRADED, BROKEN, or DISABLED (P0-5: validated)
        missing_fields: Required fields not found in shared_data
        degraded_fields: Fields in degraded_without that are missing
        message: Human-readable explanation
    """

    probe_name: str
    status: str  # "REAL", "DEGRADED", "BROKEN", "DISABLED"
    missing_fields: List[str] = field(default_factory=list)
    degraded_fields: List[str] = field(default_factory=list)
    message: str = ""

    def __post_init__(self) -> None:
        """P0-5: Validate status against ProbeStatus enum values."""
        if self.status not in _VALID_PROBE_STATUSES:
            logger.warning(
                "AOC1_INVALID_PROBE_STATUS: probe=%s status=%r "
                "is not a valid ProbeStatus value, defaulting to BROKEN",
                self.probe_name,
                self.status,
            )
            self.status = "BROKEN"


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

    # --- Observability Contract (override in subclasses) ---
    # These declarations form the probe's dependency graph.
    # The system enforces them at runtime, blocking BROKEN probes
    # and tagging DEGRADED probes.

    requires_fields: List[str] = []
    """shared_data keys this probe reads (e.g., ["flows", "dns_queries"]).
    If a required field is missing from shared_data AND is not in
    degraded_without, the probe is BROKEN and will not run."""

    requires_event_types: List[str] = []
    """Event types this probe filters on (e.g., ["MFA_CHALLENGE", "ACCOUNT_LOCKED"]).
    If the collector never generates these event types, the probe is BROKEN."""

    field_semantics: Dict[str, str] = {}
    """Expected semantic guarantee per field (e.g., {"bytes_tx": "per_flow_delta"}).
    Used by the Attribute Audit Runner for CI-time validation."""

    degraded_without: List[str] = []
    """Fields that cause DEGRADED status if missing, but don't block the probe.
    The probe can still fire with reduced detection quality."""

    # --- v2: Detection-as-Code & Lifecycle (override in subclasses) ---

    maturity: str = "experimental"
    """Probe lifecycle state: "experimental" | "stable" | "deprecated".
    Experimental probes may have higher FP rates. Deprecated probes
    are scheduled for removal and should not be used in new agents."""

    sigma_rules: List[str] = []
    """Paths to Sigma YAML rules this probe implements.
    When populated, the probe's detection logic mirrors the referenced rules."""

    yara_rules: List[str] = []
    """Paths to YARA rules this probe uses for file/memory scanning."""

    false_positive_notes: List[str] = []
    """Known conditions that cause false positives. Used by analysts to triage
    and by the FP feedback loop to auto-suppress known benign patterns."""

    evasion_notes: List[str] = []
    """Known evasion techniques against this probe. Documents detection gaps
    for red-team validation and future improvement."""

    supports_baseline: bool = False
    """Whether this probe can learn 'normal' behavior for anomaly detection.
    Baseline probes compare current state against a learned normal."""

    baseline_window_hours: int = 168
    """Baseline learning window in hours (default: 7 days).
    Only used when supports_baseline=True."""

    # --- Instance State ---

    def __init__(self) -> None:
        """Initialize probe instance."""
        self.enabled: bool = self.default_enabled
        self.last_scan: Optional[datetime] = None
        self.scan_count: int = 0
        self.error_count: int = 0
        self.last_error: Optional[str] = None
        self.readiness: Optional[ProbeReadiness] = None
        self._logger = logging.getLogger(f"probe.{self.name}")

    # --- Observability Contract Validation ---

    def validate_contract(self, context: ProbeContext) -> ProbeReadiness:
        """Check if shared_data satisfies this probe's field requirements.

        Evaluates the probe's Observability Contract against the actual
        data available in context.shared_data. Returns a ProbeReadiness
        indicating whether the probe can run at full fidelity.

        Decision logic:
            1. Platform not supported → DISABLED
            2. Any requires_fields missing AND not in degraded_without → BROKEN
            3. Any requires_event_types not satisfiable → BROKEN
            4. Any degraded_without fields missing → DEGRADED
            5. All requirements met → REAL

        Args:
            context: ProbeContext with shared_data from collector

        Returns:
            ProbeReadiness with status and diagnostics
        """
        current_platform = _platform.system().lower()

        # Check platform support
        if current_platform not in self.platforms:
            return ProbeReadiness(
                probe_name=self.name,
                status="DISABLED",
                message=f"Platform {current_platform} not in {self.platforms}",
            )

        shared_keys = set(context.shared_data.keys()) if context.shared_data else set()
        missing_critical: List[str] = []
        missing_degraded: List[str] = []

        # Check requires_fields
        for req_field in self.requires_fields:
            if req_field not in shared_keys:
                if req_field in self.degraded_without:
                    missing_degraded.append(req_field)
                else:
                    missing_critical.append(req_field)

        # Check requires_event_types — these are checked against collector
        # capabilities declared in context.config.get("collector_event_types")
        collector_event_types: Set[str] = set(
            context.config.get("collector_event_types", [])
        )
        if self.requires_event_types and collector_event_types:
            for evt_type in self.requires_event_types:
                if evt_type not in collector_event_types:
                    missing_critical.append(f"event_type:{evt_type}")

        # Determine status
        if missing_critical:
            return ProbeReadiness(
                probe_name=self.name,
                status="BROKEN",
                missing_fields=missing_critical,
                degraded_fields=missing_degraded,
                message=f"Missing critical fields: {', '.join(missing_critical)}",
            )

        if missing_degraded:
            return ProbeReadiness(
                probe_name=self.name,
                status="DEGRADED",
                missing_fields=[],
                degraded_fields=missing_degraded,
                message=f"Missing enrichment fields: {', '.join(missing_degraded)}",
            )

        return ProbeReadiness(
            probe_name=self.name,
            status="REAL",
            message="All contract requirements satisfied",
        )

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

    def scan_with_context(
        self,
        context: ProbeContext,
        bus: "AgentBus",
    ) -> List[TelemetryEvent]:
        """Scan with access to cross-agent shared context via AgentBus.

        Override this in probes that need inter-agent data (e.g., a network
        probe checking if a PID was flagged suspicious by the process agent).

        Default implementation delegates to scan() — AgentBus is ignored
        unless the probe explicitly overrides this method.

        Args:
            context: ProbeContext with shared data from this agent's collector.
            bus: AgentBus for reading other agents' ThreatContext and PeerAlerts.

        Returns:
            List of TelemetryEvents (empty if nothing to report).
        """
        return self.scan(context)

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
        """Return probe health status including contract readiness and v2 metadata.

        Returns:
            Dict with health metrics, contract status, and lifecycle info.
        """
        health: Dict[str, Any] = {
            "name": self.name,
            "enabled": self.enabled,
            "maturity": self.maturity,
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
            "scan_count": self.scan_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
        }
        if self.readiness:
            health["contract_status"] = self.readiness.status
            health["contract_message"] = self.readiness.message
        if self.requires_fields:
            health["requires_fields"] = self.requires_fields
        if self.requires_event_types:
            health["requires_event_types"] = self.requires_event_types
        if self.sigma_rules:
            health["sigma_rules"] = self.sigma_rules
        if self.yara_rules:
            health["yara_rules"] = self.yara_rules
        if self.supports_baseline:
            health["supports_baseline"] = True
            health["baseline_window_hours"] = self.baseline_window_hours
        return health

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

    # Type hint for metrics - will be provided by HardenedAgentBase when mixed
    metrics: "AgentMetrics"

    def __init__(
        self, *args, probes: Optional[List[MicroProbe]] = None, **kwargs
    ) -> None:
        """Initialize mixin state.

        Args:
            probes: Optional list of probes to register immediately
            *args, **kwargs: Passed to parent class
        """
        super().__init__(*args, **kwargs)
        self._probes: List[MicroProbe] = []
        self._probe_state: Dict[str, Dict[str, Any]] = {}  # Persistent state per probe
        self._probe_contract_registry = get_probe_contract_registry()

        # Register probes if provided
        if probes:
            self.register_probes(probes)

    def register_probe(self, probe: MicroProbe) -> None:
        """Register a micro-probe with this agent.

        Args:
            probe: MicroProbe instance to register
        """
        # Backward-compatible guard for tests/legacy agents that bypass mixin __init__.
        if not hasattr(self, "_probes"):
            self._probes = []
        if not hasattr(self, "_probe_state"):
            self._probe_state = {}
        if not hasattr(self, "_probe_contract_registry"):
            self._probe_contract_registry = get_probe_contract_registry()

        self._probes.append(probe)
        self._probe_state[probe.name] = {}
        self._probe_contract_registry.register_probe(probe)
        logger.info(f"Registered probe: {probe.name}")

    def register_probes(self, probes: Sequence[MicroProbe]) -> None:
        """Register multiple probes at once.

        Args:
            probes: List of MicroProbe instances
        """
        for probe in probes:
            self.register_probe(probe)

    def setup_probes(
        self,
        collector_event_types: Optional[List[str]] = None,
        collector_shared_data_keys: Optional[List[str]] = None,
    ) -> bool:
        """Initialize all registered probes with contract validation.

        For each probe:
            1. Check platform support → disable if unsupported
            2. Validate Observability Contract → disable BROKEN probes
            3. Call setup() → disable if setup fails
            4. Print Probe Capability Banner

        Args:
            collector_event_types: Event types this agent's collector generates.
                Used for contract validation of requires_event_types.
            collector_shared_data_keys: Top-level shared_data keys the collector
                will populate at runtime (e.g. ["flows", "dns_queries"]).
                Pre-populated with sentinel values for contract validation.

        Returns:
            True if at least one probe initialized successfully
        """
        current_platform = _platform.system().lower()

        # Pre-populate shared_data with sentinel values for keys the collector
        # will provide at runtime, so contract validation can succeed.
        setup_shared_data: Dict[str, Any] = {}
        for key in collector_shared_data_keys or []:
            setup_shared_data[key] = []  # sentinel — not real data

        contract_context = ProbeContext(
            device_id=getattr(self, "device_id", "unknown"),
            agent_name=getattr(self, "agent_name", "unknown"),
            config={"collector_event_types": collector_event_types or []},
            shared_data=setup_shared_data,
        )

        counts: Dict[str, int] = {"REAL": 0, "DEGRADED": 0, "BROKEN": 0, "DISABLED": 0}
        broken_details: List[str] = []
        degraded_details: List[str] = []

        for probe in self._probes:
            # 1. Platform check
            if current_platform not in probe.platforms:
                probe.enabled = False
                probe.readiness = ProbeReadiness(
                    probe_name=probe.name,
                    status="DISABLED",
                    message=f"Platform {current_platform} not supported",
                )
                counts["DISABLED"] += 1
                continue

            # 2. Contract validation
            readiness = probe.validate_contract(contract_context)
            probe.readiness = readiness

            if readiness.status == "BROKEN":
                probe.enabled = False
                counts["BROKEN"] += 1
                broken_details.append(f"  BROKEN: {probe.name} ({readiness.message})")
                logger.warning(
                    "Probe %s disabled: contract BROKEN — %s",
                    probe.name,
                    readiness.message,
                )
                continue

            if readiness.status == "DEGRADED":
                counts["DEGRADED"] += 1
                degraded_details.append(
                    f"  DEGRADED: {probe.name} ({readiness.message})"
                )
                logger.info(
                    "Probe %s running DEGRADED — %s",
                    probe.name,
                    readiness.message,
                )

            # 3. Normal setup
            try:
                if probe.setup():
                    if readiness.status != "DEGRADED":
                        counts["REAL"] += 1
                    logger.info(f"Probe {probe.name} initialized")
                else:
                    probe.enabled = False
                    counts["DISABLED"] += 1
                    # P0-6: Track silent probe disabling
                    if hasattr(self, "metrics"):
                        self.metrics.probes_silently_disabled += 1
                    logger.error(
                        "AOC1_PROBE_DISABLED: probe=%s reason=setup_returned_false",
                        probe.name,
                    )
            except Exception as e:
                probe.enabled = False
                probe.last_error = str(e)
                counts["DISABLED"] += 1
                # P0-6: Track silent probe disabling
                if hasattr(self, "metrics"):
                    self.metrics.probes_silently_disabled += 1
                logger.error(
                    "AOC1_PROBE_DISABLED: probe=%s reason=setup_exception error=%s",
                    probe.name,
                    e,
                )

        # P0-6: Update probe metrics counters
        total = len(self._probes)
        if hasattr(self, "metrics"):
            self.metrics.probes_total = total
            self.metrics.probes_real = counts["REAL"]
            self.metrics.probes_degraded = counts["DEGRADED"]
            self.metrics.probes_broken = counts["BROKEN"]
            self.metrics.probes_disabled = counts["DISABLED"]

        # 4. Print Probe Capability Banner
        agent_name = getattr(self, "agent_name", "unknown")
        banner_lines = [
            "",
            f"{'=' * 50}",
            f" Probe Capability Banner: {agent_name}",
            f"{'=' * 50}",
            f" {current_platform}: enabled={counts['REAL'] + counts['DEGRADED']}"
            f", degraded={counts['DEGRADED']}"
            f", disabled(broken)={counts['BROKEN']}"
            f", disabled(platform)={counts['DISABLED']}"
            f", total={total}",
        ]
        for line in broken_details:
            banner_lines.append(line)
        for line in degraded_details:
            banner_lines.append(line)
        banner_lines.append(f"{'=' * 50}")

        banner = "\n".join(banner_lines)
        logger.info(banner)

        enabled_count = counts["REAL"] + counts["DEGRADED"]
        return enabled_count > 0

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

                # P0-7: Tag DEGRADED probe events in scan_all_probes too
                if probe.readiness and probe.readiness.status == "DEGRADED":
                    for event in events:
                        event.tags.append("quality_degraded")
                        for df in probe.readiness.degraded_fields:
                            event.tags.append(f"missing_{df}")

                # Track probe events emitted (if agent has metrics)
                if events and hasattr(self, "metrics"):
                    self.metrics.record_probe_events_emitted(len(events))

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

                # Track probe errors (if agent has metrics)
                if hasattr(self, "metrics"):
                    self.metrics.record_probe_error()

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

    @property
    def probes(self) -> List[MicroProbe]:
        """Get list of registered probes.

        Returns:
            List of MicroProbe instances
        """
        return self._probes

    def run_probes(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Run all enabled probes with contract validation.

        For each enabled probe, validates its Observability Contract against
        the current context.shared_data before running scan(). BROKEN probes
        are skipped and emit a contract_violation event. DEGRADED probes run
        but their events are tagged.

        Args:
            context: ProbeContext with shared data from collector

        Returns:
            List of TelemetryEvents from all probes
        """
        all_events: List[TelemetryEvent] = []

        for probe in self._probes:
            if not probe.enabled:
                continue

            try:
                if not self._probe_contract_registry.is_registered(probe.name):
                    all_events.append(
                        TelemetryEvent(
                            event_type="probe_contract_unregistered",
                            severity=Severity.HIGH,
                            probe_name=probe.name,
                            data={
                                "probe": probe.name,
                                "message": "Probe emission blocked until contract is registered",
                            },
                            tags=[
                                "observability_contract",
                                "quality_invalid",
                                "training_exclude",
                            ],
                        )
                    )
                    continue
                self._probe_contract_registry.refresh_probe(probe.name)

                # Runtime contract validation
                if probe.requires_fields or probe.requires_event_types:
                    readiness = probe.validate_contract(context)
                    probe.readiness = readiness

                    if readiness.status == "BROKEN":
                        # Emit blindness telemetry — system reports its own gaps
                        all_events.append(
                            TelemetryEvent(
                                event_type="probe_contract_violation",
                                severity=Severity.DEBUG,
                                probe_name=probe.name,
                                data={
                                    "probe": probe.name,
                                    "status": "BROKEN",
                                    "missing_fields": readiness.missing_fields,
                                    "message": readiness.message,
                                },
                                tags=[
                                    "observability_contract",
                                    "self_audit",
                                    "quality_invalid",
                                    "training_exclude",
                                ],
                            )
                        )
                        continue  # Skip scan — contract unsatisfied

                # Update context with probe-specific state
                context.previous_state = self._probe_state.get(probe.name, {})

                # Run probe scan — use scan_with_context() if AgentBus available
                start_time = time.time()
                agent_bus = getattr(self, "agent_bus", None)
                if agent_bus is not None:
                    events = probe.scan_with_context(context, agent_bus)
                else:
                    events = probe.scan(context)
                scan_duration = time.time() - start_time

                # P0-7: Tag DEGRADED probe events + emit companion event
                if probe.readiness and probe.readiness.status == "DEGRADED":
                    for event in events:
                        event.tags.append("degraded_probe")
                        event.tags.append("quality_degraded")
                        event.tags.append("training_exclude")
                        event.data["quality_state"] = "degraded"
                        for df in probe.readiness.degraded_fields:
                            event.tags.append(f"missing_{df}")
                            if df not in event.data.get("missing_fields", []):
                                event.data.setdefault("missing_fields", []).append(df)

                    if events:
                        all_events.append(
                            TelemetryEvent(
                                event_type="aoc1_probe_degraded_firing",
                                severity=Severity.INFO,
                                probe_name=probe.name,
                                data={
                                    "probe": probe.name,
                                    "degraded_fields": probe.readiness.degraded_fields,
                                    "event_count": len(events),
                                },
                                tags=["aoc1", "probe_quality"],
                            )
                        )
                else:
                    for event in events:
                        event.tags.append("quality_valid")
                        event.data["quality_state"] = "valid"

                # Update probe metrics
                probe.last_scan = datetime.now(timezone.utc)
                probe.scan_count += 1

                # Track probe events emitted (if agent has metrics)
                if events and hasattr(self, "metrics"):
                    self.metrics.record_probe_events_emitted(len(events))

                # Enrich events with device_id
                for event in events:
                    event.device_id = context.device_id

                all_events.extend(events)

                # Publish CRITICAL/HIGH alerts to coordination bus (all agents)
                for event in events:
                    if (
                        event.severity in (Severity.CRITICAL, Severity.HIGH)
                        and hasattr(self, "coordination_publish_alert")
                    ):
                        summary = (
                            event.data.get("message")
                            or event.data.get("summary")
                            or event.event_type
                        )
                        self.coordination_publish_alert(
                            severity=event.severity.value,
                            summary=str(summary),
                            probe_name=event.probe_name,
                        )

                logger.debug(
                    f"Probe {probe.name} returned {len(events)} events "
                    f"in {scan_duration:.3f}s"
                )

            except Exception as e:
                probe.error_count += 1
                probe.last_error = str(e)

                # Track probe errors (if agent has metrics)
                if hasattr(self, "metrics"):
                    self.metrics.record_probe_error()

                logger.error(f"Probe {probe.name} scan failed: {e}", exc_info=True)

        return all_events


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "MicroProbe",
    "MicroProbeAgentMixin",
    "ProbeContext",
    "ProbeReadiness",
    "ProbeRegistry",
    "Severity",
    "TelemetryEvent",
]
