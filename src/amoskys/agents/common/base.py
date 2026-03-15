"""Hardened agent base class for all AMOSKYS agents.

This module provides the steel skeleton that every agent inherits from,
ensuring consistent behavior, resilience, and observability across the platform.

Key Features:
    - Circuit breaker pattern for EventBus failures
    - Exponential backoff retry logic
    - Local queue integration for offline resilience
    - Lifecycle hooks (setup, collect, validate, enrich, shutdown)
    - Health tracking and introspection
    - Signal handling for graceful shutdown

Usage:
    >>> class ProcAgent(HardenedAgentBase):
    ...     def setup(self):
    ...         # Initialize resources
    ...         return True
    ...
    ...     def collect_data(self):
    ...         # Gather telemetry
    ...         return [event1, event2]
    ...
    ...     def validate_event(self, event):
    ...         # Check event is valid
    ...         return ValidationResult(is_valid=True)
    ...
    >>> agent = ProcAgent(agent_name="proc", device_id="host-001")
    >>> agent.run_forever()
"""

from __future__ import annotations

import abc
import json
import logging
import signal
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any, Callable, Optional, Sequence

from amoskys.agents.common.metrics import AgentMetrics
from amoskys.config import get_config

if TYPE_CHECKING:
    from amoskys.agents.common.agent_bus import AgentBus
    from amoskys.messaging_pb2 import TelemetryEvent as ProtoEvent

logger = logging.getLogger(__name__)


# --- Circuit Breaker -------------------------------------------------------


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is OPEN and calls are blocked."""


@dataclass
class CircuitBreaker:
    """Circuit breaker for protecting against cascading failures.

    Implements the circuit breaker pattern to prevent repeated calls to
    failing services (e.g., EventBus). Transitions between three states:

    - CLOSED: Normal operation, calls allowed
    - OPEN: Failure threshold exceeded, calls blocked
    - HALF_OPEN: Testing if service recovered

    Attributes:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before trying half-open
        half_open_attempts: Successes needed to fully close circuit
    """

    failure_threshold: int = 5
    recovery_timeout: float = 30.0  # seconds
    half_open_attempts: int = 3
    _on_transition: Optional[Callable] = field(default=None, repr=False)

    state: str = field(default="CLOSED", init=False)
    failure_count: int = field(default=0, init=False)
    success_count: int = field(default=0, init=False)
    last_failure_time: float = field(default=0.0, init=False)

    def _now(self) -> float:
        return time.time()

    def _notify_transition(self, old_state: str, new_state: str) -> None:
        """AOC-1 (P0-3): Notify observer of every circuit breaker state change."""
        if self._on_transition is not None:
            try:
                self._on_transition(old_state, new_state)
            except Exception:
                pass  # Observer failure must not break circuit breaker

    def record_success(self) -> None:
        """Record successful operation."""
        if self.state in ("OPEN", "HALF_OPEN"):
            self.success_count += 1
            if self.success_count >= self.half_open_attempts:
                old_state = self.state
                self.state = "CLOSED"
                self.failure_count = 0
                self.success_count = 0
                logger.info("Circuit breaker CLOSED (recovered)")
                self._notify_transition(old_state, "CLOSED")
        else:
            # CLOSED state - reset failure count
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record failed operation."""
        self.failure_count += 1
        self.last_failure_time = self._now()
        self.success_count = 0

        # HALF_OPEN → OPEN on ANY failure (immediate reopen)
        if self.state == "HALF_OPEN":
            logger.warning("Circuit breaker OPEN (failure in HALF_OPEN)")
            self.state = "OPEN"
            self._notify_transition("HALF_OPEN", "OPEN")
            return

        # CLOSED → OPEN when threshold exceeded
        if self.failure_count >= self.failure_threshold and self.state != "OPEN":
            logger.warning("Circuit breaker OPEN (failures: %d)", self.failure_count)
            self.state = "OPEN"
            self._notify_transition("CLOSED", "OPEN")

    def _maybe_transition_half_open(self) -> None:
        """Try transitioning from OPEN to HALF_OPEN if recovery timeout passed."""
        if self.state == "OPEN":
            if self._now() - self.last_failure_time >= self.recovery_timeout:
                self.state = "HALF_OPEN"
                self.failure_count = 0
                self.success_count = 0
                logger.info("Circuit breaker HALF_OPEN (testing recovery)")
                self._notify_transition("OPEN", "HALF_OPEN")

    def allow_call(self) -> None:
        """Check if call is allowed, raise if circuit is open."""
        if self.state == "OPEN":
            self._maybe_transition_half_open()
        if self.state == "OPEN":
            raise CircuitBreakerOpen("Circuit breaker is OPEN")


# --- Validation Result -----------------------------------------------------


@dataclass
class ValidationResult:
    """Result of event validation.

    Attributes:
        is_valid: True if event passed all validation rules
        errors: List of validation error messages
    """

    is_valid: bool
    errors: list[str] = field(default_factory=list)


# --- Hardened Agent Base ---------------------------------------------------


class HardenedAgentBase(abc.ABC):
    """Base class for all AMOSKYS agents.

    Provides a consistent foundation for agent development with built-in
    resilience, observability, and error handling patterns.

    Includes MeshMixin capability: agents can publish SecurityEvents to the
    inter-agent mesh bus and receive directed watch commands from IGRIS.
    Mesh is optional — agents work without it (publish = no-op if no bus).

    Responsibilities:
        - Provide structured run loop with lifecycle hooks
        - Wrap collection/publish in error handling
        - Circuit-break EventBus on repeated failures
        - Support local queue for offline resilience
        - Track health and metrics
        - Handle signals for graceful shutdown
        - Publish to / subscribe from agent mesh (MeshMixin)

    Subclasses must implement:
        - setup(): Initialize agent resources
        - collect_data(): Gather raw telemetry
        - validate_event(): Validate individual events (optional)
        - enrich_event(): Add context to events (optional)
        - shutdown(): Cleanup resources (optional)
    """

    def __init__(
        self,
        agent_name: str,
        device_id: str,
        collection_interval: float = 10.0,
        *,
        eventbus_publisher: Optional[Any] = None,
        local_queue: Optional[Any] = None,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
        agent_bus: Optional["AgentBus"] = None,
    ) -> None:
        """Initialize hardened agent base.

        Args:
            agent_name: Unique agent identifier (e.g., "proc_agent")
            device_id: Device/host identifier (e.g., "host-001")
            collection_interval: Seconds between collection cycles
            eventbus_publisher: EventBus client for publishing
            local_queue: LocalQueue instance for offline resilience
            queue_adapter: LocalQueueAdapter for simplified queue interface
            metrics_interval: Seconds between metrics telemetry emissions
            agent_bus: AgentBus for cross-agent communication. If None,
                      agents operate in isolated mode (v1 behavior).
        """
        self.agent_name = agent_name
        self.device_id = device_id
        self.collection_interval = collection_interval
        self.eventbus_publisher = eventbus_publisher
        self.local_queue = local_queue
        self.queue_adapter = queue_adapter
        self.agent_bus = agent_bus

        self.circuit_breaker = CircuitBreaker(
            _on_transition=self._on_circuit_breaker_transition,
        )
        self.is_running: bool = False
        self._shutdown: bool = False

        # Health tracking
        self.start_time: float = time.time()
        self.last_successful_collection: float = 0.0
        self.last_heartbeat: float = 0.0
        self.last_error: Optional[str] = None
        self.collection_count: int = 0
        self.error_count: int = 0

        # Observability metrics
        self.metrics = AgentMetrics()
        self._metrics_interval_seconds = metrics_interval

        # Agent mesh (inter-agent communication) — safe no-op if bus not set
        try:
            from amoskys.mesh.mixin import MeshMixin

            MeshMixin.__init_mesh__(self)
        except Exception:
            pass  # Mesh is optional — agents work without it
        self._last_metrics_emit_ns = int(time.time() * 1e9)

        # Coordination bus — cross-process health/alert/control plane
        # All agents get this automatically; gracefully falls back to LocalBus
        self._coordination_bus = self._init_coordination_bus()

        # Wire queue adapter metrics (P0-1)
        if self.queue_adapter and hasattr(self.queue_adapter, "_metrics"):
            self.queue_adapter._metrics = self.metrics

    # ----------------- Coordination Bus (All Agents) ----------------------

    def _init_coordination_bus(self):
        """Initialize coordination bus for health/alert/control messaging.

        Tries the configured backend (env AMOSKYS_COORDINATION_BACKEND),
        falls back to LocalBus if unavailable. Never fails — agents work
        without coordination.
        """
        try:
            from amoskys.common.coordination import (
                CoordinationConfig,
                create_coordination_bus,
            )

            config = get_config()
            backend = os.environ.get("AMOSKYS_COORDINATION_BACKEND", "local")
            cfg = CoordinationConfig(
                backend=backend,
                agent_id=self.agent_name,
                eventbus_address=config.agent.bus_address,
                cert_dir=config.agent.cert_dir,
                default_topics=["CONTROL"],
            )
            try:
                bus = create_coordination_bus(cfg)
                bus.subscribe("CONTROL", self._handle_coordination_control)
                return bus
            except Exception:
                logger.warning(
                    "Coordination bus backend '%s' unavailable for %s; falling back to local",
                    backend,
                    self.agent_name,
                    exc_info=True,
                )
                return create_coordination_bus(
                    CoordinationConfig(backend="local", agent_id=self.agent_name)
                )
        except Exception:
            return None  # Coordination is fully optional

    def _handle_coordination_control(
        self, topic: str, payload: dict
    ) -> None:
        """Handle CONTROL topic signals (log level, feature toggles)."""
        target = payload.get("target")
        if target not in (None, "", "all", self.agent_name):
            return

        command = payload.get("command")
        if command == "set_log_level":
            level = str(payload.get("level", "INFO")).upper()
            logging.getLogger().setLevel(level)
            logger.info("Coordination: set_log_level=%s for %s", level, self.agent_name)

    def coordination_publish_health(
        self, loop_latency_ms: float = 0.0, **extra
    ) -> None:
        """Publish agent health to the HEALTH topic."""
        if not self._coordination_bus:
            return
        try:
            self._coordination_bus.publish(
                "HEALTH",
                {
                    "agent_id": self.agent_name,
                    "status": "healthy",
                    "loop_latency_ms": round(loop_latency_ms, 2),
                    "errors_last_min": self.error_count,
                    "collection_count": self.collection_count,
                    **extra,
                },
            )
        except Exception:
            pass  # Never break the agent for coordination

    def coordination_publish_alert(
        self, severity: str, summary: str, probe_name: str = ""
    ) -> None:
        """Publish a detection alert to the ALERT topic."""
        if not self._coordination_bus:
            return
        try:
            self._coordination_bus.publish(
                "ALERT",
                {
                    "agent_id": self.agent_name,
                    "severity": severity,
                    "probe": probe_name,
                    "summary": summary,
                },
            )
        except Exception:
            pass

    def _close_coordination_bus(self) -> None:
        """Close coordination bus on shutdown."""
        if self._coordination_bus:
            try:
                self._coordination_bus.close()
            except Exception:
                pass

    # ----------------- Lifecycle Hooks (Override These) -------------------

    @abc.abstractmethod
    def setup(self) -> bool:
        """Initialize agent resources.

        Called once on agent startup before entering main loop.

        Typical responsibilities:
            - Load configuration
            - Verify certificates exist
            - Initialize local queue/WAL
            - Load baseline/snapshot data (if applicable)
            - Test EventBus connectivity (optional)

        Returns:
            True if setup succeeded, False to abort agent startup

        Error Handling:
            Log failures and return False. Agent will exit.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def collect_data(self) -> Sequence[Any]:
        """Collect raw telemetry from the system.

        Called repeatedly on collection_interval.

        Typical responsibilities:
            - Query system APIs (psutil, logs, filesystem, etc.)
            - Parse raw data into event objects
            - Return unvalidated events (validation happens next)

        Returns:
            Sequence of raw events (dicts, domain objects, etc.)

        Raises:
            Exception: Caught by main loop, logged, cycle skipped

        Note:
            Do NOT validate or enrich here - those are separate stages.
        """
        raise NotImplementedError

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate a single event against schema/business rules.

        Called for each event after collection.

        Typical responsibilities:
            - Check required fields present
            - Validate formats (IPs, domains, paths)
            - Check value ranges (ports 0-65535, etc.)
            - Check logical constraints

        Args:
            event: Raw event from collect_data()

        Returns:
            ValidationResult with is_valid flag and error messages

        Default:
            Accepts all events (override to add validation)

        Error Handling:
            Return validation errors, don't raise exceptions.
            Invalid events are logged and dropped.
        """
        return ValidationResult(is_valid=True)

    def _validate_event_shape(self, event: Any) -> ValidationResult:
        """Base-level structural validation applied to every event.

        Ensures fundamental fields are present regardless of subclass
        validate_event() overrides. Runs before per-agent validation.
        Handles both dict events and protobuf message objects.
        """
        errors: list[str] = []

        # Protobuf messages and dict-like objects are both valid event shapes
        if isinstance(event, dict):
            device_id = event.get("device_id")
            ts = event.get("timestamp_ns")
        elif hasattr(event, "device_id"):
            # Protobuf DeviceTelemetry or similar message
            device_id = getattr(event, "device_id", None)
            ts = getattr(event, "timestamp_ns", None)
        else:
            return ValidationResult(
                is_valid=False,
                errors=[f"event has unsupported type: {type(event).__name__}"],
            )

        if not device_id or not str(device_id).strip():
            errors.append("missing or empty device_id")

        if ts is not None and isinstance(ts, (int, float)) and ts <= 0:
            errors.append(f"invalid timestamp_ns: {ts}")

        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def enrich_event(self, event: Any) -> Any:
        """Add contextual metadata to validated event.

        Called for each event after validation.

        Typical responsibilities:
            - Add hostname, platform, agent version
            - Add GeoIP lookups (if applicable)
            - Add threat intel tags (if applicable)
            - Normalize paths/formats
            - Add correlation IDs

        Args:
            event: Validated event

        Returns:
            Enriched event with additional fields

        Default:
            No enrichment (override to add context)

        Error Handling:
            Enrichment failures should NOT block event.
            Log errors and return original event.
        """
        return event

    def shutdown(self) -> None:
        """Graceful shutdown and resource cleanup.

        Called once on SIGTERM/SIGINT before process exit.

        Typical responsibilities:
            - Flush local queue to EventBus
            - Close database connections
            - Save snapshots/baselines
            - Deregister from EventBus (optional)

        Error Handling:
            Best-effort only. Log failures but don't block shutdown.
        """
        pass

    # ----------------- Observation Helpers ----------------------------------

    def _make_observation_events(
        self,
        items: list,
        domain: str,
        field_mapper,
    ):
        """Convert raw collector items to observation TelemetryEvents.

        Each item in ``items`` is mapped to a TelemetryEvent with
        ``event_type="obs_{domain}"``.  The ``field_mapper`` callable
        receives a single item and must return a ``Dict[str, Any]``
        of all fields to store as event data.

        Args:
            items: Raw collector output (list of dataclass instances).
            domain: Domain identifier (e.g. "process", "flow", "dns").
            field_mapper: Callable(item) -> Dict[str, Any].

        Returns:
            List of TelemetryEvent observation objects.
        """
        from amoskys.agents.common.probes import Severity, TelemetryEvent

        events = []
        for item in items:
            try:
                data = field_mapper(item)
                data["_domain"] = domain
                events.append(
                    TelemetryEvent(
                        event_type=f"obs_{domain}",
                        severity=Severity.INFO,
                        probe_name=f"{domain}_collector",
                        data=data,
                        confidence=0.0,
                    )
                )
            except Exception:
                pass  # Skip malformed items silently
        return events

    # ----------------- EventBus Publishing & Queue -------------------------

    def _publish_to_eventbus(self, events: Sequence[Any]) -> None:
        """Publish events to EventBus (internal).

        Args:
            events: Validated and enriched events

        Raises:
            RuntimeError: If no eventbus_publisher configured
            Exception: On publish failure (caught by retry logic)
        """
        if not self.eventbus_publisher:
            raise RuntimeError("No eventbus_publisher configured")

        # Assume publisher has .publish(events) method
        self.eventbus_publisher.publish(events)

    def _publish_with_circuit_breaker(self, events: Sequence[Any]) -> None:
        """Publish with circuit breaker protection.

        Args:
            events: Events to publish

        Raises:
            CircuitBreakerOpen: If circuit is open
            Exception: On publish failure
        """
        self.circuit_breaker.allow_call()
        try:
            self._publish_to_eventbus(events)
        except Exception:
            self.circuit_breaker.record_failure()
            raise
        else:
            self.circuit_breaker.record_success()

    def _publish_with_retry(
        self,
        events: Sequence[Any],
        *,
        max_retries: int = 3,
        backoff_base: float = 0.2,  # seconds
        backoff_cap: float = 5.0,
    ) -> None:
        """Publish with exponential backoff retry.

        Args:
            events: Events to publish
            max_retries: Maximum retry attempts
            backoff_base: Base backoff delay (seconds)
            backoff_cap: Maximum backoff delay (seconds)

        Behavior:
            - Retries on transient failures
            - Circuit breaker blocks calls when EventBus down
            - Falls back to local queue on final failure
        """
        attempt = 0
        while True:
            attempt += 1
            try:
                self._publish_with_circuit_breaker(events)
                return
            except CircuitBreakerOpen as e:
                logger.warning(
                    "Circuit OPEN for %s; enqueueing %d events locally: %s",
                    self.agent_name,
                    len(events),
                    e,
                )
                self._enqueue_locally(events)
                return
            except Exception as e:
                logger.error(
                    "Publish attempt %d/%d failed for %s: %s",
                    attempt,
                    max_retries,
                    self.agent_name,
                    e,
                    exc_info=(attempt == max_retries),  # Full trace on final failure
                )
                if attempt >= max_retries:
                    self._enqueue_locally(events)
                    return

                sleep_for = min(backoff_base * (2 ** (attempt - 1)), backoff_cap)
                time.sleep(sleep_for)

    def _enqueue_locally(self, events: Sequence[Any]) -> None:
        """Enqueue events to local queue for later retry.

        Args:
            events: Events to enqueue

        Behavior:
            Best-effort only. Logs failures but doesn't raise.
        """
        queue = self.local_queue or self.queue_adapter
        if not queue:
            logger.error(
                "DATA_LOSS: Agent %s has no local queue; " "%d events permanently lost",
                self.agent_name,
                len(events),
            )
            self.metrics.record_backpressure_drop(len(events))
            return

        for ev in events:
            try:
                queue.enqueue(ev)
            except Exception as e:
                logger.error(
                    "Failed to enqueue event for %s: %s",
                    self.agent_name,
                    e,
                    exc_info=True,
                )

    def _drain_local_queue(self, limit: int = 100) -> int:
        """Drain queued events to EventBus.

        Args:
            limit: Maximum events to drain in one call

        Returns:
            Number of events successfully drained

        Behavior:
            Attempts to publish queued events when EventBus recovers.
            Stops on first failure to avoid overwhelming recovering service.
        """
        if not self.local_queue:
            return 0

        drained = 0
        try:
            # Adapt to your LocalQueue interface
            # Expects: drain(publish_fn, limit) -> int
            if hasattr(self.local_queue, "drain"):
                drained = self.local_queue.drain(
                    publish_fn=self._publish_with_retry, limit=limit
                )
        except Exception as e:
            logger.error(
                "Error draining local queue for %s: %s",
                self.agent_name,
                e,
                exc_info=True,
            )
        return drained

    # ----------------- Metrics & Observability -----------------------------

    def _build_metrics_event(self) -> "ProtoEvent":
        """Build a TelemetryEvent encapsulating current agent metrics.

        Returns:
            ProtoEvent with event_type="agent_metrics" and metrics data
        """
        # Import here to avoid circular dependency
        from amoskys.agents.common.probes import Severity
        from amoskys.messaging_pb2 import TelemetryEvent as ProtoEvent

        metrics_dict = self.metrics.to_dict()
        now_ns = int(time.time() * 1e9)

        event = ProtoEvent(
            event_type="agent_metrics",
            severity=Severity.INFO.value,
            event_timestamp_ns=now_ns,
            source_component=self.__class__.__name__,
        )

        # Add metrics as attributes (map<string, string>)
        for k, v in metrics_dict.items():
            if v is not None:
                event.attributes[k] = str(v)

        return event

    def _maybe_emit_metrics_telemetry(self) -> None:
        """Emit agent metrics as telemetry if interval elapsed.

        Uses the same WAL/queue flush path as normal telemetry.
        Emits AGENT_METRICS DeviceTelemetry every N seconds.
        """
        now_ns = int(time.time() * 1e9)
        if (now_ns - self._last_metrics_emit_ns) < int(
            self._metrics_interval_seconds * 1e9
        ):
            return

        self._last_metrics_emit_ns = now_ns

        # Create metrics telemetry using queue_adapter or skip
        if not self.queue_adapter:
            logger.debug(
                "Agent %s: no queue_adapter configured, skipping metrics emission",
                self.agent_name,
            )
            return

        try:
            metrics_event = self._build_metrics_event()
        except Exception as exc:
            logger.exception("Failed to build metrics event: %s", exc)
            return

        try:
            # Import here to avoid circular dependency
            from amoskys.messaging_pb2 import DeviceTelemetry

            telemetry = DeviceTelemetry(
                device_id=self.device_id,
                device_type="HOST",
                protocol="AGENT_METRICS",
                timestamp_ns=now_ns,
                collection_agent=self.__class__.__name__,
                agent_version=getattr(self, "agent_version", "v2"),
                events=[metrics_event],
            )

            self.queue_adapter.enqueue(telemetry)
            self.metrics.record_events_emitted(1)

            logger.debug(
                "Agent %s emitted metrics telemetry: loops=%d/%d, events=%d, probes=%d",
                self.agent_name,
                self.metrics.loops_succeeded,
                self.metrics.loops_started,
                self.metrics.events_emitted,
                self.metrics.probe_events_emitted,
            )

        except Exception as exc:
            logger.exception("Failed to emit metrics telemetry: %s", exc)

    def start_metrics_http_server(
        self,
        host: str = "127.0.0.1",
        port: int = 9100,
    ) -> None:
        """Optional side-channel metrics endpoint for local scraping.

        Starts a daemon thread serving JSON metrics at /metrics or /metrics.json.
        Useful for Prometheus scraping or local debugging.

        Args:
            host: Bind address (default localhost only)
            port: Port to listen on (default 9100)
        """
        agent = self  # Capture reference for handler

        class _AgentMetricsHandler(BaseHTTPRequestHandler):
            """HTTP handler for agent metrics endpoint."""

            def log_message(self, format: str, *args: Any) -> None:
                """Suppress default logging."""
                pass

            def do_GET(self) -> None:
                if self.path not in ("/metrics", "/metrics.json"):
                    self.send_response(404)
                    self.end_headers()
                    return

                metrics = agent.metrics.to_dict()
                payload = json.dumps(metrics).encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = HTTPServer((host, port), _AgentMetricsHandler)

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        logger.info(
            "Metrics HTTP server for %s started on %s:%d",
            self.__class__.__name__,
            host,
            port,
        )

    # ----------------- Health & Introspection ------------------------------

    def health_summary(self) -> dict:
        """Get current agent health snapshot.

        Returns:
            Dict with health metrics for diagnostics/monitoring

        Usage:
            Can be exposed via /health endpoint or metrics
        """
        health = {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "uptime_seconds": time.time() - self.start_time,
            "last_successful_collection": self.last_successful_collection,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "circuit_breaker_state": self.circuit_breaker.state,
            "local_queue_size": (self.local_queue.size() if self.local_queue else 0),
            "agent_bus_connected": self.agent_bus is not None,
        }
        if self.agent_bus is not None:
            try:
                health["peer_agents_visible"] = len(self.agent_bus.get_active_agents())
            except Exception:
                health["peer_agents_visible"] = 0
        return health

    # ----------------- AOC-1 Observability (P0-2, P0-3) --------------------

    def _on_circuit_breaker_transition(self, old_state: str, new_state: str) -> None:
        """AOC-1 (P0-3): Track every circuit breaker state change."""
        self.metrics.record_circuit_breaker_transition(new_state)
        logger.warning(
            "AOC1_CB_TRANSITION: agent=%s %s -> %s (failures=%d)",
            self.agent_name,
            old_state,
            new_state,
            self.circuit_breaker.failure_count,
        )
        self._emit_aoc1_event(
            "aoc1_circuit_breaker_transition",
            {
                "old_state": old_state,
                "new_state": new_state,
                "failure_count": self.circuit_breaker.failure_count,
            },
        )

    def _emit_heartbeat(self) -> None:
        """AOC-1 (P0-2): Produce continuous heartbeat signal.

        Called every collection cycle regardless of success/failure.
        Updates last_heartbeat and emits heartbeat telemetry.
        """
        now_ns = int(time.time() * 1e9)
        self.last_heartbeat = time.time()
        self.metrics.record_heartbeat(now_ns)

        self._emit_aoc1_event(
            "aoc1_heartbeat",
            {
                "uptime_seconds": round(time.time() - self.start_time, 1),
                "circuit_breaker_state": self.circuit_breaker.state,
                "collection_count": self.collection_count,
                "error_count": self.error_count,
                "queue_depth": (self.queue_adapter.size() if self.queue_adapter else 0),
            },
        )

        # Publish health to coordination bus (all agents, every cycle)
        self.coordination_publish_health()

    def _emit_aoc1_event(self, event_type: str, data: dict) -> None:
        """Emit an AOC-1 observability event through the queue adapter.

        Silently drops if queue_adapter is not configured (graceful in tests).
        Observer failures must never break the agent.
        """
        if not self.queue_adapter:
            return
        try:
            from amoskys.agents.common.probes import Severity
            from amoskys.messaging_pb2 import DeviceTelemetry
            from amoskys.messaging_pb2 import TelemetryEvent as ProtoEvent

            now_ns = int(time.time() * 1e9)
            event = ProtoEvent(
                event_type=event_type,
                severity=Severity.INFO.value,
                event_timestamp_ns=now_ns,
                source_component=self.__class__.__name__,
            )
            data["agent_name"] = self.agent_name
            data["device_id"] = self.device_id
            for k, v in data.items():
                if v is not None:
                    event.attributes[k] = str(v)

            telemetry = DeviceTelemetry(
                device_id=self.device_id,
                device_type="HOST",
                protocol="AOC1_OBSERVABILITY",
                timestamp_ns=now_ns,
                collection_agent=self.__class__.__name__,
                agent_version=getattr(self, "agent_version", "v2"),
                events=[event],
            )
            self.queue_adapter.enqueue(telemetry)
        except Exception as exc:
            logger.debug("AOC-1 event %s emission failed: %s", event_type, exc)

    # ----------------- Main Loop -------------------------------------------

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle SIGTERM/SIGINT for graceful shutdown."""
        logger.info(
            "Agent %s received signal %s; shutting down", self.agent_name, signum
        )
        self.is_running = False

    def _run_one_cycle(self) -> None:
        """Execute one collection -> validate -> enrich -> publish cycle.

        Error Handling:
            All exceptions caught and logged. Agent continues running.
        """
        cycle_id = str(uuid.uuid4())[:8]  # Short ID for logging
        cycle_start = time.time()
        self.collection_count += 1

        # Track loop start
        self.metrics.record_loop_start()

        try:
            # Step 1: Collect raw data
            raw_events = self.collect_data()

            # Step 1.5: Structural pre-validation (base-level shape check)
            if not raw_events:
                logger.debug(
                    "Agent %s cycle %s: collect_data returned empty",
                    self.agent_name,
                    cycle_id,
                )
                self.metrics.record_loop_success()
                return

            # Step 2: Validate events (shape check + agent-specific rules)
            validated: list[Any] = []
            rejected: int = 0
            for ev in raw_events:
                shape = self._validate_event_shape(ev)
                if not shape.is_valid:
                    rejected += 1
                    logger.error(
                        "Agent %s shape validation failed in cycle %s: %s",
                        self.agent_name,
                        cycle_id,
                        shape.errors,
                    )
                    continue
                vr = self.validate_event(ev)
                if vr.is_valid:
                    validated.append(ev)
                else:
                    rejected += 1
                    logger.debug(
                        "Agent %s rejected event in cycle %s: %s",
                        self.agent_name,
                        cycle_id,
                        vr.errors,
                    )

            # Step 3: Enrich validated events (P0-4: failure must not block)
            enriched = []
            for ev in validated:
                try:
                    enriched.append(self.enrich_event(ev))
                except Exception as enrich_exc:
                    self.metrics.record_enrich_failure()
                    logger.warning(
                        "Agent %s enrich failed in cycle %s, "
                        "passing original event: %s",
                        self.agent_name,
                        cycle_id,
                        enrich_exc,
                    )
                    enriched.append(ev)  # Pass through unenriched

            # Step 4: Publish — prefer queue_adapter (signed envelopes),
            # then local_queue, then EventBus retry as last resort.
            # WAL processor drains local queues into the telemetry store.
            if enriched:
                if self.queue_adapter:
                    for ev in enriched:
                        self.queue_adapter.enqueue(ev)
                elif self.local_queue:
                    for ev in enriched:
                        self.local_queue.enqueue(ev)
                else:
                    self._publish_with_retry(enriched)
                self.metrics.record_events_emitted(len(enriched))

            self.last_successful_collection = time.time()
            duration = self.last_successful_collection - cycle_start

            # Track loop success (auto-timestamps)
            self.metrics.record_loop_success()

            logger.info(
                "Agent %s cycle %s complete: raw=%d valid=%d rejected=%d duration=%.3fs",
                self.agent_name,
                cycle_id,
                len(raw_events),
                len(enriched),
                rejected,
                duration,
            )

        except Exception as e:
            self.error_count += 1
            self.last_error = str(e)

            # Track loop failure (auto-timestamps)
            self.metrics.record_loop_failure(e)

            logger.exception(
                "Agent %s cycle %s failed: %s",
                self.agent_name,
                cycle_id,
                e,
            )

    def run(self) -> None:
        """Simplified agent loop for v2 agents using queue_adapter.

        Lifecycle:
            1. Run setup() - exit if fails
            2. Register signal handlers
            3. Enter main loop:
               - Run collection cycle
               - Emit metrics if interval elapsed
               - Sleep until next interval
            4. On SIGTERM/SIGINT: graceful shutdown

        This is a simpler version of run_forever() designed for v2 agents
        that use queue_adapter for all publishing (no EventBus retries).
        """
        logger.info("Starting agent %s on device %s", self.agent_name, self.device_id)

        if not self.setup():
            logger.critical("Agent %s setup failed; exiting", self.agent_name)
            sys.exit(1)

        self.is_running = True
        self._shutdown = False

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        try:
            while not self._shutdown and self.is_running:
                loop_start = time.time()
                self.metrics.record_loop_start()

                try:
                    # Collect data (returns list of DeviceTelemetry)
                    items = self.collect_data() or []

                    # Track events emitted
                    self.metrics.record_events_emitted(len(items))

                    # Flush to queue_adapter
                    if self.queue_adapter and items:
                        for item in items:
                            self.queue_adapter.enqueue(item)

                    # Track loop success (auto-timestamps)
                    self.metrics.record_loop_success()
                    self.last_successful_collection = time.time()

                except Exception as exc:
                    # Track loop failure (auto-timestamps)
                    self.metrics.record_loop_failure(exc)
                    self.error_count += 1
                    self.last_error = str(exc)
                    logger.exception(
                        "Agent %s collection failed: %s",
                        self.agent_name,
                        exc,
                    )

                # Heartbeat every cycle regardless of success/failure (P0-2)
                self._emit_heartbeat()

                # Emit metrics telemetry if interval elapsed
                self._maybe_emit_metrics_telemetry()

                # Sleep for remaining interval
                elapsed = time.time() - loop_start
                sleep_for = max(0.0, self.collection_interval - elapsed)
                if sleep_for > 0:
                    time.sleep(sleep_for)

        finally:
            try:
                self.shutdown()
            except Exception as e:
                logger.error(
                    "Agent %s shutdown failed: %s", self.agent_name, e, exc_info=True
                )
            self._close_coordination_bus()
            logger.info("Agent %s stopped", self.agent_name)

    def run_forever(self) -> None:
        """Main agent loop with setup, signal handling, and graceful shutdown.

        Lifecycle:
            1. Run setup() - exit if fails
            2. Register signal handlers
            3. Enter main loop:
               - Drain local queue if EventBus recovered
               - Run collection cycle
               - Sleep until next interval
            4. On SIGTERM/SIGINT: graceful shutdown

        Exit Conditions:
            - setup() returns False
            - SIGTERM/SIGINT received
            - Unhandled exception in loop (logged, retried)
        """
        logger.info("Starting agent %s on device %s", self.agent_name, self.device_id)

        if not self.setup():
            logger.critical("Agent %s setup failed; exiting", self.agent_name)
            sys.exit(1)

        self.is_running = True

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        try:
            while self.is_running:
                # Drain local queue first (if EventBus recovered)
                if self.circuit_breaker.state != "OPEN":
                    drained = self._drain_local_queue(limit=200)
                    if drained:
                        logger.info(
                            "Agent %s drained %d events from local queue",
                            self.agent_name,
                            drained,
                        )

                # Run collection cycle
                self._run_one_cycle()

                # Heartbeat every cycle regardless of success/failure (P0-2)
                self._emit_heartbeat()

                # Emit metrics telemetry if interval elapsed
                self._maybe_emit_metrics_telemetry()

                # Sleep until next collection
                time.sleep(self.collection_interval)

        finally:
            try:
                self.shutdown()
            except Exception as e:
                logger.error(
                    "Agent %s shutdown failed: %s", self.agent_name, e, exc_info=True
                )
            self._close_coordination_bus()
            logger.info("Agent %s stopped", self.agent_name)
