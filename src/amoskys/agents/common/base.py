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
import logging
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

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

    state: str = field(default="CLOSED", init=False)
    failure_count: int = field(default=0, init=False)
    success_count: int = field(default=0, init=False)
    last_failure_time: float = field(default=0.0, init=False)

    def _now(self) -> float:
        return time.time()

    def record_success(self) -> None:
        """Record successful operation."""
        if self.state in ("OPEN", "HALF_OPEN"):
            self.success_count += 1
            if self.success_count >= self.half_open_attempts:
                # Fully close circuit
                self.state = "CLOSED"
                self.failure_count = 0
                self.success_count = 0
                logger.info("Circuit breaker CLOSED (recovered)")
        else:
            # CLOSED state - reset failure count
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record failed operation."""
        self.failure_count += 1
        self.last_failure_time = self._now()
        self.success_count = 0
        if self.failure_count >= self.failure_threshold:
            if self.state != "OPEN":
                logger.warning(
                    "Circuit breaker OPEN (failures: %d)", self.failure_count
                )
            self.state = "OPEN"

    def _maybe_transition_half_open(self) -> None:
        """Try transitioning from OPEN to HALF_OPEN if recovery timeout passed."""
        if self.state == "OPEN":
            if self._now() - self.last_failure_time >= self.recovery_timeout:
                self.state = "HALF_OPEN"
                self.failure_count = 0
                self.success_count = 0
                logger.info("Circuit breaker HALF_OPEN (testing recovery)")

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

    Responsibilities:
        - Provide structured run loop with lifecycle hooks
        - Wrap collection/publish in error handling
        - Circuit-break EventBus on repeated failures
        - Support local queue for offline resilience
        - Track health and metrics
        - Handle signals for graceful shutdown

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
    ) -> None:
        """Initialize hardened agent base.

        Args:
            agent_name: Unique agent identifier (e.g., "proc_agent")
            device_id: Device/host identifier (e.g., "host-001")
            collection_interval: Seconds between collection cycles
            eventbus_publisher: EventBus client for publishing
            local_queue: LocalQueue instance for offline resilience
        """
        self.agent_name = agent_name
        self.device_id = device_id
        self.collection_interval = collection_interval
        self.eventbus_publisher = eventbus_publisher
        self.local_queue = local_queue

        self.circuit_breaker = CircuitBreaker()
        self.is_running: bool = False

        # Health tracking
        self.start_time: float = time.time()
        self.last_successful_collection: float = 0.0
        self.last_heartbeat: float = 0.0
        self.last_error: Optional[str] = None
        self.collection_count: int = 0
        self.error_count: int = 0

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
        if not self.local_queue:
            logger.warning(
                "Local queue not configured for %s; dropping %d events",
                self.agent_name,
                len(events),
            )
            return

        for ev in events:
            try:
                self.local_queue.enqueue(ev)
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

    # ----------------- Health & Introspection ------------------------------

    def health_summary(self) -> dict:
        """Get current agent health snapshot.

        Returns:
            Dict with health metrics for diagnostics/monitoring

        Usage:
            Can be exposed via /health endpoint or metrics
        """
        return {
            "agent_name": self.agent_name,
            "device_id": self.device_id,
            "uptime_seconds": time.time() - self.start_time,
            "last_successful_collection": self.last_successful_collection,
            "collection_count": self.collection_count,
            "error_count": self.error_count,
            "circuit_breaker_state": self.circuit_breaker.state,
            "local_queue_size": (self.local_queue.size() if self.local_queue else 0),
        }

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

        try:
            # Step 1: Collect raw data
            raw_events = self.collect_data()

            # Step 2: Validate events
            validated: list[Any] = []
            rejected: int = 0
            for ev in raw_events:
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

            # Step 3: Enrich validated events
            enriched = [self.enrich_event(ev) for ev in validated]

            # Step 4: Publish to EventBus
            if enriched:
                self._publish_with_retry(enriched)

            self.last_successful_collection = time.time()
            duration = self.last_successful_collection - cycle_start

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
            logger.error(
                "Agent %s cycle %s failed: %s",
                self.agent_name,
                cycle_id,
                e,
                exc_info=True,
            )

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

                # Sleep until next collection
                time.sleep(self.collection_interval)

        finally:
            try:
                self.shutdown()
            except Exception as e:
                logger.error(
                    "Agent %s shutdown failed: %s", self.agent_name, e, exc_info=True
                )
            logger.info("Agent %s stopped", self.agent_name)
