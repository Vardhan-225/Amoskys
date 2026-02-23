#!/usr/bin/env python3
"""Agent metrics tracking for observability.

Provides AgentMetrics container for tracking agent health and performance:
    - Loop execution stats (started, succeeded, failed)
    - Event emission counts (total events, probe events)
    - Error tracking (probe errors, last error details)
    - Timestamp tracking (last success, last failure)

Architecture:
    - HardenedAgentBase: Tracks loop-level metrics
    - MicroProbeAgentMixin: Tracks probe-level metrics
    - Strategy B: Metrics as DeviceTelemetry (protocol="AGENT_METRICS")
    - Strategy A (optional): HTTP /metrics endpoint for Prometheus

Usage:
    ```python
    class MyAgent(HardenedAgentBase):
        def __init__(self, ...):
            super().__init__(...)
            # self.metrics is automatically initialized

        def run(self):
            # Metrics automatically tracked during collection loop
            pass
    ```
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

# ---------------------------------------------------------------------------
# AOC-1 / EAC-1 Enums — shared vocabulary for all hardening phases
# ---------------------------------------------------------------------------


class CircuitBreakerState(str, Enum):
    """Typed circuit breaker states (P0-3)."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ProbeStatus(str, Enum):
    """Typed probe readiness states (P0-5)."""

    REAL = "REAL"
    DEGRADED = "DEGRADED"
    BROKEN = "BROKEN"
    DISABLED = "DISABLED"


class QueueAction(str, Enum):
    """Queue operation outcomes for drain/backpressure telemetry (P0-10/11/12)."""

    ENQUEUED = "ENQUEUED"
    BACKPRESSURE_DROP = "BACKPRESSURE_DROP"
    MAX_RETRY_DROP = "MAX_RETRY_DROP"
    DRAIN_SUCCESS = "DRAIN_SUCCESS"
    DRAIN_FAILURE = "DRAIN_FAILURE"


class SubprocessOutcome(str, Enum):
    """Subprocess execution outcomes for OS layer tracking (P0-17)."""

    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    ACCESS_DENIED = "ACCESS_DENIED"
    NOT_FOUND = "NOT_FOUND"
    NONZERO_EXIT = "NONZERO_EXIT"
    EXCEPTION = "EXCEPTION"


#: Schema version for all framework dataclasses (P0-19).
SCHEMA_VERSION = "1.0.0"


@dataclass
class AgentMetrics:
    """Container for agent health and performance metrics.

    Attributes:
        loops_started: Total number of collection loops started
        loops_succeeded: Number of loops that completed successfully
        loops_failed: Number of loops that failed with exceptions
        events_emitted: Total telemetry events emitted (DeviceTelemetry count)
        probe_events_emitted: Total threat events from probes (TelemetryEvent count)
        probe_errors: Number of probe scan() exceptions
        last_success_ns: Timestamp of last successful loop (nanoseconds)
        last_failure_ns: Timestamp of last failed loop (nanoseconds)
        last_error_type: Exception type of last error (class name)
        last_error_message: Exception message of last error
    """

    # Loop execution stats
    loops_started: int = 0
    loops_succeeded: int = 0
    loops_failed: int = 0

    # Event emission stats
    events_emitted: int = 0
    probe_events_emitted: int = 0

    # Error tracking
    probe_errors: int = 0
    last_success_ns: int = 0
    last_failure_ns: int = 0
    last_error_type: Optional[str] = None
    last_error_message: Optional[str] = None

    # --- AOC-1 Observability Counters (Phase 0) ---

    # Queue health (P0-1, P0-10, P0-11, P0-12)
    queue_backpressure_drops: int = 0
    queue_max_retry_drops: int = 0
    queue_drain_successes: int = 0
    queue_drain_failures: int = 0
    queue_current_depth: int = 0
    queue_current_bytes: int = 0

    # Circuit breaker (P0-3)
    circuit_breaker_state: str = field(default="CLOSED", repr=False)
    circuit_breaker_opens: int = 0
    circuit_breaker_half_opens: int = 0
    circuit_breaker_recoveries: int = 0

    # Heartbeat (P0-2)
    last_heartbeat_ns: int = 0
    heartbeat_count: int = 0

    # Probe coverage (P0-6, P0-7)
    probes_total: int = 0
    probes_real: int = 0
    probes_degraded: int = 0
    probes_broken: int = 0
    probes_disabled: int = 0
    probes_silently_disabled: int = 0

    # Enrichment and subprocess (P0-4, P0-17, P0-18)
    enrich_failures: int = 0
    subprocess_failures: int = 0
    subprocess_access_denied: int = 0

    def record_loop_start(self) -> None:
        """Record the start of a collection loop."""
        self.loops_started += 1

    def record_loop_success(self, timestamp_ns: Optional[int] = None) -> None:
        """Record successful completion of a collection loop.

        Args:
            timestamp_ns: Optional loop completion timestamp (nanoseconds).
                         If not provided, uses current time.
        """
        self.loops_succeeded += 1
        self.last_success_ns = timestamp_ns if timestamp_ns else int(time.time() * 1e9)

    def record_loop_failure(
        self, exc: BaseException, timestamp_ns: Optional[int] = None
    ) -> None:
        """Record failed collection loop.

        Args:
            exc: Exception that caused the failure
            timestamp_ns: Optional loop failure timestamp (nanoseconds).
                         If not provided, uses current time.
        """
        self.loops_failed += 1
        self.last_failure_ns = timestamp_ns if timestamp_ns else int(time.time() * 1e9)
        self.last_error_type = exc.__class__.__name__
        msg = str(exc)
        if len(msg) > 256:
            msg = msg[:253] + "..."
        self.last_error_message = msg

    def record_events_emitted(self, count: int) -> None:
        """Record telemetry events emitted to queue.

        Args:
            count: Number of DeviceTelemetry messages emitted
        """
        if count > 0:
            self.events_emitted += count

    def record_probe_events_emitted(self, count: int) -> None:
        """Record threat events detected by probes.

        Args:
            count: Number of TelemetryEvent objects from probe.scan()
        """
        if count > 0:
            self.probe_events_emitted += count

    def record_probe_error(self) -> None:
        """Record a probe scan() exception."""
        self.probe_errors += 1

    # --- AOC-1 record methods ---

    def record_backpressure_drop(self, count: int = 1) -> None:
        """Record events dropped due to queue backpressure (P0-10)."""
        self.queue_backpressure_drops += count

    def record_max_retry_drop(self, count: int = 1) -> None:
        """Record events dropped after exhausting max retries (P0-12)."""
        self.queue_max_retry_drops += count

    def record_drain_success(self, count: int = 1) -> None:
        """Record successfully drained events (P0-11)."""
        self.queue_drain_successes += count

    def record_drain_failure(self, count: int = 1) -> None:
        """Record failed drain attempts (P0-11)."""
        self.queue_drain_failures += count

    def record_circuit_breaker_transition(self, new_state: str) -> None:
        """Record a circuit breaker state transition (P0-3)."""
        self.circuit_breaker_state = new_state
        if new_state == CircuitBreakerState.OPEN.value:
            self.circuit_breaker_opens += 1
        elif new_state == CircuitBreakerState.HALF_OPEN.value:
            self.circuit_breaker_half_opens += 1
        elif (
            new_state == CircuitBreakerState.CLOSED.value
            and self.circuit_breaker_opens > 0
        ):
            self.circuit_breaker_recoveries += 1

    def record_heartbeat(self, timestamp_ns: Optional[int] = None) -> None:
        """Record a heartbeat emission (P0-2)."""
        self.last_heartbeat_ns = timestamp_ns or int(time.time() * 1e9)
        self.heartbeat_count += 1

    def record_enrich_failure(self) -> None:
        """Record an enrich_event() exception (P0-4)."""
        self.enrich_failures += 1

    def record_subprocess_failure(self, access_denied: bool = False) -> None:
        """Record a subprocess failure (P0-17, P0-18)."""
        self.subprocess_failures += 1
        if access_denied:
            self.subprocess_access_denied += 1

    def to_dict(self) -> dict:
        """Convert metrics to dictionary for serialization.

        Returns:
            Dictionary with all metric fields (using dataclasses.asdict)
        """
        return asdict(self)

    @property
    def success_rate(self) -> float:
        """Calculate loop success rate.

        Returns:
            Success rate as fraction [0.0, 1.0], or 1.0 if no loops
        """
        if self.loops_started == 0:
            return 1.0
        return self.loops_succeeded / self.loops_started

    @property
    def failure_rate(self) -> float:
        """Calculate loop failure rate.

        Returns:
            Failure rate as fraction [0.0, 1.0], or 0.0 if no loops
        """
        if self.loops_started == 0:
            return 0.0
        return self.loops_failed / self.loops_started
