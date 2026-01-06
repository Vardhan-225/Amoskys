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
from dataclasses import asdict, dataclass
from typing import Optional


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

    def record_loop_failure(self, exc: BaseException, timestamp_ns: Optional[int] = None) -> None:
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
