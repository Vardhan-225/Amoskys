"""Tests for AOC-1 enums and AgentMetrics extensions (Phase 0).

Verifies the shared type vocabulary and observability counters added
to support the Foundation Hardening sprint.
"""

import time

import pytest

from amoskys.agents.common.metrics import (
    SCHEMA_VERSION,
    AgentMetrics,
    CircuitBreakerState,
    ProbeStatus,
    QueueAction,
    SubprocessOutcome,
)

# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestCircuitBreakerState:
    def test_values(self):
        assert CircuitBreakerState.CLOSED.value == "CLOSED"
        assert CircuitBreakerState.OPEN.value == "OPEN"
        assert CircuitBreakerState.HALF_OPEN.value == "HALF_OPEN"

    def test_str_enum(self):
        assert str(CircuitBreakerState.OPEN) == "CircuitBreakerState.OPEN"
        assert CircuitBreakerState.OPEN == "OPEN"

    def test_membership(self):
        assert "CLOSED" in {s.value for s in CircuitBreakerState}


class TestProbeStatus:
    def test_values(self):
        assert ProbeStatus.REAL.value == "REAL"
        assert ProbeStatus.DEGRADED.value == "DEGRADED"
        assert ProbeStatus.BROKEN.value == "BROKEN"
        assert ProbeStatus.DISABLED.value == "DISABLED"

    def test_str_enum(self):
        assert ProbeStatus.DEGRADED == "DEGRADED"


class TestQueueAction:
    def test_values(self):
        assert QueueAction.ENQUEUED.value == "ENQUEUED"
        assert QueueAction.BACKPRESSURE_DROP.value == "BACKPRESSURE_DROP"
        assert QueueAction.MAX_RETRY_DROP.value == "MAX_RETRY_DROP"
        assert QueueAction.DRAIN_SUCCESS.value == "DRAIN_SUCCESS"
        assert QueueAction.DRAIN_FAILURE.value == "DRAIN_FAILURE"


class TestSubprocessOutcome:
    def test_values(self):
        assert SubprocessOutcome.SUCCESS.value == "SUCCESS"
        assert SubprocessOutcome.TIMEOUT.value == "TIMEOUT"
        assert SubprocessOutcome.ACCESS_DENIED.value == "ACCESS_DENIED"
        assert SubprocessOutcome.NOT_FOUND.value == "NOT_FOUND"
        assert SubprocessOutcome.NONZERO_EXIT.value == "NONZERO_EXIT"
        assert SubprocessOutcome.EXCEPTION.value == "EXCEPTION"


class TestSchemaVersion:
    def test_format(self):
        parts = SCHEMA_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)


# ---------------------------------------------------------------------------
# AgentMetrics AOC-1 counter tests
# ---------------------------------------------------------------------------


class TestAgentMetricsAOC1:
    def test_defaults(self):
        m = AgentMetrics()
        assert m.queue_backpressure_drops == 0
        assert m.queue_max_retry_drops == 0
        assert m.queue_drain_successes == 0
        assert m.queue_drain_failures == 0
        assert m.queue_current_depth == 0
        assert m.queue_current_bytes == 0
        assert m.circuit_breaker_state == "CLOSED"
        assert m.circuit_breaker_opens == 0
        assert m.circuit_breaker_half_opens == 0
        assert m.circuit_breaker_recoveries == 0
        assert m.last_heartbeat_ns == 0
        assert m.heartbeat_count == 0
        assert m.probes_total == 0
        assert m.probes_real == 0
        assert m.probes_degraded == 0
        assert m.probes_broken == 0
        assert m.probes_disabled == 0
        assert m.probes_silently_disabled == 0
        assert m.enrich_failures == 0
        assert m.subprocess_failures == 0
        assert m.subprocess_access_denied == 0

    def test_record_backpressure_drop(self):
        m = AgentMetrics()
        m.record_backpressure_drop(3)
        assert m.queue_backpressure_drops == 3
        m.record_backpressure_drop()
        assert m.queue_backpressure_drops == 4

    def test_record_max_retry_drop(self):
        m = AgentMetrics()
        m.record_max_retry_drop(2)
        assert m.queue_max_retry_drops == 2

    def test_record_drain_success(self):
        m = AgentMetrics()
        m.record_drain_success(10)
        assert m.queue_drain_successes == 10

    def test_record_drain_failure(self):
        m = AgentMetrics()
        m.record_drain_failure()
        m.record_drain_failure()
        assert m.queue_drain_failures == 2

    def test_record_enrich_failure(self):
        m = AgentMetrics()
        m.record_enrich_failure()
        assert m.enrich_failures == 1

    def test_record_subprocess_failure_basic(self):
        m = AgentMetrics()
        m.record_subprocess_failure()
        assert m.subprocess_failures == 1
        assert m.subprocess_access_denied == 0

    def test_record_subprocess_failure_access_denied(self):
        m = AgentMetrics()
        m.record_subprocess_failure(access_denied=True)
        assert m.subprocess_failures == 1
        assert m.subprocess_access_denied == 1

    def test_record_heartbeat_auto_timestamp(self):
        m = AgentMetrics()
        before = int(time.time() * 1e9)
        m.record_heartbeat()
        after = int(time.time() * 1e9)
        assert m.heartbeat_count == 1
        assert before <= m.last_heartbeat_ns <= after

    def test_record_heartbeat_explicit_timestamp(self):
        m = AgentMetrics()
        ts = 1_700_000_000_000_000_000
        m.record_heartbeat(timestamp_ns=ts)
        assert m.last_heartbeat_ns == ts
        assert m.heartbeat_count == 1


class TestCircuitBreakerTransitionMetrics:
    def test_open_transition(self):
        m = AgentMetrics()
        m.record_circuit_breaker_transition("OPEN")
        assert m.circuit_breaker_state == "OPEN"
        assert m.circuit_breaker_opens == 1

    def test_half_open_transition(self):
        m = AgentMetrics()
        m.record_circuit_breaker_transition("HALF_OPEN")
        assert m.circuit_breaker_state == "HALF_OPEN"
        assert m.circuit_breaker_half_opens == 1

    def test_recovery_after_open(self):
        m = AgentMetrics()
        m.record_circuit_breaker_transition("OPEN")
        m.record_circuit_breaker_transition("HALF_OPEN")
        m.record_circuit_breaker_transition("CLOSED")
        assert m.circuit_breaker_recoveries == 1
        assert m.circuit_breaker_state == "CLOSED"

    def test_closed_without_prior_open_no_recovery(self):
        m = AgentMetrics()
        m.record_circuit_breaker_transition("CLOSED")
        assert m.circuit_breaker_recoveries == 0

    def test_multiple_open_close_cycles(self):
        m = AgentMetrics()
        for _ in range(3):
            m.record_circuit_breaker_transition("OPEN")
            m.record_circuit_breaker_transition("HALF_OPEN")
            m.record_circuit_breaker_transition("CLOSED")
        assert m.circuit_breaker_opens == 3
        assert m.circuit_breaker_half_opens == 3
        assert m.circuit_breaker_recoveries == 3


class TestAgentMetricsToDict:
    def test_includes_aoc1_fields(self):
        m = AgentMetrics()
        m.record_backpressure_drop(5)
        m.record_heartbeat()
        d = m.to_dict()
        assert d["queue_backpressure_drops"] == 5
        assert d["heartbeat_count"] == 1
        assert "circuit_breaker_state" in d
        assert "probes_total" in d
        assert "enrich_failures" in d
        assert "subprocess_failures" in d

    def test_existing_fields_preserved(self):
        m = AgentMetrics()
        m.record_loop_start()
        m.record_loop_success()
        m.record_events_emitted(5)
        d = m.to_dict()
        assert d["loops_started"] == 1
        assert d["loops_succeeded"] == 1
        assert d["events_emitted"] == 5
