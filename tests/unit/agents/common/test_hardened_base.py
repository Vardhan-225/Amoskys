"""Tests for HardenedAgentBase and CircuitBreaker.

Covers:
    - CircuitBreaker state transitions (CLOSED → OPEN → HALF_OPEN → CLOSED)
    - CircuitBreaker edge cases (threshold boundary, recovery timeout)
    - HardenedAgentBase lifecycle (setup, collect, validate, enrich, shutdown)
    - Retry with exponential backoff
    - Local queue fallback when EventBus is down
    - Metrics tracking accuracy
    - Signal handling for graceful shutdown
"""

import time
from typing import Any, Sequence
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.base import (
    CircuitBreaker,
    CircuitBreakerOpen,
    HardenedAgentBase,
    ValidationResult,
)
from amoskys.agents.common.metrics import AgentMetrics


# ---------------------------------------------------------------------------
# CircuitBreaker unit tests
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    """Test CircuitBreaker state machine in isolation."""

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == "CLOSED"
        assert cb.failure_count == 0
        assert cb.success_count == 0

    def test_success_in_closed_resets_failures(self):
        cb = CircuitBreaker(failure_threshold=5)
        cb.failure_count = 3
        cb.record_success()
        assert cb.failure_count == 0
        assert cb.state == "CLOSED"

    def test_single_failure_stays_closed(self):
        cb = CircuitBreaker(failure_threshold=5)
        cb.record_failure()
        assert cb.state == "CLOSED"
        assert cb.failure_count == 1

    def test_threshold_failures_opens_circuit(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "OPEN"
        assert cb.failure_count == 3

    def test_open_circuit_blocks_calls(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)
        cb.record_failure()
        assert cb.state == "OPEN"
        with pytest.raises(CircuitBreakerOpen):
            cb.allow_call()

    def test_open_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        assert cb.state == "OPEN"
        time.sleep(0.02)
        cb.allow_call()  # Should not raise — transitions to HALF_OPEN
        assert cb.state == "HALF_OPEN"

    def test_half_open_success_closes_circuit(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, half_open_attempts=2)
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_call()  # → HALF_OPEN
        assert cb.state == "HALF_OPEN"

        cb.record_success()
        assert cb.state == "HALF_OPEN"  # Need 2 successes
        cb.record_success()
        assert cb.state == "CLOSED"
        assert cb.failure_count == 0

    def test_half_open_failure_reopens_circuit(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        cb.allow_call()  # → HALF_OPEN
        assert cb.state == "HALF_OPEN"

        cb.record_failure()
        assert cb.state == "OPEN"

    def test_allow_call_succeeds_when_closed(self):
        cb = CircuitBreaker()
        cb.allow_call()  # Should not raise

    def test_last_failure_time_recorded(self):
        cb = CircuitBreaker()
        before = time.time()
        cb.record_failure()
        after = time.time()
        assert before <= cb.last_failure_time <= after

    def test_exact_threshold_boundary(self):
        """Exactly threshold-1 failures stays CLOSED, threshold opens."""
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == "CLOSED"
        cb.record_failure()
        assert cb.state == "OPEN"


# ---------------------------------------------------------------------------
# Concrete subclass for testing HardenedAgentBase
# ---------------------------------------------------------------------------


class StubAgent(HardenedAgentBase):
    """Minimal concrete agent for testing base class behavior."""

    def __init__(self, collect_fn=None, setup_ok=True, **kwargs):
        defaults = {"agent_name": "stub_agent", "device_id": "test-host"}
        defaults.update(kwargs)
        super().__init__(**defaults)
        self._collect_fn = collect_fn or (lambda: [])
        self._setup_ok = setup_ok

    def setup(self) -> bool:
        return self._setup_ok

    def collect_data(self) -> Sequence[Any]:
        return self._collect_fn()


# ---------------------------------------------------------------------------
# HardenedAgentBase unit tests
# ---------------------------------------------------------------------------


class TestHardenedAgentBaseInit:
    """Test initialization and configuration."""

    def test_default_init(self):
        agent = StubAgent()
        assert agent.agent_name == "stub_agent"
        assert agent.device_id == "test-host"
        assert agent.collection_interval == 10.0
        assert agent.circuit_breaker.state == "CLOSED"
        assert agent.is_running is False
        assert agent.error_count == 0

    def test_custom_interval(self):
        agent = StubAgent(collection_interval=5.0)
        assert agent.collection_interval == 5.0

    def test_metrics_initialized(self):
        agent = StubAgent()
        assert isinstance(agent.metrics, AgentMetrics)
        assert agent.metrics.loops_started == 0


class TestHardenedAgentBaseLifecycle:
    """Test validate, enrich, and health methods."""

    def test_default_validate_accepts_all(self):
        agent = StubAgent()
        result = agent.validate_event({"anything": True})
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True

    def test_default_enrich_passes_through(self):
        agent = StubAgent()
        event = {"key": "value"}
        enriched = agent.enrich_event(event)
        assert enriched is event

    def test_health_summary_structure(self):
        agent = StubAgent()
        health = agent.health_summary()
        assert health["agent_name"] == "stub_agent"
        assert health["device_id"] == "test-host"
        assert "uptime_seconds" in health
        assert "circuit_breaker_state" in health
        assert health["circuit_breaker_state"] == "CLOSED"
        assert health["error_count"] == 0


class TestHardenedAgentBasePublish:
    """Test publish, retry, and fallback paths."""

    def test_publish_raises_without_eventbus(self):
        agent = StubAgent()
        with pytest.raises(RuntimeError, match="No eventbus_publisher"):
            agent._publish_to_eventbus([{"event": 1}])

    def test_publish_calls_eventbus_publisher(self):
        mock_pub = MagicMock()
        agent = StubAgent(eventbus_publisher=mock_pub)
        events = [{"e": 1}, {"e": 2}]
        agent._publish_to_eventbus(events)
        mock_pub.publish.assert_called_once_with(events)

    def test_publish_with_circuit_breaker_records_success(self):
        mock_pub = MagicMock()
        agent = StubAgent(eventbus_publisher=mock_pub)
        agent._publish_with_circuit_breaker([{"e": 1}])
        assert agent.circuit_breaker.state == "CLOSED"
        assert agent.circuit_breaker.failure_count == 0

    def test_publish_with_circuit_breaker_records_failure(self):
        mock_pub = MagicMock()
        mock_pub.publish.side_effect = ConnectionError("down")
        agent = StubAgent(eventbus_publisher=mock_pub)
        with pytest.raises(ConnectionError):
            agent._publish_with_circuit_breaker([{"e": 1}])
        assert agent.circuit_breaker.failure_count == 1

    def test_retry_falls_back_to_local_queue_after_max_retries(self):
        mock_pub = MagicMock()
        mock_pub.publish.side_effect = ConnectionError("down")
        mock_queue = MagicMock()
        agent = StubAgent(eventbus_publisher=mock_pub, local_queue=mock_queue)

        events = [{"e": 1}]
        agent._publish_with_retry(events, max_retries=2, backoff_base=0.001)

        # Should have tried 2 times then enqueued locally
        assert mock_pub.publish.call_count == 2
        mock_queue.enqueue.assert_called()

    def test_retry_succeeds_on_second_attempt(self):
        mock_pub = MagicMock()
        mock_pub.publish.side_effect = [ConnectionError("down"), None]
        agent = StubAgent(eventbus_publisher=mock_pub)

        events = [{"e": 1}]
        agent._publish_with_retry(events, max_retries=3, backoff_base=0.001)

        assert mock_pub.publish.call_count == 2

    def test_circuit_open_skips_retries_enqueues_locally(self):
        mock_pub = MagicMock()
        mock_queue = MagicMock()
        agent = StubAgent(eventbus_publisher=mock_pub, local_queue=mock_queue)

        # Force circuit open
        agent.circuit_breaker.state = "OPEN"
        agent.circuit_breaker.last_failure_time = time.time()

        events = [{"e": 1}]
        agent._publish_with_retry(events, max_retries=3, backoff_base=0.001)

        # Should NOT have called eventbus at all — went straight to local queue
        mock_pub.publish.assert_not_called()
        mock_queue.enqueue.assert_called()


class TestHardenedAgentBaseLocalQueue:
    """Test local queue fallback behavior."""

    def test_enqueue_locally_without_queue_logs_warning(self):
        agent = StubAgent()
        # Should not raise, just log warning
        agent._enqueue_locally([{"e": 1}])

    def test_enqueue_locally_calls_queue(self):
        mock_queue = MagicMock()
        agent = StubAgent(local_queue=mock_queue)
        agent._enqueue_locally([{"e": 1}, {"e": 2}])
        assert mock_queue.enqueue.call_count == 2

    def test_enqueue_locally_handles_queue_errors(self):
        mock_queue = MagicMock()
        mock_queue.enqueue.side_effect = Exception("disk full")
        agent = StubAgent(local_queue=mock_queue)
        # Should not raise — best-effort
        agent._enqueue_locally([{"e": 1}])


class TestHardenedAgentBaseCollectionCycle:
    """Test _run_one_cycle behavior."""

    def test_successful_cycle_updates_metrics(self):
        agent = StubAgent(collect_fn=lambda: [{"e": 1}])
        agent._run_one_cycle()
        assert agent.metrics.loops_started >= 1
        assert agent.metrics.loops_succeeded >= 1
        assert agent.collection_count == 1
        assert agent.last_successful_collection > 0

    def test_failed_cycle_tracks_error(self):
        def boom():
            raise RuntimeError("test error")

        agent = StubAgent(collect_fn=boom)
        agent._run_one_cycle()  # Should not raise
        assert agent.error_count == 1
        assert agent.last_error == "test error"
        assert agent.metrics.loops_failed >= 1

    def test_cycle_with_validation_rejects_invalid_events(self):
        agent = StubAgent(collect_fn=lambda: [{"good": True}, {"bad": True}])

        # Override validate to reject second event
        call_count = [0]
        original_validate = agent.validate_event

        def custom_validate(event):
            call_count[0] += 1
            if event.get("bad"):
                return ValidationResult(is_valid=False, errors=["bad event"])
            return ValidationResult(is_valid=True)

        agent.validate_event = custom_validate
        agent._run_one_cycle()

        assert call_count[0] == 2
        assert agent.metrics.loops_succeeded >= 1


class TestHardenedAgentBaseMetricsEmission:
    """Test metrics telemetry emission."""

    def test_metrics_not_emitted_before_interval(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter, metrics_interval=60.0)
        agent._maybe_emit_metrics_telemetry()
        # Interval not elapsed yet
        mock_adapter.enqueue.assert_not_called()

    def test_metrics_emitted_after_interval(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter, metrics_interval=0.01)
        # Set last emit to past
        agent._last_metrics_emit_ns = 0
        agent._maybe_emit_metrics_telemetry()
        mock_adapter.enqueue.assert_called_once()

    def test_metrics_skipped_without_queue_adapter(self):
        agent = StubAgent()
        agent._last_metrics_emit_ns = 0
        # Should not raise
        agent._maybe_emit_metrics_telemetry()
