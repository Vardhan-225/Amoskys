"""Extended tests for HardenedAgentBase — covering uncovered code paths.

Covers:
    - CircuitBreaker transition callback (_notify_transition)
    - Observer failure in _notify_transition does not break CB
    - _on_circuit_breaker_transition wired to metrics
    - _emit_heartbeat (with and without queue_adapter)
    - _emit_aoc1_event (success, no adapter, exception paths)
    - _handle_signal sets is_running=False
    - _drain_local_queue (with drain, without drain, exception)
    - health_summary with local_queue present
    - _build_metrics_event builds proper ProtoEvent
    - _maybe_emit_metrics_telemetry edge cases
    - start_metrics_http_server
    - run() loop (setup failure, collection, shutdown exception)
    - run_forever() loop (drain, cycle, shutdown exception)
    - Enrichment failure in _run_one_cycle passes original event
    - _enqueue_locally records backpressure_drop metric when no queue
"""

import signal
import sys
import time
from typing import Any, Sequence
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest

from amoskys.agents.common.base import (
    CircuitBreaker,
    CircuitBreakerOpen,
    HardenedAgentBase,
    ValidationResult,
)
from amoskys.agents.common.metrics import AgentMetrics

# ---------------------------------------------------------------------------
# Concrete stub for testing
# ---------------------------------------------------------------------------


class StubAgent(HardenedAgentBase):
    """Minimal concrete agent for testing base class behavior."""

    def __init__(self, collect_fn=None, setup_ok=True, **kwargs):
        defaults = {"agent_name": "stub", "device_id": "test-host"}
        defaults.update(kwargs)
        super().__init__(**defaults)
        self._collect_fn = collect_fn or (lambda: [])
        self._setup_ok = setup_ok
        self.shutdown_called = False

    def setup(self) -> bool:
        return self._setup_ok

    def collect_data(self) -> Sequence[Any]:
        return self._collect_fn()

    def shutdown(self) -> None:
        self.shutdown_called = True


# ---------------------------------------------------------------------------
# CircuitBreaker _notify_transition tests
# ---------------------------------------------------------------------------


class TestCircuitBreakerNotifyTransition:
    """Test the _on_transition callback plumbing."""

    def test_transition_callback_called_on_open(self):
        transitions = []
        cb = CircuitBreaker(
            failure_threshold=2,
            _on_transition=lambda old, new: transitions.append((old, new)),
        )
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "OPEN"
        assert ("CLOSED", "OPEN") in transitions

    def test_transition_callback_called_on_half_open(self):
        transitions = []
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.0,
            _on_transition=lambda old, new: transitions.append((old, new)),
        )
        cb.record_failure()
        assert cb.state == "OPEN"
        # Advance past recovery timeout
        with patch.object(cb, "_now", return_value=cb.last_failure_time + 1.0):
            cb.allow_call()
        assert cb.state == "HALF_OPEN"
        assert ("OPEN", "HALF_OPEN") in transitions

    def test_transition_callback_called_on_close_from_half_open(self):
        transitions = []
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.0,
            half_open_attempts=1,
            _on_transition=lambda old, new: transitions.append((old, new)),
        )
        cb.record_failure()
        with patch.object(cb, "_now", return_value=cb.last_failure_time + 1.0):
            cb.allow_call()
        cb.record_success()
        assert cb.state == "CLOSED"
        # Should see HALF_OPEN -> CLOSED (or OPEN -> CLOSED depending on path)
        assert any(new == "CLOSED" for old, new in transitions)

    def test_transition_callback_called_on_reopen_from_half_open(self):
        transitions = []
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.0,
            _on_transition=lambda old, new: transitions.append((old, new)),
        )
        cb.record_failure()
        with patch.object(cb, "_now", return_value=cb.last_failure_time + 1.0):
            cb.allow_call()
        assert cb.state == "HALF_OPEN"
        cb.record_failure()
        assert cb.state == "OPEN"
        assert ("HALF_OPEN", "OPEN") in transitions

    def test_observer_failure_does_not_break_circuit_breaker(self):
        """Observer raising should not crash the circuit breaker."""

        def bad_observer(old, new):
            raise RuntimeError("observer exploded")

        cb = CircuitBreaker(
            failure_threshold=1,
            _on_transition=bad_observer,
        )
        # Should not raise even though observer throws
        cb.record_failure()
        assert cb.state == "OPEN"

    def test_no_callback_when_none(self):
        """No callback registered should silently do nothing."""
        cb = CircuitBreaker(failure_threshold=1, _on_transition=None)
        cb.record_failure()
        assert cb.state == "OPEN"


# ---------------------------------------------------------------------------
# _on_circuit_breaker_transition (agent method)
# ---------------------------------------------------------------------------


class TestAgentCircuitBreakerTransition:
    """Test the agent-level CB transition handler."""

    def test_transition_updates_metrics(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter)
        agent._on_circuit_breaker_transition("CLOSED", "OPEN")
        assert agent.metrics.circuit_breaker_state == "OPEN"
        assert agent.metrics.circuit_breaker_opens == 1

    def test_transition_emits_aoc1_event(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter)
        with patch.object(agent, "_emit_aoc1_event") as mock_emit:
            agent._on_circuit_breaker_transition("CLOSED", "OPEN")
            mock_emit.assert_called_once()
            call_args = mock_emit.call_args
            assert call_args[0][0] == "aoc1_circuit_breaker_transition"

    def test_cb_wired_to_agent_handler(self):
        """When CB transitions, agent handler should fire automatically."""
        mock_adapter = MagicMock()
        agent = StubAgent(
            queue_adapter=mock_adapter,
            eventbus_publisher=MagicMock(
                publish=MagicMock(side_effect=RuntimeError("fail"))
            ),
        )
        # Force enough failures to open circuit
        for _ in range(5):
            try:
                agent._publish_with_circuit_breaker([{"e": 1}])
            except Exception:
                pass
        assert agent.circuit_breaker.state == "OPEN"
        assert agent.metrics.circuit_breaker_opens >= 1


# ---------------------------------------------------------------------------
# _emit_heartbeat
# ---------------------------------------------------------------------------


class TestEmitHeartbeat:

    def test_heartbeat_updates_last_heartbeat(self):
        agent = StubAgent()
        before = time.time()
        agent._emit_heartbeat()
        assert agent.last_heartbeat >= before

    def test_heartbeat_records_metric(self):
        agent = StubAgent()
        agent._emit_heartbeat()
        assert agent.metrics.heartbeat_count >= 1
        assert agent.metrics.last_heartbeat_ns > 0

    def test_heartbeat_without_queue_adapter_does_not_crash(self):
        agent = StubAgent()
        agent.queue_adapter = None
        # Should not raise
        agent._emit_heartbeat()

    def test_heartbeat_with_queue_adapter_emits_event(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter)
        agent._emit_heartbeat()
        # _emit_aoc1_event should be called which calls queue_adapter.enqueue
        mock_adapter.enqueue.assert_called()


# ---------------------------------------------------------------------------
# _emit_aoc1_event
# ---------------------------------------------------------------------------


class TestEmitAoc1Event:

    def test_no_adapter_silently_returns(self):
        agent = StubAgent()
        agent.queue_adapter = None
        # Should not raise
        agent._emit_aoc1_event("test_event", {"key": "val"})

    def test_with_adapter_enqueues(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter)
        agent._emit_aoc1_event("test_event", {"key": "val"})
        mock_adapter.enqueue.assert_called_once()

    def test_exception_in_emit_does_not_propagate(self):
        mock_adapter = MagicMock()
        mock_adapter.enqueue.side_effect = RuntimeError("boom")
        agent = StubAgent(queue_adapter=mock_adapter)
        # Should not raise
        agent._emit_aoc1_event("test_event", {"key": "val"})

    def test_none_values_skipped_in_attributes(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter)
        agent._emit_aoc1_event("test_event", {"present": "yes", "absent": None})
        # Just verify no crash — None values should be skipped
        mock_adapter.enqueue.assert_called_once()


# ---------------------------------------------------------------------------
# _handle_signal
# ---------------------------------------------------------------------------


class TestHandleSignal:

    def test_signal_sets_is_running_false(self):
        agent = StubAgent()
        agent.is_running = True
        agent._handle_signal(signal.SIGTERM, None)
        assert agent.is_running is False

    def test_signal_works_for_sigint(self):
        agent = StubAgent()
        agent.is_running = True
        agent._handle_signal(signal.SIGINT, None)
        assert agent.is_running is False


# ---------------------------------------------------------------------------
# _drain_local_queue
# ---------------------------------------------------------------------------


class TestDrainLocalQueue:

    def test_no_queue_returns_zero(self):
        agent = StubAgent()
        assert agent._drain_local_queue() == 0

    def test_queue_with_drain_method(self):
        mock_queue = MagicMock()
        mock_queue.drain.return_value = 5
        agent = StubAgent(local_queue=mock_queue)
        result = agent._drain_local_queue(limit=50)
        assert result == 5
        mock_queue.drain.assert_called_once()

    def test_queue_without_drain_method(self):
        mock_queue = MagicMock(spec=[])  # no drain method
        agent = StubAgent(local_queue=mock_queue)
        result = agent._drain_local_queue()
        assert result == 0

    def test_drain_exception_returns_zero(self):
        mock_queue = MagicMock()
        mock_queue.drain.side_effect = RuntimeError("disk error")
        agent = StubAgent(local_queue=mock_queue)
        result = agent._drain_local_queue()
        assert result == 0


# ---------------------------------------------------------------------------
# health_summary
# ---------------------------------------------------------------------------


class TestHealthSummary:

    def test_health_summary_with_local_queue(self):
        mock_queue = MagicMock()
        mock_queue.size.return_value = 42
        agent = StubAgent(local_queue=mock_queue)
        health = agent.health_summary()
        assert health["local_queue_size"] == 42

    def test_health_summary_without_local_queue(self):
        agent = StubAgent()
        health = agent.health_summary()
        assert health["local_queue_size"] == 0

    def test_health_summary_uptime(self):
        agent = StubAgent()
        agent.start_time = time.time() - 100.0
        health = agent.health_summary()
        assert health["uptime_seconds"] >= 99.0


# ---------------------------------------------------------------------------
# _build_metrics_event
# ---------------------------------------------------------------------------


class TestBuildMetricsEvent:

    def test_build_metrics_event_returns_proto(self):
        agent = StubAgent()
        event = agent._build_metrics_event()
        assert event.event_type == "agent_metrics"
        assert event.source_component == "StubAgent"

    def test_build_metrics_event_includes_metrics(self):
        agent = StubAgent()
        agent.metrics.loops_started = 10
        agent.metrics.loops_succeeded = 9
        event = agent._build_metrics_event()
        assert "loops_started" in dict(event.attributes)
        assert event.attributes["loops_started"] == "10"


# ---------------------------------------------------------------------------
# _maybe_emit_metrics_telemetry edge cases
# ---------------------------------------------------------------------------


class TestMaybeEmitMetricsTelemetry:

    def test_no_emission_when_interval_not_elapsed(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter, metrics_interval=9999.0)
        agent._maybe_emit_metrics_telemetry()
        mock_adapter.enqueue.assert_not_called()

    def test_emission_when_interval_elapsed(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter, metrics_interval=0.001)
        agent._last_metrics_emit_ns = 0
        agent._maybe_emit_metrics_telemetry()
        mock_adapter.enqueue.assert_called_once()

    def test_no_adapter_logs_debug_and_returns(self):
        agent = StubAgent()
        agent._last_metrics_emit_ns = 0
        # Should not raise
        agent._maybe_emit_metrics_telemetry()

    def test_build_metrics_failure_handled(self):
        mock_adapter = MagicMock()
        agent = StubAgent(queue_adapter=mock_adapter, metrics_interval=0.001)
        agent._last_metrics_emit_ns = 0
        with patch.object(
            agent, "_build_metrics_event", side_effect=RuntimeError("boom")
        ):
            # Should not raise
            agent._maybe_emit_metrics_telemetry()
        mock_adapter.enqueue.assert_not_called()

    def test_enqueue_failure_handled(self):
        mock_adapter = MagicMock()
        mock_adapter.enqueue.side_effect = RuntimeError("queue full")
        agent = StubAgent(queue_adapter=mock_adapter, metrics_interval=0.001)
        agent._last_metrics_emit_ns = 0
        # Should not raise
        agent._maybe_emit_metrics_telemetry()


# ---------------------------------------------------------------------------
# _enqueue_locally metrics tracking
# ---------------------------------------------------------------------------


class TestEnqueueLocallyMetrics:

    def test_no_queue_records_backpressure_drop(self):
        agent = StubAgent()
        agent._enqueue_locally([{"e": 1}, {"e": 2}])
        assert agent.metrics.queue_backpressure_drops == 2


# ---------------------------------------------------------------------------
# _run_one_cycle enrichment failure path
# ---------------------------------------------------------------------------


class TestRunOneCycleEnrichFailure:

    def test_enrich_failure_passes_original_event(self):
        _ts = int(time.time() * 1e9)
        events = [
            {"id": 1, "device_id": "test-host", "timestamp_ns": _ts},
            {"id": 2, "device_id": "test-host", "timestamp_ns": _ts},
        ]

        def collect():
            return events

        agent = StubAgent(collect_fn=collect)
        agent.enrich_event = MagicMock(side_effect=RuntimeError("enrich fail"))

        agent._run_one_cycle()
        # Despite enrich failures, metrics should show success (events still published)
        assert agent.metrics.enrich_failures == 2
        assert agent.last_successful_collection > 0

    def test_enrich_failure_records_metric(self):
        _ts = int(time.time() * 1e9)
        agent = StubAgent(
            collect_fn=lambda: [
                {"id": 1, "device_id": "test-host", "timestamp_ns": _ts}
            ]
        )
        agent.enrich_event = MagicMock(side_effect=ValueError("bad"))
        agent._run_one_cycle()
        assert agent.metrics.enrich_failures == 1


# ---------------------------------------------------------------------------
# run() loop
# ---------------------------------------------------------------------------


class TestRunLoop:

    def test_run_exits_on_setup_failure(self):
        agent = StubAgent(setup_ok=False)
        with pytest.raises(SystemExit) as exc_info:
            agent.run()
        assert exc_info.value.code == 1

    def test_run_calls_shutdown_on_exit(self):
        call_count = [0]

        def collect():
            call_count[0] += 1
            if call_count[0] >= 1:
                # Stop after first collection
                agent._shutdown = True
            return []

        agent = StubAgent(collect_fn=collect, collection_interval=0.001)
        with patch("amoskys.agents.common.base.time.sleep"):
            agent.run()
        assert agent.shutdown_called

    def test_run_handles_collection_exception(self):
        call_count = [0]

        def failing_collect():
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("collection boom")
            # Stop on second call
            agent.is_running = False
            return []

        agent = StubAgent(collect_fn=failing_collect, collection_interval=0.001)
        with patch("amoskys.agents.common.base.time.sleep"):
            agent.run()
        assert agent.error_count >= 1
        assert agent.last_error == "collection boom"

    def test_run_enqueues_items_to_queue_adapter(self):
        call_count = [0]

        def collect():
            call_count[0] += 1
            if call_count[0] >= 2:
                agent._shutdown = True
                return []
            return [MagicMock(), MagicMock()]

        mock_adapter = MagicMock()
        agent = StubAgent(
            collect_fn=collect,
            queue_adapter=mock_adapter,
            collection_interval=0.001,
        )
        with patch("amoskys.agents.common.base.time.sleep"):
            agent.run()
        assert mock_adapter.enqueue.call_count >= 2

    def test_run_shutdown_exception_handled(self):
        call_count = [0]

        def collect():
            call_count[0] += 1
            agent._shutdown = True
            return []

        agent = StubAgent(collect_fn=collect, collection_interval=0.001)
        agent.shutdown = MagicMock(side_effect=RuntimeError("shutdown fail"))
        with patch("amoskys.agents.common.base.time.sleep"):
            # Should not raise even though shutdown fails
            agent.run()


# ---------------------------------------------------------------------------
# run_forever() loop
# ---------------------------------------------------------------------------


class TestRunForeverLoop:

    def test_run_forever_exits_on_setup_failure(self):
        agent = StubAgent(setup_ok=False)
        with pytest.raises(SystemExit):
            agent.run_forever()

    def test_run_forever_drains_queue_when_cb_not_open(self):
        call_count = [0]

        def collect():
            call_count[0] += 1
            if call_count[0] >= 1:
                agent.is_running = False
            return []

        mock_queue = MagicMock()
        mock_queue.drain.return_value = 0
        agent = StubAgent(
            collect_fn=collect,
            local_queue=mock_queue,
            collection_interval=0.001,
        )
        with patch("amoskys.agents.common.base.time.sleep"):
            agent.run_forever()
        mock_queue.drain.assert_called()

    def test_run_forever_skips_drain_when_cb_open(self):
        call_count = [0]

        def collect():
            call_count[0] += 1
            agent.is_running = False
            return []

        mock_queue = MagicMock()
        mock_queue.drain.return_value = 0
        agent = StubAgent(
            collect_fn=collect,
            local_queue=mock_queue,
            collection_interval=0.001,
        )
        agent.circuit_breaker.state = "OPEN"
        agent.circuit_breaker.last_failure_time = time.time()
        with patch("amoskys.agents.common.base.time.sleep"):
            agent.run_forever()
        mock_queue.drain.assert_not_called()

    def test_run_forever_calls_heartbeat_and_metrics(self):
        call_count = [0]

        def collect():
            call_count[0] += 1
            agent.is_running = False
            return []

        agent = StubAgent(collect_fn=collect, collection_interval=0.001)
        with patch("amoskys.agents.common.base.time.sleep"):
            with patch.object(agent, "_emit_heartbeat") as hb_mock:
                with patch.object(agent, "_maybe_emit_metrics_telemetry") as mt_mock:
                    agent.run_forever()
                    hb_mock.assert_called()
                    mt_mock.assert_called()

    def test_run_forever_shutdown_exception_handled(self):
        call_count = [0]

        def collect():
            call_count[0] += 1
            agent.is_running = False
            return []

        agent = StubAgent(collect_fn=collect, collection_interval=0.001)
        agent.shutdown = MagicMock(side_effect=RuntimeError("shutdown fail"))
        with patch("amoskys.agents.common.base.time.sleep"):
            # Should not raise
            agent.run_forever()


# ---------------------------------------------------------------------------
# start_metrics_http_server
# ---------------------------------------------------------------------------


class TestStartMetricsHttpServer:

    def test_server_starts_daemon_thread(self):
        agent = StubAgent()
        with patch("amoskys.agents.common.base.HTTPServer") as mock_server_cls:
            mock_server = MagicMock()
            mock_server_cls.return_value = mock_server
            with patch(
                "amoskys.agents.common.base.threading.Thread"
            ) as mock_thread_cls:
                mock_thread = MagicMock()
                mock_thread_cls.return_value = mock_thread
                agent.start_metrics_http_server(host="127.0.0.1", port=9999)
                mock_thread.start.assert_called_once()
                mock_thread_cls.assert_called_once()
                call_kwargs = mock_thread_cls.call_args
                assert call_kwargs[1]["daemon"] is True


# ---------------------------------------------------------------------------
# Queue adapter metrics wiring in __init__
# ---------------------------------------------------------------------------


class TestQueueAdapterMetricsWiring:

    def test_queue_adapter_metrics_wired(self):
        mock_adapter = MagicMock()
        mock_adapter._metrics = None
        agent = StubAgent(queue_adapter=mock_adapter)
        assert mock_adapter._metrics is agent.metrics

    def test_queue_adapter_without_metrics_attr_ignored(self):
        mock_adapter = MagicMock(spec=["enqueue", "size"])
        # Should not crash
        agent = StubAgent(queue_adapter=mock_adapter)
