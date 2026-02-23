"""
Tests for amoskys.intelligence.score_junction

Covers:
  - CorrelatedEvent dataclass construction
  - EventBuffer: add, windowed retrieval, cleanup
  - CorrelationEngine: rule matching, correlation detection
  - ScoreJunction: full pipeline (process_telemetry → ThreatScore)
  - ThreatScore: level thresholds, confidence calculation
  - Proto bug regression guards (GAP-05)
"""

import asyncio
import time
import uuid
from typing import List
from unittest.mock import MagicMock

import pytest

from amoskys.intel.models import ThreatLevel
from amoskys.intelligence.score_junction import (
    CorrelatedEvent,
    CorrelationEngine,
    EventBuffer,
    ScoreJunction,
    ThreatScore,
)
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

# ── Helpers ──────────────────────────────────────────────────────────


def _now_ns() -> int:
    return int(time.time() * 1e9)


def _make_event(
    device_id: str = "dev-1",
    agent: str = "proc_agent",
    event_type: str = "METRIC",
    severity: str = "INFO",
    metric_name: str | None = None,
    metric_value: float | None = None,
    alert_type: str | None = None,
    ts_ns: int | None = None,
) -> CorrelatedEvent:
    return CorrelatedEvent(
        event_id=str(uuid.uuid4()),
        device_id=device_id,
        timestamp_ns=ts_ns or _now_ns(),
        agent_source=agent,
        event_type=event_type,
        severity=severity,
        metric_name=metric_name,
        metric_value=metric_value,
        alert_type=alert_type,
    )


def _make_envelope(
    device_id: str = "dev-1",
    agent: str = "proc_agent",
    events: list | None = None,
) -> telemetry_pb2.UniversalEnvelope:
    """Build a real protobuf UniversalEnvelope for ScoreJunction."""
    env = telemetry_pb2.UniversalEnvelope()
    dt = env.device_telemetry
    dt.device_id = device_id
    dt.collection_agent = agent

    if events:
        for ev_spec in events:
            ev = dt.events.add()
            ev.event_id = ev_spec.get("event_id", str(uuid.uuid4()))
            ev.event_type = ev_spec.get("event_type", "METRIC")
            ev.severity = ev_spec.get("severity", "INFO")
            ev.event_timestamp_ns = ev_spec.get("timestamp_ns", _now_ns())

            if "metric_name" in ev_spec:
                ev.metric_data.metric_name = ev_spec["metric_name"]
                if "metric_value" in ev_spec:
                    ev.metric_data.numeric_value = ev_spec["metric_value"]

            if "alarm_type" in ev_spec:
                ev.alarm_data.alarm_type = ev_spec["alarm_type"]
    return env


# ═══════════════════════════════════════════════════════════════════
# CorrelatedEvent
# ═══════════════════════════════════════════════════════════════════


class TestCorrelatedEvent:
    """Basic dataclass sanity."""

    def test_default_fields(self):
        ev = _make_event()
        assert ev.correlation_score == 0.0
        assert ev.correlated_with == []
        assert ev.threat_indicators == []
        assert ev.additional_context == {}

    def test_custom_fields(self):
        ev = _make_event(
            device_id="router-7",
            agent="snmp_agent",
            event_type="ALARM",
            severity="CRITICAL",
            metric_name="ifInOctets",
            metric_value=1_000_000.0,
        )
        assert ev.device_id == "router-7"
        assert ev.agent_source == "snmp_agent"
        assert ev.metric_value == 1_000_000.0

    def test_alert_type_field(self):
        ev = _make_event(alert_type="SUSPICIOUS_PROCESS")
        assert ev.alert_type == "SUSPICIOUS_PROCESS"


# ═══════════════════════════════════════════════════════════════════
# EventBuffer
# ═══════════════════════════════════════════════════════════════════


class TestEventBuffer:

    def test_add_and_retrieve(self):
        buf = EventBuffer(window_seconds=300)
        ev = _make_event(device_id="d1")
        buf.add_event(ev)
        assert len(buf.all_events) == 1
        result = buf.get_events_in_window("d1", _now_ns())
        assert len(result) == 1
        assert result[0].event_id == ev.event_id

    def test_empty_entity(self):
        buf = EventBuffer()
        result = buf.get_events_in_window("nonexistent", _now_ns())
        assert result == []

    def test_window_filtering(self):
        buf = EventBuffer(window_seconds=60)
        now = _now_ns()
        old_ev = _make_event(device_id="d1", ts_ns=now - 120_000_000_000)
        recent_ev = _make_event(device_id="d1", ts_ns=now - 30_000_000_000)
        buf.add_event(old_ev)
        buf.add_event(recent_ev)

        result = buf.get_events_in_window("d1", now)
        assert len(result) == 1
        assert result[0].event_id == recent_ev.event_id

    def test_cleanup_removes_old(self):
        buf = EventBuffer(window_seconds=60)
        now = _now_ns()
        old_ev = _make_event(device_id="d1", ts_ns=now - 120_000_000_000)
        buf.add_event(old_ev)

        buf.cleanup_old_events(now)
        assert "d1" not in buf.events_by_entity

    def test_cleanup_keeps_recent(self):
        buf = EventBuffer(window_seconds=60)
        now = _now_ns()
        ev = _make_event(device_id="d1", ts_ns=now - 10_000_000_000)
        buf.add_event(ev)

        buf.cleanup_old_events(now)
        assert "d1" in buf.events_by_entity
        assert len(buf.events_by_entity["d1"]) == 1

    def test_multi_entity_isolation(self):
        buf = EventBuffer(window_seconds=300)
        ev_a = _make_event(device_id="A")
        ev_b = _make_event(device_id="B")
        buf.add_event(ev_a)
        buf.add_event(ev_b)

        assert len(buf.get_events_in_window("A", _now_ns())) == 1
        assert len(buf.get_events_in_window("B", _now_ns())) == 1

    def test_maxlen_global_buffer(self):
        buf = EventBuffer()
        for i in range(10_001):
            buf.add_event(_make_event(device_id=f"d-{i}"))
        assert len(buf.all_events) == 10_000

    def test_maxlen_entity_buffer(self):
        buf = EventBuffer()
        for i in range(1_001):
            buf.add_event(_make_event(device_id="d1"))
        assert len(buf.events_by_entity["d1"]) == 1_000


# ═══════════════════════════════════════════════════════════════════
# CorrelationEngine
# ═══════════════════════════════════════════════════════════════════


class TestCorrelationEngine:

    def test_rules_loaded(self):
        engine = CorrelationEngine()
        assert len(engine.rules) >= 3

    def test_no_correlations_for_benign(self):
        engine = CorrelationEngine()
        events = [_make_event(agent="proc_agent", event_type="METRIC", metric_value=10)]
        result = engine.correlate_events(events)
        assert result == []

    def test_high_cpu_suspicious_process_correlation(self):
        """Rule: high_cpu_suspicious_process — high CPU + suspicious process alert."""
        engine = CorrelationEngine()
        events = [
            _make_event(
                agent="proc_agent",
                event_type="METRIC",
                metric_name="proc_cpu_percent",
                metric_value=95.0,
            ),
            _make_event(
                agent="proc_agent",
                event_type="ALERT",
                alert_type="SUSPICIOUS_PROCESS",
            ),
        ]
        correlations = engine.correlate_events(events)
        assert len(correlations) >= 1
        rule_names = [c[0] for c in correlations]
        assert "high_cpu_suspicious_process" in rule_names

    def test_single_condition_met_partial_match(self):
        """If only 1 of 2 conditions met → still matches at ≥50% threshold."""
        engine = CorrelationEngine()
        events = [
            _make_event(
                agent="proc_agent",
                event_type="METRIC",
                metric_name="proc_cpu_percent",
                metric_value=95.0,
            ),
        ]
        correlations = engine.correlate_events(events)
        matched_rules = [c[0] for c in correlations]
        assert "high_cpu_suspicious_process" in matched_rules

    def test_matches_condition_agent_mismatch(self):
        engine = CorrelationEngine()
        ev = _make_event(agent="wrong_agent")
        cond = {"agent": "proc_agent"}
        assert engine._matches_condition(ev, cond) is False

    def test_matches_condition_event_type_mismatch(self):
        engine = CorrelationEngine()
        ev = _make_event(event_type="METRIC")
        cond = {"event_type": "ALERT"}
        assert engine._matches_condition(ev, cond) is False

    def test_matches_condition_metric_name_matching(self):
        engine = CorrelationEngine()
        ev = _make_event(metric_name="proc_cpu_percent")
        cond = {"metric": "cpu_percent"}
        assert engine._matches_condition(ev, cond) is True

    def test_matches_condition_metric_name_mismatch(self):
        engine = CorrelationEngine()
        ev = _make_event(metric_name="proc_memory")
        cond = {"metric": "cpu_percent"}
        assert engine._matches_condition(ev, cond) is False

    def test_matches_condition_threshold_pass(self):
        engine = CorrelationEngine()
        ev = _make_event(metric_value=90.0)
        cond = {"threshold": 80}
        assert engine._matches_condition(ev, cond) is True

    def test_matches_condition_threshold_fail(self):
        engine = CorrelationEngine()
        ev = _make_event(metric_value=50.0)
        cond = {"threshold": 80}
        assert engine._matches_condition(ev, cond) is False

    def test_matches_condition_alert_type_match(self):
        engine = CorrelationEngine()
        ev = _make_event(alert_type="SUSPICIOUS_PROCESS")
        cond = {"alert_type": "SUSPICIOUS_PROCESS"}
        assert engine._matches_condition(ev, cond) is True

    def test_matches_condition_alert_type_mismatch(self):
        engine = CorrelationEngine()
        ev = _make_event(alert_type="NORMAL")
        cond = {"alert_type": "SUSPICIOUS_PROCESS"}
        assert engine._matches_condition(ev, cond) is False

    def test_empty_condition_matches_everything(self):
        engine = CorrelationEngine()
        ev = _make_event()
        assert engine._matches_condition(ev, {}) is True

    def test_correlation_score_is_positive(self):
        engine = CorrelationEngine()
        events = [
            _make_event(
                agent="proc_agent", metric_name="proc_cpu_percent", metric_value=95.0
            ),
            _make_event(
                agent="proc_agent", event_type="ALERT", alert_type="SUSPICIOUS_PROCESS"
            ),
        ]
        correlations = engine.correlate_events(events)
        for name, score, evts in correlations:
            assert score > 0.0


# ═══════════════════════════════════════════════════════════════════
# ThreatScore
# ═══════════════════════════════════════════════════════════════════


class TestThreatScore:

    def test_construction(self):
        ts = ThreatScore(
            entity_id="dev-1",
            entity_type="device",
            score=75.0,
            threat_level=ThreatLevel.HIGH,
            confidence=0.8,
            contributing_events=["e1", "e2"],
            indicators=["high_cpu_suspicious_process"],
            timestamp_ns=_now_ns(),
            time_window_seconds=300,
        )
        assert ts.score == 75.0
        assert ts.threat_level == ThreatLevel.HIGH
        assert ts.confidence == 0.8
        assert len(ts.contributing_events) == 2


# ═══════════════════════════════════════════════════════════════════
# ScoreJunction
# ═══════════════════════════════════════════════════════════════════


class TestScoreJunction:

    def test_init_defaults(self):
        sj = ScoreJunction()
        assert sj.correlation_window == 300
        assert sj.stats["events_processed"] == 0

    def test_init_custom_window(self):
        sj = ScoreJunction(config={"correlation_window_seconds": 60})
        assert sj.correlation_window == 60

    def test_get_entity_score_none(self):
        sj = ScoreJunction()
        assert sj.get_entity_score("nonexistent") is None

    def test_get_statistics(self):
        sj = ScoreJunction()
        stats = sj.get_statistics()
        assert "events_processed" in stats
        assert "correlations_found" in stats
        assert "threats_detected" in stats
        assert "entities_tracked" in stats

    # ── Async process_telemetry tests ────────────────────────────

    @pytest.mark.asyncio
    async def test_process_empty_envelope(self):
        """Envelope without device_telemetry → None."""
        sj = ScoreJunction()
        env = telemetry_pb2.UniversalEnvelope()
        result = await sj.process_telemetry(env)
        assert result is None

    @pytest.mark.asyncio
    async def test_process_single_event_no_correlation(self):
        """Single benign metric event → no threat (needs ≥2 events to correlate)."""
        sj = ScoreJunction()
        env = _make_envelope(
            events=[
                {
                    "event_type": "METRIC",
                    "severity": "INFO",
                    "metric_name": "uptime",
                    "metric_value": 1234.0,
                }
            ]
        )
        result = await sj.process_telemetry(env)
        assert result is None
        assert sj.stats["events_processed"] == 1

    @pytest.mark.asyncio
    async def test_process_increments_events_processed(self):
        sj = ScoreJunction()
        env = _make_envelope(
            events=[
                {"event_type": "METRIC", "metric_name": "a", "metric_value": 1.0},
                {"event_type": "METRIC", "metric_name": "b", "metric_value": 2.0},
                {"event_type": "METRIC", "metric_name": "c", "metric_value": 3.0},
            ]
        )
        await sj.process_telemetry(env)
        assert sj.stats["events_processed"] == 3

    @pytest.mark.asyncio
    async def test_process_threat_detection(self):
        """High CPU + suspicious process → should trigger correlation."""
        sj = ScoreJunction()

        env = _make_envelope(
            agent="proc_agent",
            events=[
                {
                    "event_type": "METRIC",
                    "severity": "WARN",
                    "metric_name": "proc_cpu_percent",
                    "metric_value": 95.0,
                },
                {
                    "event_type": "ALARM",
                    "severity": "CRITICAL",
                    "alarm_type": "SUSPICIOUS_PROCESS",
                },
            ],
        )
        result = await sj.process_telemetry(env)
        assert sj.stats["correlations_found"] >= 1

    @pytest.mark.asyncio
    async def test_process_multi_call_accumulates(self):
        """Multiple calls accumulate events in the buffer."""
        sj = ScoreJunction()
        for i in range(5):
            env = _make_envelope(
                events=[
                    {
                        "event_type": "METRIC",
                        "metric_name": f"metric_{i}",
                        "metric_value": float(i),
                    }
                ]
            )
            await sj.process_telemetry(env)
        assert sj.stats["events_processed"] == 5

    # ── _compute_threat_score ────────────────────────────────────

    def test_compute_score_thresholds(self):
        """Verify threat level thresholds: 0-20→BENIGN, 20-40→LOW, 40-60→MEDIUM, 60-80→HIGH, 80+→CRITICAL."""
        sj = ScoreJunction()
        now = _now_ns()
        ev1 = _make_event()
        ev2 = _make_event()

        correlations = [("test_rule", 0.35, [ev1, ev2])]
        ts = sj._compute_threat_score("dev-1", correlations, [ev1, ev2], now)
        assert ts.threat_level == ThreatLevel.LOW
        assert 20 <= ts.score < 40

    def test_compute_score_critical(self):
        sj = ScoreJunction()
        now = _now_ns()
        ev = _make_event()
        correlations = [("rule_a", 0.85, [ev])]
        ts = sj._compute_threat_score("dev-1", correlations, [ev], now)
        assert ts.threat_level == ThreatLevel.CRITICAL
        assert ts.score >= 80

    def test_compute_score_benign(self):
        sj = ScoreJunction()
        now = _now_ns()
        ev = _make_event()
        correlations = [("rule_a", 0.1, [ev])]
        ts = sj._compute_threat_score("dev-1", correlations, [ev], now)
        assert ts.threat_level == ThreatLevel.BENIGN
        assert ts.score < 20

    def test_compute_score_capped_at_100(self):
        sj = ScoreJunction()
        now = _now_ns()
        ev = _make_event()
        correlations = [("r1", 0.9, [ev]), ("r2", 0.9, [ev])]
        ts = sj._compute_threat_score("dev-1", correlations, [ev], now)
        assert ts.score <= 100.0

    def test_compute_confidence(self):
        sj = ScoreJunction()
        now = _now_ns()
        events = [_make_event() for _ in range(5)]
        correlations = [("rule", 0.5, events)]
        ts = sj._compute_threat_score("dev-1", correlations, events, now)
        assert ts.confidence == pytest.approx(0.5, abs=0.01)

    def test_compute_confidence_max(self):
        sj = ScoreJunction()
        now = _now_ns()
        events = [_make_event() for _ in range(20)]
        correlations = [("rule", 0.5, events)]
        ts = sj._compute_threat_score("dev-1", correlations, events, now)
        assert ts.confidence == 1.0

    def test_compute_indicators(self):
        sj = ScoreJunction()
        now = _now_ns()
        ev = _make_event()
        correlations = [("rule_alpha", 0.5, [ev]), ("rule_beta", 0.3, [ev])]
        ts = sj._compute_threat_score("dev-1", correlations, [ev], now)
        assert "rule_alpha" in ts.indicators
        assert "rule_beta" in ts.indicators

    # ── _convert_to_correlated_event (proto field mapping) ───────

    def test_convert_metric_event(self):
        """Metric data extracted correctly from protobuf event."""
        sj = ScoreJunction()
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_id = "e-1"
        ev.event_type = "METRIC"
        ev.severity = "INFO"
        ev.event_timestamp_ns = _now_ns()
        ev.metric_data.metric_name = "cpu_usage"
        ev.metric_data.numeric_value = 42.5

        result = sj._convert_to_correlated_event(ev, "dev-1", "proc_agent")
        assert result.metric_name == "cpu_usage"
        assert result.metric_value == 42.5
        assert result.device_id == "dev-1"
        assert result.agent_source == "proc_agent"

    def test_convert_alarm_event(self):
        """alarm_data.alarm_type extracted correctly (GAP-05 regression guard)."""
        sj = ScoreJunction()
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_id = "e-2"
        ev.event_type = "ALARM"
        ev.severity = "CRITICAL"
        ev.event_timestamp_ns = _now_ns()
        ev.alarm_data.alarm_type = "SUSPICIOUS_PROCESS"

        result = sj._convert_to_correlated_event(ev, "dev-1", "proc_agent")
        assert result.alert_type == "SUSPICIOUS_PROCESS"

    def test_convert_no_metric_no_alarm(self):
        """Event with no metric or alarm data → None for both."""
        sj = ScoreJunction()
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_id = "e-3"
        ev.event_type = "LOG"
        ev.severity = "INFO"
        ev.event_timestamp_ns = _now_ns()

        result = sj._convert_to_correlated_event(ev, "dev-1", "proc_agent")
        assert result.metric_name is None
        assert result.alert_type is None

    def test_convert_zero_metric_value(self):
        """Proto3 scalar default 0.0 → treated as None (GAP-05 regression guard)."""
        sj = ScoreJunction()
        ev = telemetry_pb2.TelemetryEvent()
        ev.event_id = "e-4"
        ev.event_type = "METRIC"
        ev.severity = "INFO"
        ev.event_timestamp_ns = _now_ns()
        ev.metric_data.metric_name = "idle"
        # numeric_value defaults to 0.0 in proto3

        result = sj._convert_to_correlated_event(ev, "dev-1", "proc_agent")
        assert result.metric_name == "idle"
        # 0.0 is falsy → or None → None
        assert result.metric_value is None


# ═══════════════════════════════════════════════════════════════════
# GAP-05 Regression Guards
# ═══════════════════════════════════════════════════════════════════


class TestGAP05RegressionGuards:
    """Ensure the 3 proto bugs don't regress."""

    def test_no_alert_data_hasfield(self):
        """score_junction must NOT use 'alert_data' as a proto field — proto field is 'alarm_data'."""
        import inspect

        source = inspect.getsource(ScoreJunction._convert_to_correlated_event)
        # Check only executable lines (skip comments and docstrings)
        code_lines = [
            line.strip()
            for line in source.splitlines()
            if line.strip()
            and not line.strip().startswith("#")
            and not line.strip().startswith('"""')
        ]
        code_only = "\n".join(code_lines)
        assert (
            'HasField("alert_data")' not in code_only
        ), "Proto field is 'alarm_data', not 'alert_data'"
        assert (
            "event.alert_data" not in code_only
        ), "Proto field is 'alarm_data', not 'alert_data'"
        assert "alarm_data" in code_only

    def test_no_hasfield_numeric_value(self):
        """Proto3 scalar doubles don't support HasField — must not use it."""
        import inspect

        source = inspect.getsource(ScoreJunction._convert_to_correlated_event)
        assert (
            'HasField("numeric_value")' not in source
        ), "Proto3 scalar double cannot use HasField"


# ═══════════════════════════════════════════════════════════════════
# P0-W4: EventBuffer Bounds & Entity Eviction
# ═══════════════════════════════════════════════════════════════════


class TestEventBufferBounds:
    """Window_seconds must be clamped to [60, 3600]."""

    def test_window_too_low_raises(self):
        with pytest.raises(ValueError, match="window_seconds must be between"):
            EventBuffer(window_seconds=10)

    def test_window_too_high_raises(self):
        with pytest.raises(ValueError, match="window_seconds must be between"):
            EventBuffer(window_seconds=7200)

    def test_window_valid_min(self):
        buf = EventBuffer(window_seconds=60)
        assert buf.window_seconds == 60

    def test_window_valid_max(self):
        buf = EventBuffer(window_seconds=3600)
        assert buf.window_seconds == 3600

    def test_entity_eviction_at_limit(self):
        """When max_entities is exceeded, oldest entity is evicted."""
        buf = EventBuffer(window_seconds=300, max_entities=3)
        for i in range(5):
            buf.add_event(_make_event(device_id=f"dev-{i}"))

        # Only 3 entities should remain
        assert len(buf.events_by_entity) <= 3


class TestScoreJunctionWindowClamping:
    """ScoreJunction clamps out-of-range correlation_window_seconds."""

    def test_junction_clamps_low_window(self):
        sj = ScoreJunction(config={"correlation_window_seconds": 10})
        assert sj.correlation_window >= 60

    def test_junction_clamps_high_window(self):
        sj = ScoreJunction(config={"correlation_window_seconds": 9999})
        assert sj.correlation_window <= 3600
