"""Tests for AOC-1 probe observability (Phase 3).

Validates:
    - P0-5: ProbeReadiness.__post_init__ validates status against ProbeStatus
    - P0-6: Silent probe disabling tracked in metrics
    - P0-7: DEGRADED probes emit companion aoc1_probe_degraded_firing event
    - P0-7: scan_all_probes tags DEGRADED events with quality_degraded
"""

import logging
from typing import Any, Dict, List

import pytest

from amoskys.agents.common.metrics import AgentMetrics
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    ProbeReadiness,
    Severity,
    TelemetryEvent,
)

# ---------------------------------------------------------------------------
# Test probes
# ---------------------------------------------------------------------------


class HealthyProbe(MicroProbe):
    name = "healthy_probe"
    description = "Always works"
    requires_fields: List[str] = []

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        return [self._create_event("test_event", Severity.INFO, {"status": "ok"})]


class FailingSetupProbe(MicroProbe):
    name = "failing_setup"
    description = "Setup returns False"
    requires_fields: List[str] = []

    def setup(self) -> bool:
        return False

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        return []


class ExplodingSetupProbe(MicroProbe):
    name = "exploding_setup"
    description = "Setup throws"
    requires_fields: List[str] = []

    def setup(self) -> bool:
        raise RuntimeError("setup boom")

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        return []


class DegradedProbe(MicroProbe):
    name = "degraded_probe"
    description = "Runs degraded when enrichment missing"
    requires_fields = ["main_data", "optional_enrichment"]
    degraded_without = ["optional_enrichment"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        return [
            self._create_event("degraded_detection", Severity.MEDIUM, {"found": True}),
            self._create_event("degraded_detection_2", Severity.LOW, {"found": True}),
        ]


class BrokenProbe(MicroProbe):
    name = "broken_probe"
    description = "Missing critical field"
    requires_fields = ["critical_data"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        return []


# ---------------------------------------------------------------------------
# Minimal agent stub for mixin testing
# ---------------------------------------------------------------------------


class StubAgent(MicroProbeAgentMixin):
    """Minimal agent that satisfies MicroProbeAgentMixin requirements."""

    def __init__(self, **kwargs):
        self.device_id = "test-device"
        self.agent_name = "test_agent"
        self.metrics = AgentMetrics()
        super().__init__(**kwargs)


# ---------------------------------------------------------------------------
# P0-5: ProbeReadiness status validation
# ---------------------------------------------------------------------------


class TestProbeReadinessValidation:
    def test_valid_statuses_accepted(self):
        for status in ("REAL", "DEGRADED", "BROKEN", "DISABLED"):
            pr = ProbeReadiness(probe_name="test", status=status)
            assert pr.status == status

    def test_invalid_status_defaults_to_broken(self, caplog):
        with caplog.at_level(logging.WARNING):
            pr = ProbeReadiness(probe_name="bad_probe", status="INVALID")

        assert pr.status == "BROKEN"
        assert "AOC1_INVALID_PROBE_STATUS" in caplog.text
        assert "bad_probe" in caplog.text

    def test_empty_status_defaults_to_broken(self):
        pr = ProbeReadiness(probe_name="test", status="")
        assert pr.status == "BROKEN"

    def test_case_sensitive(self):
        pr = ProbeReadiness(probe_name="test", status="real")
        assert pr.status == "BROKEN"  # lowercase not valid


# ---------------------------------------------------------------------------
# P0-6: Silent probe disabling tracked in metrics
# ---------------------------------------------------------------------------


class TestSilentProbeDisabling:
    def test_setup_false_increments_silently_disabled(self):
        agent = StubAgent()
        agent.register_probe(HealthyProbe())
        agent.register_probe(FailingSetupProbe())
        agent.setup_probes()

        assert agent.metrics.probes_silently_disabled == 1

    def test_setup_exception_increments_silently_disabled(self):
        agent = StubAgent()
        agent.register_probe(HealthyProbe())
        agent.register_probe(ExplodingSetupProbe())
        agent.setup_probes()

        assert agent.metrics.probes_silently_disabled == 1

    def test_multiple_failures_accumulate(self):
        agent = StubAgent()
        agent.register_probe(FailingSetupProbe())
        agent.register_probe(ExplodingSetupProbe())
        agent.setup_probes()

        assert agent.metrics.probes_silently_disabled == 2

    def test_setup_false_logs_aoc1_prefix(self, caplog):
        agent = StubAgent()
        agent.register_probe(FailingSetupProbe())

        with caplog.at_level(logging.ERROR):
            agent.setup_probes()

        assert "AOC1_PROBE_DISABLED" in caplog.text
        assert "failing_setup" in caplog.text

    def test_setup_exception_logs_aoc1_prefix(self, caplog):
        agent = StubAgent()
        agent.register_probe(ExplodingSetupProbe())

        with caplog.at_level(logging.ERROR):
            agent.setup_probes()

        assert "AOC1_PROBE_DISABLED" in caplog.text
        assert "exploding_setup" in caplog.text


# ---------------------------------------------------------------------------
# P0-6: Probe metrics counters updated after setup
# ---------------------------------------------------------------------------


class TestProbeMetricsCounters:
    def test_all_counters_set(self):
        agent = StubAgent()
        agent.register_probe(HealthyProbe())
        agent.register_probe(FailingSetupProbe())
        agent.setup_probes()

        assert agent.metrics.probes_total == 2
        assert agent.metrics.probes_real == 1
        assert agent.metrics.probes_disabled >= 1

    def test_degraded_counted(self):
        agent = StubAgent()
        agent.register_probe(DegradedProbe())
        agent.setup_probes(collector_shared_data_keys=["main_data"])

        assert agent.metrics.probes_degraded == 1

    def test_broken_counted(self):
        agent = StubAgent()
        agent.register_probe(BrokenProbe())
        agent.setup_probes()

        assert agent.metrics.probes_broken == 1


# ---------------------------------------------------------------------------
# P0-7: DEGRADED companion event in run_probes()
# ---------------------------------------------------------------------------


class TestDegradedCompanionEvent:
    def test_degraded_probe_emits_companion(self):
        agent = StubAgent()
        agent.register_probe(DegradedProbe())
        agent.setup_probes(collector_shared_data_keys=["main_data"])

        context = ProbeContext(
            device_id="test-device",
            agent_name="test_agent",
            shared_data={"main_data": [1, 2, 3]},
        )
        events = agent.run_probes(context)

        companion = [e for e in events if e.event_type == "aoc1_probe_degraded_firing"]
        assert len(companion) == 1
        assert companion[0].data["probe"] == "degraded_probe"
        assert companion[0].data["event_count"] == 2
        assert "optional_enrichment" in companion[0].data["degraded_fields"]

    def test_degraded_events_tagged(self):
        agent = StubAgent()
        agent.register_probe(DegradedProbe())
        agent.setup_probes(collector_shared_data_keys=["main_data"])

        context = ProbeContext(
            device_id="test-device",
            agent_name="test_agent",
            shared_data={"main_data": [1, 2, 3]},
        )
        events = agent.run_probes(context)

        detection_events = [
            e for e in events if e.event_type.startswith("degraded_detection")
        ]
        assert len(detection_events) == 2
        for ev in detection_events:
            assert "degraded_probe" in ev.tags
            assert "missing_optional_enrichment" in ev.tags

    def test_no_companion_when_no_events(self):
        """If degraded probe returns empty list, no companion emitted."""

        class EmptyDegradedProbe(MicroProbe):
            name = "empty_degraded"
            requires_fields = ["data", "extra"]
            degraded_without = ["extra"]

            def scan(self, context):
                return []

        agent = StubAgent()
        agent.register_probe(EmptyDegradedProbe())
        agent.setup_probes(collector_shared_data_keys=["data"])

        context = ProbeContext(
            device_id="test-device",
            agent_name="test_agent",
            shared_data={"data": []},
        )
        events = agent.run_probes(context)
        companion = [e for e in events if e.event_type == "aoc1_probe_degraded_firing"]
        assert len(companion) == 0


# ---------------------------------------------------------------------------
# P0-7: scan_all_probes quality tagging
# ---------------------------------------------------------------------------


class TestScanAllProbesQualityTagging:
    def test_degraded_events_tagged_quality_degraded(self):
        agent = StubAgent()
        probe = DegradedProbe()
        agent.register_probe(probe)
        agent.setup_probes(collector_shared_data_keys=["main_data"])

        # Manually set readiness for scan_all_probes path
        probe.readiness = ProbeReadiness(
            probe_name="degraded_probe",
            status="DEGRADED",
            degraded_fields=["optional_enrichment"],
        )

        events = agent.scan_all_probes()

        detection_events = [
            e for e in events if e.event_type.startswith("degraded_detection")
        ]
        assert len(detection_events) == 2
        for ev in detection_events:
            assert "quality_degraded" in ev.tags
            assert "missing_optional_enrichment" in ev.tags

    def test_real_probe_no_quality_tag(self):
        agent = StubAgent()
        agent.register_probe(HealthyProbe())
        agent.setup_probes()

        events = agent.scan_all_probes()
        for ev in events:
            assert "quality_degraded" not in ev.tags
