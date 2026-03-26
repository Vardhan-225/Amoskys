"""macOS Shield Observatory agents — unit tests.

Tests the three new macOS Shield agents:
    1. MacOSInfostealerGuardAgent  (10 probes)
    2. MacOSQuarantineGuardAgent   (8 probes)
    3. MacOSProvenanceAgent        (8 probes)

Each agent is verified for:
    - Successful instantiation (dependencies mocked)
    - Correct probe count
    - Valid MITRE ATT&CK technique IDs on every probe
    - Platform "darwin" on every probe
    - Inheritance from MicroProbeAgentMixin + HardenedAgentBase
    - Callable collector class

AGENT_REGISTRY registration is also verified for all three agents.

Run:
    PYTHONPATH=src:. .venv/bin/python3 -m pytest tests/unit/agents/test_macos_shield_agents.py -v
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import MicroProbeAgentMixin

# ---------------------------------------------------------------------------
# Fixtures: mock heavy I/O dependencies so agents can be instantiated in CI
# ---------------------------------------------------------------------------

_QUEUE_ADAPTER_PATH = "amoskys.agents.common.queue_adapter.LocalQueueAdapter"
_MITRE_RE = re.compile(r"^T\d+(\.\d+)?$")


def _make_mock_queue_adapter():
    """Return a MagicMock that satisfies LocalQueueAdapter's interface."""
    mock = MagicMock()
    mock.enqueue = MagicMock()
    mock.size = MagicMock(return_value=0)
    return mock


# ---------------------------------------------------------------------------
# InfostealerGuard
# ---------------------------------------------------------------------------


class TestInfostealerGuardAgent:
    """Tests for MacOSInfostealerGuardAgent."""

    @pytest.fixture(autouse=True)
    def _agent(self):
        with patch(_QUEUE_ADAPTER_PATH, return_value=_make_mock_queue_adapter()):
            from amoskys.agents.os.macos.infostealer_guard.agent import (
                MacOSInfostealerGuardAgent,
            )

            self.agent = MacOSInfostealerGuardAgent(collection_interval=999)

    def test_instantiation(self):
        """Agent can be instantiated with mocked dependencies."""
        assert self.agent is not None
        assert self.agent.agent_name == "macos_infostealer_guard"

    def test_probe_count(self):
        """InfostealerGuard has exactly 14 probes."""
        assert len(self.agent._probes) == 14

    def test_probes_have_valid_mitre_techniques(self):
        """Every probe declares at least one valid MITRE technique ID."""
        for probe in self.agent._probes:
            assert (
                len(probe.mitre_techniques) >= 1
            ), f"Probe {probe.name} has no MITRE techniques"
            for tid in probe.mitre_techniques:
                assert _MITRE_RE.match(
                    tid
                ), f"Probe {probe.name}: invalid MITRE ID {tid!r}"

    def test_probes_target_darwin(self):
        """Every probe targets platform 'darwin'."""
        for probe in self.agent._probes:
            assert (
                "darwin" in probe.platforms
            ), f"Probe {probe.name} does not target darwin: {probe.platforms}"

    def test_inherits_mixin_and_base(self):
        """Agent inherits from both MicroProbeAgentMixin and HardenedAgentBase."""
        assert isinstance(self.agent, MicroProbeAgentMixin)
        assert isinstance(self.agent, HardenedAgentBase)

    def test_collector_class_exists_and_callable(self):
        """Collector class is importable and callable."""
        from amoskys.agents.os.macos.infostealer_guard.collector import (
            MacOSInfostealerGuardCollector,
        )

        assert callable(MacOSInfostealerGuardCollector)


# ---------------------------------------------------------------------------
# QuarantineGuard
# ---------------------------------------------------------------------------


class TestQuarantineGuardAgent:
    """Tests for MacOSQuarantineGuardAgent."""

    @pytest.fixture(autouse=True)
    def _agent(self):
        with patch(_QUEUE_ADAPTER_PATH, return_value=_make_mock_queue_adapter()):
            from amoskys.agents.os.macos.quarantine_guard.agent import (
                MacOSQuarantineGuardAgent,
            )

            self.agent = MacOSQuarantineGuardAgent(collection_interval=999)

    def test_instantiation(self):
        """Agent can be instantiated with mocked dependencies."""
        assert self.agent is not None
        assert self.agent.agent_name == "macos_quarantine_guard"

    def test_probe_count(self):
        """QuarantineGuard has exactly 8 probes."""
        assert len(self.agent._probes) == 8

    def test_probes_have_valid_mitre_techniques(self):
        """Every probe declares at least one valid MITRE technique ID."""
        for probe in self.agent._probes:
            assert (
                len(probe.mitre_techniques) >= 1
            ), f"Probe {probe.name} has no MITRE techniques"
            for tid in probe.mitre_techniques:
                assert _MITRE_RE.match(
                    tid
                ), f"Probe {probe.name}: invalid MITRE ID {tid!r}"

    def test_probes_target_darwin(self):
        """Every probe targets platform 'darwin'."""
        for probe in self.agent._probes:
            assert (
                "darwin" in probe.platforms
            ), f"Probe {probe.name} does not target darwin: {probe.platforms}"

    def test_inherits_mixin_and_base(self):
        """Agent inherits from both MicroProbeAgentMixin and HardenedAgentBase."""
        assert isinstance(self.agent, MicroProbeAgentMixin)
        assert isinstance(self.agent, HardenedAgentBase)

    def test_collector_class_exists_and_callable(self):
        """Collector class is importable and callable."""
        from amoskys.agents.os.macos.quarantine_guard.collector import (
            MacOSQuarantineGuardCollector,
        )

        assert callable(MacOSQuarantineGuardCollector)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


class TestProvenanceAgent:
    """Tests for MacOSProvenanceAgent."""

    @pytest.fixture(autouse=True)
    def _agent(self):
        with patch(_QUEUE_ADAPTER_PATH, return_value=_make_mock_queue_adapter()):
            from amoskys.agents.os.macos.provenance.agent import MacOSProvenanceAgent

            self.agent = MacOSProvenanceAgent(collection_interval=999)

    def test_instantiation(self):
        """Agent can be instantiated with mocked dependencies."""
        assert self.agent is not None
        assert self.agent.agent_name == "macos_provenance"

    def test_probe_count(self):
        """Provenance has exactly 8 probes."""
        assert len(self.agent._probes) == 8

    def test_probes_have_valid_mitre_techniques(self):
        """Every probe declares at least one valid MITRE technique ID."""
        for probe in self.agent._probes:
            assert (
                len(probe.mitre_techniques) >= 1
            ), f"Probe {probe.name} has no MITRE techniques"
            for tid in probe.mitre_techniques:
                assert _MITRE_RE.match(
                    tid
                ), f"Probe {probe.name}: invalid MITRE ID {tid!r}"

    def test_probes_target_darwin(self):
        """Every probe targets platform 'darwin'."""
        for probe in self.agent._probes:
            assert (
                "darwin" in probe.platforms
            ), f"Probe {probe.name} does not target darwin: {probe.platforms}"

    def test_inherits_mixin_and_base(self):
        """Agent inherits from both MicroProbeAgentMixin and HardenedAgentBase."""
        assert isinstance(self.agent, MicroProbeAgentMixin)
        assert isinstance(self.agent, HardenedAgentBase)

    def test_collector_class_exists_and_callable(self):
        """Collector class is importable and callable."""
        from amoskys.agents.os.macos.provenance.collector import (
            MacOSProvenanceCollector,
        )

        assert callable(MacOSProvenanceCollector)


# ---------------------------------------------------------------------------
# AGENT_REGISTRY
# ---------------------------------------------------------------------------


class TestAgentRegistration:
    """Verify all three Shield agents are registered in AGENT_REGISTRY."""

    def test_infostealer_guard_registered(self):
        """macos_infostealer_guard is in AGENT_REGISTRY."""
        from amoskys.agents import AGENT_REGISTRY

        assert "macos_infostealer_guard" in AGENT_REGISTRY

    def test_quarantine_guard_registered(self):
        """macos_quarantine_guard is in AGENT_REGISTRY."""
        from amoskys.agents import AGENT_REGISTRY

        assert "macos_quarantine_guard" in AGENT_REGISTRY

    def test_provenance_registered(self):
        """macos_provenance is in AGENT_REGISTRY."""
        from amoskys.agents import AGENT_REGISTRY

        assert "macos_provenance" in AGENT_REGISTRY
