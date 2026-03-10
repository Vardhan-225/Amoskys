"""Tests for amoskys.observability.probe_audit — Probe audit trail.

Covers:
    - audit_probe: platform check, undeclared fields, event type checks,
      field semantics, degraded fields, REAL verdict
    - run_audit: import success, import failure
    - summarize_audit: by-verdict and by-agent summaries
    - print_table: output formatting, edge cases
    - AGENT_PROBE_MAP and COLLECTOR_EVENT_TYPES structure
"""

import io
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from amoskys.observability.probe_audit import (
    AGENT_PROBE_MAP,
    COLLECTOR_EVENT_TYPES,
    audit_probe,
    print_table,
    run_audit,
    summarize_audit,
)

# ---------------------------------------------------------------------------
# Helper: create probe-like objects
# ---------------------------------------------------------------------------


def _make_probe(
    name="test_probe",
    platforms=None,
    requires_fields=None,
    requires_event_types=None,
    field_semantics=None,
    degraded_without=None,
):
    """Create a probe-like SimpleNamespace for testing."""
    probe = SimpleNamespace()
    probe.name = name
    if platforms is not None:
        probe.platforms = platforms
    if requires_fields is not None:
        probe.requires_fields = requires_fields
    if requires_event_types is not None:
        probe.requires_event_types = requires_event_types
    if field_semantics is not None:
        probe.field_semantics = field_semantics
    if degraded_without is not None:
        probe.degraded_without = degraded_without
    return probe


# ---------------------------------------------------------------------------
# AGENT_PROBE_MAP structure
# ---------------------------------------------------------------------------


class TestAgentProbeMap:

    def test_all_entries_have_module_and_factory(self):
        for agent_name, info in AGENT_PROBE_MAP.items():
            assert "module" in info, f"{agent_name} missing 'module'"
            assert "factory" in info, f"{agent_name} missing 'factory'"

    def test_known_agents_present(self):
        expected = {"proc", "fim", "flow", "dns", "peripheral", "auth", "persistence"}
        assert expected.issubset(set(AGENT_PROBE_MAP.keys()))


class TestCollectorEventTypes:

    def test_auth_event_types(self):
        assert "SSH_LOGIN_SUCCESS" in COLLECTOR_EVENT_TYPES["auth"]
        assert "SUDO_COMMAND" in COLLECTOR_EVENT_TYPES["auth"]

    def test_persistence_event_types(self):
        assert "USER_LAUNCH_AGENT" in COLLECTOR_EVENT_TYPES["persistence"]
        assert "CRON_USER" in COLLECTOR_EVENT_TYPES["persistence"]


# ---------------------------------------------------------------------------
# audit_probe
# ---------------------------------------------------------------------------


class TestAuditProbe:

    def test_real_verdict_with_full_contract(self):
        probe = _make_probe(
            name="proc_tree",
            platforms=["darwin", "linux"],
            requires_fields=["pid", "ppid", "name"],
            requires_event_types=[],
            field_semantics={"pid": "Process ID"},
        )
        result = audit_probe(probe, "proc", "darwin")
        assert result["verdict"] == "REAL"
        assert result["probe"] == "proc_tree"
        assert result["agent"] == "proc"
        assert result["issues"] == []

    def test_disabled_verdict_on_unsupported_platform(self):
        probe = _make_probe(
            name="linux_only",
            platforms=["linux"],
            requires_fields=["field1"],
        )
        result = audit_probe(probe, "proc", "darwin")
        assert result["verdict"] == "DISABLED"
        assert any("darwin" in i for i in result["issues"])

    def test_undeclared_verdict_when_no_requires_fields(self):
        """When requires_fields attribute is missing (None), verdict is UNDECLARED."""
        probe = SimpleNamespace(name="bare_probe")
        # Do not set requires_fields at all
        result = audit_probe(probe, "proc", "darwin")
        assert result["verdict"] == "UNDECLARED"
        assert any("requires_fields" in i.lower() for i in result["issues"])

    def test_broken_verdict_on_missing_event_type(self):
        probe = _make_probe(
            name="auth_probe",
            platforms=["darwin"],
            requires_fields=["user"],
            requires_event_types=["NONEXISTENT_EVENT"],
            field_semantics={"user": "username"},
        )
        result = audit_probe(probe, "auth", "darwin")
        assert result["verdict"] == "BROKEN"
        assert any("NONEXISTENT_EVENT" in i for i in result["issues"])

    def test_event_type_check_skipped_when_no_collector_events(self):
        """When the agent has no known collector events, event type check is skipped."""
        probe = _make_probe(
            name="flow_probe",
            platforms=["darwin"],
            requires_fields=["src_ip"],
            requires_event_types=["SOME_EVENT"],
            field_semantics={"src_ip": "Source IP"},
        )
        result = audit_probe(probe, "flow", "darwin")
        # flow is not in COLLECTOR_EVENT_TYPES, so set is empty, check skipped
        assert result["verdict"] == "REAL"

    def test_missing_field_semantics_warning(self):
        probe = _make_probe(
            name="undoc_probe",
            platforms=["darwin"],
            requires_fields=["field1"],
            requires_event_types=[],
            field_semantics={},  # empty
        )
        result = audit_probe(probe, "proc", "darwin")
        assert any("field_semantics" in i.lower() for i in result["issues"])

    def test_degraded_verdict(self):
        probe = _make_probe(
            name="degraded_probe",
            platforms=["darwin"],
            requires_fields=["field1"],
            requires_event_types=[],
            field_semantics={"field1": "desc"},
            degraded_without=["field2", "field3"],
        )
        result = audit_probe(probe, "proc", "darwin")
        assert result["verdict"] == "DEGRADED"
        assert any("field2" in i for i in result["issues"])

    def test_empty_platform_string_skips_platform_check(self):
        """When target_platform is empty string, platform check is skipped."""
        probe = _make_probe(
            name="any_platform",
            platforms=["windows"],
            requires_fields=["field1"],
            requires_event_types=[],
            field_semantics={"field1": "desc"},
        )
        result = audit_probe(probe, "proc", "")
        assert result["verdict"] == "REAL"

    def test_default_platforms_when_not_set(self):
        """When probe has no platforms attribute, defaults to all three."""
        probe = SimpleNamespace(name="default_plat")
        probe.requires_fields = ["a"]
        probe.requires_event_types = []
        probe.field_semantics = {"a": "desc"}
        result = audit_probe(probe, "proc", "darwin")
        assert result["platforms"] == ["linux", "darwin", "windows"]
        assert result["verdict"] == "REAL"

    def test_broken_verdict_does_not_become_degraded(self):
        """If verdict is already BROKEN, degraded_without should not change it."""
        probe = _make_probe(
            name="broken_and_degraded",
            platforms=["darwin"],
            requires_fields=["field1"],
            requires_event_types=["NONEXISTENT_EVENT"],
            field_semantics={"field1": "desc"},
            degraded_without=["field2"],
        )
        result = audit_probe(probe, "auth", "darwin")
        # BROKEN takes precedence due to event type check
        assert result["verdict"] == "BROKEN"


# ---------------------------------------------------------------------------
# run_audit
# ---------------------------------------------------------------------------


class TestRunAudit:

    def test_run_audit_with_mocked_agents(self):
        """Mock the imports to test run_audit without real agent modules."""
        fake_probe = _make_probe(
            name="mock_probe",
            platforms=["darwin"],
            requires_fields=["field1"],
            requires_event_types=[],
            field_semantics={"field1": "desc"},
        )
        mock_mod = MagicMock()
        mock_mod.create_proc_probes.return_value = [fake_probe]

        single_map = {
            "proc": {
                "module": "amoskys.agents.shared.process.probes",
                "factory": "create_proc_probes",
            }
        }
        with patch(
            "amoskys.observability.probe_audit.importlib.import_module"
        ) as mock_import:
            mock_import.return_value = mock_mod
            with patch.dict(AGENT_PROBE_MAP, single_map, clear=True):
                results = run_audit("darwin")

        assert len(results) == 1
        assert results[0]["probe"] == "mock_probe"
        assert results[0]["verdict"] == "REAL"

    def test_run_audit_handles_import_error(self):
        single_map = {"broken": {"module": "fakemod", "factory": "create_probes"}}
        with patch(
            "amoskys.observability.probe_audit.importlib.import_module"
        ) as mock_import:
            mock_import.side_effect = ImportError("No module named 'fakemod'")
            with patch.dict(AGENT_PROBE_MAP, single_map, clear=True):
                results = run_audit("darwin")

        assert len(results) == 1
        assert results[0]["verdict"] == "ERROR"
        assert results[0]["agent"] == "broken"

    def test_run_audit_handles_factory_error(self):
        mock_mod = MagicMock()
        # getattr(mock_mod, "create_probes") returns a MagicMock auto-attr;
        # set the side_effect on that auto-attr
        mock_mod.create_probes.side_effect = RuntimeError("factory exploded")

        single_map = {"broken": {"module": "mod", "factory": "create_probes"}}
        with patch(
            "amoskys.observability.probe_audit.importlib.import_module"
        ) as mock_import:
            mock_import.return_value = mock_mod
            with patch.dict(AGENT_PROBE_MAP, single_map, clear=True):
                results = run_audit("darwin")

        assert len(results) == 1
        assert results[0]["verdict"] == "ERROR"

    def test_run_audit_empty_platform(self):
        """Run audit with no platform filter."""
        fake_probe = _make_probe(
            name="any_probe",
            platforms=["darwin"],
            requires_fields=["f"],
            requires_event_types=[],
            field_semantics={"f": "x"},
        )
        mock_mod = MagicMock()
        mock_mod.create_probes.return_value = [fake_probe]

        single_map = {"test": {"module": "mod", "factory": "create_probes"}}
        with patch(
            "amoskys.observability.probe_audit.importlib.import_module"
        ) as mock_import:
            mock_import.return_value = mock_mod
            with patch.dict(AGENT_PROBE_MAP, single_map, clear=True):
                results = run_audit("")

        assert len(results) == 1
        assert results[0]["verdict"] == "REAL"

    def test_run_audit_multiple_probes_per_agent(self):
        probes = [
            _make_probe(
                name=f"probe_{i}",
                platforms=["darwin"],
                requires_fields=["f"],
                requires_event_types=[],
                field_semantics={"f": "x"},
            )
            for i in range(3)
        ]
        mock_mod = MagicMock()
        mock_mod.create_probes.return_value = probes

        single_map = {"test": {"module": "mod", "factory": "create_probes"}}
        with patch(
            "amoskys.observability.probe_audit.importlib.import_module"
        ) as mock_import:
            mock_import.return_value = mock_mod
            with patch.dict(AGENT_PROBE_MAP, single_map, clear=True):
                results = run_audit("darwin")

        assert len(results) == 3


# ---------------------------------------------------------------------------
# summarize_audit
# ---------------------------------------------------------------------------


class TestSummarizeAudit:

    def test_empty_results(self):
        summary = summarize_audit([])
        assert summary["total"] == 0
        assert summary["real"] == 0
        assert summary["broken"] == 0

    def test_counts_by_verdict(self):
        results = [
            {"probe": "p1", "agent": "a1", "verdict": "REAL"},
            {"probe": "p2", "agent": "a1", "verdict": "REAL"},
            {"probe": "p3", "agent": "a2", "verdict": "BROKEN"},
            {"probe": "p4", "agent": "a2", "verdict": "DEGRADED"},
            {"probe": "p5", "agent": "a3", "verdict": "DISABLED"},
            {"probe": "p6", "agent": "a3", "verdict": "ERROR"},
        ]
        summary = summarize_audit(results)
        assert summary["total"] == 6
        assert summary["real"] == 2
        assert summary["broken"] == 1
        assert summary["degraded"] == 1
        assert summary["disabled"] == 1
        assert summary["error"] == 1

    def test_by_agent_breakdown(self):
        results = [
            {"probe": "p1", "agent": "proc", "verdict": "REAL"},
            {"probe": "p2", "agent": "proc", "verdict": "DEGRADED"},
            {"probe": "p3", "agent": "fim", "verdict": "BROKEN"},
        ]
        summary = summarize_audit(results)
        assert summary["by_agent"]["proc"]["total"] == 2
        assert summary["by_agent"]["proc"]["REAL"] == 1
        assert summary["by_agent"]["proc"]["DEGRADED"] == 1
        assert summary["by_agent"]["fim"]["BROKEN"] == 1

    def test_unknown_agent_handled(self):
        results = [{"probe": "p1", "verdict": "REAL"}]
        summary = summarize_audit(results)
        assert "unknown" in summary["by_agent"]

    def test_unknown_verdict_counted_in_total(self):
        results = [
            {"probe": "p1", "agent": "a", "verdict": "UNDECLARED"},
        ]
        summary = summarize_audit(results)
        assert summary["total"] == 1
        # UNDECLARED is not one of the standard summary keys
        assert summary["real"] == 0


# ---------------------------------------------------------------------------
# print_table
# ---------------------------------------------------------------------------


class TestPrintTable:

    def test_prints_output(self, capsys):
        results = [
            {"probe": "p1", "agent": "proc", "verdict": "REAL", "issues": []},
            {
                "probe": "p2",
                "agent": "fim",
                "verdict": "BROKEN",
                "issues": ["missing event"],
            },
        ]
        print_table(results)
        captured = capsys.readouterr()
        assert "AMOSKYS" in captured.out
        assert "REAL" in captured.out
        assert "BROKEN" in captured.out
        assert "missing event" in captured.out

    def test_empty_results(self, capsys):
        print_table([])
        captured = capsys.readouterr()
        assert "TOTAL: 0" in captured.out

    def test_all_verdicts(self, capsys):
        results = [
            {"probe": f"p_{v.lower()}", "agent": "test", "verdict": v, "issues": []}
            for v in ["REAL", "DEGRADED", "BROKEN", "DISABLED", "UNDECLARED", "ERROR"]
        ]
        print_table(results)
        captured = capsys.readouterr()
        for v in ["REAL", "DEGRADED", "BROKEN", "DISABLED", "UNDECLARED", "ERROR"]:
            assert v in captured.out

    def test_active_percentage(self, capsys):
        results = [
            {"probe": "p1", "agent": "a", "verdict": "REAL", "issues": []},
            {"probe": "p2", "agent": "a", "verdict": "DEGRADED", "issues": []},
            {"probe": "p3", "agent": "a", "verdict": "BROKEN", "issues": []},
            {"probe": "p4", "agent": "a", "verdict": "DISABLED", "issues": []},
        ]
        print_table(results)
        captured = capsys.readouterr()
        # Active = REAL + DEGRADED = 2 out of 4 = 50.0%
        assert "50.0%" in captured.out

    def test_issues_displayed_with_dash(self, capsys):
        results = [
            {
                "probe": "p1",
                "agent": "proc",
                "verdict": "BROKEN",
                "issues": ["event type missing"],
            },
        ]
        print_table(results)
        captured = capsys.readouterr()
        assert "event type missing" in captured.out
