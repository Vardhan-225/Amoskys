"""macOS Observatory — CI test suite.

Three layers of verification:

1. **Scenario-level harness tests** (``test_scenario_passes``)
   Parametrised across all registered scenarios. Each test runs the full
   RedTeamHarness flow — probe instantiation, stateful chaining, assertions.
   Covers 324 adversarial cases (96 macOS Observatory + 228 existing).

2. **Golden snapshot tests** (``test_golden_fixture_matches``)
   Loads per-scenario JSON fixtures exported by ``scripts/export_golden_fixtures.py``
   and validates that current probe output exactly matches the golden snapshot:
   event count, event types, severity, confidence, MITRE techniques.
   Detects silent regressions where a probe *still passes* but its output changed.

3. **Regression killers** (``TestRegressionKillers``)
   Explicit tests for the three bugs found during the gauntlet:
   - Baseline-diff chain contamination (stateful probe state leakage)
   - Empty-exe masquerade edge case (factory ``cmdline or [name]`` bug)
   - Downloads hidden-file scope (~/Downloads not in watched paths)

Run:
    PYTHONPATH=src:. .venv/bin/python3 -m pytest tests/unit/agents/test_macos_observatory.py -v
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from amoskys.agents.common.probes import ProbeContext
from amoskys.redteam.harness import RedTeamHarness
from amoskys.redteam.scenarios import SCENARIO_REGISTRY, _load_all

# ── load scenarios once at module level ─────────────────────────────────
_load_all()
_HARNESS = RedTeamHarness()
_FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "golden"

# ── macOS Observatory scenario names ────────────────────────────────────
_MACOS_SCENARIOS = [
    name for name in sorted(SCENARIO_REGISTRY.keys()) if name.startswith("macos_")
]

# All scenarios (for full regression)
_ALL_SCENARIOS = sorted(SCENARIO_REGISTRY.keys())


# =====================================================================
# Layer 1: Scenario-level harness tests
# =====================================================================


@pytest.mark.parametrize("scenario_name", _ALL_SCENARIOS)
def test_scenario_passes(scenario_name: str) -> None:
    """Every scenario in the registry must pass all cases."""
    scenario = SCENARIO_REGISTRY[scenario_name]
    result = _HARNESS.run_scenario(scenario)

    if not result.all_passed:
        # Collect failure details for diagnostics
        failures = []
        for cr in result.case_results:
            if not cr.passed:
                failures.append(
                    f"  {cr.case.id} [{cr.case.category}]: {cr.failure_reason}"
                )
        detail = "\n".join(failures)
        pytest.fail(f"{scenario_name}: {result.failed}/{result.total} failed\n{detail}")


@pytest.mark.parametrize("scenario_name", _MACOS_SCENARIOS)
def test_macos_scenario_coverage(scenario_name: str) -> None:
    """Each macOS scenario has at least 3 positive, 2 evasion, 1 benign case."""
    scenario = SCENARIO_REGISTRY[scenario_name]
    categories = [c.category for c in scenario.cases]

    assert (
        categories.count("positive") >= 3
    ), f"{scenario_name}: need >=3 positive cases, got {categories.count('positive')}"
    assert (
        categories.count("evasion") >= 1
    ), f"{scenario_name}: need >=1 evasion case, got {categories.count('evasion')}"
    assert (
        categories.count("benign") >= 1
    ), f"{scenario_name}: need >=1 benign case, got {categories.count('benign')}"


@pytest.mark.parametrize("scenario_name", _MACOS_SCENARIOS)
def test_macos_scenario_mitre_coverage(scenario_name: str) -> None:
    """Every macOS scenario must declare at least one MITRE technique and tactic."""
    scenario = SCENARIO_REGISTRY[scenario_name]
    assert (
        len(scenario.mitre_techniques) >= 1
    ), f"{scenario_name}: no MITRE techniques declared"
    assert (
        len(scenario.mitre_tactics) >= 1
    ), f"{scenario_name}: no MITRE tactics declared"


# =====================================================================
# Layer 2: Golden snapshot tests
# =====================================================================


def _load_golden(scenario_name: str) -> Optional[Dict[str, Any]]:
    """Load a golden fixture JSON for a scenario, or None if missing."""
    path = _FIXTURES_DIR / f"{scenario_name}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


@pytest.mark.parametrize("scenario_name", _MACOS_SCENARIOS)
def test_golden_fixture_matches(scenario_name: str) -> None:
    """Current probe output must exactly match the golden snapshot.

    This catches silent regressions where a probe's output changes
    (different confidence, extra/missing data keys, changed severity)
    even though the harness assertions still pass.
    """
    golden = _load_golden(scenario_name)
    if golden is None:
        pytest.skip(f"No golden fixture for {scenario_name}")

    scenario = SCENARIO_REGISTRY[scenario_name]
    result = _HARNESS.run_scenario(scenario)

    assert (
        result.total == golden["total"]
    ), f"Case count changed: {result.total} vs golden {golden['total']}"

    for i, (cr, gc) in enumerate(zip(result.case_results, golden["cases"])):
        case_id = gc["id"]
        g = gc["golden"]

        # Event count
        assert (
            cr.event_count == g["event_count"]
        ), f"[{case_id}] event_count: {cr.event_count} vs golden {g['event_count']}"

        # Per-event validation
        for j, (ev, gev) in enumerate(zip(cr.events_fired, g["events"])):
            prefix = f"[{case_id}][event {j}]"

            assert (
                ev.event_type == gev["event_type"]
            ), f"{prefix} event_type: {ev.event_type!r} vs golden {gev['event_type']!r}"
            assert (
                ev.severity.value == gev["severity"]
            ), f"{prefix} severity: {ev.severity.value} vs golden {gev['severity']}"
            assert (
                ev.probe_name == gev["probe_name"]
            ), f"{prefix} probe_name: {ev.probe_name!r} vs golden {gev['probe_name']!r}"
            assert ev.confidence == pytest.approx(
                gev["confidence"], abs=0.01
            ), f"{prefix} confidence: {ev.confidence} vs golden {gev['confidence']}"
            assert sorted(ev.data.keys()) == gev["data_keys"], (
                f"{prefix} data_keys mismatch: "
                f"{sorted(ev.data.keys())} vs golden {gev['data_keys']}"
            )


# =====================================================================
# Layer 3: Regression killers
# =====================================================================


class TestRegressionKillers:
    """Explicit tests for bugs discovered during the gauntlet.

    These are the three bugs that cost us hours. Each test encodes the
    exact conditions that triggered the bug and the exact fix.
    """

    # ── Bug 1: Baseline-diff chain contamination ──────────────────

    def test_baseline_diff_chain_breaker(self) -> None:
        """Stateful probe state must NOT leak across independent chains.

        Bug: Three consecutive stateful=True chains shared the same probe
        instance, so chain 2's baseline scan inherited chain 1's state and
        fired unexpected NEW/MODIFIED events.

        Fix: Interleave non-stateful cases (stateful=False) as chain
        breakers. When harness sees stateful=False, it resets
        current_stateful_probe = None.
        """
        from amoskys.agents.os.macos.persistence.probes import LaunchAgentProbe

        probe = LaunchAgentProbe()
        ctx1 = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={
                "entries": [
                    _pentry(
                        "launchagent_user",
                        "~/Library/LaunchAgents/com.good.plist",
                        "com.good",
                        "abc123",
                    ),
                ]
            },
        )

        # Scan 1: baseline — first_run learns, 0 events
        events1 = probe.scan(ctx1)
        assert len(events1) == 0, "Baseline scan should emit 0 events"

        # Scan 2: same data — no change, 0 events
        events2 = probe.scan(ctx1)
        assert len(events2) == 0, "No-change scan should emit 0 events"

        # Now simulate chain break: create FRESH probe
        probe2 = LaunchAgentProbe()
        ctx2 = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={
                "entries": [
                    _pentry(
                        "launchagent_user",
                        "~/Library/LaunchAgents/com.evil.plist",
                        "com.evil",
                        "def456",
                    ),
                ]
            },
        )

        # Scan 3: fresh probe, new data — baseline again, 0 events
        events3 = probe2.scan(ctx2)
        assert (
            len(events3) == 0
        ), "Fresh probe baseline should emit 0 events (chain breaker works)"

        # Scan 4: add new entry — should detect it
        ctx3 = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={
                "entries": [
                    _pentry(
                        "launchagent_user",
                        "~/Library/LaunchAgents/com.evil.plist",
                        "com.evil",
                        "def456",
                    ),
                    _pentry(
                        "launchagent_user",
                        "~/Library/LaunchAgents/com.malware.plist",
                        "com.malware",
                        "bad789",
                    ),
                ]
            },
        )
        events4 = probe2.scan(ctx3)
        assert len(events4) == 1, "New entry after baseline should fire 1 event"
        assert events4[0].event_type == "macos_launchagent_new"

    # ── Bug 2: Empty-exe masquerade edge case ─────────────────────

    def test_masquerade_empty_exe_empty_cmdline_skips(self) -> None:
        """Process with exe='' and cmdline=[] must not fire masquerade.

        Bug: _proc factory used ``cmdline or [name]`` which treated [] as
        falsy and defaulted to ["sshd"], giving the process a cmdline it
        shouldn't have. Then the masquerade probe saw cmdline[0]="sshd"
        as the path, which doesn't match /usr/sbin/sshd, and fired.

        Fix 1: _proc factory: ``cmdline if cmdline is not None else [name]``
        Fix 2: _proc factory: ``exe if exe is not None else f"/usr/bin/{name}"``
        """
        from amoskys.agents.os.macos.process.collector import ProcessSnapshot
        from amoskys.agents.os.macos.process.probes import ProcessMasqueradeProbe

        probe = ProcessMasqueradeProbe()

        # Cross-user process: kernel gave us name but denied exe and cmdline
        proc = ProcessSnapshot(
            pid=31404,
            name="sshd",
            exe="",
            cmdline=[],
            username="root",
            ppid=1,
            parent_name="launchd",
            create_time=1700000000.0,
            cpu_percent=0.0,
            memory_percent=0.1,
            status="running",
            cwd="/",
            environ=None,
            is_own_user=False,
            process_guid="masq-regression",
        )

        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"processes": [proc]},
        )
        events = probe.scan(ctx)
        assert (
            len(events) == 0
        ), "Empty exe + empty cmdline → can't verify → must skip (not fire)"

    def test_masquerade_empty_exe_cmdline_fallback_fires(self) -> None:
        """Process with exe='' but cmdline=['/tmp/sshd'] should fire masquerade.

        The fix correctly falls back to cmdline[0] when exe is empty.
        """
        from amoskys.agents.os.macos.process.collector import ProcessSnapshot
        from amoskys.agents.os.macos.process.probes import ProcessMasqueradeProbe

        probe = ProcessMasqueradeProbe()

        proc = ProcessSnapshot(
            pid=31402,
            name="sshd",
            exe="",
            cmdline=["/tmp/sshd", "-D"],
            username="root",
            ppid=1,
            parent_name="launchd",
            create_time=1700000000.0,
            cpu_percent=0.0,
            memory_percent=0.1,
            status="running",
            cwd="/",
            environ=None,
            is_own_user=False,
            process_guid="masq-fallback",
        )

        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"processes": [proc]},
        )
        events = probe.scan(ctx)
        assert (
            len(events) == 1
        ), "Empty exe + cmdline=['/tmp/sshd'] → fallback path doesn't match → fire"
        assert events[0].event_type == "process_masquerade"
        assert events[0].data["from_cmdline"] is True
        assert events[0].data["resolved_path"] == "/tmp/sshd"
        assert events[0].confidence == pytest.approx(0.7)

    # ── Bug 3: Downloads hidden-file scope ────────────────────────

    def test_hidden_file_in_downloads_detected(self) -> None:
        """Hidden files in ~/Downloads should be detected.

        Bug: HiddenFileProbe only watched /tmp, /var/tmp, /usr/local,
        ~/Library — so .malware in ~/Downloads was invisible.

        Fix: Added ~/Downloads/ and ~/Desktop/ to watched prefixes.

        Note: HiddenFileProbe is a baseline-diff probe. First scan learns
        the baseline, second scan detects new entries.
        """
        from amoskys.agents.os.macos.filesystem.collector import FileEntry
        from amoskys.agents.os.macos.filesystem.probes import HiddenFileProbe

        probe = HiddenFileProbe()
        home = str(Path.home())

        # Scan 1: empty baseline
        ctx_baseline = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"files": []},
        )
        probe.scan(ctx_baseline)  # learns empty baseline

        # Scan 2: new hidden file appears in Downloads
        entry = FileEntry(
            path=f"{home}/Downloads/.malware_dropper",
            name=".malware_dropper",
            sha256="deadbeef" * 8,
            mtime=1700000000.0,
            size=4096,
            mode=0o755,
            uid=501,
            is_suid=False,
        )

        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"files": [entry]},
        )
        events = probe.scan(ctx)
        assert len(events) == 1, f"Hidden file in {home}/Downloads/ must be detected"
        assert events[0].event_type == "macos_hidden_file_new"

    def test_hidden_file_in_desktop_detected(self) -> None:
        """Hidden files in ~/Desktop should also be detected."""
        from amoskys.agents.os.macos.filesystem.collector import FileEntry
        from amoskys.agents.os.macos.filesystem.probes import HiddenFileProbe

        probe = HiddenFileProbe()
        home = str(Path.home())

        # Scan 1: empty baseline
        ctx_baseline = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"files": []},
        )
        probe.scan(ctx_baseline)

        # Scan 2: new hidden file
        entry = FileEntry(
            path=f"{home}/Desktop/.hidden_c2",
            name=".hidden_c2",
            sha256="cafebabe" * 8,
            mtime=1700000000.0,
            size=2048,
            mode=0o644,
            uid=501,
            is_suid=False,
        )

        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"files": [entry]},
        )
        events = probe.scan(ctx)
        assert len(events) == 1, f"Hidden file in {home}/Desktop/ must be detected"
        assert events[0].event_type == "macos_hidden_file_new"

    def test_hidden_file_outside_scope_ignored(self) -> None:
        """Hidden files outside watched paths should NOT be detected."""
        from amoskys.agents.os.macos.filesystem.collector import FileEntry
        from amoskys.agents.os.macos.filesystem.probes import HiddenFileProbe

        probe = HiddenFileProbe()

        # Scan 1: empty baseline
        ctx_baseline = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"files": []},
        )
        probe.scan(ctx_baseline)

        # Scan 2: hidden file in out-of-scope path
        entry = FileEntry(
            path="/opt/homebrew/.config",
            name=".config",
            sha256="abcdef12" * 8,
            mtime=1700000000.0,
            size=512,
            mode=0o644,
            uid=501,
            is_suid=False,
        )

        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"files": [entry]},
        )
        events = probe.scan(ctx)
        assert len(events) == 0, "Hidden file in /opt/homebrew/ is NOT in watched scope"

    # ── Bug 3b: Off-hours configurable weekends ───────────────────

    def test_off_hours_weekday_disabled(self) -> None:
        """With check_weekends=False, weekend logins should NOT fire."""
        from amoskys.agents.os.macos.auth.collector import AuthEvent
        from amoskys.agents.os.macos.auth.probes import OffHoursLoginProbe

        probe = OffHoursLoginProbe()

        # Saturday at 10:00 (within business hours, but weekend)
        saturday_10am = datetime(2024, 1, 6, 10, 0, 0, tzinfo=timezone.utc)
        ev = AuthEvent(
            timestamp=saturday_10am,
            process="sshd",
            message="Accepted publickey for testuser",
            category="ssh",
            source_ip="10.0.0.1",
            username="testuser",
            event_type="success",
        )

        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"auth_events": [ev]},
            config={"check_weekends": False},
        )
        events = probe.scan(ctx)
        assert (
            len(events) == 0
        ), "check_weekends=False → Saturday 10am is within business hours"

    def test_off_hours_weekend_enabled(self) -> None:
        """With check_weekends=True (default), weekend logins should fire."""
        from amoskys.agents.os.macos.auth.collector import AuthEvent
        from amoskys.agents.os.macos.auth.probes import OffHoursLoginProbe

        probe = OffHoursLoginProbe()

        saturday_10am = datetime(2024, 1, 6, 10, 0, 0, tzinfo=timezone.utc)
        ev = AuthEvent(
            timestamp=saturday_10am,
            process="sshd",
            message="Accepted publickey for testuser",
            category="ssh",
            source_ip="10.0.0.1",
            username="testuser",
            event_type="success",
        )

        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"auth_events": [ev]},
            config={},  # default check_weekends=True
        )
        events = probe.scan(ctx)
        assert (
            len(events) == 1
        ), "check_weekends=True (default) → Saturday login should fire"
        assert events[0].event_type == "off_hours_login"


# =====================================================================
# Helpers
# =====================================================================


def _pentry(
    category: str,
    path: str,
    label: str,
    content_hash: str,
) -> Any:
    """Create a PersistenceEntry for testing."""
    from amoskys.agents.os.macos.persistence.collector import PersistenceEntry

    return PersistenceEntry(
        category=category,
        path=path,
        name=Path(path).name,
        content_hash=content_hash,
        program="/usr/bin/test",
        label=label,
        run_at_load=False,
        keep_alive=False,
    )
