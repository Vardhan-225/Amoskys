"""QA tests for Gap 1 (NetworkSentinel log path) and Gap 4 (InfostealerGuard process_name).

Gap 1: AccessLogCollector.log_paths must point to <project_root>/logs/amoskys_web.log,
       not <project_root>/src/logs/amoskys_web.log (off-by-one parents[] index).

Gap 4: _parse_lsof_lines must resolve full psutil name before allowlist check,
       and must treat _APPLE_PROC_PREFIX as a prefix wildcard for com.apple.* names.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Gap 1: NetworkSentinel log path ──────────────────────────────────────────


def test_access_log_collector_project_root_is_correct():
    """Auto-discovered log path must be under project root, not src/."""
    from amoskys.agents.os.macos.network_sentinel.collector import AccessLogCollector

    collector = AccessLogCollector()
    assert collector.log_paths, "log_paths must not be empty"

    for p in collector.log_paths:
        path = Path(p)
        # Must not contain src/logs — that was the off-by-one bug
        assert (
            "src/logs" not in p and "src\\logs" not in p
        ), f"Log path is under src/ — parents[6] fix not applied: {p}"
        # Parent directory must be a 'logs' folder
        assert (
            path.parent.name == "logs"
        ), f"Expected parent dir to be 'logs', got '{path.parent.name}' in: {p}"


def test_access_log_collector_path_matches_flask_log_path():
    """The auto-discovered path must match what Flask writes to."""
    from amoskys.agents.os.macos.network_sentinel.collector import AccessLogCollector

    collector = AccessLogCollector()
    sentinel_log = Path(collector.log_paths[0])

    # Flask writes to: web/app/../../../logs/amoskys_web.log → <project_root>/logs/
    flask_app_init = Path(__file__).resolve()
    # Navigate to project root: tests/unit/agents/ -> tests/unit/ -> tests/ -> project
    project_root = flask_app_init.parents[
        3
    ]  # up from tests/unit/agents/test_gap_fixes.py
    expected = project_root / "logs" / "amoskys_web.log"

    assert sentinel_log.resolve() == expected.resolve(), (
        f"NetworkSentinel reads from {sentinel_log}\n"
        f"Flask writes to           {expected}\n"
        "These must match — AccessLogCollector would read an empty file."
    )


def test_access_log_collector_custom_paths_override():
    """Explicit log_paths must bypass auto-discovery."""
    from amoskys.agents.os.macos.network_sentinel.collector import AccessLogCollector

    custom = ["/custom/path/access.log"]
    collector = AccessLogCollector(log_paths=custom)
    assert collector.log_paths == custom


# ── Gap 4: InfostealerGuard process_name resolution ──────────────────────────


MOCK_LSOF_HEADER = "COMMAND         PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"


def _make_lsof_line(command, pid, path="/Users/x/Library/Keychains/login.keychain-db"):
    """Build a minimal lsof output line."""
    return f"{command:<15} {pid}  akash  mem  REG  1,5  4096  12345 {path}\n"


def test_parse_lsof_lines_resolves_full_name_via_psutil():
    """Truncated lsof name must be replaced with full psutil name."""
    from amoskys.agents.os.macos.infostealer_guard.collector import (
        _EXPECTED_ACCESSORS,
        _parse_lsof_lines,
    )

    # lsof truncates 'com.apple.MaliciousApp' → 'com.apple'
    output = MOCK_LSOF_HEADER + _make_lsof_line("com.apple", 9999)

    mock_proc = MagicMock()
    mock_proc.name.return_value = "com.apple.MaliciousApp"

    import psutil

    with patch.object(psutil, "Process", return_value=mock_proc):
        # Use an empty expected set so nothing is filtered
        results = _parse_lsof_lines(output, "keychain", expected=set())

    assert len(results) == 1
    assert (
        results[0].process_name == "com.apple.MaliciousApp"
    ), f"Expected 'com.apple.MaliciousApp', got '{results[0].process_name}'"


def test_parse_lsof_lines_apple_prefix_filtered_when_sentinel_present():
    """com.apple.* names must be filtered when _APPLE_PROC_PREFIX is in expected."""
    from amoskys.agents.os.macos.infostealer_guard.collector import (
        _APPLE_PROC_PREFIX,
        _EXPECTED_ACCESSORS,
        _parse_lsof_lines,
    )

    # lsof truncates 'com.apple.SafariServices' → 'com.apple'
    output = MOCK_LSOF_HEADER + _make_lsof_line("com.apple", 1234)

    mock_proc = MagicMock()
    mock_proc.name.return_value = "com.apple.SafariServices"

    import psutil

    with patch.object(psutil, "Process", return_value=mock_proc):
        # Include the sentinel — should filter out all com.apple.* names
        results = _parse_lsof_lines(output, "keychain", expected={_APPLE_PROC_PREFIX})

    assert (
        len(results) == 0
    ), f"com.apple.SafariServices should be filtered by prefix sentinel, got {results}"


def test_parse_lsof_lines_apple_prefix_passes_through_when_sentinel_absent():
    """com.apple.* name must NOT be filtered if the expected set lacks the sentinel."""
    from amoskys.agents.os.macos.infostealer_guard.collector import _parse_lsof_lines

    output = MOCK_LSOF_HEADER + _make_lsof_line("com.apple", 5555)

    mock_proc = MagicMock()
    mock_proc.name.return_value = "com.apple.SomeApp"

    import psutil

    with patch.object(psutil, "Process", return_value=mock_proc):
        # Expected set has no sentinel — process should appear
        results = _parse_lsof_lines(output, "chrome_creds", expected={"Google Chrome"})

    assert len(results) == 1
    assert results[0].process_name == "com.apple.SomeApp"


def test_parse_lsof_lines_non_apple_process_always_visible():
    """Non-Apple suspicious processes must always appear regardless of sentinel."""
    from amoskys.agents.os.macos.infostealer_guard.collector import (
        _APPLE_PROC_PREFIX,
        _parse_lsof_lines,
    )

    output = MOCK_LSOF_HEADER + _make_lsof_line("malware", 7777)

    mock_proc = MagicMock()
    mock_proc.name.return_value = "malware_stealer"

    import psutil

    with patch.object(psutil, "Process", return_value=mock_proc):
        results = _parse_lsof_lines(output, "keychain", expected={_APPLE_PROC_PREFIX})

    assert len(results) == 1
    assert results[0].process_name == "malware_stealer"


def test_parse_lsof_lines_psutil_unavailable_falls_back_to_lsof_name():
    """If psutil raises, must keep the lsof-truncated name (graceful degradation)."""
    from amoskys.agents.os.macos.infostealer_guard.collector import _parse_lsof_lines

    output = MOCK_LSOF_HEADER + _make_lsof_line("truncated", 8888)

    import psutil

    with patch.object(psutil, "Process", side_effect=psutil.NoSuchProcess(8888)):
        results = _parse_lsof_lines(output, "keychain", expected=set())

    assert len(results) == 1
    assert results[0].process_name == "truncated"


def test_apple_proc_prefix_constant_value():
    """_APPLE_PROC_PREFIX must be exactly 'com.apple' — sentinel value correctness."""
    from amoskys.agents.os.macos.infostealer_guard.collector import _APPLE_PROC_PREFIX

    assert _APPLE_PROC_PREFIX == "com.apple"


def test_expected_accessors_use_constant_not_literal():
    """_EXPECTED_ACCESSORS keychain and safari sets must contain _APPLE_PROC_PREFIX."""
    from amoskys.agents.os.macos.infostealer_guard.collector import (
        _APPLE_PROC_PREFIX,
        _EXPECTED_ACCESSORS,
    )

    assert (
        _APPLE_PROC_PREFIX in _EXPECTED_ACCESSORS["keychain"]
    ), "keychain expected set must include _APPLE_PROC_PREFIX sentinel"
    assert (
        _APPLE_PROC_PREFIX in _EXPECTED_ACCESSORS["safari"]
    ), "safari expected set must include _APPLE_PROC_PREFIX sentinel"
