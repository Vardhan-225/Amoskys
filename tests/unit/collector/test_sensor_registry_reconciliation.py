"""The sensor registry must detect agents that were never wired in.

The original reconciliation compared REQUESTED against LOADED, and announced
"All 18 registered sensors loaded — no blind spots" while three agent packages
sat on disk connected to nothing. Two of them were file integrity monitoring
and USB device monitoring, and both had produced zero events in the lifetime of
the database.

A subtraction can only find what someone remembered to put in the minuend. The
blind-spot detector had the exact flaw it was written to catch, one level up.
"""

import os

import pytest

AGENTS_DIR = "src/amoskys/agents/os/macos"


def _packages_on_disk():
    return {
        d for d in os.listdir(AGENTS_DIR)
        if os.path.isdir(os.path.join(AGENTS_DIR, d))
        and not d.startswith("__")
        and os.path.exists(os.path.join(AGENTS_DIR, d, "agent.py"))
    }


def _requested_packages():
    import re
    src = open("src/amoskys/collector_main.py").read()
    return {
        m.split(".")[-2]
        for m in re.findall(r'_try_load\(\s*"([^"]+)"', src)
        if "." in m
    }


def test_every_agent_package_is_either_wired_or_explicitly_excluded():
    """Fails the moment someone adds an agent and forgets to register it.

    `esf` is the one legitimate exclusion: it is fed by the Sentinel's exec
    stream and collected by its own tailer, not polled on an interval. Any
    other unwired package is dead code that reads as coverage.
    """
    EXPLICIT_EXCLUSIONS = {"esf"}
    unwired = _packages_on_disk() - _requested_packages() - EXPLICIT_EXCLUSIONS
    assert not unwired, (
        f"agent package(s) exist but are never requested: {sorted(unwired)}. "
        "Either wire them into collector_main._load_agents or delete them — "
        "unreachable sensor code reads as coverage it does not provide."
    )


def test_reconciliation_compares_packages_not_registered_names():
    """Registered names legitimately differ from package names.

    network -> "flow" and process -> "proc". Comparing registered names against
    directory names would report both as unwired forever, and a warning that
    is always wrong trains the operator to ignore it — which is how the real
    one would then be missed.
    """
    req = _requested_packages()
    assert "network" in req and "process" in req, (
        "reconciliation must resolve aliases via module path, not display name"
    )


def test_load_agents_emits_the_unwired_check(caplog):
    """The check must actually run, not merely exist."""
    import logging
    import platform

    if platform.system() != "Darwin":
        pytest.skip("collector agents are macOS-only")

    from amoskys.collector_main import _load_agents

    # caplog does not see this logger (its records do not propagate to the
    # root handler pytest installs), so attach a handler directly rather than
    # asserting on an empty string and concluding the check never ran.
    records = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    lg = logging.getLogger("amoskys.collector")
    h = _Capture()
    lg.addHandler(h)
    old_level = lg.level
    lg.setLevel(logging.INFO)
    try:
        _load_agents()
    finally:
        lg.removeHandler(h)
        lg.setLevel(old_level)

    text = "\n".join(records)
    assert ("UNWIRED AGENTS" in text or "Sensor registry complete" in text), (
        f"the on-disk reconciliation produced no verdict at all; saw: {text[:200]}"
    )
