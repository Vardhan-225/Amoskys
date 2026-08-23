"""A thread that is alive but not progressing must be reported.

The collector's health check tested thread.is_alive(). A thread wedged inside
_run_one_cycle is alive, so it passed — while emitting neither results nor
errors, because the loop only logs when a cycle RETURNS or RAISES.

Observed: macos_filesystem started cleanly (setup complete, 10 probes,
interval=60s) and then logged nothing for three hours, ~180 missed cycles,
while macos_peripheral — same base class, same loop, started in the same
second — cycled every 60s throughout. No error was raised and none was logged,
because none happened. Absence of output was indistinguishable from a sensor
with nothing to say.
"""

import logging
import time

from amoskys.collector_main import _report_stalled_agents


class _FakeAgentThread:
    def __init__(self, name, interval, start, end, status="running", cycles=5):
        self.agent_name = name
        self.interval = interval
        self.last_cycle_start = start
        self.last_cycle_end = end
        self.status = status
        self.cycle_count = cycles


def test_agent_stuck_mid_cycle_is_reported():
    now = time.time()
    stuck = _FakeAgentThread("macos_filesystem", 60, start=now - 3600, end=now - 3660)
    assert _report_stalled_agents([stuck], logging.getLogger("t")) == ["macos_filesystem"]


def test_healthy_agent_is_not_reported():
    """last_cycle_end after last_cycle_start means the cycle returned."""
    now = time.time()
    ok = _FakeAgentThread("macos_peripheral", 60, start=now - 30, end=now - 29)
    assert _report_stalled_agents([ok], logging.getLogger("t")) == []


def test_a_merely_slow_cycle_does_not_cry_wolf():
    """Threshold is 5 intervals, so a slow cycle or a burst of lock contention
    is tolerated. A detector that fires on normal variance gets muted, and then
    the real stall is missed."""
    now = time.time()
    slow = _FakeAgentThread("macos_dns", 60, start=now - 120, end=now - 180)
    assert _report_stalled_agents([slow], logging.getLogger("t")) == []


def test_short_interval_agents_get_a_floor():
    """realtime_sensor runs at 2s; 5 intervals is 10s, which normal jitter can
    exceed. The floor keeps a fast agent from being declared stalled on noise."""
    now = time.time()
    fast = _FakeAgentThread("realtime_sensor", 2, start=now - 30, end=now - 40)
    assert _report_stalled_agents([fast], logging.getLogger("t")) == []
    really = _FakeAgentThread("realtime_sensor", 2, start=now - 300, end=now - 400)
    assert _report_stalled_agents([really], logging.getLogger("t")) == ["realtime_sensor"]


def test_agents_that_never_started_are_not_stall_reported():
    now = time.time()
    never = _FakeAgentThread("x", 60, start=0.0, end=0.0, status="setup_failed")
    assert _report_stalled_agents([never], logging.getLogger("t")) == []


def test_the_error_names_the_agent_and_the_duration(caplog):
    now = time.time()
    stuck = _FakeAgentThread("macos_filesystem", 60, start=now - 3600, end=now - 3660)
    lg = logging.getLogger("stall-test")
    records = []

    class _H(logging.Handler):
        def emit(self, r):
            records.append(r.getMessage())

    lg.addHandler(_H())
    lg.setLevel(logging.ERROR)
    _report_stalled_agents([stuck], lg)
    text = "\n".join(records)
    assert "AGENT STALLED" in text and "macos_filesystem" in text
    assert "neither results nor errors" in text
