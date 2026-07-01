"""Causal kill-chain probe tests (detection roadmap increment 2).

The rewritten FullKillChainProbe must:
  * NEVER fire on benign co-occurrence (the old base-rate-fallacy FP)
  * fire on a genuine ordered download→execute→act chain by ONE actor
  * respect chronological order (exec before download = no chain)
  * require a same-pid action (no network/credential = no alert yet)
"""

from __future__ import annotations

import time

import pytest

from amoskys.agents.common.probes import ProbeContext
from amoskys.agents.os.macos.provenance.collector import NewProcess, TimelineEvent
from amoskys.agents.os.macos.provenance.probes import FullKillChainProbe


def _ctx(timeline, new_processes=None, pid_connections=None) -> ProbeContext:
    return ProbeContext(
        device_id="test-device",
        agent_name="test",
        shared_data={
            "timeline": timeline,
            "new_processes": new_processes or [],
            "pid_connections": pid_connections or {},
        },
    )


def _download(ts: float, path: str) -> TimelineEvent:
    name = path.rsplit("/", 1)[-1]
    return TimelineEvent(
        timestamp=ts,
        event_type="file_created",
        pid=0,
        app_name="Downloads",
        detail=f"file={name} size=1337 path={path}",
    )


def _spawn(ts: float, pid: int, exe: str, name: str = "proc") -> TimelineEvent:
    return TimelineEvent(
        timestamp=ts,
        event_type="process_spawned",
        pid=pid,
        app_name=name,
        detail=f"exe={exe} ppid=1 parent=launchd",
    )


def _app(ts: float, category: str, app: str) -> TimelineEvent:
    return TimelineEvent(
        timestamp=ts,
        event_type="app_active",
        pid=0,
        app_name=app,
        detail=f"category={category} app={app}",
    )


def _proc(pid: int, exe: str, create_time: float, cmdline=None) -> NewProcess:
    return NewProcess(
        pid=pid,
        name=exe.rsplit("/", 1)[-1],
        exe=exe,
        cmdline=cmdline or [exe],
        ppid=1,
        parent_name="launchd",
        create_time=create_time,
    )


class TestBenignCoOccurrenceNeverFires:
    """The old probe fired on ANY messaging+browser+download+spawn+connect
    co-occurring in 300s — the steady state of a developer machine."""

    def test_dev_machine_steady_state_no_alert(self):
        probe = FullKillChainProbe()
        now = time.time()
        timeline = [
            _app(now - 200, "messaging", "Slack"),
            _app(now - 200, "browser", "Safari"),
            _download(now - 150, "/Users/dev/Downloads/report.pdf"),
            # unrelated process (an IDE helper), NOT the downloaded file
            _spawn(now - 100, 4242, "/Applications/VSCode.app/Contents/MacOS/code"),
        ]
        procs = [_proc(4242, "/Applications/VSCode.app/Contents/MacOS/code", now - 100)]
        # the unrelated process talks to the network (normal)
        conns = {4242: ["1.2.3.4:443"]}
        events = probe.scan(_ctx(timeline, procs, conns))
        assert events == [], "benign co-occurrence must NOT assert a kill chain"

    def test_download_without_execution_no_alert(self):
        probe = FullKillChainProbe()
        now = time.time()
        timeline = [_download(now - 60, "/Users/dev/Downloads/x.bin")]
        events = probe.scan(_ctx(timeline))
        assert events == []


class TestCausalChainFires:
    def test_download_execute_network_chain_alerts(self):
        probe = FullKillChainProbe()
        now = time.time()
        payload = "/Users/dev/Downloads/invoice.app"
        timeline = [
            _app(now - 250, "browser", "Safari"),
            _download(now - 200, payload),
            _spawn(now - 100, 6666, payload, name="invoice"),
        ]
        procs = [_proc(6666, payload, now - 100)]
        conns = {6666: ["185.220.101.7:443"]}
        events = probe.scan(_ctx(timeline, procs, conns))
        assert len(events) == 1, "ordered same-actor chain must alert"
        data = events[0].data
        assert data["causally_linked"] is True
        assert data["ordered"] is True
        assert data["chain"]["download"]["path"] == payload
        assert data["chain"]["execute"]["pid"] == 6666
        assert data["chain"]["network_egress"] == ["185.220.101.7:443"]
        assert "browser" in data["delivery_context"]

    def test_chain_dedupes_within_window(self):
        probe = FullKillChainProbe()
        now = time.time()
        payload = "/Users/dev/Downloads/x.bin"
        timeline = [_download(now - 200, payload), _spawn(now - 100, 7777, payload)]
        procs = [_proc(7777, payload, now - 100)]
        conns = {7777: ["9.9.9.9:8443"]}
        assert len(probe.scan(_ctx(timeline, procs, conns))) == 1
        # Second scan of the same window: no duplicate alert
        assert probe.scan(_ctx([], [], conns)) == []


class TestOrderAndActorRequired:
    def test_execution_before_download_no_alert(self):
        """The exe path matching a LATER download is not a chain."""
        probe = FullKillChainProbe()
        now = time.time()
        payload = "/Users/dev/Downloads/tool.bin"
        timeline = [
            _spawn(now - 200, 8888, payload),  # runs FIRST
            _download(now - 100, payload),  # file appears AFTER
        ]
        procs = [_proc(8888, payload, now - 200)]
        conns = {8888: ["8.8.8.8:53"]}
        assert probe.scan(_ctx(timeline, procs, conns)) == []

    def test_executed_download_with_no_action_no_alert(self):
        """Downloaded file runs but never acts (no net, no creds) — watch, don't cry."""
        probe = FullKillChainProbe()
        now = time.time()
        payload = "/Users/dev/Downloads/installer.pkg"
        timeline = [_download(now - 200, payload), _spawn(now - 100, 9999, payload)]
        procs = [_proc(9999, payload, now - 100)]
        assert probe.scan(_ctx(timeline, procs, {})) == []

    def test_network_by_different_pid_no_alert(self):
        """Egress by an UNRELATED process must not complete someone else's chain."""
        probe = FullKillChainProbe()
        now = time.time()
        payload = "/Users/dev/Downloads/thing.bin"
        timeline = [_download(now - 200, payload), _spawn(now - 100, 1111, payload)]
        procs = [_proc(1111, payload, now - 100)]
        conns = {2222: ["6.6.6.6:1337"]}  # different actor
        assert probe.scan(_ctx(timeline, procs, conns)) == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
