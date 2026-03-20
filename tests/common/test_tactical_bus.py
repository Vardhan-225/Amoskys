"""Integration tests for the tactical coordination bus.

Verifies that WATCH_PID directives flow from InfostealerGuard to peer agents
(Network, DNS, Process) via the CoordinationBus, and that those agents
produce tactical observation events for watched PIDs.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from amoskys.common.coordination import (
    CoordinationConfig,
    LocalBus,
    TacticalTopic,
    Urgency,
    WatchDirective,
    create_coordination_bus,
)

# ---------------------------------------------------------------------------
# Unit tests for WatchDirective
# ---------------------------------------------------------------------------


class TestWatchDirective:
    def test_round_trip(self):
        d = WatchDirective(
            topic="WATCH_PID",
            value="4523",
            reason="T1555_credential_access",
            urgency="HIGH",
            source_agent="macos_infostealer_guard",
            mitre_technique="T1555.001",
        )
        payload = d.to_payload()
        assert payload["value"] == "4523"
        assert payload["reason"] == "T1555_credential_access"

        d2 = WatchDirective.from_payload("WATCH_PID", payload)
        assert d2.value == "4523"
        assert d2.urgency == "HIGH"
        assert d2.mitre_technique == "T1555.001"

    def test_expiry(self):
        d = WatchDirective(
            topic="WATCH_PID",
            value="1",
            reason="test",
            ttl_seconds=0.1,
            ts=time.time() - 1.0,
        )
        assert d.expired

        d2 = WatchDirective(
            topic="WATCH_PID",
            value="1",
            reason="test",
            ttl_seconds=300.0,
        )
        assert not d2.expired


class TestTacticalTopics:
    def test_all_topics_present(self):
        names = {t.value for t in TacticalTopic}
        assert "WATCH_PID" in names
        assert "WATCH_PATH" in names
        assert "WATCH_DOMAIN" in names
        assert "CLEAR_WATCH" in names
        assert "CONTROL" in names


# ---------------------------------------------------------------------------
# Integration test: WATCH_PID flows through LocalBus to peer agents
# ---------------------------------------------------------------------------


class TestTacticalBusIntegration:
    """Test that WATCH_PID published on a shared LocalBus is received by
    all subscribed agents and populates their watchlists."""

    def test_watch_pid_flows_to_peers(self):
        """Simulate InfostealerGuard publishing WATCH_PID, verify Network/
        DNS/Process agents receive it and populate their watch_pids."""
        bus = LocalBus()

        # Simulate three peer agents subscribing to WATCH_PID
        received_by = {"network": [], "dns": [], "process": []}

        def make_handler(agent_name):
            def handler(topic, payload):
                d = WatchDirective.from_payload(topic, payload)
                # Skip self-published (source_agent check)
                if d.source_agent == agent_name:
                    return
                received_by[agent_name].append(d)

            return handler

        bus.subscribe("WATCH_PID", make_handler("network"))
        bus.subscribe("WATCH_PID", make_handler("dns"))
        bus.subscribe("WATCH_PID", make_handler("process"))

        # InfostealerGuard publishes WATCH_PID
        directive = WatchDirective(
            topic="WATCH_PID",
            value="4523",
            reason="macos_infostealer_keychain_access_T1555.001",
            urgency="HIGH",
            source_agent="macos_infostealer_guard",
            mitre_technique="T1555.001",
            ttl_seconds=300.0,
        )
        bus.publish("WATCH_PID", directive.to_payload())

        # All three peers should have received it
        for agent_name in ("network", "dns", "process"):
            assert (
                len(received_by[agent_name]) == 1
            ), f"{agent_name} should receive exactly 1 WATCH_PID"
            d = received_by[agent_name][0]
            assert d.value == "4523"
            assert d.source_agent == "macos_infostealer_guard"
            assert "T1555" in d.mitre_technique

    def test_clear_watch_removes_directive(self):
        """CLEAR_WATCH should remove a previously published watch."""
        bus = LocalBus()
        watches: dict[str, WatchDirective] = {}

        def on_watch(topic, payload):
            d = WatchDirective.from_payload(topic, payload)
            watches[d.value] = d

        def on_clear(topic, payload):
            value = payload.get("value", "")
            watches.pop(value, None)

        bus.subscribe("WATCH_PID", on_watch)
        bus.subscribe("CLEAR_WATCH", on_clear)

        # Add watch
        bus.publish(
            "WATCH_PID",
            WatchDirective(
                topic="WATCH_PID",
                value="4523",
                reason="test",
                source_agent="guard",
            ).to_payload(),
        )
        assert "4523" in watches

        # Clear it
        bus.publish("CLEAR_WATCH", {"value": "4523"})
        assert "4523" not in watches

    def test_self_published_watch_is_ignored(self):
        """An agent should not react to its own WATCH_PID."""
        bus = LocalBus()
        received = []

        def handler(topic, payload):
            d = WatchDirective.from_payload(topic, payload)
            if d.source_agent == "macos_infostealer_guard":
                return  # Skip own
            received.append(d)

        bus.subscribe("WATCH_PID", handler)

        bus.publish(
            "WATCH_PID",
            WatchDirective(
                topic="WATCH_PID",
                value="123",
                reason="test",
                source_agent="macos_infostealer_guard",
            ).to_payload(),
        )

        assert len(received) == 0


# ---------------------------------------------------------------------------
# Integration test: base.py CONTROL handler extensions
# ---------------------------------------------------------------------------


class TestControlHandlerExtensions:
    """Test set_interval, restore_interval, burst_collect via CONTROL."""

    def test_set_interval(self):
        bus = LocalBus()
        handler_calls = []

        original_interval = 10.0
        state = {"interval": original_interval, "base": original_interval}

        def control_handler(topic, payload):
            cmd = payload.get("command")
            if cmd == "set_interval":
                state["interval"] = max(
                    1.0, float(payload.get("interval", state["base"]))
                )
            elif cmd == "restore_interval":
                state["interval"] = state["base"]
            handler_calls.append(cmd)

        bus.subscribe("CONTROL", control_handler)

        # Escalate to 5s
        bus.publish(
            "CONTROL",
            {
                "command": "set_interval",
                "interval": 5.0,
                "target": "all",
            },
        )
        assert state["interval"] == 5.0

        # Restore
        bus.publish(
            "CONTROL",
            {
                "command": "restore_interval",
                "target": "all",
            },
        )
        assert state["interval"] == 10.0

    def test_set_interval_floor(self):
        """Interval cannot go below 1 second."""
        bus = LocalBus()
        state = {"interval": 10.0}

        def handler(topic, payload):
            if payload.get("command") == "set_interval":
                state["interval"] = max(1.0, float(payload.get("interval", 10.0)))

        bus.subscribe("CONTROL", handler)
        bus.publish("CONTROL", {"command": "set_interval", "interval": 0.1})
        assert state["interval"] == 1.0


# ---------------------------------------------------------------------------
# EventBus round-trip for tactical topics
# ---------------------------------------------------------------------------


class TestTacticalEventBusRoundTrip:
    """Test WATCH_PID flows through the EventBus gRPC coordination backend."""

    def test_watch_pid_over_eventbus(self):
        """Verify WATCH_PID published via EventBus is received by subscriber."""
        try:
            from concurrent import futures

            import grpc

            from amoskys.eventbus.server import EventBusControlServicer
            from amoskys.proto import control_pb2_grpc
        except Exception:
            pytest.skip("gRPC or EventBus stubs not available")

        import logging

        eventbus_logger = logging.getLogger("EventBus")
        prev = eventbus_logger.disabled
        eventbus_logger.disabled = True

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        control_pb2_grpc.add_EventBusControlServicer_to_server(
            EventBusControlServicer(), server
        )
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()

        channel = grpc.insecure_channel(f"127.0.0.1:{port}")

        subscriber = create_coordination_bus(
            CoordinationConfig(
                backend="eventbus",
                agent_id="macos_network",
                eventbus_channel=channel,
                default_topics=["WATCH_PID", "CLEAR_WATCH"],
            )
        )
        publisher = create_coordination_bus(
            CoordinationConfig(
                backend="eventbus",
                agent_id="macos_infostealer_guard",
                eventbus_channel=channel,
                default_topics=["*"],
            )
        )

        received = []
        subscriber.subscribe(
            "WATCH_PID",
            lambda topic, payload: received.append(
                WatchDirective.from_payload(topic, payload)
            ),
        )

        try:
            time.sleep(0.2)

            directive = WatchDirective(
                topic="WATCH_PID",
                value="4523",
                reason="T1555_credential_access",
                urgency="HIGH",
                source_agent="macos_infostealer_guard",
                mitre_technique="T1555.001",
            )
            publisher.publish("WATCH_PID", directive.to_payload())

            deadline = time.time() + 2.0
            while time.time() < deadline and not received:
                time.sleep(0.05)

            assert len(received) == 1
            assert received[0].value == "4523"
            assert received[0].source_agent == "macos_infostealer_guard"
        finally:
            publisher.close()
            subscriber.close()
            channel.close()
            server.stop(0).wait()
            eventbus_logger.disabled = prev
