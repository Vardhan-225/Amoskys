from __future__ import annotations

import logging
import time
from concurrent import futures

import grpc

from amoskys.common.coordination import CoordinationConfig, create_coordination_bus
from amoskys.eventbus.server import EventBusControlServicer
from amoskys.proto import control_pb2_grpc


def test_local_coordination_bus_publish_and_subscribe():
    bus = create_coordination_bus(CoordinationConfig(backend="local", agent_id="local"))
    received = []

    bus.subscribe("HEALTH", lambda topic, payload: received.append((topic, payload)))
    bus.publish("HEALTH", {"status": "ok"})

    assert received == [("HEALTH", {"status": "ok"})]


def test_eventbus_coordination_bus_round_trip():
    eventbus_logger = logging.getLogger("EventBus")
    previous_disabled = eventbus_logger.disabled
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
            agent_id="cortex_dashboard",
            eventbus_channel=channel,
            default_topics=["ALERT"],
        )
    )
    publisher = create_coordination_bus(
        CoordinationConfig(
            backend="eventbus",
            agent_id="macos_process",
            eventbus_channel=channel,
            default_topics=["*"],
        )
    )

    received = []
    subscriber.subscribe(
        "ALERT", lambda topic, payload: received.append((topic, payload))
    )

    try:
        time.sleep(0.2)
        publisher.publish(
            "ALERT",
            {
                "agent_id": "macos_process",
                "severity": "CRITICAL",
                "summary": "suspicious child process",
            },
        )

        deadline = time.time() + 2.0
        while time.time() < deadline and not received:
            time.sleep(0.05)

        assert received == [
            (
                "ALERT",
                {
                    "agent_id": "macos_process",
                    "severity": "CRITICAL",
                    "summary": "suspicious child process",
                },
            )
        ]
    finally:
        publisher.close()
        subscriber.close()
        channel.close()
        server.stop(0).wait()
        eventbus_logger.disabled = previous_disabled
