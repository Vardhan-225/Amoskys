"""Cross-process coordination bus abstraction for agents and dashboard.

Tactical topics (lateral nervous system):
    CONTROL      — log level, interval override, watchlist directives, mode changes
    HEALTH       — periodic agent heartbeat
    ALERT        — detection alert from a probe
    WATCH_PID    — "focus collection on this PID" (InfostealerGuard → Network/Process/DNS)
    WATCH_PATH   — "focus collection on this file path" (FIM → other agents)
    WATCH_DOMAIN — "focus collection on this domain" (DNS → Network)
    CLEAR_WATCH  — remove a previously published watch directive
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, DefaultDict, Dict, List, Optional

try:
    import grpc
except Exception:  # pragma: no cover - optional dependency in some test contexts
    grpc = None

try:
    from amoskys.proto import control_pb2, control_pb2_grpc
except Exception:  # pragma: no cover - generated stubs may not exist yet
    control_pb2 = None
    control_pb2_grpc = None

logger = logging.getLogger(__name__)

Handler = Callable[[str, Dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Tactical topics — the lateral nervous system
# ---------------------------------------------------------------------------


class TacticalTopic(str, Enum):
    """Named topics for the coordination bus."""

    CONTROL = "CONTROL"
    HEALTH = "HEALTH"
    ALERT = "ALERT"
    WATCH_PID = "WATCH_PID"
    WATCH_PATH = "WATCH_PATH"
    WATCH_DOMAIN = "WATCH_DOMAIN"
    CLEAR_WATCH = "CLEAR_WATCH"


class Urgency(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class WatchDirective:
    """A tactical watch directive published on the coordination bus.

    Agents publish these when they detect something worth coordinated attention.
    Peer agents consume them to tighten collection around the target.
    """

    topic: str  # WATCH_PID | WATCH_PATH | WATCH_DOMAIN
    value: str  # The PID, path, or domain to watch
    reason: str  # Why — e.g. "T1555_credential_access"
    urgency: str = "HIGH"
    source_agent: str = ""
    mitre_technique: str = ""
    ttl_seconds: float = 300.0  # Auto-expire after 5 minutes by default
    ts: float = field(default_factory=time.time)

    def to_payload(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "reason": self.reason,
            "urgency": self.urgency,
            "source_agent": self.source_agent,
            "mitre_technique": self.mitre_technique,
            "ttl_seconds": self.ttl_seconds,
            "ts": self.ts,
        }

    @classmethod
    def from_payload(cls, topic: str, payload: Dict[str, Any]) -> "WatchDirective":
        return cls(
            topic=topic,
            value=str(payload.get("value", "")),
            reason=str(payload.get("reason", "")),
            urgency=str(payload.get("urgency", "HIGH")),
            source_agent=str(payload.get("source_agent", "")),
            mitre_technique=str(payload.get("mitre_technique", "")),
            ttl_seconds=float(payload.get("ttl_seconds", 300.0)),
            ts=float(payload.get("ts", time.time())),
        )

    @property
    def expired(self) -> bool:
        return (time.time() - self.ts) > self.ttl_seconds


@dataclass
class CoordinationConfig:
    """Configuration for a coordination bus backend."""

    backend: str = "local"  # "local" | "eventbus"
    agent_id: str = "unknown"
    eventbus_address: Optional[str] = None
    cert_dir: Optional[str] = None
    eventbus_channel: Any = None
    default_topics: Optional[List[str]] = None
    max_payload_bytes: int = 4096
    stream_retry_seconds: float = 2.0


class CoordinationBus:
    """Abstract coordination bus interface."""

    def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    def subscribe(self, topic: str, handler: Handler) -> None:
        raise NotImplementedError

    def close(self) -> None:
        """Best-effort cleanup hook for long-lived backends."""


class LocalBus(CoordinationBus):
    """Simple in-process pub/sub bus."""

    def __init__(self) -> None:
        self._subs: DefaultDict[str, List[Handler]] = defaultdict(list)
        self._lock = threading.Lock()

    def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            handlers = list(self._subs.get(topic, []))
            handlers.extend(self._subs.get("*", []))

        for handler in handlers:
            try:
                handler(topic, payload)
            except Exception:
                logger.exception("Coordination handler failed for topic=%s", topic)

    def subscribe(self, topic: str, handler: Handler) -> None:
        with self._lock:
            self._subs[topic].append(handler)


def _create_eventbus_channel(address: str, cert_dir: str):
    """Create a gRPC channel using existing EventBus TLS conventions."""

    if grpc is None:
        raise RuntimeError("grpc is required for EventBus coordination backend")

    ca_path = os.path.join(cert_dir, "ca.crt")
    with open(ca_path, "rb") as f:
        ca = f.read()

    client_cert_path = os.path.join(cert_dir, "agent.crt")
    client_key_path = os.path.join(cert_dir, "agent.key")

    if os.path.exists(client_cert_path) and os.path.exists(client_key_path):
        with open(client_cert_path, "rb") as f:
            crt = f.read()
        with open(client_key_path, "rb") as f:
            key = f.read()
        creds = grpc.ssl_channel_credentials(
            root_certificates=ca,
            private_key=key,
            certificate_chain=crt,
        )
    else:
        creds = grpc.ssl_channel_credentials(root_certificates=ca)
        logger.warning(
            "CoordinationBus using one-way TLS for EventBus at %s (client certs missing)",
            address,
        )

    return grpc.secure_channel(address, creds)


class EventBusCoordinationBus(CoordinationBus):
    """Coordination bus backed by EventBus control RPCs."""

    def __init__(self, cfg: CoordinationConfig) -> None:
        if control_pb2 is None or control_pb2_grpc is None:
            raise RuntimeError("EventBus control proto stubs are not available")

        if cfg.eventbus_channel is not None:
            channel = cfg.eventbus_channel
            self._owns_channel = False
        else:
            if not cfg.eventbus_address or not cfg.cert_dir:
                raise ValueError(
                    "eventbus_address and cert_dir are required for EventBus backend"
                )
            channel = _create_eventbus_channel(cfg.eventbus_address, cfg.cert_dir)
            self._owns_channel = True

        self._agent_id = cfg.agent_id
        self._local = LocalBus()
        self._stub = control_pb2_grpc.EventBusControlStub(channel)
        self._channel = channel
        self._default_topics = cfg.default_topics or ["*"]
        self._max_payload_bytes = max(256, int(cfg.max_payload_bytes))
        self._stream_retry_seconds = max(0.5, float(cfg.stream_retry_seconds))
        self._started = False
        self._closed = False
        self._lock = threading.Lock()
        self._listener: Optional[threading.Thread] = None

    def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        self._local.publish(topic, payload)

        if self._closed:
            return

        try:
            payload_json = self._encode_payload(topic, payload)
            signal = control_pb2.AgentSignal(
                id=str(uuid.uuid4()),
                source=self._agent_id,
                target=str(payload.get("target", "all") or "all"),
                topic=topic,
                payload_json=payload_json,
                ts_ns=time.time_ns(),
            )
            self._stub.PublishSignal(signal, timeout=2.0)
        except Exception:
            logger.exception("Failed to publish coordination signal topic=%s", topic)

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._local.subscribe(topic, handler)

        with self._lock:
            if not self._started:
                self._started = True
                self._listener = threading.Thread(
                    target=self._run_listener,
                    name=f"coord-listener-{self._agent_id}",
                    daemon=True,
                )
                self._listener.start()

    def close(self) -> None:
        self._closed = True
        if self._owns_channel and self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                logger.debug("Failed to close coordination channel", exc_info=True)

    def _run_listener(self) -> None:
        backoff = self._stream_retry_seconds

        while not self._closed:
            request = control_pb2.SignalSubscribe(
                agent_id=self._agent_id,
                topics=self._default_topics,
            )
            try:
                for signal in self._stub.SubscribeSignals(request):
                    if self._closed:
                        return
                    payload = self._decode_payload(signal.payload_json)
                    self._local.publish(signal.topic, payload)
                backoff = self._stream_retry_seconds
            except Exception:
                if self._closed:
                    return
                logger.warning(
                    "Coordination stream disconnected for %s; retrying in %.1fs",
                    self._agent_id,
                    backoff,
                    exc_info=True,
                )
                time.sleep(backoff)
                backoff = min(backoff * 2.0, 10.0)

    def _encode_payload(self, topic: str, payload: Dict[str, Any]) -> str:
        payload_json = json.dumps(payload, default=str, separators=(",", ":"))
        if len(payload_json.encode("utf-8")) <= self._max_payload_bytes:
            return payload_json

        truncated = {
            "truncated": True,
            "topic": topic,
            "payload_preview": payload_json[: self._max_payload_bytes],
        }
        return json.dumps(truncated, separators=(",", ":"))

    @staticmethod
    def _decode_payload(payload_json: str) -> Dict[str, Any]:
        if not payload_json:
            return {}
        try:
            value = json.loads(payload_json)
            return value if isinstance(value, dict) else {"value": value}
        except Exception:
            logger.debug("Coordination payload JSON decode failed", exc_info=True)
            return {}


def create_coordination_bus(cfg: CoordinationConfig) -> CoordinationBus:
    """Factory for creating a coordination backend."""

    backend = (cfg.backend or "local").lower()
    if backend == "eventbus":
        return EventBusCoordinationBus(cfg)
    return LocalBus()
