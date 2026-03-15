"""Dashboard coordination-bus wiring."""

from __future__ import annotations

import logging
import os
from typing import Dict, Optional

from amoskys.common.coordination import (
    CoordinationBus,
    CoordinationConfig,
    create_coordination_bus,
)
from amoskys.config import get_config

from .websocket import broadcast_dashboard_event

logger = logging.getLogger(__name__)

_coord_bus: Optional[CoordinationBus] = None


def init_control_bus() -> CoordinationBus:
    """Initialize the dashboard coordination bus once."""

    global _coord_bus
    if _coord_bus is not None:
        return _coord_bus

    config = get_config()
    backend = os.getenv("AMOSKYS_COORDINATION_BACKEND", "local")
    cfg = CoordinationConfig(
        backend=backend,
        agent_id="cortex_dashboard",
        eventbus_address=config.agent.bus_address,
        cert_dir=config.agent.cert_dir,
        default_topics=["HEALTH", "ALERT"],
    )

    try:
        _coord_bus = create_coordination_bus(cfg)
    except Exception as exc:
        logger.warning(
            "Dashboard coordination bus backend '%s' unavailable, falling back to local: %s",
            backend,
            exc,
        )
        _coord_bus = create_coordination_bus(
            CoordinationConfig(backend="local", agent_id="cortex_dashboard")
        )

    _coord_bus.subscribe("HEALTH", _handle_health)
    _coord_bus.subscribe("ALERT", _handle_alert)
    logger.info("Dashboard coordination bus initialized via %s", backend)
    return _coord_bus


def get_control_bus() -> Optional[CoordinationBus]:
    return _coord_bus


def _handle_health(topic: str, payload: Dict[str, object]) -> None:
    _ = topic
    message = {
        "agent_id": payload.get("agent_id"),
        "status": payload.get("status", "unknown"),
        "loop_latency_ms": payload.get("loop_latency_ms"),
        "errors_last_min": payload.get("errors_last_min"),
        "collection_count": payload.get("collection_count"),
    }
    broadcast_dashboard_event("agent_health_update", message, room="cortex")
    broadcast_dashboard_event("agent_health_update", message, room="agents")


def _handle_alert(topic: str, payload: Dict[str, object]) -> None:
    _ = topic
    message = {
        "agent_id": payload.get("agent_id"),
        "severity": payload.get("severity", "INFO"),
        "probe": payload.get("probe"),
        "summary": payload.get("summary"),
    }
    broadcast_dashboard_event("agent_alert_signal", message, room="cortex")
    broadcast_dashboard_event("agent_alert_signal", message, room="soc")
