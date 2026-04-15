"""
AMOSKYS Neural Security Command Platform
WebSocket Handler for Real-time Dashboard Updates
Phase 2.4 Implementation - Fixed Version
"""

import logging
import os
import time
from threading import Thread

from flask_socketio import SocketIO, emit, join_room, leave_room

from .dashboard.telemetry_bridge import get_telemetry_store
from .dashboard.utils import (
    calculate_threat_score,
    get_event_clustering_data,
    get_live_agents_data,
    get_live_metrics_data,
    get_live_threats_data,
    get_neural_readiness_status,
)

logger = logging.getLogger(__name__)


def _get_cors_origins():
    """Get CORS allowed origins from environment. Empty list means same-origin only."""
    origins = os.environ.get("CORS_ALLOWED_ORIGINS", "")
    if not origins:
        return []
    return [o.strip() for o in origins.split(",") if o.strip()]


socketio = SocketIO(cors_allowed_origins=_get_cors_origins())

# Active connections tracking
active_connections = {}
update_threads = {}


def broadcast_dashboard_event(
    event_name: str,
    payload: dict,
    *,
    room: str | None = None,
    org_id: str | None = None,
) -> None:
    """Emit a dashboard websocket event, scoped to an org when provided.

    If *org_id* is given the event is sent only to clients whose
    ``org-{org_id}`` room matches.  If *room* is also given it is
    further narrowed to ``org-{org_id}-{room}``.
    """
    kwargs = {"namespace": "/dashboard"}
    if org_id and room:
        kwargs["to"] = f"org-{org_id}-{room}"
    elif org_id:
        kwargs["to"] = f"org-{org_id}"
    elif room:
        kwargs["to"] = room
    socketio.emit(event_name, payload, **kwargs)


def _get_live_incidents() -> dict:
    """Fetch open incidents from TelemetryStore for real-time push."""
    try:
        store = get_telemetry_store()
        if store is None:
            return {"incidents": [], "incident_count": 0}
        incidents = store.get_incidents(status="open", limit=10)
        return {"incidents": incidents, "incident_count": len(incidents)}
    except Exception:
        return {"incidents": [], "incident_count": 0}


def _get_live_posture() -> dict:
    """Fetch nerve posture score for real-time push."""
    try:
        store = get_telemetry_store()
        if store is None:
            return {}
        posture = store.compute_nerve_posture(hours=24)
        return {
            "posture_score": posture.get("posture_score", 100.0),
            "threat_level": posture.get("threat_level", "clear"),
            "model": posture.get("model", "nerve_signal_v1"),
        }
    except Exception:
        return {}


def _get_live_signals() -> dict:
    """Fetch open signals for real-time push."""
    try:
        store = get_telemetry_store()
        if store is None:
            return {"signals": [], "signal_count": 0}
        signals = store.get_signals(status="open", limit=20)
        return {"signals": signals, "signal_count": len(signals)}
    except Exception:
        return {"signals": [], "signal_count": 0}


class DashboardUpdater:
    """Real-time dashboard data updater"""

    def __init__(self, socketio_instance):
        self.socketio = socketio_instance
        self.running = False
        self._prev_incident_count = 0
        self._prev_signal_count = 0

    def start_updates(self):
        """Start real-time data updates"""
        if not self.running:
            self.running = True
            thread = Thread(target=self._update_loop)
            thread.daemon = True
            thread.start()
            logger.info("Dashboard updater started")

    def stop_updates(self):
        """Stop real-time data updates"""
        self.running = False
        logger.info("Dashboard updater stopped")

    def _update_loop(self):
        """Main update loop for real-time data"""
        while self.running:
            try:
                # Update every 5 seconds
                time.sleep(5)

                if len(active_connections) > 0:
                    # Collect all real-time data — isolate each fetch so
                    # one failure doesn't kill the entire update cycle.
                    updates = {"timestamp": time.time()}

                    try:
                        incident_data = _get_live_incidents()
                        updates["incidents"] = incident_data["incidents"]
                        updates["incident_count"] = incident_data["incident_count"]
                    except Exception:
                        incident_data = {"incidents": [], "incident_count": 0}
                        updates["incidents"] = []
                        updates["incident_count"] = 0

                    for key, fn in (
                        ("threats", get_live_threats_data),
                        ("agents", get_live_agents_data),
                        ("metrics", get_live_metrics_data),
                        ("threat_score", calculate_threat_score),
                        ("events", get_event_clustering_data),
                        ("neural", get_neural_readiness_status),
                        ("posture", _get_live_posture),
                        ("signals", _get_live_signals),
                    ):
                        try:
                            updates[key] = fn()
                        except Exception as exc:
                            logger.debug("Update fetch '%s' failed: %s", key, exc)
                            updates[key] = {}

                    # Broadcast per-org so tenants only see their own data.
                    # Collect unique org_ids from connected clients.
                    org_ids = {
                        conn.get("org_id", "default")
                        for conn in active_connections.values()
                    }

                    for oid in org_ids:
                        org_room = f"org-{oid}"
                        self.socketio.emit(
                            "dashboard_update",
                            updates,
                            namespace="/dashboard",
                            to=org_room,
                        )

                        # Push incident update to SOC sub-room on change
                        if incident_data["incident_count"] != self._prev_incident_count:
                            self.socketio.emit(
                                "incidents_update",
                                incident_data,
                                namespace="/dashboard",
                                to=f"org-{oid}-soc",
                            )

                        # Push signal update to SOC sub-room on change
                        signal_data = updates.get("signals", {})
                        sig_count = (
                            signal_data.get("signal_count", 0)
                            if isinstance(signal_data, dict)
                            else 0
                        )
                        if sig_count != self._prev_signal_count:
                            self.socketio.emit(
                                "signals_update",
                                signal_data,
                                namespace="/dashboard",
                                to=f"org-{oid}-soc",
                            )

                    self._prev_incident_count = incident_data["incident_count"]
                    self._prev_signal_count = (
                        signal_data.get("signal_count", 0)
                        if isinstance(signal_data, dict)
                        else 0
                    )

                    logger.debug(f"Sent updates to {len(active_connections)} clients")

            except Exception as e:
                logger.error(f"Error in update loop: {str(e)}")
                time.sleep(1)  # Brief pause on error


# Global updater instance
updater = DashboardUpdater(socketio)


@socketio.on("connect", namespace="/dashboard")
def handle_connect(_auth=None):
    """Handle client connection — requires valid session cookie."""
    from flask import request as flask_request

    # Authenticate: reject unauthenticated WebSocket connections
    session_token = flask_request.cookies.get("amoskys_session")
    if not session_token:
        logger.warning("WebSocket connect rejected: no session cookie")
        return False  # SocketIO disconnects the client

    try:
        from amoskys.auth import AuthService
        from amoskys.db.web_db import get_web_session_context

        with get_web_session_context() as db:
            auth = AuthService(db)
            result = auth.validate_and_refresh_session(
                token=session_token,
                ip_address=flask_request.headers.get(
                    "X-Forwarded-For", flask_request.remote_addr
                ),
                user_agent=flask_request.headers.get("User-Agent"),
            )
            if not result.is_valid:
                logger.warning("WebSocket connect rejected: invalid session")
                return False
    except Exception as e:
        logger.error("WebSocket auth check failed: %s", e)
        return False

    client_id = flask_request.sid

    # Extract org_id from the validated session for room scoping
    user_org_id = getattr(result.user, "org_id", None) or "default"

    active_connections[client_id] = {
        "connected_at": time.time(),
        "rooms": [],
        "org_id": user_org_id,
    }

    # Auto-join the org-level room so broadcasts are tenant-scoped
    join_room(f"org-{user_org_id}")

    logger.info("Dashboard client connected: %s (org=%s)", client_id, user_org_id)

    # Start updater if first connection
    if len(active_connections) == 1:
        updater.start_updates()

    # Send initial data
    incident_data = _get_live_incidents()
    initial_data = {
        "threats": get_live_threats_data(),
        "agents": get_live_agents_data(),
        "metrics": get_live_metrics_data(),
        "threat_score": calculate_threat_score(),
        "events": get_event_clustering_data(),
        "neural": get_neural_readiness_status(),
        "incidents": incident_data["incidents"],
        "incident_count": incident_data["incident_count"],
        "timestamp": time.time(),
    }

    emit("initial_data", initial_data)


@socketio.on("disconnect", namespace="/dashboard")
def handle_disconnect(reason=None):
    """Handle client disconnection

    Args:
        reason: Optional disconnect reason (may be passed by some SocketIO implementations)
    """
    from flask import request as flask_request

    client_id = flask_request.sid

    if client_id in active_connections:
        del active_connections[client_id]
        logger.info(f"Dashboard client disconnected: {client_id}")

    # Stop updater if no connections
    if len(active_connections) == 0:
        updater.stop_updates()


@socketio.on("join_dashboard", namespace="/dashboard")
def handle_join_dashboard(data):
    """Handle client joining specific dashboard room"""
    from flask import request as flask_request

    dashboard_type = data.get("dashboard", "cortex")
    client_id = flask_request.sid

    # Scope room by org so broadcasts are tenant-isolated
    org_id = active_connections.get(client_id, {}).get("org_id", "default")
    scoped_room = f"org-{org_id}-{dashboard_type}"

    join_room(scoped_room)

    if client_id in active_connections:
        active_connections[client_id]["rooms"].append(scoped_room)

    logger.info("Client %s joined dashboard: %s (room=%s)", client_id, dashboard_type, scoped_room)
    emit("joined_dashboard", {"dashboard": dashboard_type})


@socketio.on("leave_dashboard", namespace="/dashboard")
def handle_leave_dashboard(data):
    """Handle client leaving specific dashboard room"""
    from flask import request as flask_request

    dashboard_type = data.get("dashboard", "cortex")
    client_id = flask_request.sid

    org_id = active_connections.get(client_id, {}).get("org_id", "default")
    scoped_room = f"org-{org_id}-{dashboard_type}"

    leave_room(scoped_room)

    if (
        client_id in active_connections
        and scoped_room in active_connections[client_id]["rooms"]
    ):
        active_connections[client_id]["rooms"].remove(scoped_room)

    logger.info("Client %s left dashboard: %s", client_id, dashboard_type)
    emit("left_dashboard", {"dashboard": dashboard_type})


@socketio.on("request_update", namespace="/dashboard")
def handle_request_update(data):
    """Handle manual update request from client"""
    from flask import request as flask_request

    dashboard_type = data.get("dashboard", "all")
    client_id = flask_request.sid

    try:
        if dashboard_type == "all" or dashboard_type == "cortex":
            updates = {
                "threats": get_live_threats_data(),
                "agents": get_live_agents_data(),
                "metrics": get_live_metrics_data(),
                "threat_score": calculate_threat_score(),
                "timestamp": time.time(),
            }
            emit("dashboard_update", updates)

        elif dashboard_type == "soc":
            soc_incidents = _get_live_incidents()
            updates = {
                "threats": get_live_threats_data(),
                "events": get_event_clustering_data(),
                "incidents": soc_incidents["incidents"],
                "incident_count": soc_incidents["incident_count"],
                "timestamp": time.time(),
            }
            emit("soc_update", updates)

        elif dashboard_type == "agents":
            updates = {"agents": get_live_agents_data(), "timestamp": time.time()}
            emit("agents_update", updates)

        elif dashboard_type == "system":
            updates = {"metrics": get_live_metrics_data(), "timestamp": time.time()}
            emit("system_update", updates)

        elif dashboard_type == "neural":
            updates = {
                "neural": get_neural_readiness_status(),
                "timestamp": time.time(),
            }
            emit("neural_update", updates)

        logger.debug(
            f"Manual update sent to client {client_id} for dashboard {dashboard_type}"
        )

    except Exception as e:
        logger.error(f"Error handling update request: {str(e)}")
        emit("error", {"message": "Update failed", "error": str(e)})


@socketio.on("ping", namespace="/dashboard")
def handle_ping():
    """Handle ping for connection testing"""
    emit("pong", {"timestamp": time.time()})


def get_connection_stats():
    """Get current connection statistics"""
    return {
        "active_connections": len(active_connections),
        "updater_running": updater.running,
        "connections": {
            client_id: {
                "connected_at": conn["connected_at"],
                "rooms": conn["rooms"],
                "duration": time.time() - conn["connected_at"],
            }
            for client_id, conn in active_connections.items()
        },
    }


def init_socketio(app):
    """Initialize SocketIO with Flask app"""
    socketio.init_app(app, async_mode="threading")
    logger.info("SocketIO initialized for real-time dashboard updates")
    return socketio
