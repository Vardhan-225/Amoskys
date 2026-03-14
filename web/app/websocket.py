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

                    # Emit to all connected clients
                    self.socketio.emit(
                        "dashboard_update", updates, namespace="/dashboard"
                    )

                    # Push dedicated incident update to SOC room on new incidents
                    if incident_data["incident_count"] != self._prev_incident_count:
                        self.socketio.emit(
                            "incidents_update",
                            incident_data,
                            namespace="/dashboard",
                            to="soc",
                        )
                        self._prev_incident_count = incident_data["incident_count"]

                    # Push dedicated signal update to SOC room on new signals
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
                            to="soc",
                        )
                        self._prev_signal_count = sig_count

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
    active_connections[client_id] = {"connected_at": time.time(), "rooms": []}

    logger.info(f"Dashboard client connected: {client_id}")

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

    join_room(dashboard_type)

    if client_id in active_connections:
        active_connections[client_id]["rooms"].append(dashboard_type)

    logger.info(f"Client {client_id} joined dashboard: {dashboard_type}")
    emit("joined_dashboard", {"dashboard": dashboard_type})


@socketio.on("leave_dashboard", namespace="/dashboard")
def handle_leave_dashboard(data):
    """Handle client leaving specific dashboard room"""
    from flask import request as flask_request

    dashboard_type = data.get("dashboard", "cortex")
    client_id = flask_request.sid

    leave_room(dashboard_type)

    if (
        client_id in active_connections
        and dashboard_type in active_connections[client_id]["rooms"]
    ):
        active_connections[client_id]["rooms"].remove(dashboard_type)

    logger.info(f"Client {client_id} left dashboard: {dashboard_type}")
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
