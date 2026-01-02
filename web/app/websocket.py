"""
AMOSKYS Neural Security Command Platform
WebSocket Handler for Real-time Dashboard Updates
Phase 2.4 Implementation - Fixed Version
"""

import logging
import time
import uuid
from threading import Thread

from flask_socketio import SocketIO, emit, join_room, leave_room

from .dashboard.utils import (
    calculate_threat_score,
    get_event_clustering_data,
    get_live_agents_data,
    get_live_metrics_data,
    get_live_threats_data,
    get_neural_readiness_status,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

socketio = SocketIO(cors_allowed_origins="*")

# Active connections tracking
active_connections = {}
update_threads = {}


class DashboardUpdater:
    """Real-time dashboard data updater"""

    def __init__(self, socketio_instance):
        self.socketio = socketio_instance
        self.running = False

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
                    # Collect all real-time data
                    updates = {
                        "threats": get_live_threats_data(),
                        "agents": get_live_agents_data(),
                        "metrics": get_live_metrics_data(),
                        "threat_score": calculate_threat_score(),
                        "events": get_event_clustering_data(),
                        "neural": get_neural_readiness_status(),
                        "timestamp": time.time(),
                    }

                    # Emit to all connected clients
                    self.socketio.emit(
                        "dashboard_update", updates, namespace="/dashboard"
                    )
                    logger.debug(f"Sent updates to {len(active_connections)} clients")

            except Exception as e:
                logger.error(f"Error in update loop: {str(e)}")
                time.sleep(1)  # Brief pause on error


# Global updater instance
updater = DashboardUpdater(socketio)


@socketio.on("connect", namespace="/dashboard")
def handle_connect():
    """Handle client connection"""
    client_id = str(uuid.uuid4())
    active_connections[client_id] = {"connected_at": time.time(), "rooms": []}

    logger.info(f"Dashboard client connected: {client_id}")

    # Start updater if first connection
    if len(active_connections) == 1:
        updater.start_updates()

    # Send initial data
    initial_data = {
        "threats": get_live_threats_data(),
        "agents": get_live_agents_data(),
        "metrics": get_live_metrics_data(),
        "threat_score": calculate_threat_score(),
        "events": get_event_clustering_data(),
        "neural": get_neural_readiness_status(),
        "timestamp": time.time(),
    }

    emit("initial_data", initial_data)


@socketio.on("disconnect", namespace="/dashboard")
def handle_disconnect(reason=None):
    """Handle client disconnection

    Args:
        reason: Optional disconnect reason (may be passed by some SocketIO implementations)
    """
    client_id = str(
        uuid.uuid4()
    )  # Note: In real implementation, track this per session

    if client_id in active_connections:
        del active_connections[client_id]
        logger.info(f"Dashboard client disconnected: {client_id}")

    # Stop updater if no connections
    if len(active_connections) == 0:
        updater.stop_updates()


@socketio.on("join_dashboard", namespace="/dashboard")
def handle_join_dashboard(data):
    """Handle client joining specific dashboard room"""
    dashboard_type = data.get("dashboard", "cortex")
    client_id = str(
        uuid.uuid4()
    )  # Note: In real implementation, track this per session

    join_room(dashboard_type)

    if client_id in active_connections:
        active_connections[client_id]["rooms"].append(dashboard_type)

    logger.info(f"Client {client_id} joined dashboard: {dashboard_type}")
    emit("joined_dashboard", {"dashboard": dashboard_type})


@socketio.on("leave_dashboard", namespace="/dashboard")
def handle_leave_dashboard(data):
    """Handle client leaving specific dashboard room"""
    dashboard_type = data.get("dashboard", "cortex")
    client_id = str(
        uuid.uuid4()
    )  # Note: In real implementation, track this per session

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
    dashboard_type = data.get("dashboard", "all")
    client_id = str(
        uuid.uuid4()
    )  # Note: In real implementation, track this per session

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
            updates = {
                "threats": get_live_threats_data(),
                "events": get_event_clustering_data(),
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
