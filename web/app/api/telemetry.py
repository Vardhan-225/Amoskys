"""
AMOSKYS API Telemetry Module
Real-time agent telemetry from EventBus WAL storage
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timezone
import sqlite3
import os
import sys

# Add src to path for protobuf imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

from amoskys.proto import universal_telemetry_pb2

telemetry_bp = Blueprint("telemetry", __name__, url_prefix="/telemetry")

# WAL database path - from /web/app/api/ to /data/wal/flowagent.db
# Go up from api/ to app/, then app/ to web/, then web/ to project root, then into data/wal/
WAL_DB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "data", "wal", "flowagent.db"
)


def get_wal_connection():
    """Get a connection to the WAL database with same params as EventBus"""
    return sqlite3.connect(
        WAL_DB_PATH,
        timeout=5.0,
        isolation_level=None,  # Autocommit mode
        check_same_thread=False,
    )


@telemetry_bp.route("/recent", methods=["GET"])
def get_recent_telemetry():
    """Get recent telemetry events from all agents"""
    try:
        limit = min(int(request.args.get("limit", 50)), 500)  # Max 500

        conn = get_wal_connection()
        cursor = conn.execute(
            "SELECT id, idem, ts_ns, bytes FROM wal ORDER BY ts_ns DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()

        events = []
        for row_id, idem, ts_ns, env_bytes in rows:
            try:
                # Deserialize the protobuf envelope
                envelope = universal_telemetry_pb2.UniversalEnvelope()
                envelope.ParseFromString(env_bytes)

                # Extract telemetry data
                event_data = {
                    "id": row_id,
                    "idempotency_key": idem,
                    "timestamp_ns": ts_ns,
                    "timestamp": datetime.fromtimestamp(
                        ts_ns / 1e9, tz=timezone.utc
                    ).isoformat(),
                }

                # Parse different telemetry types
                if envelope.HasField("device_telemetry"):
                    dt = envelope.device_telemetry
                    event_data["type"] = "device_telemetry"
                    event_data["device_id"] = dt.device_id
                    event_data["device_type"] = universal_telemetry_pb2.DeviceType.Name(
                        dt.device_type
                    )

                    # Extract metrics from events
                    metrics = []
                    for event in dt.events:
                        if (
                            event.event_type
                            == universal_telemetry_pb2.TelemetryEvent.METRIC
                        ):
                            metric_data = {
                                "name": event.metric.name,
                                "type": universal_telemetry_pb2.MetricType.Name(
                                    event.metric.metric_type
                                ),
                                "value": event.metric.value,
                                "unit": event.metric.unit,
                            }
                            metrics.append(metric_data)

                    event_data["metrics"] = metrics
                    event_data["event_count"] = len(dt.events)

                elif envelope.HasField("process"):
                    proc = envelope.process
                    event_data["type"] = "process"
                    event_data["pid"] = proc.pid
                    event_data["name"] = proc.name
                    event_data["exe"] = proc.exe
                    event_data["cmdline"] = " ".join(proc.cmdline)

                elif envelope.HasField("flow"):
                    flow = envelope.flow
                    event_data["type"] = "flow"
                    event_data["src_ip"] = flow.src_ip
                    event_data["dst_ip"] = flow.dst_ip
                    event_data["src_port"] = flow.src_port
                    event_data["dst_port"] = flow.dst_port

                else:
                    event_data["type"] = "unknown"

                events.append(event_data)

            except Exception as parse_err:
                # Skip events that fail to parse
                continue

        return jsonify({"status": "success", "count": len(events), "events": events})

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@telemetry_bp.route("/agents", methods=["GET"])
def get_agent_summary():
    """Get summary of agent telemetry"""
    try:
        conn = get_wal_connection()

        # Get total event count
        cursor = conn.execute("SELECT COUNT(*) FROM wal")
        total_events = cursor.fetchone()[0]

        # Get recent events to extract agent info
        cursor = conn.execute("SELECT bytes FROM wal ORDER BY ts_ns DESC LIMIT 100")
        rows = cursor.fetchall()
        conn.close()

        # Track unique agents and their metrics
        agents = {}

        for (env_bytes,) in rows:
            try:
                envelope = universal_telemetry_pb2.UniversalEnvelope()
                envelope.ParseFromString(env_bytes)

                if envelope.HasField("device_telemetry"):
                    dt = envelope.device_telemetry
                    device_id = dt.device_id

                    if device_id not in agents:
                        agents[device_id] = {
                            "device_id": device_id,
                            "device_type": universal_telemetry_pb2.DeviceType.Name(
                                dt.device_type
                            ),
                            "event_count": 0,
                            "latest_metrics": {},
                            "last_seen": None,
                        }

                    agents[device_id]["event_count"] += 1

                    # Update timestamp
                    ts = datetime.fromtimestamp(envelope.ts_ns / 1e9, tz=timezone.utc)
                    if (
                        agents[device_id]["last_seen"] is None
                        or ts > agents[device_id]["last_seen"]
                    ):
                        agents[device_id]["last_seen"] = ts.isoformat()

                    # Extract latest metrics
                    for event in dt.events:
                        if (
                            event.event_type
                            == universal_telemetry_pb2.TelemetryEvent.METRIC
                        ):
                            agents[device_id]["latest_metrics"][event.metric.name] = {
                                "value": event.metric.value,
                                "unit": event.metric.unit,
                            }

            except Exception:
                continue

        return jsonify(
            {
                "status": "success",
                "total_events": total_events,
                "agent_count": len(agents),
                "agents": list(agents.values()),
            }
        )

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@telemetry_bp.route("/metrics/<device_id>", methods=["GET"])
def get_device_metrics(device_id):
    """Get latest metrics for a specific device"""
    try:
        limit = min(int(request.args.get("limit", 10)), 100)

        conn = get_wal_connection()
        cursor = conn.execute(
            "SELECT ts_ns, bytes FROM wal ORDER BY ts_ns DESC LIMIT ?",
            (limit * 5,),  # Get more to filter
        )
        rows = cursor.fetchall()
        conn.close()

        metrics_history = []

        for ts_ns, env_bytes in rows:
            try:
                envelope = universal_telemetry_pb2.UniversalEnvelope()
                envelope.ParseFromString(env_bytes)

                if envelope.HasField("device_telemetry"):
                    dt = envelope.device_telemetry

                    if dt.device_id == device_id:
                        timestamp = datetime.fromtimestamp(
                            ts_ns / 1e9, tz=timezone.utc
                        ).isoformat()

                        for event in dt.events:
                            if (
                                event.event_type
                                == universal_telemetry_pb2.TelemetryEvent.METRIC
                            ):
                                metrics_history.append(
                                    {
                                        "timestamp": timestamp,
                                        "name": event.metric.name,
                                        "value": event.metric.value,
                                        "unit": event.metric.unit,
                                    }
                                )

                        if len(metrics_history) >= limit:
                            break

            except Exception:
                continue

        return jsonify(
            {
                "status": "success",
                "device_id": device_id,
                "count": len(metrics_history),
                "metrics": metrics_history,
            }
        )

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@telemetry_bp.route("/stats", methods=["GET"])
def get_telemetry_stats():
    """Get overall telemetry statistics"""
    try:
        conn = get_wal_connection()

        # Get total count and time range
        cursor = conn.execute("SELECT COUNT(*), MIN(ts_ns), MAX(ts_ns) FROM wal")
        total, min_ts, max_ts = cursor.fetchone()
        conn.close()

        stats = {
            "total_events": total or 0,
            "earliest_event": None,
            "latest_event": None,
            "time_span_seconds": 0,
        }

        if min_ts and max_ts:
            stats["earliest_event"] = datetime.fromtimestamp(
                min_ts / 1e9, tz=timezone.utc
            ).isoformat()
            stats["latest_event"] = datetime.fromtimestamp(
                max_ts / 1e9, tz=timezone.utc
            ).isoformat()
            stats["time_span_seconds"] = (max_ts - min_ts) / 1e9

        return jsonify({"status": "success", "stats": stats})

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
