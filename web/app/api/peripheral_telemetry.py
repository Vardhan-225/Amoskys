"""
AMOSKYS Peripheral Telemetry API
Fetches and displays USB/Bluetooth/peripheral device events
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from .rate_limiter import require_rate_limit
import sqlite3
import os

peripheral_bp = Blueprint('peripheral_telemetry', __name__, url_prefix='/peripheral-telemetry')

# Path to permanent telemetry database
TELEMETRY_DB_PATH = os.path.join(os.path.dirname(__file__), '../../../data/telemetry.db')


def safe_int(value, default=0, min_val=None, max_val=None):
    """Safely parse integer from request parameter"""
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return max_val
        return result
    except (ValueError, TypeError):
        return default


def get_db_connection():
    """Create connection to telemetry database"""
    if not os.path.exists(TELEMETRY_DB_PATH):
        return None
    conn = sqlite3.connect(TELEMETRY_DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


@peripheral_bp.route('/recent', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_recent_events():
    """Get recent peripheral events"""
    limit = safe_int(request.args.get('limit', 100), default=100, min_val=1, max_val=500)

    conn = get_db_connection()
    if not conn:
        return jsonify({'events': [], 'message': 'No data available yet'}), 200

    try:
        cursor = conn.execute("""
            SELECT *
            FROM peripheral_events
            ORDER BY timestamp_ns DESC
            LIMIT ?
        """, (limit,))

        events = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'events': events,
            'count': len(events),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@peripheral_bp.route('/connected', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_connected_devices():
    """Get currently connected peripheral devices"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'devices': [], 'message': 'No data available'}), 200

    try:
        # Get latest event for each peripheral device
        cursor = conn.execute("""
            SELECT
                peripheral_device_id,
                device_name,
                device_type,
                vendor_id,
                product_id,
                manufacturer,
                connection_status,
                is_authorized,
                risk_score,
                MAX(timestamp_ns) as last_seen_ns,
                timestamp_dt as last_seen_dt
            FROM peripheral_events
            GROUP BY peripheral_device_id
            HAVING connection_status = 'CONNECTED'
            ORDER BY last_seen_ns DESC
        """)

        devices = []
        for row in cursor.fetchall():
            device = dict(row)
            # Calculate how long ago device was seen
            last_seen = datetime.fromisoformat(device['last_seen_dt'])
            device['seconds_since_seen'] = int((datetime.now() - last_seen).total_seconds())
            devices.append(device)

        return jsonify({
            'devices': devices,
            'count': len(devices),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@peripheral_bp.route('/stats', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_peripheral_stats():
    """Get aggregated peripheral statistics"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database not available'}), 500

    try:
        # Total events
        cursor = conn.execute("SELECT COUNT(*) as count FROM peripheral_events")
        total_events = cursor.fetchone()['count']

        # Unique devices
        cursor = conn.execute("SELECT COUNT(DISTINCT peripheral_device_id) as count FROM peripheral_events")
        unique_devices = cursor.fetchone()['count']

        # Device type distribution
        cursor = conn.execute("""
            SELECT device_type, COUNT(*) as count
            FROM peripheral_events
            WHERE device_type IS NOT NULL
            GROUP BY device_type
        """)
        type_dist = {row['device_type']: row['count'] for row in cursor.fetchall()}

        # Connection status distribution
        cursor = conn.execute("""
            SELECT connection_status, COUNT(*) as count
            FROM peripheral_events
            WHERE connection_status IS NOT NULL
            GROUP BY connection_status
        """)
        status_dist = {row['connection_status']: row['count'] for row in cursor.fetchall()}

        # Unauthorized devices count
        cursor = conn.execute("""
            SELECT COUNT(DISTINCT peripheral_device_id) as count
            FROM peripheral_events
            WHERE is_authorized = 0
        """)
        unauthorized_count = cursor.fetchone()['count']

        # High risk devices (risk_score > 0.7)
        cursor = conn.execute("""
            SELECT COUNT(DISTINCT peripheral_device_id) as count
            FROM peripheral_events
            WHERE risk_score > 0.7
        """)
        high_risk_count = cursor.fetchone()['count']

        # Recent connections (last hour)
        one_hour_ago = int((datetime.now() - timedelta(hours=1)).timestamp() * 1e9)
        cursor = conn.execute("""
            SELECT COUNT(*) as count
            FROM peripheral_events
            WHERE timestamp_ns > ? AND connection_status = 'CONNECTED'
        """, (one_hour_ago,))
        recent_connections = cursor.fetchone()['count']

        # Time range
        cursor = conn.execute("""
            SELECT MIN(timestamp_dt) as start, MAX(timestamp_dt) as end
            FROM peripheral_events
        """)
        time_range = cursor.fetchone()

        return jsonify({
            'total_events': total_events,
            'unique_devices': unique_devices,
            'unauthorized_devices': unauthorized_count,
            'high_risk_devices': high_risk_count,
            'recent_connections_1h': recent_connections,
            'device_type_distribution': type_dist,
            'connection_status_distribution': status_dist,
            'collection_period': {
                'start': time_range['start'],
                'end': time_range['end']
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@peripheral_bp.route('/timeline', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_connection_timeline():
    """Get timeline of device connections/disconnections"""
    hours = safe_int(request.args.get('hours', 24), default=24, min_val=1, max_val=168)

    conn = get_db_connection()
    if not conn:
        return jsonify({'events': [], 'message': 'No data available'}), 200

    try:
        cutoff_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1e9)

        cursor = conn.execute("""
            SELECT
                timestamp_ns,
                timestamp_dt,
                device_name,
                device_type,
                connection_status,
                previous_status,
                is_authorized,
                risk_score
            FROM peripheral_events
            WHERE timestamp_ns > ?
            ORDER BY timestamp_ns DESC
        """, (cutoff_time,))

        events = []
        for row in cursor.fetchall():
            event = dict(row)
            # Add human-readable time
            event_time = datetime.fromisoformat(event['timestamp_dt'])
            event['hours_ago'] = round((datetime.now() - event_time).total_seconds() / 3600, 1)
            events.append(event)

        return jsonify({
            'events': events,
            'count': len(events),
            'time_window_hours': hours,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@peripheral_bp.route('/high-risk', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_high_risk_devices():
    """Get high-risk peripheral devices (risk_score > 0.5)"""
    limit = safe_int(request.args.get('limit', 50), default=50, min_val=1, max_val=200)

    conn = get_db_connection()
    if not conn:
        return jsonify({'devices': [], 'message': 'No data available'}), 200

    try:
        cursor = conn.execute("""
            SELECT
                peripheral_device_id,
                device_name,
                device_type,
                vendor_id,
                product_id,
                manufacturer,
                MAX(risk_score) as max_risk_score,
                is_authorized,
                COUNT(*) as event_count,
                MAX(timestamp_dt) as last_seen
            FROM peripheral_events
            WHERE risk_score > 0.5
            GROUP BY peripheral_device_id
            ORDER BY max_risk_score DESC
            LIMIT ?
        """, (limit,))

        devices = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'devices': devices,
            'count': len(devices),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@peripheral_bp.route('/unauthorized', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_unauthorized_devices():
    """Get unauthorized peripheral devices"""
    limit = safe_int(request.args.get('limit', 50), default=50, min_val=1, max_val=200)

    conn = get_db_connection()
    if not conn:
        return jsonify({'devices': [], 'message': 'No data available'}), 200

    try:
        cursor = conn.execute("""
            SELECT
                peripheral_device_id,
                device_name,
                device_type,
                vendor_id,
                product_id,
                manufacturer,
                MAX(risk_score) as max_risk_score,
                COUNT(*) as event_count,
                MAX(timestamp_dt) as last_seen
            FROM peripheral_events
            WHERE is_authorized = 0
            GROUP BY peripheral_device_id
            ORDER BY max_risk_score DESC
            LIMIT ?
        """, (limit,))

        devices = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'devices': devices,
            'count': len(devices),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@peripheral_bp.route('/device/<device_id>', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_device_history(device_id):
    """Get event history for a specific device"""
    conn = get_db_connection()
    if not conn:
        return jsonify({'events': [], 'message': 'No data available'}), 200

    try:
        cursor = conn.execute("""
            SELECT *
            FROM peripheral_events
            WHERE peripheral_device_id = ?
            ORDER BY timestamp_ns DESC
        """, (device_id,))

        events = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'device_id': device_id,
            'events': events,
            'event_count': len(events),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@peripheral_bp.route('/search', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def search_devices():
    """Search peripheral devices by name, type, or manufacturer"""
    device_name = request.args.get('name', '')
    device_type = request.args.get('type', '')
    manufacturer = request.args.get('manufacturer', '')
    limit = safe_int(request.args.get('limit', 100), default=100, min_val=1, max_val=500)

    conn = get_db_connection()
    if not conn:
        return jsonify({'events': [], 'message': 'No data available'}), 200

    try:
        query = "SELECT * FROM peripheral_events WHERE 1=1"
        params = []

        if device_name:
            query += " AND device_name LIKE ?"
            params.append(f"%{device_name}%")

        if device_type:
            query += " AND device_type = ?"
            params.append(device_type)

        if manufacturer:
            query += " AND manufacturer LIKE ?"
            params.append(f"%{manufacturer}%")

        query += " ORDER BY timestamp_ns DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(query, params)
        events = [dict(row) for row in cursor.fetchall()]

        return jsonify({
            'events': events,
            'count': len(events),
            'filters_applied': {
                'name': device_name or None,
                'type': device_type or None,
                'manufacturer': manufacturer or None
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
