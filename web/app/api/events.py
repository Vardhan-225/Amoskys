"""
AMOSKYS API Events Module
Security event ingestion and management
"""

from flask import Blueprint, request, jsonify, g
from datetime import datetime, timezone
from .agent_auth import require_auth
from .rate_limiter import require_rate_limit
import hashlib
import json

events_bp = Blueprint('events', __name__, url_prefix='/events')

# In-memory event store (replace with database in production)
EVENT_STORE = []
EVENT_STATS = {
    'total_events': 0,
    'events_last_hour': 0,
    'events_by_type': {},
    'events_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
}

def validate_event_schema(event_data):
    """Validate incoming event data structure"""
    required_fields = ['event_type', 'severity', 'source_ip', 'description']
    
    for field in required_fields:
        if field not in event_data:
            return False, f"Missing required field: {field}"
    
    # Validate severity levels
    valid_severities = ['low', 'medium', 'high', 'critical']
    if event_data['severity'] not in valid_severities:
        return False, f"Invalid severity. Must be one of: {valid_severities}"
    
    return True, None

@events_bp.route('/submit', methods=['POST'])
@require_auth(permissions=['event.submit'])
@require_rate_limit(max_requests=100, window_seconds=60)
def submit_event():
    """Submit a security event to AMOSKYS"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400
    
    # Validate event schema
    is_valid, error_msg = validate_event_schema(data)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    agent_id = g.current_user['agent_id']
    
    # Create event record
    event_record = {
        'event_id': hashlib.sha256(f"{agent_id}-{datetime.now().isoformat()}-{json.dumps(data, sort_keys=True)}".encode()).hexdigest()[:16],
        'agent_id': agent_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': data['event_type'],
        'severity': data['severity'],
        'source_ip': data['source_ip'],
        'destination_ip': data.get('destination_ip'),
        'source_port': data.get('source_port'),
        'destination_port': data.get('destination_port'),
        'protocol': data.get('protocol'),
        'description': data['description'],
        'metadata': data.get('metadata', {}),
        'status': 'new'
    }
    
    # Store event
    EVENT_STORE.append(event_record)
    
    # Update statistics
    EVENT_STATS['total_events'] += 1
    EVENT_STATS['events_by_type'][data['event_type']] = EVENT_STATS['events_by_type'].get(data['event_type'], 0) + 1
    EVENT_STATS['events_by_severity'][data['severity']] += 1
    
    return jsonify({
        'status': 'success',
        'message': 'Event submitted successfully',
        'event_id': event_record['event_id'],
        'timestamp': event_record['timestamp']
    })

@events_bp.route('/list', methods=['GET'])
@require_auth()
def list_events():
    """List recent security events"""
    # Query parameters
    limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    agent_id = request.args.get('agent_id')
    
    # Filter events
    filtered_events = EVENT_STORE.copy()
    
    if severity:
        filtered_events = [e for e in filtered_events if e['severity'] == severity]
    
    if event_type:
        filtered_events = [e for e in filtered_events if e['event_type'] == event_type]
    
    if agent_id:
        filtered_events = [e for e in filtered_events if e['agent_id'] == agent_id]
    
    # Sort by timestamp (newest first) and limit
    filtered_events.sort(key=lambda x: x['timestamp'], reverse=True)
    filtered_events = filtered_events[:limit]
    
    return jsonify({
        'status': 'success',
        'event_count': len(filtered_events),
        'total_events': len(EVENT_STORE),
        'events': filtered_events
    })

@events_bp.route('/<event_id>', methods=['GET'])
@require_auth()
def get_event(event_id):
    """Get details of a specific event"""
    event = next((e for e in EVENT_STORE if e['event_id'] == event_id), None)
    
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    
    return jsonify({
        'status': 'success',
        'event': event
    })

@events_bp.route('/<event_id>/status', methods=['PUT'])
@require_auth(permissions=['event.update'])
def update_event_status(event_id):
    """Update event status (new, investigating, resolved, false_positive)"""
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({'error': 'Status field required'}), 400
    
    valid_statuses = ['new', 'investigating', 'resolved', 'false_positive']
    if data['status'] not in valid_statuses:
        return jsonify({'error': f'Invalid status. Must be one of: {valid_statuses}'}), 400
    
    # Find and update event
    event = next((e for e in EVENT_STORE if e['event_id'] == event_id), None)
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    
    event['status'] = data['status']
    event['updated_at'] = datetime.now(timezone.utc).isoformat()
    event['updated_by'] = g.current_user['agent_id']
    
    if 'notes' in data:
        event['notes'] = data['notes']
    
    return jsonify({
        'status': 'success',
        'message': f'Event {event_id} status updated to {data["status"]}',
        'event': event
    })

@events_bp.route('/stats', methods=['GET'])
@require_auth()
def event_statistics():
    """Get event statistics and trends"""
    # Calculate events in last hour
    current_time = datetime.now(timezone.utc)
    one_hour_ago = current_time.replace(hour=current_time.hour-1) if current_time.hour > 0 else current_time.replace(day=current_time.day-1, hour=23)
    
    events_last_hour = len([
        e for e in EVENT_STORE 
        if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) > one_hour_ago
    ])
    
    # Recent event types
    recent_types = {}
    for event in EVENT_STORE[-100:]:  # Last 100 events
        event_type = event['event_type']
        recent_types[event_type] = recent_types.get(event_type, 0) + 1
    
    return jsonify({
        'status': 'success',
        'timestamp': current_time.isoformat(),
        'stats': {
            'total_events': len(EVENT_STORE),
            'events_last_hour': events_last_hour,
            'events_by_severity': EVENT_STATS['events_by_severity'],
            'recent_event_types': recent_types,
            'average_events_per_hour': round(len(EVENT_STORE) / max(1, (current_time.hour + 1)), 2)
        }
    })

@events_bp.route('/schema', methods=['GET'])
def event_schema():
    """Get the event submission schema"""
    schema = {
        'required_fields': [
            'event_type',
            'severity',
            'source_ip',
            'description'
        ],
        'optional_fields': [
            'destination_ip',
            'source_port',
            'destination_port',
            'protocol',
            'metadata'
        ],
        'field_descriptions': {
            'event_type': 'Type of security event (e.g., network_anomaly, malware_detection, intrusion_attempt)',
            'severity': 'Event severity level: low, medium, high, critical',
            'source_ip': 'Source IP address of the event',
            'destination_ip': 'Destination IP address (if applicable)',
            'source_port': 'Source port number (if applicable)',
            'destination_port': 'Destination port number (if applicable)',
            'protocol': 'Network protocol (TCP, UDP, ICMP, etc.)',
            'description': 'Human-readable description of the event',
            'metadata': 'Additional event-specific data as key-value pairs'
        },
        'severity_levels': ['low', 'medium', 'high', 'critical'],
        'example_event': {
            'event_type': 'network_anomaly',
            'severity': 'medium',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'source_port': 443,
            'destination_port': 22,
            'protocol': 'TCP',
            'description': 'Unusual SSH connection attempt from HTTPS port',
            'metadata': {
                'bytes_transferred': 1024,
                'connection_duration': 30,
                'user_agent': 'curl/7.68.0'
            }
        }
    }
    
    return jsonify({
        'status': 'success',
        'schema': schema
    })
