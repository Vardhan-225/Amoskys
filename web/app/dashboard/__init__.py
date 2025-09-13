"""
AMOSKYS Cortex Dashboard Module
Phase 2.4 - Neural Security Visualization Interface

This module implements the AMOSKYS Cortex Dashboard, providing real-time
visualization of security events, agent status, and system metrics through
an intelligent neural interface.
"""

from flask import Blueprint, render_template, jsonify, request
from datetime import datetime, timezone, timedelta
import json

# Constants
UTC_TIMEZONE_SUFFIX = '+00:00'

# Dashboard Blueprint
dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

# Import dashboard utilities
from .utils import (
    get_threat_timeline_data,
    get_agent_health_summary,
    get_system_metrics_snapshot,
    calculate_threat_score,
    get_event_clustering_data
)

@dashboard_bp.route('/')
def cortex_home():
    """AMOSKYS Cortex Dashboard - Main Neural Interface"""
    return render_template('dashboard/cortex.html')

@dashboard_bp.route('/cortex')
def cortex_dashboard():
    """AMOSKYS Cortex Dashboard - Command Center"""
    return render_template('dashboard/cortex.html')

@dashboard_bp.route('/soc')
def security_operations_center():
    """Security Operations Center - Live Threat Monitoring"""
    return render_template('dashboard/soc.html')

@dashboard_bp.route('/agents')
def agent_management():
    """Agent Management Dashboard - Neural Network Status"""
    return render_template('dashboard/agents.html')

@dashboard_bp.route('/system')
def system_monitoring():
    """System Health Monitoring - Platform Vitals"""
    return render_template('dashboard/system.html')

@dashboard_bp.route('/neural')
def neural_insights():
    """Neural Insights Dashboard - AI Detection Visualization"""
    return render_template('dashboard/neural.html')

# Real-time Data Endpoints
@dashboard_bp.route('/api/live/threats')
def live_threats():
    """Real-time threat feed for dashboard"""
    from ..api.events import EVENT_STORE
    
    # Get recent events (last 24 hours)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    
    recent_events = []
    for event in EVENT_STORE:
        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', UTC_TIMEZONE_SUFFIX))
        if event_time > cutoff:
            recent_events.append({
                'id': event['event_id'],
                'type': event['event_type'],
                'severity': event['severity'],
                'source_ip': event['source_ip'],
                'description': event['description'],
                'timestamp': event['timestamp'],
                'agent_id': event['agent_id']
            })
    
    # Sort by timestamp (newest first)
    recent_events.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        'status': 'success',
        'threats': recent_events[:50],  # Last 50 events
        'count': len(recent_events),
        'timestamp': now.isoformat()
    })

@dashboard_bp.route('/api/live/agents')
def live_agents():
    """Real-time agent status for dashboard"""
    from ..api.agents import AGENT_REGISTRY
    
    agents_data = []
    current_time = datetime.now(timezone.utc)
    
    for agent_id, info in AGENT_REGISTRY.items():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', UTC_TIMEZONE_SUFFIX))
        seconds_since_ping = (current_time - last_seen).total_seconds()
        
        # Determine status
        if seconds_since_ping <= 60:
            status = 'online'
            status_color = '#00ff88'
        elif seconds_since_ping <= 300:
            status = 'active'
            status_color = '#ffaa00'
        elif seconds_since_ping <= 600:
            status = 'stale'
            status_color = '#ff6600'
        else:
            status = 'offline'
            status_color = '#ff0000'
        
        agents_data.append({
            'agent_id': agent_id,
            'hostname': info.get('hostname', 'unknown'),
            'status': status,
            'status_color': status_color,
            'last_seen': info['last_seen'],
            'seconds_since_ping': int(seconds_since_ping),
            'platform': info.get('platform', 'unknown'),
            'capabilities': info.get('capabilities', [])
        })
    
    return jsonify({
        'status': 'success',
        'agents': agents_data,
        'total_agents': len(agents_data),
        'timestamp': current_time.isoformat()
    })

@dashboard_bp.route('/api/live/metrics')
def live_metrics():
    """Real-time system metrics for dashboard"""
    import psutil
    
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network I/O
        network = psutil.net_io_counters()
        
        # Process info
        process = psutil.Process()
        
        metrics = {
            'cpu': {
                'percent': cpu_percent,
                'count': psutil.cpu_count()
            },
            'memory': {
                'percent': memory.percent,
                'used_gb': memory.used / (1024**3),
                'total_gb': memory.total / (1024**3)
            },
            'disk': {
                'percent': (disk.used / disk.total) * 100,
                'used_gb': disk.used / (1024**3),
                'total_gb': disk.total / (1024**3)
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'process': {
                'memory_percent': process.memory_percent(),
                'cpu_percent': process.cpu_percent(),
                'threads': process.num_threads()
            }
        }
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@dashboard_bp.route('/api/live/threat-score')
def live_threat_score():
    """Real-time threat score calculation"""
    from ..api.events import EVENT_STORE
    
    # Calculate threat score based on recent events
    now = datetime.now(timezone.utc)
    last_hour = now - timedelta(hours=1)
    
    severity_weights = {'low': 1, 'medium': 3, 'high': 7, 'critical': 15}
    
    total_score = 0
    event_count = 0
    
    for event in EVENT_STORE:
        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', UTC_TIMEZONE_SUFFIX))
        if event_time > last_hour:
            severity = event['severity']
            total_score += severity_weights.get(severity, 1)
            event_count += 1
    
    # Normalize score (0-100)
    if event_count > 0:
        base_score = min(total_score, 100)
        # Apply time decay
        minutes_factor = min((now - last_hour).total_seconds() / 3600, 1.0)
        threat_score = int(base_score * minutes_factor)
    else:
        threat_score = 0
    
    # Determine threat level
    if threat_score >= 75:
        threat_level = 'CRITICAL'
        threat_color = '#ff0000'
    elif threat_score >= 50:
        threat_level = 'HIGH'
        threat_color = '#ff6600'
    elif threat_score >= 25:
        threat_level = 'MEDIUM'
        threat_color = '#ffaa00'
    else:
        threat_level = 'LOW'
        threat_color = '#00ff88'
    
    return jsonify({
        'status': 'success',
        'threat_score': threat_score,
        'threat_level': threat_level,
        'threat_color': threat_color,
        'event_count': event_count,
        'timestamp': now.isoformat()
    })

@dashboard_bp.route('/api/live/event-clustering')
def event_clustering():
    """Event clustering data for visualization"""
    from ..api.events import EVENT_STORE
    
    # Cluster events by type and source IP
    clusters = {
        'by_type': {},
        'by_severity': {},
        'by_source_ip': {},
        'by_hour': {}
    }
    
    now = datetime.now(timezone.utc)
    
    for event in EVENT_STORE:
        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', UTC_TIMEZONE_SUFFIX))
        
        # Cluster by type
        event_type = event['event_type']
        clusters['by_type'][event_type] = clusters['by_type'].get(event_type, 0) + 1
        
        # Cluster by severity
        severity = event['severity']
        clusters['by_severity'][severity] = clusters['by_severity'].get(severity, 0) + 1
        
        # Cluster by source IP (top 10)
        source_ip = event['source_ip']
        clusters['by_source_ip'][source_ip] = clusters['by_source_ip'].get(source_ip, 0) + 1
        
        # Cluster by hour (last 24 hours)
        hour_key = event_time.strftime('%H:00')
        clusters['by_hour'][hour_key] = clusters['by_hour'].get(hour_key, 0) + 1
    
    # Limit source IP clusters to top 10
    top_ips = sorted(clusters['by_source_ip'].items(), key=lambda x: x[1], reverse=True)[:10]
    clusters['by_source_ip'] = dict(top_ips)
    
    return jsonify({
        'status': 'success',
        'clusters': clusters,
        'timestamp': now.isoformat()
    })

@dashboard_bp.route('/api/neural/readiness')
def neural_readiness():
    """Neural engine readiness assessment"""
    from .utils import get_neural_readiness_status
    
    try:
        readiness_data = get_neural_readiness_status()
        
        return jsonify({
            'status': 'success',
            'readiness': readiness_data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500
