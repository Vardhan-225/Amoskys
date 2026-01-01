"""
AMOSKYS Cortex Dashboard Module
Phase 2.4 - Neural Security Visualization Interface

This module implements the AMOSKYS Cortex Dashboard, providing real-time
visualization of security events, agent status, and system metrics through
an intelligent neural interface.
"""

from flask import Blueprint, render_template, jsonify, request
from datetime import datetime, timezone, timedelta
from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login, get_current_user
import json
import time

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
@require_login
def cortex_home():
    """AMOSKYS Cortex Dashboard - Main Neural Interface"""
    user = get_current_user()
    return render_template('dashboard/cortex.html', user=user)

@dashboard_bp.route('/cortex')
@require_login
def cortex_dashboard():
    """AMOSKYS Cortex Dashboard - Command Center"""
    user = get_current_user()
    return render_template('dashboard/cortex.html', user=user)

@dashboard_bp.route('/marketplace')
@require_login
def agent_marketplace():
    """Agent Marketplace - Perspective Selection and Deployment"""
    user = get_current_user()
    return render_template('dashboard/marketplace.html', user=user)

@dashboard_bp.route('/evidence-chain')
@require_login
def evidence_chain_viewer():
    """Evidence Chain Viewer - Attack Reconstruction and Correlation"""
    user = get_current_user()
    return render_template('dashboard/evidence-chain.html', user=user)

@dashboard_bp.route('/timeline-replay')
@require_login
def timeline_replay():
    """Threat Timeline Replay - Step-by-step Attack Reconstruction"""
    user = get_current_user()
    return render_template('dashboard/timeline-replay.html', user=user)

@dashboard_bp.route('/query-builder')
@require_login
def query_builder():
    """Query Builder - Complex Security Event Query Interface"""
    user = get_current_user()
    return render_template('dashboard/query-builder.html', user=user)

@dashboard_bp.route('/perspective-selector')
@require_login
def perspective_selector():
    """Agent Perspective Selector - Multi-viewpoint Analysis Configuration"""
    user = get_current_user()
    return render_template('dashboard/perspective-selector.html', user=user)

@dashboard_bp.route('/soc')
@require_login
def security_operations_center():
    """Security Operations Center - Live Threat Monitoring"""
    user = get_current_user()
    return render_template('dashboard/soc.html', user=user)

@dashboard_bp.route('/agents')
@require_login
def agent_management():
    """Agent Management Dashboard - Neural Network Status"""
    user = get_current_user()
    return render_template('dashboard/agents.html', user=user)

@dashboard_bp.route('/system')
@require_login
def system_monitoring():
    """System Health Monitoring - Platform Vitals"""
    user = get_current_user()
    return render_template('dashboard/system.html', user=user)

@dashboard_bp.route('/neural')
@require_login
def neural_insights():
    """Neural Insights Dashboard - AI Detection Visualization"""
    user = get_current_user()
    return render_template('dashboard/neural.html', user=user)

@dashboard_bp.route('/processes')
@require_login
def process_telemetry():
    """Process Telemetry Dashboard - Mac Process Monitoring"""
    user = get_current_user()
    return render_template('dashboard/processes.html', user=user)

@dashboard_bp.route('/peripherals')
@require_login
def peripheral_monitoring():
    """Peripheral Monitoring Dashboard - USB/Bluetooth Device Tracking"""
    user = get_current_user()
    return render_template('dashboard/peripherals.html', user=user)

@dashboard_bp.route('/database')
@require_login
def database_manager():
    """Database Manager - Zero-Trust Data Management"""
    user = get_current_user()
    return render_template('dashboard/database_manager.html', user=user)

@dashboard_bp.route('/my-agents')
@require_login
def my_agents():
    """User Agent Management - Deploy and Monitor Your Agents"""
    user = get_current_user()
    return render_template('dashboard/my-agents.html', user=user)

@dashboard_bp.route('/deploy')
@require_login
def deploy_agent():
    """Agent Deployment Portal - Download and Deploy"""
    user = get_current_user()
    return render_template('dashboard/deploy.html', user=user)

# Real-time Data Endpoints
@dashboard_bp.route('/api/live/threats')
@require_rate_limit(max_requests=100, window_seconds=60)
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
@require_rate_limit(max_requests=100, window_seconds=60)
def live_agents():
    """Real-time agent status for dashboard with actual process detection"""
    from .agent_discovery import get_all_agents_status

    agent_data = get_all_agents_status()

    # Format for dashboard consumption
    agents_formatted = []
    for agent in agent_data['agents']:
        # Determine uptime from first process if running
        uptime_seconds = 0
        if agent['processes']:
            uptime_seconds = agent['processes'][0]['uptime_seconds']

        agents_formatted.append({
            'agent_id': agent['agent_id'],
            'hostname': agent.get('name', agent['agent_id']),
            'status': agent['status'],
            'status_color': agent.get('color', '#00ff88'),
            'last_seen': agent['last_check'],
            'seconds_since_ping': 0 if agent['running'] else 999999,
            'platform': agent_data['platform'],
            'capabilities': agent['capabilities'],
            'running': agent['running'],
            'instances': agent['instances'],
            'monitors': agent['monitors'],
            'neurons': agent['neurons'],
            'blockers': agent['blockers'],
            'warnings': agent['warnings'],
            'uptime_seconds': uptime_seconds,
            'critical': agent['critical']
        })

    return jsonify({
        'status': 'success',
        'agents': agents_formatted,
        'total_agents': len(agents_formatted),
        'summary': agent_data['summary'],
        'timestamp': agent_data['timestamp']
    })

@dashboard_bp.route('/api/available-agents')
def available_agents():
    """List available agent types that can be deployed on this platform"""
    from .agent_discovery import get_available_agents, get_platform_name

    available_agents_list = get_available_agents()
    current_time = datetime.now(timezone.utc)

    return jsonify({
        'status': 'success',
        'platform': get_platform_name(),
        'agents': available_agents_list,
        'count': len(available_agents_list),
        'timestamp': current_time.isoformat()
    })

@dashboard_bp.route('/api/live/metrics')
@require_rate_limit(max_requests=100, window_seconds=60)
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
                'count': psutil.cpu_count(),
                'cores': psutil.cpu_count(),
                'status': 'healthy' if cpu_percent < 80 else ('warning' if cpu_percent < 90 else 'critical')
            },
            'memory': {
                'percent': memory.percent,
                'used_gb': memory.used / (1024**3),
                'total_gb': memory.total / (1024**3),
                'available_gb': memory.available / (1024**3),
                'status': 'healthy' if memory.percent < 80 else ('warning' if memory.percent < 90 else 'critical')
            },
            'disk': {
                'percent': (disk.used / disk.total) * 100,
                'used_gb': disk.used / (1024**3),
                'total_gb': disk.total / (1024**3),
                'status': 'healthy' if (disk.used / disk.total * 100) < 80 else ('warning' if (disk.used / disk.total * 100) < 90 else 'critical')
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'bytes_sent_mb': network.bytes_sent / (1024**2),
                'bytes_recv_mb': network.bytes_recv / (1024**2),
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'process': {
                'memory_percent': process.memory_percent(),
                'cpu_percent': process.cpu_percent(),
                'threads': process.num_threads(),
                'status': 'running'
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

# Agent Control Endpoints (Phase 8)
@dashboard_bp.route('/api/agents/status', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def agents_detailed_status():
    """Get detailed status of all agents with health checks"""
    from .agent_control import get_all_agents_status_detailed
    
    try:
        status_data = get_all_agents_status_detailed()
        return jsonify({
            'status': 'success',
            'data': status_data,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@dashboard_bp.route('/api/agents/<agent_id>/status', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def agent_status(agent_id):
    """Get detailed status of a specific agent"""
    from .agent_control import get_agent_status
    
    try:
        status = get_agent_status(agent_id)
        return jsonify({
            'status': 'success',
            'data': status,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@dashboard_bp.route('/api/agents/<agent_id>/start', methods=['POST'])
@require_rate_limit(max_requests=20, window_seconds=60)
def start_agent(agent_id):
    """Start a stopped agent"""
    from .agent_control import start_agent as start_agent_fn
    
    try:
        result = start_agent_fn(agent_id)
        status_code = 200 if result.get('status') in ('started', 'already_running') else 400
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({
            'status': 'error',
            'agent_id': agent_id,
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@dashboard_bp.route('/api/agents/<agent_id>/stop', methods=['POST'])
@require_rate_limit(max_requests=20, window_seconds=60)
def stop_agent(agent_id):
    """Stop a running agent"""
    from .agent_control import stop_agent as stop_agent_fn
    
    try:
        result = stop_agent_fn(agent_id)
        status_code = 200 if result.get('status') in ('stopped', 'force_killed', 'not_running') else 400
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({
            'status': 'error',
            'agent_id': agent_id,
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@dashboard_bp.route('/api/agents/<agent_id>/health', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def agent_health_check(agent_id):
    """Perform health check on a specific agent"""
    from .agent_control import health_check_agent
    
    try:
        health = health_check_agent(agent_id)
        status_code = 200 if health.get('healthy') else 400
        return jsonify({
            'status': 'success',
            'data': health,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), status_code
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@dashboard_bp.route('/api/agents/<agent_id>/logs', methods=['GET'])
@require_rate_limit(max_requests=50, window_seconds=60)
def agent_logs(agent_id):
    """Get startup logs for an agent"""
    from .agent_control import get_startup_logs
    
    lines = request.args.get('lines', default=50, type=int)
    
    try:
        logs = get_startup_logs(agent_id, lines=min(lines, 500))
        return jsonify({
            'status': 'success',
            'data': logs,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

@dashboard_bp.route('/api/agents/restart-all', methods=['POST'])
@require_rate_limit(max_requests=5, window_seconds=60)
def restart_all_agents():
    """Restart all agents (with proper shutdown and restart)"""
    from .agent_control import stop_agent as stop_agent_fn, start_agent as start_agent_fn
    from .agent_discovery import AGENT_CATALOG
    
    try:
        results = {
            'total': len(AGENT_CATALOG),
            'stopped': 0,
            'started': 0,
            'failed': 0,
            'agents': {}
        }
        
        # First, stop all running agents
        for agent_id in AGENT_CATALOG:
            stop_result = stop_agent_fn(agent_id)
            if stop_result.get('status') in ('stopped', 'force_killed', 'not_running'):
                results['stopped'] += 1
            results['agents'][agent_id] = {'stopped': stop_result.get('status')}
        
        # Wait a moment between shutdown and startup
        time.sleep(2)
        
        # Then, start critical agents
        for agent_id, config in AGENT_CATALOG.items():
            if config.get('critical', False):
                start_result = start_agent_fn(agent_id)
                if start_result.get('status') in ('started', 'already_running'):
                    results['started'] += 1
                else:
                    results['failed'] += 1
                results['agents'][agent_id]['started'] = start_result.get('status')
        
        return jsonify({
            'status': 'success',
            'data': results,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500
