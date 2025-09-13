"""
AMOSKYS API System Module
System health, metrics, and administrative endpoints
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
from .auth import require_auth
import psutil
import platform
import os

system_bp = Blueprint('system', __name__, url_prefix='/system')

@system_bp.route('/health', methods=['GET'])
def system_health():
    """System health check endpoint (no auth required for monitoring)"""
    try:
        # Basic system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        health_status = 'healthy'
        
        # Determine health status based on metrics
        if cpu_percent > 90 or memory.percent > 90 or (disk.used / disk.total * 100) > 95:
            health_status = 'degraded'
        
        return jsonify({
            'status': health_status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'uptime': psutil.boot_time(),
            'system': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture()[0]
            },
            'metrics': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.used / disk.total * 100,
                'available_memory_gb': memory.available / (1024**3)
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e)
        }), 500

@system_bp.route('/info', methods=['GET'])
@require_auth()
def system_info():
    """Detailed system information (requires authentication)"""
    try:
        # Network interfaces
        network_info = {}
        for interface, addrs in psutil.net_if_addrs().items():
            network_info[interface] = [addr.address for addr in addrs]
        
        # Process information
        current_process = psutil.Process()
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'system': {
                'hostname': platform.node(),
                'platform': platform.platform(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture(),
                'boot_time': psutil.boot_time(),
                'timezone': str(datetime.now().astimezone().tzinfo)
            },
            'hardware': {
                'cpu_count': psutil.cpu_count(),
                'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
                'memory_total_gb': psutil.virtual_memory().total / (1024**3),
                'disk_total_gb': psutil.disk_usage('/').total / (1024**3)
            },
            'network': network_info,
            'process': {
                'pid': current_process.pid,
                'memory_percent': current_process.memory_percent(),
                'cpu_percent': current_process.cpu_percent(),
                'create_time': current_process.create_time(),
                'num_threads': current_process.num_threads()
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e)
        }), 500

@system_bp.route('/metrics', methods=['GET'])
@require_auth()
def system_metrics():
    """Detailed system performance metrics"""
    try:
        # CPU metrics
        cpu_times = psutil.cpu_times()
        cpu_stats = psutil.cpu_stats()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk metrics
        disk_usage = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # Network metrics
        network_io = psutil.net_io_counters()
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'cpu': {
                'percent': psutil.cpu_percent(interval=1),
                'count': psutil.cpu_count(),
                'times': cpu_times._asdict(),
                'stats': cpu_stats._asdict()
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free,
                'buffers': getattr(memory, 'buffers', 0),
                'cached': getattr(memory, 'cached', 0)
            },
            'swap': {
                'total': swap.total,
                'used': swap.used,
                'free': swap.free,
                'percent': swap.percent
            },
            'disk': {
                'total': disk_usage.total,
                'used': disk_usage.used,
                'free': disk_usage.free,
                'percent': disk_usage.used / disk_usage.total * 100,
                'io': disk_io._asdict() if disk_io else None
            },
            'network': {
                'io': network_io._asdict() if network_io else None
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e)
        }), 500

@system_bp.route('/status', methods=['GET'])
@require_auth()
def system_status():
    """AMOSKYS platform status and component health"""
    from ..api.agents import AGENT_REGISTRY
    from ..api.events import EVENT_STORE, EVENT_STATS
    
    # Calculate active agents
    current_time = datetime.now(timezone.utc)
    active_agents = 0
    
    for info in AGENT_REGISTRY.values():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', '+00:00'))
        if (current_time - last_seen).total_seconds() <= 300:  # 5 minutes
            active_agents += 1
    
    # Recent events (last hour)
    one_hour_ago = current_time.replace(hour=current_time.hour-1) if current_time.hour > 0 else current_time.replace(day=current_time.day-1, hour=23)
    recent_events = len([
        e for e in EVENT_STORE 
        if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) > one_hour_ago
    ])
    
    # System health check
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').used / psutil.disk_usage('/').total * 100
        
        # Determine overall health
        if cpu_percent > 90 or memory_percent > 90 or disk_percent > 95:
            system_health = 'degraded'
        elif cpu_percent > 70 or memory_percent > 70 or disk_percent > 80:
            system_health = 'warning'
        else:
            system_health = 'healthy'
    except (psutil.Error, OSError):
        system_health = 'unknown'
    
    return jsonify({
        'status': 'operational',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'platform': 'AMOSKYS Neural Security Command Platform',
        'version': '2.3.0-alpha',
        'components': {
            'api_gateway': 'operational',
            'web_interface': 'operational',
            'event_bus': 'ready',
            'neural_core': 'standby'
        },
        'metrics': {
            'total_agents': len(AGENT_REGISTRY),
            'active_agents': active_agents,
            'total_events': len(EVENT_STORE),
            'events_last_hour': recent_events,
            'system_health': system_health
        },
        'uptime': {
            'system_boot_time': psutil.boot_time(),
            'current_time': current_time.isoformat()
        }
    })

@system_bp.route('/config', methods=['GET'])
@require_auth(permissions=['system.config'])
def get_config():
    """Get current system configuration (admin only)"""
    # Only return non-sensitive configuration
    config = {
        'api_version': '2.3.0',
        'max_events_per_request': 1000,
        'agent_timeout_seconds': 300,
        'jwt_expiry_hours': 24,
        'rate_limiting': {
            'enabled': True,
            'requests_per_minute': 60
        },
        'features': {
            'event_ingestion': True,
            'agent_management': True,
            'real_time_monitoring': True,
            'neural_detection': False  # Phase 2.5
        }
    }
    
    return jsonify({
        'status': 'success',
        'config': config
    })

@system_bp.route('/logs', methods=['GET'])
@require_auth(permissions=['system.logs'])
def get_logs():
    """Get recent system logs (admin only)"""
    # This is a placeholder - in production, integrate with proper logging system
    logs = [
        {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': 'INFO',
            'component': 'api_gateway',
            'message': 'API Gateway Phase 2.3 initialized successfully'
        },
        {
            'timestamp': (datetime.now(timezone.utc).replace(minute=datetime.now().minute-1)).isoformat(),
            'level': 'INFO',
            'component': 'auth',
            'message': 'JWT authentication enabled'
        },
        {
            'timestamp': (datetime.now(timezone.utc).replace(minute=datetime.now().minute-2)).isoformat(),
            'level': 'INFO',
            'component': 'events',
            'message': 'Event ingestion endpoint activated'
        }
    ]
    
    return jsonify({
        'status': 'success',
        'logs': logs
    })
