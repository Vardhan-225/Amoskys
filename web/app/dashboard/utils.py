"""
AMOSKYS Cortex Dashboard Utilities
Phase 2.4 - Neural Security Data Processing

This module provides utility functions for the AMOSKYS Cortex Dashboard,
including data aggregation, visualization helpers, and real-time processing.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import statistics
import json

# Constants
UTC_TIMEZONE_SUFFIX = '+00:00'


def get_threat_timeline_data(hours: int = 24) -> Dict[str, Any]:
    """
    Generate threat timeline data for visualization
    
    Args:
        hours: Number of hours to look back
        
    Returns:
        Dict containing timeline data and statistics
    """
    from ..api.events import EVENT_STORE
    
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    
    timeline_data = []
    hourly_counts = {}
    severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    
    for event in EVENT_STORE:
        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', UTC_TIMEZONE_SUFFIX))
        
        if event_time > cutoff:
            # Add to timeline
            timeline_data.append({
                'timestamp': event['timestamp'],
                'type': event['event_type'],
                'severity': event['severity'],
                'source': event['source_ip'],
                'description': event['description']
            })
            
            # Count by hour
            hour_key = event_time.strftime('%Y-%m-%d %H:00')
            hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
            
            # Count by severity
            severity_counts[event['severity']] += 1
    
    return {
        'timeline': sorted(timeline_data, key=lambda x: x['timestamp']),
        'hourly_counts': hourly_counts,
        'severity_distribution': severity_counts,
        'total_events': len(timeline_data),
        'time_range': f'Last {hours} hours'
    }


def get_agent_health_summary() -> Dict[str, Any]:
    """
    Generate comprehensive agent health summary
    
    Returns:
        Dict containing agent status and health metrics
    """
    from ..api.agents import AGENT_REGISTRY
    
    current_time = datetime.now(timezone.utc)
    status_counts = {'online': 0, 'active': 0, 'stale': 0, 'offline': 0}
    agent_details = []
    response_times = []
    
    for agent_id, info in AGENT_REGISTRY.items():
        last_seen = datetime.fromisoformat(info['last_seen'].replace('Z', UTC_TIMEZONE_SUFFIX))
        seconds_since_ping = (current_time - last_seen).total_seconds()
        
        # Determine status
        if seconds_since_ping <= 60:
            status = 'online'
        elif seconds_since_ping <= 300:
            status = 'active'
        elif seconds_since_ping <= 600:
            status = 'stale'
        else:
            status = 'offline'
        
        status_counts[status] += 1
        response_times.append(seconds_since_ping)
        
        agent_details.append({
            'agent_id': agent_id,
            'status': status,
            'hostname': info.get('hostname', 'unknown'),
            'platform': info.get('platform', 'unknown'),
            'last_seen': info['last_seen'],
            'response_time': seconds_since_ping,
            'capabilities': info.get('capabilities', [])
        })
    
    # Calculate health score (0-100)
    total_agents = len(agent_details)
    if total_agents > 0:
        health_score = int(
            (status_counts['online'] * 1.0 + 
             status_counts['active'] * 0.8 + 
             status_counts['stale'] * 0.4) / total_agents * 100
        )
    else:
        health_score = 0
    
    return {
        'total_agents': total_agents,
        'status_distribution': status_counts,
        'health_score': health_score,
        'agent_details': sorted(agent_details, key=lambda x: x['response_time']),
        'avg_response_time': statistics.mean(response_times) if response_times else 0,
        'max_response_time': max(response_times) if response_times else 0
    }


def get_system_metrics_snapshot() -> Dict[str, Any]:
    """
    Generate system metrics snapshot for monitoring
    
    Returns:
        Dict containing current system performance metrics
    """
    import psutil
    
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        
        # Network metrics
        network = psutil.net_io_counters()
        
        # Process metrics
        current_process = psutil.Process()
        
        return {
            'cpu': {
                'percent': round(cpu_percent, 1),
                'cores': cpu_count,
                'status': 'critical' if cpu_percent > 85 else 'warning' if cpu_percent > 70 else 'healthy'
            },
            'memory': {
                'percent': round(memory.percent, 1),
                'used_gb': round(memory.used / (1024**3), 2),
                'total_gb': round(memory.total / (1024**3), 2),
                'status': 'critical' if memory.percent > 90 else 'warning' if memory.percent > 75 else 'healthy'
            },
            'disk': {
                'percent': round((disk.used / disk.total) * 100, 1),
                'used_gb': round(disk.used / (1024**3), 2),
                'total_gb': round(disk.total / (1024**3), 2),
                'status': 'critical' if disk.used/disk.total > 0.9 else 'warning' if disk.used/disk.total > 0.8 else 'healthy'
            },
            'network': {
                'bytes_sent_mb': round(network.bytes_sent / (1024**2), 2),
                'bytes_recv_mb': round(network.bytes_recv / (1024**2), 2),
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'process': {
                'memory_percent': round(current_process.memory_percent(), 2),
                'cpu_percent': round(current_process.cpu_percent(), 1),
                'threads': current_process.num_threads(),
                'status': 'healthy'
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        return {
            'error': f'Failed to collect metrics: {str(e)}',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def calculate_threat_score(time_window_hours: int = 1) -> Dict[str, Any]:
    """
    Calculate current threat score based on recent events
    
    Args:
        time_window_hours: Time window for threat calculation
        
    Returns:
        Dict containing threat score and analysis
    """
    from ..api.events import EVENT_STORE
    
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=time_window_hours)
    
    # Severity weights for threat calculation
    severity_weights = {
        'low': 1,
        'medium': 3,
        'high': 7,
        'critical': 15
    }
    
    # Event type multipliers
    type_multipliers = {
        'network_anomaly': 1.2,
        'intrusion_attempt': 1.5,
        'malware_detection': 2.0,
        'data_exfiltration': 2.5,
        'system_compromise': 3.0
    }
    
    total_score = 0
    event_count = 0
    event_breakdown = {}
    
    for event in EVENT_STORE:
        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', UTC_TIMEZONE_SUFFIX))
        
        if event_time > cutoff:
            severity = event['severity']
            event_type = event['event_type']
            
            # Calculate event score
            base_score = severity_weights.get(severity, 1)
            type_multiplier = type_multipliers.get(event_type, 1.0)
            event_score = base_score * type_multiplier
            
            total_score += event_score
            event_count += 1
            
            # Track event breakdown
            if event_type not in event_breakdown:
                event_breakdown[event_type] = {'count': 0, 'score': 0}
            event_breakdown[event_type]['count'] += 1
            event_breakdown[event_type]['score'] += event_score
    
    # Normalize score (0-100)
    if event_count > 0:
        # Base normalization
        normalized_score = min(total_score / 10, 100)  # Divide by 10 for reasonable scaling
        
        # Apply time decay
        time_factor = min(time_window_hours / 24, 1.0)  # Scale based on time window
        threat_score = int(normalized_score * time_factor)
    else:
        threat_score = 0
    
    # Determine threat level and color
    if threat_score >= 75:
        threat_level = 'CRITICAL'
        threat_color = '#ff0000'
        recommended_action = 'Immediate response required'
    elif threat_score >= 50:
        threat_level = 'HIGH'
        threat_color = '#ff6600'
        recommended_action = 'Investigate and respond'
    elif threat_score >= 25:
        threat_level = 'MEDIUM'
        threat_color = '#ffaa00'
        recommended_action = 'Monitor closely'
    else:
        threat_level = 'LOW'
        threat_color = '#00ff88'
        recommended_action = 'Normal monitoring'
    
    return {
        'threat_score': threat_score,
        'threat_level': threat_level,
        'threat_color': threat_color,
        'recommended_action': recommended_action,
        'event_count': event_count,
        'time_window_hours': time_window_hours,
        'event_breakdown': event_breakdown,
        'calculation_details': {
            'raw_score': total_score,
            'normalized_score': min(total_score / 10, 100) if event_count > 0 else 0
        }
    }


def get_event_clustering_data() -> Dict[str, Any]:
    """
    Generate event clustering data for visualization
    
    Returns:
        Dict containing various event clustering analyses
    """
    from ..api.events import EVENT_STORE
    
    clusters = {
        'by_type': {},
        'by_severity': {},
        'by_source_ip': {},
        'by_hour': {},
        'by_agent': {}
    }
    
    # Time-based clustering (last 24 hours)
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    
    for event in EVENT_STORE:
        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', UTC_TIMEZONE_SUFFIX))
        
        if event_time > last_24h:
            # Cluster by type
            event_type = event['event_type']
            clusters['by_type'][event_type] = clusters['by_type'].get(event_type, 0) + 1
            
            # Cluster by severity
            severity = event['severity']
            clusters['by_severity'][severity] = clusters['by_severity'].get(severity, 0) + 1
            
            # Cluster by source IP
            source_ip = event['source_ip']
            clusters['by_source_ip'][source_ip] = clusters['by_source_ip'].get(source_ip, 0) + 1
            
            # Cluster by hour
            hour_key = event_time.strftime('%H:00')
            clusters['by_hour'][hour_key] = clusters['by_hour'].get(hour_key, 0) + 1
            
            # Cluster by agent
            agent_id = event['agent_id']
            clusters['by_agent'][agent_id] = clusters['by_agent'].get(agent_id, 0) + 1
    
    # Sort and limit results for better visualization
    clusters['by_source_ip'] = dict(
        sorted(clusters['by_source_ip'].items(), key=lambda x: x[1], reverse=True)[:15]
    )
    
    # Calculate cluster statistics
    total_events = sum(clusters['by_type'].values())
    most_active_type = max(clusters['by_type'].items(), key=lambda x: x[1]) if clusters['by_type'] else ('none', 0)
    most_active_ip = max(clusters['by_source_ip'].items(), key=lambda x: x[1]) if clusters['by_source_ip'] else ('none', 0)
    
    return {
        'clusters': clusters,
        'statistics': {
            'total_events': total_events,
            'unique_types': len(clusters['by_type']),
            'unique_ips': len(clusters['by_source_ip']),
            'unique_agents': len(clusters['by_agent']),
            'most_active_type': most_active_type,
            'most_active_ip': most_active_ip
        },
        'time_range': 'Last 24 hours'
    }


def format_bytes(bytes_value: float) -> str:
    """
    Format bytes into human-readable format
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.2 GB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_time_duration(seconds: float) -> str:
    """
    Format seconds into human-readable duration
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)
        return f"{minutes}m {remaining_seconds}s"
    else:
        hours = int(seconds // 3600)
        remaining_minutes = int((seconds % 3600) // 60)
        return f"{hours}h {remaining_minutes}m"


def get_neural_readiness_status() -> Dict[str, Any]:
    """
    Assess system readiness for Phase 2.5 Neural Engine integration
    
    Returns:
        Dict containing neural readiness assessment
    """
    # Check data pipeline health
    threat_data = get_threat_timeline_data(24)
    agent_data = get_agent_health_summary()
    system_data = get_system_metrics_snapshot()
    
    # Neural readiness criteria
    criteria = {
        'data_flow': {
            'description': 'Sufficient event data for training',
            'status': 'ready' if threat_data['total_events'] >= 10 else 'limited',
            'score': min(threat_data['total_events'] / 50, 1.0) * 100
        },
        'agent_connectivity': {
            'description': 'Agent network operational',
            'status': 'ready' if agent_data['health_score'] >= 80 else 'degraded' if agent_data['health_score'] >= 50 else 'critical',
            'score': agent_data['health_score']
        },
        'system_performance': {
            'description': 'System resources adequate',
            'status': 'ready' if system_data.get('cpu', {}).get('status') == 'healthy' and system_data.get('memory', {}).get('status') == 'healthy' else 'warning',
            'score': 100 - max(system_data.get('cpu', {}).get('percent', 0), system_data.get('memory', {}).get('percent', 0))
        }
    }
    
    # Calculate overall readiness score
    overall_score = sum(c['score'] for c in criteria.values()) / len(criteria)
    
    # Determine readiness level
    if overall_score >= 85:
        readiness_level = 'OPTIMAL'
        readiness_color = '#00ff88'
    elif overall_score >= 70:
        readiness_level = 'READY'
        readiness_color = '#ffaa00'
    elif overall_score >= 50:
        readiness_level = 'LIMITED'
        readiness_color = '#ff6600'
    else:
        readiness_level = 'NOT_READY'
        readiness_color = '#ff0000'
    
    return {
        'overall_score': round(overall_score, 1),
        'readiness_level': readiness_level,
        'readiness_color': readiness_color,
        'criteria': criteria,
        'recommendations': _get_neural_recommendations(criteria),
        'next_phase_eta': 'Phase 2.5 Neural Engine integration possible' if overall_score >= 70 else 'Optimization needed before Phase 2.5'
    }


def _get_neural_recommendations(criteria: Dict[str, Any]) -> List[str]:
    """
    Generate recommendations for improving neural readiness
    
    Args:
        criteria: Neural readiness criteria assessment
        
    Returns:
        List of recommendation strings
    """
    recommendations = []
    
    if criteria['data_flow']['score'] < 80:
        recommendations.append("Increase event data collection to improve training dataset")
    
    if criteria['agent_connectivity']['score'] < 80:
        recommendations.append("Improve agent connectivity and reduce response times")
    
    if criteria['system_performance']['score'] < 80:
        recommendations.append("Optimize system resources for neural processing workloads")
    
    if not recommendations:
        recommendations.append("System ready for Phase 2.5 Neural Engine implementation")
    
    return recommendations


# Live Data Functions for Dashboard APIs
# These functions provide real-time data for dashboard endpoints

def get_live_threats_data() -> Dict[str, Any]:
    """Get live threats data for real-time dashboard updates"""
    timeline_data = get_threat_timeline_data(hours=24)
    
    return {
        'recent_events': timeline_data['timeline'][-10:],  # Last 10 events
        'hourly_stats': timeline_data['hourly_counts'],
        'severity_distribution': timeline_data['severity_distribution'],
        'total_events': len(timeline_data['timeline']),
        'threat_trend': 'stable',  # Default trend value
        'last_updated': datetime.now(timezone.utc).isoformat()
    }

def get_live_agents_data() -> Dict[str, Any]:
    """Get live agent data for real-time dashboard updates"""
    agent_summary = get_agent_health_summary()
    
    return {
        'agent_count': agent_summary['total_agents'],
        'online_agents': agent_summary['status_distribution']['online'],
        'offline_agents': agent_summary['status_distribution']['offline'],
        'agent_list': agent_summary['agent_details'],
        'network_health': agent_summary['health_score'],
        'performance_metrics': {
            'avg_response_time': agent_summary['avg_response_time'],
            'max_response_time': agent_summary['max_response_time']
        },
        'last_updated': datetime.now(timezone.utc).isoformat()
    }

def get_live_metrics_data() -> Dict[str, Any]:
    """Get live system metrics for real-time dashboard updates"""
    metrics = get_system_metrics_snapshot()
    
    return {
        'cpu_usage': metrics['cpu']['percent'],
        'memory_usage': metrics['memory']['percent'],
        'disk_usage': metrics['disk']['percent'],
        'network_io': metrics['network'],
        'process_count': metrics.get('processes', {}).get('total', 0),
        'uptime': 0,  # Could be calculated from system boot time
        'last_updated': datetime.now(timezone.utc).isoformat()
    }
