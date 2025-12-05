"""
AMOSKYS Agent Discovery and Monitoring
Discovers running agents, monitors health, and maps to neural architecture
"""

import psutil
import socket
import platform
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# Comprehensive Agent Registry
AGENT_CATALOG = {
    'eventbus': {
        'id': 'eventbus',
        'name': 'EventBus Server',
        'description': 'Central message broker for distributed telemetry ingestion via gRPC with mTLS',
        'type': 'Infrastructure',
        'port': 50051,
        'platform': ['linux', 'darwin', 'windows'],
        'capabilities': ['message-routing', 'grpc-server', 'tls-auth', 'deduplication', 'backpressure'],
        'monitors': ['FlowEvents', 'ProcessEvents', 'NetworkEvents', 'SNMPEvents'],
        'path': 'amoskys-eventbus',
        'process_patterns': ['amoskys-eventbus', 'eventbus'],
        'protocol': 'gRPC/mTLS',
        'neurons': ['Ingestion Layer', 'Message Bus', 'Event Router'],
        'guarded_resources': {
            'infrastructure': ['Event Distribution', 'Message Queue'],
            'protocols': ['gRPC', 'TLS 1.3']
        },
        'critical': True,
        'color': '#FF6B35'
    },
    'proc_agent': {
        'id': 'proc_agent',
        'name': 'Process Monitor Agent',
        'description': 'Native process monitoring for macOS/Linux with behavioral analysis and anomaly detection',
        'type': 'Collector',
        'port': None,
        'platform': ['darwin', 'linux'],
        'capabilities': ['process-monitoring', 'cpu-tracking', 'memory-tracking', 'lifecycle-events', 'threat-detection'],
        'monitors': ['Mac Processes', 'Linux Processes', 'Resource Usage', 'Process Trees', 'Suspicious Behavior'],
        'path': 'src/amoskys/agents/proc/proc_agent.py',
        'process_patterns': ['proc_agent', 'ProcAgent'],
        'protocol': 'gRPC Client → EventBus',
        'neurons': ['Process Sensor', 'Behavioral Analyzer', 'Anomaly Detector'],
        'guarded_resources': {
            'operating_systems': ['macOS', 'Linux'],
            'data_types': ['Process Events', 'CPU Metrics', 'Memory Stats']
        },
        'critical': False,
        'color': '#4ECDC4'
    },
    'mac_telemetry': {
        'id': 'mac_telemetry',
        'name': 'Mac Telemetry Generator',
        'description': 'Continuous macOS process telemetry generator for validation and system testing',
        'type': 'Generator',
        'port': None,
        'platform': ['darwin'],
        'capabilities': ['process-scanning', 'telemetry-generation', 'grpc-publish', 'continuous-monitoring'],
        'monitors': ['Mac Processes', 'System State'],
        'path': 'generate_mac_telemetry.py',
        'process_patterns': ['generate_mac_telemetry', 'mac_telemetry'],
        'protocol': 'gRPC Client → EventBus',
        'neurons': ['Data Generator', 'Test Harness'],
        'guarded_resources': {
            'operating_systems': ['macOS'],
            'purpose': ['Testing', 'Validation']
        },
        'critical': False,
        'color': '#95E1D3'
    },
    'flow_agent': {
        'id': 'flow_agent',
        'name': 'FlowAgent (WAL Subscriber)',
        'description': 'Subscribes to EventBus WAL for reliable network flow event processing and storage',
        'type': 'Processor',
        'port': None,
        'platform': ['linux', 'darwin'],
        'capabilities': ['wal-subscription', 'flow-processing', 'sqlite-storage', 'event-correlation'],
        'monitors': ['Network Flows', 'Flow Events', 'Connection States'],
        'path': 'src/amoskys/agents/flowagent/main.py',
        'process_patterns': ['flowagent', 'FlowAgent'],
        'protocol': 'SQLite WAL',
        'neurons': ['Flow Processor', 'Storage Layer', 'Data Persistence'],
        'guarded_resources': {
            'data_types': ['Network Flows', 'Connection Events'],
            'storage': ['Write-Ahead Log', 'SQLite Database']
        },
        'critical': False,
        'color': '#F38181'
    },
    'snmp_agent': {
        'id': 'snmp_agent',
        'name': 'SNMP Collector Agent',
        'description': 'Network device monitoring via SNMP for routers, switches, and IoT devices',
        'type': 'Collector',
        'port': 161,
        'platform': ['linux', 'darwin', 'windows'],
        'capabilities': ['snmp-polling', 'device-discovery', 'metrics-collection', 'trap-handling'],
        'monitors': ['Routers', 'Switches', 'IoT Devices', 'Network Equipment', 'Interface Stats'],
        'path': 'src/amoskys/agents/snmp/snmp_agent.py',
        'process_patterns': ['snmp_agent', 'SNMPAgent'],
        'protocol': 'SNMPv2c/v3',
        'neurons': ['Device Sensor', 'Network Intelligence', 'SNMP Parser'],
        'guarded_resources': {
            'devices': ['SNMP-enabled Network Equipment', 'IoT Devices'],
            'protocols': ['SNMP'],
            'networks': ['LAN', 'IoT Networks']
        },
        'critical': False,
        'color': '#AA96DA'
    },
    'device_scanner': {
        'id': 'device_scanner',
        'name': 'Device Discovery Scanner',
        'description': 'Automatic network device discovery and inventory management with fingerprinting',
        'type': 'Discovery',
        'port': None,
        'platform': ['linux', 'darwin'],
        'capabilities': ['network-scanning', 'device-fingerprinting', 'auto-discovery', 'inventory-mgmt'],
        'monitors': ['Network Devices', 'New Endpoints', 'Network Topology'],
        'path': 'src/amoskys/agents/discovery/device_scanner.py',
        'process_patterns': ['device_scanner', 'DeviceScanner'],
        'protocol': 'ARP/ICMP/mDNS',
        'neurons': ['Discovery Engine', 'Topology Mapper'],
        'guarded_resources': {
            'networks': ['Local Network', 'Subnets'],
            'purpose': ['Asset Discovery', 'Network Mapping']
        },
        'critical': False,
        'color': '#FCBAD3'
    }
}


def get_platform_name() -> str:
    """Get friendly platform name"""
    sys = platform.system().lower()
    if sys == 'darwin':
        return 'macOS'
    elif sys == 'linux':
        return 'Linux'
    elif sys == 'windows':
        return 'Windows'
    return sys.capitalize()


def check_port_listening(port: int) -> bool:
    """Check if a port is actively listening"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0  # 0 means connection successful (port open)
    except Exception:
        return False


def find_processes_by_patterns(patterns: List[str]) -> List[Dict[str, Any]]:
    """Find all processes matching any of the patterns"""
    matches = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'status', 'cpu_percent', 'memory_percent']):
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            name = proc.info['name'] or ''

            # Check if any pattern matches
            for pattern in patterns:
                if pattern in cmdline or pattern in name:
                    matches.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': cmdline,
                        'status': proc.info['status'],
                        'cpu_percent': proc.info.get('cpu_percent', 0),
                        'memory_percent': proc.info.get('memory_percent', 0),
                        'uptime_seconds': int(datetime.now().timestamp() - proc.info['create_time'])
                    })
                    break  # Don't double-count same process
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matches


def detect_agent_status(agent_config: Dict) -> Dict[str, Any]:
    """Detect comprehensive status for an agent"""
    status = {
        'running': False,
        'health': 'stopped',
        'instances': 0,
        'processes': [],
        'port_status': None,
        'blockers': [],
        'warnings': [],
        'last_check': datetime.now(timezone.utc).isoformat()
    }

    # Check platform compatibility
    current_platform = platform.system().lower()
    if current_platform not in agent_config['platform']:
        status['health'] = 'incompatible'
        status['blockers'].append(f"Not compatible with {get_platform_name()}")
        return status

    # Check if agent path exists
    agent_path = Path(agent_config['path'])
    if not agent_path.exists() and not agent_config['path'].startswith('amoskys-'):
        status['warnings'].append(f"Agent file not found: {agent_config['path']}")

    # Find running processes
    processes = find_processes_by_patterns(agent_config['process_patterns'])
    if processes:
        status['running'] = True
        status['instances'] = len(processes)
        status['processes'] = processes
        status['health'] = 'online'

        # Add warning if multiple instances detected
        if len(processes) > 1:
            status['warnings'].append(f"{len(processes)} instances detected (expected 1)")

    # Check port status if applicable
    if agent_config['port']:
        port_listening = check_port_listening(agent_config['port'])
        status['port_status'] = 'listening' if port_listening else 'closed'

        if port_listening and not status['running']:
            status['health'] = 'stale'
            status['warnings'].append(f"Port {agent_config['port']} is listening but process not detected")
        elif not port_listening and status['running']:
            status['warnings'].append(f"Process running but port {agent_config['port']} not listening")
        elif not port_listening and not status['running']:
            status['blockers'].append(f"Port {agent_config['port']} not listening")

    # Determine final health
    if status['running']:
        status['health'] = 'online'
    elif status['health'] != 'incompatible':
        status['health'] = 'stopped'

    return status


def get_all_agents_status() -> Dict[str, Any]:
    """Get comprehensive status of all agents"""
    current_platform = get_platform_name()
    agents_status = []

    for agent_id, agent_config in AGENT_CATALOG.items():
        agent_status = detect_agent_status(agent_config)

        # Build comprehensive agent info
        agent_info = {
            'agent_id': agent_id,
            'name': agent_config['name'],
            'description': agent_config['description'],
            'type': agent_config['type'],
            'status': agent_status['health'],
            'running': agent_status['running'],
            'instances': agent_status['instances'],
            'processes': agent_status['processes'],
            'port': agent_config['port'],
            'port_status': agent_status['port_status'],
            'capabilities': agent_config['capabilities'],
            'monitors': agent_config['monitors'],
            'guarded_resources': agent_config['guarded_resources'],
            'neurons': agent_config['neurons'],
            'protocol': agent_config['protocol'],
            'platform_compatible': platform.system().lower() in agent_config['platform'],
            'supported_platforms': [get_platform_name()] if platform.system().lower() in agent_config['platform'] else [],
            'blockers': agent_status['blockers'],
            'warnings': agent_status['warnings'],
            'critical': agent_config.get('critical', False),
            'color': agent_config.get('color', '#00ff88'),
            'last_check': agent_status['last_check']
        }

        agents_status.append(agent_info)

    # Calculate summary
    total = len(agents_status)
    online = sum(1 for a in agents_status if a['status'] == 'online')
    stopped = sum(1 for a in agents_status if a['status'] == 'stopped')
    incompatible = sum(1 for a in agents_status if a['status'] == 'incompatible')

    return {
        'platform': current_platform,
        'summary': {
            'total': total,
            'online': online,
            'stopped': stopped,
            'incompatible': incompatible,
            'health_percentage': round((online / total * 100), 1) if total > 0 else 0
        },
        'agents': agents_status,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


def get_available_agents() -> List[Dict[str, Any]]:
    """Get list of agents compatible with current platform"""
    current_platform = platform.system().lower()
    available = []

    for agent_id, agent_config in AGENT_CATALOG.items():
        if current_platform in agent_config['platform']:
            available.append({
                'id': agent_id,
                'name': agent_config['name'],
                'description': agent_config['description'],
                'type': agent_config['type'],
                'port': agent_config['port'],
                'platform': [get_platform_name()],
                'capabilities': agent_config['capabilities'],
                'monitors': agent_config['monitors'],
                'protocol': agent_config['protocol'],
                'neurons': agent_config['neurons'],
                'guarded_resources': agent_config['guarded_resources'],
                'color': agent_config.get('color', '#00ff88')
            })

    return available
