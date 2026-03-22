"""
AMOSKYS Agent Discovery and Monitoring
Discovers running agents, monitors health, and maps to neural architecture
"""

import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import psutil

# Comprehensive Agent Registry — all 11 agents (EventBus + 10 security agents)
# Each agent uses `python -m amoskys.agents.<module>` via the standardized CLI framework.
AGENT_CATALOG = {
    "eventbus": {
        "id": "eventbus",
        "name": "EventBus Server",
        "description": "Central message broker for distributed telemetry ingestion via gRPC with mTLS",
        "type": "Infrastructure",
        "module": "amoskys.eventbus.server",
        "port": 50051,
        "platform": ["linux", "darwin", "windows"],
        "capabilities": [
            "message-routing",
            "grpc-server",
            "tls-auth",
            "deduplication",
            "backpressure",
        ],
        "monitors": ["FlowEvents", "ProcessEvents", "NetworkEvents"],
        "path": "src/amoskys/eventbus/server.py",
        "process_patterns": [
            "amoskys.eventbus.server",
            "eventbus/server.py",
            "amoskys-eventbus",
        ],
        "protocol": "gRPC/mTLS",
        "neurons": ["Ingestion Layer", "Message Bus", "Event Router"],
        "guarded_resources": {
            "infrastructure": ["Event Distribution", "Message Queue"],
            "protocols": ["gRPC", "TLS 1.3"],
        },
        "critical": True,
        "color": "#FF6B35",
    },
    "proc_agent": {
        "id": "proc_agent",
        "name": "Process Monitor Agent",
        "description": "Native process monitoring with LOLBin detection, code signing verification, and behavioral anomaly detection",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.process",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "process-monitoring",
            "lolbin-detection",
            "code-signing",
            "behavioral-analysis",
            "threat-detection",
        ],
        "monitors": ["Processes", "CPU/Memory", "Process Trees", "Suspicious Behavior"],
        "path": "src/amoskys/agents/shared/process/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.process",
            "amoskys.agents.os.macos.process",
            "ProcAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Process Sensor", "Behavioral Analyzer", "Anomaly Detector"],
        "guarded_resources": {
            "operating_systems": ["macOS", "Linux"],
            "data_types": ["Process Events", "CPU Metrics", "Memory Stats"],
        },
        "critical": False,
        "color": "#4ECDC4",
    },
    "dns_agent": {
        "id": "dns_agent",
        "name": "DNS Threat Detector",
        "description": "DNS-based threat detection including DGA domains, tunneling, fast-flux, beaconing, and blocklist enforcement",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.dns",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "dga-detection",
            "dns-tunneling",
            "fast-flux",
            "beaconing-detection",
            "blocklist-enforcement",
        ],
        "monitors": ["DNS Queries", "DGA Domains", "DNS Tunneling", "Beaconing"],
        "path": "src/amoskys/agents/shared/dns/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.dns",
            "amoskys.agents.os.macos.dns",
            "DNSAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["DNS Sensor", "DGA Analyzer", "Tunnel Detector"],
        "guarded_resources": {
            "protocols": ["DNS"],
            "data_types": ["DNS Events", "Domain Analysis", "Threat Indicators"],
        },
        "critical": False,
        "color": "#00AAFF",
    },
    "auth_agent": {
        "id": "auth_agent",
        "name": "Authentication Guard",
        "description": "Authentication monitoring with brute-force detection, impossible travel, sudo escalation, and MFA bypass detection",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.auth",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "brute-force-detection",
            "impossible-travel",
            "sudo-escalation",
            "mfa-bypass",
            "off-hours-login",
        ],
        "monitors": ["Login Attempts", "SSH Sessions", "Sudo Usage", "MFA Events"],
        "path": "src/amoskys/agents/shared/auth/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.auth",
            "amoskys.agents.os.macos.auth",
            "AuthGuardAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Auth Sensor", "Brute-Force Analyzer", "Travel Detector"],
        "guarded_resources": {
            "attack_vectors": [
                "Brute Force",
                "Credential Stuffing",
                "Privilege Escalation",
            ],
            "data_types": ["Auth Events", "Login Attempts", "Session Data"],
        },
        "critical": False,
        "color": "#FF6B35",
    },
    "fim_agent": {
        "id": "fim_agent",
        "name": "File Integrity Monitor",
        "description": "File integrity monitoring for SUID escalation, webshell drops, config backdoors, library hijacking, and bootloader tampering",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.filesystem",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "suid-detection",
            "webshell-detection",
            "config-backdoor",
            "library-hijack",
            "bootloader-tampering",
        ],
        "monitors": ["File Changes", "SUID/SGID", "Webshells", "Config Files"],
        "path": "src/amoskys/agents/shared/filesystem/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.filesystem",
            "amoskys.agents.os.macos.filesystem",
            "FIMAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["File Sensor", "Integrity Analyzer", "Baseline Engine"],
        "guarded_resources": {
            "attack_vectors": ["Webshell Drop", "SUID Escalation", "Config Backdoor"],
            "data_types": ["File Events", "Integrity Hashes", "Baseline Diffs"],
        },
        "critical": False,
        "color": "#00FF88",
    },
    "flow_agent": {
        "id": "flow_agent",
        "name": "Network Flow Analyzer",
        "description": "Network traffic analysis with C2 beaconing detection, lateral movement, data exfiltration, and tunnel detection",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.network",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "c2-beaconing",
            "lateral-movement",
            "data-exfiltration",
            "tunnel-detection",
            "flow-analysis",
        ],
        "monitors": ["Network Flows", "Connections", "Traffic Patterns", "Tunnels"],
        "path": "src/amoskys/agents/shared/network/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.network",
            "amoskys.agents.os.macos.network",
            "FlowAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Flow Sensor", "C2 Detector", "Exfiltration Analyzer"],
        "guarded_resources": {
            "data_types": ["Network Flows", "Connection Events"],
            "attack_vectors": [
                "C2 Communication",
                "Data Exfiltration",
                "Lateral Movement",
            ],
        },
        "critical": False,
        "color": "#F38181",
    },
    "persistence_agent": {
        "id": "persistence_agent",
        "name": "Persistence Guard",
        "description": "Persistence mechanism detection across LaunchAgents, systemd, cron, SSH keys, shell profiles, and browser extensions",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.persistence",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "launchagent-monitoring",
            "cron-detection",
            "systemd-monitoring",
            "ssh-key-tracking",
            "shell-profile-monitoring",
        ],
        "monitors": [
            "LaunchAgents",
            "Cron Jobs",
            "Systemd Units",
            "SSH Keys",
            "Shell Profiles",
        ],
        "path": "src/amoskys/agents/shared/persistence/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.persistence",
            "amoskys.agents.os.macos.persistence",
            "PersistenceGuard",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Persistence Sensor", "Schedule Analyzer", "Key Tracker"],
        "guarded_resources": {
            "attack_vectors": [
                "LaunchAgent Hijacking",
                "Cron Backdoor",
                "SSH Key Injection",
            ],
            "data_types": ["Persistence Events", "Schedule Changes", "Key Events"],
        },
        "critical": False,
        "color": "#AA96DA",
    },
    "peripheral_agent": {
        "id": "peripheral_agent",
        "name": "Peripheral Monitor",
        "description": "USB/Bluetooth device monitoring with BadUSB detection, unauthorized device tracking, and data exfiltration prevention",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.peripheral",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "usb-monitoring",
            "badusb-detection",
            "device-fingerprinting",
            "unauthorized-detection",
            "risk-scoring",
        ],
        "monitors": ["USB Devices", "Bluetooth", "HID Devices", "Storage Devices"],
        "path": "src/amoskys/agents/shared/peripheral/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.peripheral",
            "amoskys.agents.os.macos.peripheral",
            "PeripheralAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": [
            "Physical Security Sensor",
            "Device Fingerprinter",
            "Risk Analyzer",
        ],
        "guarded_resources": {
            "attack_vectors": ["BadUSB", "HID Injection", "Data Exfiltration"],
            "data_types": ["Device Events", "Connection States", "Risk Scores"],
        },
        "critical": False,
        "color": "#FF6B9D",
    },
    "kernel_audit_agent": {
        "id": "kernel_audit_agent",
        "name": "Kernel Audit Engine",
        "description": "Kernel-level syscall monitoring for privilege escalation, ptrace abuse, kernel module loads, and audit subsystem tampering",
        "type": "Collector",
        "module": "amoskys.agents.os.linux.kernel_audit",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "syscall-monitoring",
            "privilege-escalation",
            "ptrace-detection",
            "module-load-tracking",
            "audit-tampering",
        ],
        "monitors": ["Syscalls", "Privilege Changes", "Kernel Modules", "Audit Log"],
        "path": "src/amoskys/agents/os/linux/kernel_audit/kernel_audit_agent.py",
        "process_patterns": [
            "amoskys.agents.os.linux.kernel_audit",
            "kernel_audit_agent",
            "KernelAuditAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Kernel Sensor", "Escalation Detector", "Module Tracker"],
        "guarded_resources": {
            "attack_vectors": [
                "Privilege Escalation",
                "Container Escape",
                "Rootkit Installation",
            ],
            "data_types": ["Audit Events", "Syscall Traces", "Module Events"],
        },
        "critical": False,
        "color": "#FFD93D",
    },
    "device_discovery_agent": {
        "id": "device_discovery_agent",
        "name": "Device Discovery Scanner",
        "description": "Network asset discovery with ARP enumeration, port scanning, rogue DHCP/DNS detection, and vulnerability bannering",
        "type": "Discovery",
        "module": "amoskys.agents.os.macos.discovery",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "arp-enumeration",
            "port-scanning",
            "rogue-detection",
            "device-fingerprinting",
            "vulnerability-bannering",
        ],
        "monitors": [
            "Network Devices",
            "New Endpoints",
            "Rogue Services",
            "Open Ports",
        ],
        "path": "src/amoskys/agents/shared/device_discovery/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.discovery",
            "device_discovery",
            "device_scanner",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Discovery Engine", "Topology Mapper", "Rogue Detector"],
        "guarded_resources": {
            "networks": ["Local Network", "Subnets"],
            "purpose": ["Asset Discovery", "Network Mapping", "Shadow IT Detection"],
        },
        "critical": False,
        "color": "#FCBAD3",
    },
    "protocol_collectors_agent": {
        "id": "protocol_collectors_agent",
        "name": "Protocol Threat Collector",
        "description": "Protocol-level threat detection for HTTP anomalies, TLS issues, SSH brute-force, DNS tunneling, and SQL injection",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.protocol_collectors",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "http-anomaly-detection",
            "tls-inspection",
            "ssh-brute-force",
            "sql-injection",
            "rdp-abuse",
        ],
        "monitors": ["HTTP Traffic", "TLS Sessions", "SSH Sessions", "SQL Queries"],
        "path": "src/amoskys/agents/shared/protocol_collectors/protocol_collectors.py",
        "process_patterns": [
            "amoskys.agents.os.macos.protocol_collectors",
            "protocol_collectors",
            "ProtocolCollectors",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Protocol Sensor", "HTTP Analyzer", "TLS Inspector"],
        "guarded_resources": {
            "protocols": ["HTTP", "HTTPS", "SSH", "DNS", "RDP"],
            "attack_vectors": ["SQL Injection", "HTTP Smuggling", "TLS Downgrade"],
        },
        "critical": False,
        "color": "#95E1D3",
    },
    # ─── L7 Gap-Closure Agents ───
    "applog_agent": {
        "id": "applog_agent",
        "name": "Application Log Analyzer",
        "description": "Application log aggregation with webshell detection, log tampering, credential harvesting, and error spike analysis",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.applog",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "log-tampering-detection",
            "credential-harvest-detection",
            "webshell-detection",
            "error-spike-analysis",
            "log-injection-detection",
            "container-breakout-detection",
        ],
        "monitors": [
            "System Logs",
            "Application Logs",
            "Web Server Logs",
            "Container Logs",
        ],
        "path": "src/amoskys/agents/shared/applog/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.applog",
            "amoskys.agents.os.macos.applog",
            "AppLogAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Log Sensor", "Pattern Analyzer", "Anomaly Detector"],
        "guarded_resources": {
            "attack_vectors": [
                "Log Tampering",
                "Webshell Access",
                "Credential Harvesting",
            ],
            "data_types": ["Log Events", "Error Rates", "Access Patterns"],
        },
        "critical": False,
        "color": "#E8A87C",
    },
    "db_activity_agent": {
        "id": "db_activity_agent",
        "name": "Database Activity Monitor",
        "description": "Database query monitoring with SQL injection detection, privilege escalation, bulk extraction, and schema enumeration",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.db_activity",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "sql-injection-detection",
            "privilege-escalation-query",
            "bulk-extraction-detection",
            "schema-enumeration",
            "stored-proc-abuse",
            "ddl-change-tracking",
        ],
        "monitors": [
            "SQL Queries",
            "Database Connections",
            "Schema Changes",
            "Query Logs",
        ],
        "path": "src/amoskys/agents/shared/db_activity/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.db_activity",
            "amoskys.agents.os.macos.db_activity",
            "DBActivityAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["DB Sensor", "Query Analyzer", "Schema Monitor"],
        "guarded_resources": {
            "attack_vectors": [
                "SQL Injection",
                "Privilege Escalation",
                "Data Exfiltration",
            ],
            "data_types": ["Query Events", "Schema Changes", "Connection States"],
        },
        "critical": False,
        "color": "#20B2AA",
    },
    "http_inspector_agent": {
        "id": "http_inspector_agent",
        "name": "HTTP Inspector",
        "description": "Deep HTTP payload analysis with XSS, SSRF, path traversal, API abuse, and suspicious upload detection",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.http_inspector",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "xss-detection",
            "ssrf-detection",
            "path-traversal",
            "api-abuse-detection",
            "data-exfil-detection",
            "suspicious-upload",
        ],
        "monitors": [
            "HTTP Payloads",
            "Request/Response Bodies",
            "Upload Files",
            "WebSocket Frames",
        ],
        "path": "src/amoskys/agents/shared/http_inspector/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.http_inspector",
            "amoskys.agents.os.macos.http_inspector",
            "HTTPInspectorAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["HTTP Sensor", "Payload Analyzer", "Exfil Detector"],
        "guarded_resources": {
            "attack_vectors": ["XSS", "SSRF", "Path Traversal", "API Abuse"],
            "data_types": ["HTTP Events", "Payload Analysis", "Upload Events"],
        },
        "critical": False,
        "color": "#7B68EE",
    },
    "internet_activity_agent": {
        "id": "internet_activity_agent",
        "name": "Internet Activity Monitor",
        "description": "Outbound connection monitoring with cloud exfil, TOR/VPN usage, crypto mining, and unusual geo-connection detection",
        "type": "Collector",
        "module": "amoskys.agents.os.macos.internet_activity",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "cloud-exfil-detection",
            "tor-vpn-detection",
            "crypto-mining-detection",
            "geo-anomaly-detection",
            "shadow-it-detection",
            "dns-over-https-detection",
        ],
        "monitors": [
            "Outbound Connections",
            "Browser Activity",
            "Cloud Services",
            "Geo Locations",
        ],
        "path": "src/amoskys/agents/shared/internet_activity/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.internet_activity",
            "amoskys.agents.os.macos.internet_activity",
            "InternetActivityAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Connection Sensor", "Geo Analyzer", "Exfil Detector"],
        "guarded_resources": {
            "attack_vectors": [
                "Cloud Exfiltration",
                "TOR/VPN Evasion",
                "Crypto Mining",
            ],
            "data_types": [
                "Connection Events",
                "Geo Data",
                "Browser History",
            ],
        },
        "critical": False,
        "color": "#DA70D6",
    },
    "net_scanner_agent": {
        "id": "net_scanner_agent",
        "name": "Network Scanner",
        "description": "Active network probing with new service detection, port changes, rogue services, SSL cert issues, and topology changes",
        "type": "Discovery",
        "module": "amoskys.agents.os.macos.discovery",
        "port": None,
        "platform": ["darwin", "linux"],
        "capabilities": [
            "service-detection",
            "port-change-tracking",
            "rogue-service-detection",
            "ssl-cert-inspection",
            "banner-grabbing",
            "topology-monitoring",
        ],
        "monitors": [
            "Network Services",
            "Open Ports",
            "SSL Certificates",
            "Network Topology",
        ],
        "path": "src/amoskys/agents/shared/net_scanner/agent.py",
        "process_patterns": [
            "amoskys.agents.os.macos.discovery",
            "net_scanner_agent",
            "NetScannerAgent",
        ],
        "protocol": "LocalQueue → EventBus",
        "neurons": ["Scan Engine", "Diff Analyzer", "Topology Mapper"],
        "guarded_resources": {
            "attack_vectors": [
                "Rogue Services",
                "Unauthorized Listeners",
                "ARP Spoofing",
            ],
            "data_types": [
                "Service Events",
                "Port Scans",
                "Topology Diffs",
            ],
        },
        "critical": False,
        "color": "#FF7F50",
    },
    "wal_processor": {
        "id": "wal_processor",
        "name": "WAL Processor",
        "description": "Write-Ahead Log processor: enrichment, scoring, fusion, and SOMA pipeline",
        "type": "Infrastructure",
        "module": "amoskys.storage.wal_processor",
        "port": None,
        "platform": ["linux", "darwin", "windows"],
        "capabilities": [
            "enrichment",
            "scoring",
            "fusion",
            "soma",
            "wal-processing",
        ],
        "monitors": [],
        "path": "src/amoskys/storage/wal_processor.py",
        "process_patterns": [
            "amoskys.storage.wal_processor",
            "wal_processor.py",
        ],
        "protocol": "SQLite WAL",
        "neurons": ["Enrichment Pipeline", "Scoring Engine", "Fusion Engine"],
        "guarded_resources": {
            "infrastructure": ["WAL Processing", "Event Enrichment"],
            "protocols": ["SQLite"],
        },
        "critical": True,
        "color": "#FFB347",
    },
}


def get_platform_name() -> str:
    """Get friendly platform name"""
    sys = platform.system().lower()
    if sys == "darwin":
        return "macOS"
    elif sys == "linux":
        return "Linux"
    elif sys == "windows":
        return "Windows"
    return sys.capitalize()


def check_port_listening(port: int) -> bool:
    """Check if a port is actively listening"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        return result == 0  # 0 means connection successful (port open)
    except Exception:
        return False


def find_processes_by_patterns(patterns: List[str]) -> List[Dict[str, Any]]:
    """Find all processes matching any of the patterns"""
    matches = []
    for proc in psutil.process_iter(
        [
            "pid",
            "name",
            "cmdline",
            "create_time",
            "status",
            "cpu_percent",
            "memory_percent",
        ]
    ):
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            name = proc.info["name"] or ""

            # Check if any pattern matches
            for pattern in patterns:
                if pattern in cmdline or pattern in name:
                    matches.append(
                        {
                            "pid": proc.info["pid"],
                            "name": proc.info["name"],
                            "cmdline": cmdline,
                            "status": proc.info["status"],
                            "cpu_percent": proc.info.get("cpu_percent", 0),
                            "memory_percent": proc.info.get("memory_percent", 0),
                            "uptime_seconds": int(
                                datetime.now().timestamp() - proc.info["create_time"]
                            ),
                        }
                    )
                    break  # Don't double-count same process
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matches


def _check_collector_heartbeat(agent_id: str) -> bool:
    """Check if an agent is alive inside collector_main via heartbeat.

    In the new architecture, agents run as threads inside collector_main,
    not as separate processes. The collector writes a heartbeat JSON that
    lists all active agent threads. This is the primary health signal.
    """
    import json as _json

    project_root = Path(__file__).resolve().parents[3]
    heartbeat_dir = project_root / "data" / "heartbeats"

    # Check collector heartbeat (has list of active agents)
    collector_hb = heartbeat_dir / "collector.json"
    if collector_hb.exists():
        try:
            hb = _json.loads(collector_hb.read_text())
            # Timestamp may be ISO string or unix float
            hb_ts = hb.get("timestamp", 0)
            if isinstance(hb_ts, (int, float)):
                age = abs(datetime.now(timezone.utc).timestamp() - hb_ts)
            elif isinstance(hb_ts, str) and hb_ts:
                hb_dt = datetime.fromisoformat(hb_ts.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - hb_dt).total_seconds()
            else:
                age = 999
            if age < 60:
                running = hb.get("agents_running", hb.get("agent_count", 0))
                if running > 0:
                    return True
        except Exception:
            pass

    # Check individual agent heartbeats (legacy format)
    # Map agent_id to heartbeat file names
    hb_names = [
        agent_id.replace("_agent", ""),
        agent_id.replace("_", ""),
        agent_id,
    ]
    for name in hb_names:
        hb_path = heartbeat_dir / f"{name}.json"
        if hb_path.exists():
            try:
                hb = _json.loads(hb_path.read_text())
                hb_ts = hb.get("timestamp", "")
                if hb_ts:
                    hb_dt = datetime.fromisoformat(hb_ts.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - hb_dt).total_seconds()
                    if age < 120:  # 2 min tolerance
                        return True
            except Exception:
                pass
    return False


def _check_pid_file(name: str) -> bool:
    """Check if a process is alive via PID file (collector/analyzer/dashboard)."""
    project_root = Path(__file__).resolve().parents[3]
    pid_file = project_root / "data" / "pids" / f"{name}.pid"
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        return psutil.pid_exists(pid)
    except (ValueError, OSError):
        return False


def detect_agent_status(agent_config: Dict) -> Dict[str, Any]:
    """Detect comprehensive status for an agent.

    Detection priority:
      1. Collector heartbeat (new arch: agents as threads in collector_main)
      2. PID file check (collector/analyzer/dashboard processes)
      3. Process pattern search (legacy: agents as separate processes)

    This handles both architectures:
      - Old: each agent = separate python process (detectable by cmdline)
      - New: all agents = threads inside collector_main (detectable by heartbeat)
    """
    status = {
        "running": False,
        "health": "stopped",
        "instances": 0,
        "processes": [],
        "port_status": None,
        "blockers": [],
        "warnings": [],
        "last_check": datetime.now(timezone.utc).isoformat(),
        "detection_method": "none",
    }

    # Check platform compatibility
    current_platform = platform.system().lower()
    if current_platform not in agent_config["platform"]:
        status["health"] = "incompatible"
        status["blockers"].append(f"Not compatible with {get_platform_name()}")
        return status

    agent_id = agent_config.get("id", "")

    # Priority 1: Check collector heartbeat (new architecture)
    # Agents run as threads inside collector_main — no individual processes
    if _check_collector_heartbeat(agent_id):
        status["running"] = True
        status["instances"] = 1
        status["health"] = "online"
        status["detection_method"] = "collector_heartbeat"
        return status

    # Priority 2: Check PID files for infrastructure processes
    for pid_name in ["collector", "analyzer", "dashboard"]:
        if pid_name in agent_id or agent_id in ("eventbus", "wal_processor"):
            if _check_pid_file(pid_name):
                status["running"] = True
                status["instances"] = 1
                status["health"] = "online"
                status["detection_method"] = "pid_file"
                return status

    # Priority 3: Legacy process detection (agents as separate processes)
    agent_path = Path(agent_config.get("path", ""))
    if not agent_path.exists() and not agent_config.get("path", "").startswith(
        "amoskys-"
    ):
        status["warnings"].append(
            f"Agent file not found: {agent_config.get('path', '')}"
        )

    processes = find_processes_by_patterns(agent_config.get("process_patterns", []))
    if processes:
        status["running"] = True
        status["instances"] = len(processes)
        status["processes"] = processes
        status["health"] = "online"
        status["detection_method"] = "process_pattern"

        # Add warning if multiple instances detected
        if len(processes) > 1:
            status["warnings"].append(
                f"{len(processes)} instances detected (expected 1)"
            )

    # Check port status if applicable
    if agent_config["port"]:
        port_listening = check_port_listening(agent_config["port"])
        status["port_status"] = "listening" if port_listening else "closed"

        if port_listening and not status["running"]:
            status["health"] = "stale"
            status["warnings"].append(
                f"Port {agent_config['port']} is listening but process not detected"
            )
        elif not port_listening and status["running"]:
            status["warnings"].append(
                f"Process running but port {agent_config['port']} not listening"
            )
        elif not port_listening and not status["running"]:
            status["blockers"].append(f"Port {agent_config['port']} not listening")

    # Determine final health
    if status["running"]:
        status["health"] = "online"
    elif status["health"] != "incompatible":
        status["health"] = "stopped"

    return status


def get_all_agents_status() -> Dict[str, Any]:
    """Get comprehensive status of all agents"""
    current_platform = get_platform_name()
    agents_status = []

    for agent_id, agent_config in AGENT_CATALOG.items():
        agent_status = detect_agent_status(agent_config)

        # Build comprehensive agent info
        agent_info = {
            "agent_id": agent_id,
            "name": agent_config["name"],
            "description": agent_config["description"],
            "type": agent_config["type"],
            "status": agent_status["health"],
            "running": agent_status["running"],
            "instances": agent_status["instances"],
            "processes": agent_status["processes"],
            "port": agent_config["port"],
            "port_status": agent_status["port_status"],
            "capabilities": agent_config["capabilities"],
            "monitors": agent_config["monitors"],
            "guarded_resources": agent_config["guarded_resources"],
            "neurons": agent_config["neurons"],
            "protocol": agent_config["protocol"],
            "platform_compatible": platform.system().lower()
            in agent_config["platform"],
            "supported_platforms": (
                [get_platform_name()]
                if platform.system().lower() in agent_config["platform"]
                else []
            ),
            "blockers": agent_status["blockers"],
            "warnings": agent_status["warnings"],
            "critical": agent_config.get("critical", False),
            "color": agent_config.get("color", "#00ff88"),
            "last_check": agent_status["last_check"],
        }

        agents_status.append(agent_info)

    # Calculate summary
    total = len(agents_status)
    online = sum(1 for a in agents_status if a["status"] == "online")
    stopped = sum(1 for a in agents_status if a["status"] == "stopped")
    incompatible = sum(1 for a in agents_status if a["status"] == "incompatible")

    return {
        "platform": current_platform,
        "summary": {
            "total": total,
            "online": online,
            "stopped": stopped,
            "incompatible": incompatible,
            "health_percentage": round((online / total * 100), 1) if total > 0 else 0,
        },
        "agents": agents_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_available_agents() -> List[Dict[str, Any]]:
    """Get list of agents compatible with current platform"""
    current_platform = platform.system().lower()
    available = []

    for agent_id, agent_config in AGENT_CATALOG.items():
        if current_platform in agent_config["platform"]:
            available.append(
                {
                    "id": agent_id,
                    "name": agent_config["name"],
                    "description": agent_config["description"],
                    "type": agent_config["type"],
                    "port": agent_config["port"],
                    "platform": [get_platform_name()],
                    "capabilities": agent_config["capabilities"],
                    "monitors": agent_config["monitors"],
                    "protocol": agent_config["protocol"],
                    "neurons": agent_config["neurons"],
                    "guarded_resources": agent_config["guarded_resources"],
                    "color": agent_config.get("color", "#00ff88"),
                }
            )

    return available
