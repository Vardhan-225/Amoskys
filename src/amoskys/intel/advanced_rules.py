"""
AMOSKYS Advanced Correlation Rules

World-class attack detection through sophisticated correlation patterns.
These rules detect complex multi-stage attacks that evade simple detection.

Design Philosophy:
    - Multi-signal correlation (require multiple weak signals to fire)
    - Temporal analysis (attacks unfold over time)
    - Kill chain awareness (detect progression through attack phases)
    - Behavioral baselining (deviation from normal is suspicious)
    - Cross-agent correlation (combine signals from all agents)

Rule Categories:
    1. APT Detection - Advanced Persistent Threat patterns
    2. Living-off-the-Land - Abuse of legitimate tools
    3. Defense Evasion - Attempts to avoid detection
    4. Credential Theft Chains - Multi-step credential attacks
    5. Lateral Movement Patterns - Network spreading
    6. Data Staging & Exfiltration - Theft patterns
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from amoskys.intel.models import Incident, MitreTactic, Severity, TelemetryEventView

logger = logging.getLogger(__name__)


# =============================================================================
# APT DETECTION RULES
# =============================================================================


def rule_apt_initial_access_chain(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect APT-style initial access followed by reconnaissance

    Pattern (within 10 minutes):
        1. Unusual authentication (SSH from rare IP, or first-time user)
        2. Discovery commands (whoami, id, uname, ifconfig, ps)
        3. File enumeration (find, locate, ls on sensitive dirs)

    This pattern indicates an attacker has gained access and is
    performing initial reconnaissance before further actions.
    """
    # Step 1: Find suspicious authentication
    auth_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_outcome") == "SUCCESS"
        and e.security_event.get("event_action") in ["SSH", "LOGIN"]
    ]

    if not auth_events:
        return None

    # Step 2: Find discovery commands within 10 min of auth
    discovery_commands = [
        "whoami",
        "id",
        "uname",
        "hostname",
        "ifconfig",
        "ipconfig",
        "netstat",
        "ps aux",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "env",
        "printenv",
        "set",
    ]

    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    for auth_event in auth_events:
        auth_time = auth_event.timestamp
        discovery_found = []

        for proc_event in process_events:
            time_diff = (proc_event.timestamp - auth_time).total_seconds()

            if 0 < time_diff <= 600:  # 10 minutes
                cmdline = proc_event.process_event.get("cmdline", "").lower()
                exe = proc_event.process_event.get("executable_path", "").lower()

                for cmd in discovery_commands:
                    if cmd in cmdline or cmd in exe:
                        discovery_found.append(
                            {
                                "event": proc_event,
                                "command": cmd,
                                "time_after_auth": time_diff,
                            }
                        )
                        break

        # Need at least 3 different discovery commands
        if len(discovery_found) >= 3:
            event_ids = [auth_event.event_id]
            event_ids.extend([d["event"].event_id for d in discovery_found])

            commands_found = [d["command"] for d in discovery_found]
            source_ip = auth_event.security_event.get("source_ip", "unknown")
            user = auth_event.security_event.get("user_name", "unknown")

            incident = Incident(
                incident_id=f"apt_initial_access_{device_id}_{int(auth_time.timestamp())}",
                device_id=device_id,
                severity=Severity.HIGH,
                tactics=[
                    MitreTactic.INITIAL_ACCESS.value,
                    MitreTactic.DISCOVERY.value,
                ],
                techniques=[
                    "T1021.004",  # SSH
                    "T1033",  # System Owner/User Discovery
                    "T1082",  # System Information Discovery
                    "T1016",  # System Network Configuration Discovery
                ],
                rule_name="apt_initial_access_chain",
                summary=f"APT-style initial access: {source_ip} → {user}, "
                f"followed by {len(discovery_found)} discovery commands",
                event_ids=event_ids,
                metadata={
                    "source_ip": source_ip,
                    "target_user": user,
                    "discovery_commands": ", ".join(commands_found[:5]),
                    "discovery_count": str(len(discovery_found)),
                },
            )

            incident.start_ts = auth_time
            incident.end_ts = discovery_found[-1]["event"].timestamp

            logger.warning(
                f"APT initial access chain detected: {source_ip} → {device_id}"
            )
            return incident

    return None


def rule_fileless_attack(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect fileless attack patterns

    Pattern:
        - Process spawned from interpreter (python, bash, perl, ruby)
        - Downloading content (curl, wget) piped directly to execution
        - Or executing encoded commands (base64)
        - With network connection to external IP

    Fileless attacks avoid writing to disk, making them harder to detect.
    """
    # Suspicious interpreter patterns
    fileless_patterns = [
        # Download and execute
        ("curl.*\\|.*sh", "download_and_execute"),
        ("curl.*\\|.*bash", "download_and_execute"),
        ("wget.*-O.*-.*\\|", "download_and_execute"),
        ("curl.*\\|.*python", "download_and_execute"),
        # Base64 decode and execute
        ("base64.*-d.*\\|.*sh", "encoded_execution"),
        ("base64.*-d.*\\|.*bash", "encoded_execution"),
        ("echo.*\\|.*base64.*-d.*\\|", "encoded_execution"),
        # In-memory execution
        ("python.*-c.*import", "memory_execution"),
        ("perl.*-e.*", "memory_execution"),
        ("ruby.*-e.*", "memory_execution"),
        # PowerShell-style (if on cross-platform)
        ("pwsh.*-enc", "encoded_execution"),
        ("pwsh.*-e.*FromBase64", "encoded_execution"),
    ]

    import re

    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    flow_events = [e for e in events if e.event_type == "FLOW" and e.flow_event]

    for proc_event in process_events:
        cmdline = proc_event.process_event.get("cmdline", "")
        exe_path = proc_event.process_event.get("executable_path", "")

        for pattern, attack_type in fileless_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                # Check for associated network activity
                has_network = False
                network_dest = None

                for flow in flow_events:
                    time_diff = abs(
                        (flow.timestamp - proc_event.timestamp).total_seconds()
                    )
                    if time_diff <= 30:  # Within 30 seconds
                        has_network = True
                        network_dest = f"{flow.flow_event.get('dst_ip')}:{flow.flow_event.get('dst_port')}"
                        break

                severity = Severity.CRITICAL if has_network else Severity.HIGH

                event_ids = [proc_event.event_id]
                if has_network:
                    event_ids.append(flow.event_id)

                incident = Incident(
                    incident_id=f"fileless_{device_id}_{int(proc_event.timestamp.timestamp())}",
                    device_id=device_id,
                    severity=severity,
                    tactics=[
                        MitreTactic.EXECUTION.value,
                        MitreTactic.DEFENSE_EVASION.value,
                    ],
                    techniques=[
                        "T1059",  # Command and Scripting Interpreter
                        "T1027",  # Obfuscated Files or Information
                        "T1105",  # Ingress Tool Transfer
                    ],
                    rule_name="fileless_attack",
                    summary=f"Fileless attack detected: {attack_type}"
                    + (f" with network to {network_dest}" if has_network else ""),
                    event_ids=event_ids,
                    metadata={
                        "attack_type": attack_type,
                        "command": cmdline[:200],
                        "executable": exe_path,
                        "has_network": str(has_network),
                        "network_destination": network_dest or "none",
                    },
                )

                incident.start_ts = proc_event.timestamp
                incident.end_ts = proc_event.timestamp

                logger.critical(
                    f"Fileless attack detected on {device_id}: {attack_type}"
                )
                return incident

    return None


# =============================================================================
# DEFENSE EVASION RULES
# =============================================================================


def rule_log_tampering(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect log tampering attempts

    Pattern:
        - Deletion or truncation of log files
        - Modification of audit configurations
        - Disabling of logging services
        - Clearing of shell history

    Log tampering is a key indicator of an attacker covering tracks.
    """
    tampering_patterns = {
        # Log file modification
        "rm.*\\.log": ("log_deletion", ["T1070.002"]),
        "rm.*syslog": ("log_deletion", ["T1070.002"]),
        "rm.*auth\\.log": ("log_deletion", ["T1070.002"]),
        "rm.*/var/log": ("log_deletion", ["T1070.002"]),
        "truncate.*log": ("log_truncation", ["T1070.002"]),
        ">.*\\.log": ("log_truncation", ["T1070.002"]),
        "cat.*/dev/null.*>.*log": ("log_truncation", ["T1070.002"]),
        # History clearing
        "history.*-c": ("history_clear", ["T1070.003"]),
        "rm.*\\.bash_history": ("history_clear", ["T1070.003"]),
        "rm.*\\.zsh_history": ("history_clear", ["T1070.003"]),
        "unset.*HISTFILE": ("history_clear", ["T1070.003"]),
        "export.*HISTSIZE=0": ("history_clear", ["T1070.003"]),
        # Audit modification
        "auditctl.*-D": ("audit_disable", ["T1562.001"]),
        "launchctl.*unload.*audit": ("audit_disable", ["T1562.001"]),
        "rm.*/var/audit": ("audit_clear", ["T1070.002"]),
        # Timestamp modification
        "touch.*-t": ("timestamp_stomp", ["T1070.006"]),
        "touch.*-d": ("timestamp_stomp", ["T1070.006"]),
    }

    import re

    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    audit_events = [e for e in events if e.event_type == "AUDIT" and e.audit_event]

    detected_tampering = []

    # Check process commands
    for proc_event in process_events:
        cmdline = proc_event.process_event.get("cmdline", "")

        for pattern, (tamper_type, techniques) in tampering_patterns.items():
            if re.search(pattern, cmdline, re.IGNORECASE):
                detected_tampering.append(
                    {
                        "event": proc_event,
                        "type": tamper_type,
                        "techniques": techniques,
                        "command": cmdline,
                    }
                )
                break

    # Check file deletions/modifications of logs
    for audit_event in audit_events:
        action = audit_event.audit_event.get("action_performed", "")
        path = audit_event.attributes.get("file_path", "")

        if action in ["DELETED", "MODIFIED"]:
            if "/var/log" in path or ".log" in path or "history" in path.lower():
                detected_tampering.append(
                    {
                        "event": audit_event,
                        "type": "log_file_" + action.lower(),
                        "techniques": ["T1070.002"],
                        "path": path,
                    }
                )

    if not detected_tampering:
        return None

    event_ids = [d["event"].event_id for d in detected_tampering]
    tamper_types = list(set(d["type"] for d in detected_tampering))
    all_techniques = []
    for d in detected_tampering:
        all_techniques.extend(d.get("techniques", []))

    # Multiple tampering attempts = very suspicious
    severity = Severity.CRITICAL if len(detected_tampering) >= 2 else Severity.HIGH

    incident = Incident(
        incident_id=f"log_tampering_{device_id}_{int(datetime.now().timestamp())}",
        device_id=device_id,
        severity=severity,
        tactics=[MitreTactic.DEFENSE_EVASION.value],
        techniques=list(set(all_techniques)),
        rule_name="log_tampering",
        summary=f"Log tampering detected: {len(detected_tampering)} attempts "
        f"({', '.join(tamper_types[:3])})",
        event_ids=event_ids,
        metadata={
            "tampering_types": ", ".join(tamper_types),
            "attempt_count": str(len(detected_tampering)),
        },
    )

    timestamps = [d["event"].timestamp for d in detected_tampering]
    incident.start_ts = min(timestamps)
    incident.end_ts = max(timestamps)

    logger.critical(f"Log tampering detected on {device_id}")
    return incident


def rule_security_tool_disable(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect attempts to disable security tools

    Pattern:
        - Killing or stopping security processes
        - Unloading security kernel extensions
        - Modifying security configurations
        - Disabling firewall or endpoint protection
    """
    disable_patterns = {
        # Process killing
        "kill.*sentinel": ("edr_kill", ["T1562.001"]),
        "kill.*crowdstrike": ("edr_kill", ["T1562.001"]),
        "kill.*carbonblack": ("edr_kill", ["T1562.001"]),
        "kill.*malware": ("edr_kill", ["T1562.001"]),
        "pkill.*security": ("edr_kill", ["T1562.001"]),
        # Service stopping
        "launchctl.*stop.*security": ("service_stop", ["T1562.001"]),
        "launchctl.*unload.*security": ("service_stop", ["T1562.001"]),
        # Firewall disabling
        "pfctl.*-d": ("firewall_disable", ["T1562.004"]),
        "/usr/libexec/ApplicationFirewall.*--setglobalstate.*off": (
            "firewall_disable",
            ["T1562.004"],
        ),
        # Gatekeeper disabling
        "spctl.*--master-disable": ("gatekeeper_disable", ["T1553.001"]),
        "spctl.*--disable": ("gatekeeper_disable", ["T1553.001"]),
        # SIP modification attempts
        "csrutil.*disable": ("sip_disable", ["T1562.001"]),
        # Kernel extension unloading
        "kextunload": ("kext_unload", ["T1562.001"]),
    }

    import re

    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    for proc_event in process_events:
        cmdline = proc_event.process_event.get("cmdline", "")

        for pattern, (disable_type, techniques) in disable_patterns.items():
            if re.search(pattern, cmdline, re.IGNORECASE):
                incident = Incident(
                    incident_id=f"security_disable_{device_id}_{int(proc_event.timestamp.timestamp())}",
                    device_id=device_id,
                    severity=Severity.CRITICAL,
                    tactics=[MitreTactic.DEFENSE_EVASION.value],
                    techniques=techniques,
                    rule_name="security_tool_disable",
                    summary=f"Security tool disabled: {disable_type}",
                    event_ids=[proc_event.event_id],
                    metadata={
                        "disable_type": disable_type,
                        "command": cmdline[:200],
                        "user": proc_event.process_event.get("username", "unknown"),
                    },
                )

                incident.start_ts = proc_event.timestamp
                incident.end_ts = proc_event.timestamp

                logger.critical(
                    f"Security tool disabled on {device_id}: {disable_type}"
                )
                return incident

    return None


# =============================================================================
# CREDENTIAL THEFT CHAIN RULES
# =============================================================================


def rule_credential_dumping_chain(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect credential dumping attack chains

    Pattern (within 5 minutes):
        1. Access to keychain or credential stores
        2. Execution of credential extraction tools
        3. Optional: Network exfiltration of credentials

    This detects multi-step credential theft attacks.
    """
    # Credential access patterns
    cred_access_patterns = [
        "security.*find-generic-password",
        "security.*find-internet-password",
        "security.*dump-keychain",
        "security.*export",
        "sqlite3.*Login.*Data",  # Chrome passwords
        "cat.*/etc/shadow",
        "cat.*id_rsa",
        "strings.*keychain",
    ]

    import re

    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    audit_events = [e for e in events if e.event_type == "AUDIT" and e.audit_event]

    cred_events = []

    # Check processes for credential access commands
    for proc_event in process_events:
        cmdline = proc_event.process_event.get("cmdline", "")

        for pattern in cred_access_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                cred_events.append(
                    {
                        "event": proc_event,
                        "type": "command",
                        "detail": cmdline[:100],
                    }
                )
                break

    # Check file access to credential stores
    cred_paths = [
        "Keychains",
        ".ssh/id_",
        "Login Data",
        "cookies.sqlite",
        ".aws/credentials",
    ]

    for audit_event in audit_events:
        path = audit_event.attributes.get("file_path", "")
        action = audit_event.audit_event.get("action_performed", "")

        if action in ["READ", "OPEN", "ACCESSED"]:
            for cred_path in cred_paths:
                if cred_path in path:
                    cred_events.append(
                        {
                            "event": audit_event,
                            "type": "file_access",
                            "detail": path,
                        }
                    )
                    break

    # Need multiple credential access events to indicate theft chain
    if len(cred_events) < 2:
        return None

    # Check if events are temporally correlated (within 5 minutes)
    cred_events.sort(key=lambda x: x["event"].timestamp)
    time_span = (
        cred_events[-1]["event"].timestamp - cred_events[0]["event"].timestamp
    ).total_seconds()

    if time_span > 300:  # Events too spread out
        return None

    event_ids = [c["event"].event_id for c in cred_events]
    details = [c["detail"] for c in cred_events]

    incident = Incident(
        incident_id=f"cred_dump_{device_id}_{int(cred_events[0]['event'].timestamp.timestamp())}",
        device_id=device_id,
        severity=Severity.CRITICAL,
        tactics=[MitreTactic.CREDENTIAL_ACCESS.value],
        techniques=[
            "T1555",  # Credentials from Password Stores
            "T1555.001",  # Keychain
            "T1552.001",  # Credentials in Files
        ],
        rule_name="credential_dumping_chain",
        summary=f"Credential dumping chain: {len(cred_events)} access attempts",
        event_ids=event_ids,
        metadata={
            "access_count": str(len(cred_events)),
            "access_details": "; ".join(details[:5]),
            "time_span_seconds": str(int(time_span)),
        },
    )

    incident.start_ts = cred_events[0]["event"].timestamp
    incident.end_ts = cred_events[-1]["event"].timestamp

    logger.critical(f"Credential dumping chain detected on {device_id}")
    return incident


# =============================================================================
# LATERAL MOVEMENT RULES
# =============================================================================


def rule_ssh_key_theft_and_pivot(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect SSH key theft followed by lateral movement

    Pattern:
        1. Access to SSH private keys (read ~/.ssh/id_*)
        2. Followed by outbound SSH connections to new hosts

    This indicates an attacker is using stolen keys to pivot.
    """
    audit_events = [e for e in events if e.event_type == "AUDIT" and e.audit_event]

    flow_events = [e for e in events if e.event_type == "FLOW" and e.flow_event]

    # Find SSH key access
    key_access_events = []
    for audit_event in audit_events:
        path = audit_event.attributes.get("file_path", "")
        action = audit_event.audit_event.get("action_performed", "")

        if action in ["READ", "OPEN", "COPIED"]:
            if ".ssh/id_" in path and "pub" not in path:
                key_access_events.append(audit_event)

    if not key_access_events:
        return None

    # Find outbound SSH connections after key access
    ssh_connections = []
    for key_event in key_access_events:
        for flow_event in flow_events:
            time_diff = (flow_event.timestamp - key_event.timestamp).total_seconds()

            if 0 < time_diff <= 600:  # Within 10 minutes
                if flow_event.flow_event.get("dst_port") == 22:
                    if flow_event.flow_event.get("direction") == "OUTBOUND":
                        ssh_connections.append(
                            {
                                "key_event": key_event,
                                "flow_event": flow_event,
                                "dest": flow_event.flow_event.get("dst_ip"),
                            }
                        )

    if not ssh_connections:
        return None

    # Build incident
    event_ids = []
    destinations = set()

    for conn in ssh_connections:
        event_ids.append(conn["key_event"].event_id)
        event_ids.append(conn["flow_event"].event_id)
        destinations.add(conn["dest"])

    event_ids = list(set(event_ids))  # Dedupe

    incident = Incident(
        incident_id=f"ssh_pivot_{device_id}_{int(ssh_connections[0]['key_event'].timestamp.timestamp())}",
        device_id=device_id,
        severity=Severity.CRITICAL,
        tactics=[
            MitreTactic.CREDENTIAL_ACCESS.value,
            MitreTactic.LATERAL_MOVEMENT.value,
        ],
        techniques=[
            "T1552.004",  # Private Keys
            "T1021.004",  # Remote Services: SSH
        ],
        rule_name="ssh_key_theft_and_pivot",
        summary=f"SSH key theft with pivot to {len(destinations)} host(s): "
        f"{', '.join(list(destinations)[:3])}",
        event_ids=event_ids,
        metadata={
            "pivot_destinations": ", ".join(destinations),
            "destination_count": str(len(destinations)),
        },
    )

    incident.start_ts = ssh_connections[0]["key_event"].timestamp
    incident.end_ts = ssh_connections[-1]["flow_event"].timestamp

    logger.critical(f"SSH key theft and pivot detected on {device_id}")
    return incident


def rule_internal_reconnaissance(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect internal network reconnaissance

    Pattern:
        - Port scanning (connections to many ports on same host)
        - Host sweeping (connections to many hosts on same port)
        - Network enumeration commands (arp, nmap, netstat)

    This indicates an attacker mapping the internal network.
    """
    flow_events = [e for e in events if e.event_type == "FLOW" and e.flow_event]

    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    # Check for reconnaissance commands
    recon_commands = [
        "nmap",
        "masscan",
        "arp -a",
        "arp-scan",
        "netstat",
        "ping -c",
        "fping",
        "nbtscan",
        "smbclient -L",
    ]


    recon_process_events = []
    for proc_event in process_events:
        cmdline = proc_event.process_event.get("cmdline", "")

        for cmd in recon_commands:
            if cmd in cmdline.lower():
                recon_process_events.append(proc_event)
                break

    # Check for scanning behavior in flows
    # Port scan: many ports to same destination
    dest_ports: Dict[str, Set[int]] = defaultdict(set)
    # Host sweep: many destinations on same port
    port_dests: Dict[int, Set[str]] = defaultdict(set)

    for flow in flow_events:
        dst_ip = flow.flow_event.get("dst_ip", "")
        dst_port = flow.flow_event.get("dst_port", 0)

        if dst_ip and dst_port:
            dest_ports[dst_ip].add(dst_port)
            port_dests[dst_port].add(dst_ip)

    # Thresholds for scanning detection
    port_scan_threshold = 10  # 10+ ports to same host
    host_sweep_threshold = 10  # 10+ hosts on same port

    port_scan_targets = [
        ip for ip, ports in dest_ports.items() if len(ports) >= port_scan_threshold
    ]

    host_sweep_ports = [
        port for port, hosts in port_dests.items() if len(hosts) >= host_sweep_threshold
    ]

    # Need either recon commands or scanning behavior
    if not recon_process_events and not port_scan_targets and not host_sweep_ports:
        return None

    # Build summary
    scan_types = []
    if recon_process_events:
        scan_types.append("recon commands")
    if port_scan_targets:
        scan_types.append(f"port scan ({len(port_scan_targets)} targets)")
    if host_sweep_ports:
        scan_types.append(
            f"host sweep (port {', '.join(map(str, host_sweep_ports[:3]))})"
        )

    event_ids = [e.event_id for e in recon_process_events]

    incident = Incident(
        incident_id=f"internal_recon_{device_id}_{int(datetime.now().timestamp())}",
        device_id=device_id,
        severity=Severity.HIGH,
        tactics=[MitreTactic.DISCOVERY.value],
        techniques=[
            "T1046",  # Network Service Discovery
            "T1018",  # Remote System Discovery
        ],
        rule_name="internal_reconnaissance",
        summary=f"Internal reconnaissance detected: {', '.join(scan_types)}",
        event_ids=event_ids,
        metadata={
            "scan_types": ", ".join(scan_types),
            "port_scan_targets": ", ".join(port_scan_targets[:5]),
            "host_sweep_ports": ", ".join(map(str, host_sweep_ports[:5])),
        },
    )

    incident.start_ts = datetime.now() - timedelta(minutes=30)
    incident.end_ts = datetime.now()

    logger.warning(f"Internal reconnaissance detected on {device_id}")
    return incident


# =============================================================================
# DATA EXFILTRATION RULES
# =============================================================================


def rule_staged_exfiltration(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect data staging followed by exfiltration

    Pattern (within 30 minutes):
        1. Archive creation (tar, zip, ditto) of sensitive data
        2. Followed by large outbound transfer or upload command

    This is a classic data theft pattern.
    """
    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    flow_events = [e for e in events if e.event_type == "FLOW" and e.flow_event]

    # Find staging commands (archive creation)
    staging_patterns = [
        ("tar.*-c", "tar archive"),
        ("zip.*-r", "zip archive"),
        ("ditto.*-c", "ditto archive"),
        ("hdiutil.*create", "disk image"),
        ("7z.*a", "7zip archive"),
    ]

    import re

    staging_events = []
    for proc_event in process_events:
        cmdline = proc_event.process_event.get("cmdline", "")

        for pattern, archive_type in staging_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                # Check if archiving sensitive data
                sensitive_dirs = [
                    "Documents",
                    "Desktop",
                    ".ssh",
                    "Keychains",
                    "Downloads",
                    "/Users",
                ]
                if any(d in cmdline for d in sensitive_dirs):
                    staging_events.append(
                        {
                            "event": proc_event,
                            "type": archive_type,
                            "command": cmdline,
                        }
                    )
                    break

    if not staging_events:
        return None

    # Find exfiltration after staging
    exfil_patterns = [
        "curl.*-F",
        "curl.*--data-binary",
        "curl.*-T",
        "scp.*@",
        "rsync.*@",
    ]

    exfil_events = []
    for staging in staging_events:
        staging_time = staging["event"].timestamp

        for proc_event in process_events:
            time_diff = (proc_event.timestamp - staging_time).total_seconds()

            if 0 < time_diff <= 1800:  # 30 minutes
                cmdline = proc_event.process_event.get("cmdline", "")

                for pattern in exfil_patterns:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        exfil_events.append(
                            {
                                "staging_event": staging,
                                "exfil_event": proc_event,
                                "exfil_command": cmdline,
                            }
                        )
                        break

    # Also check for large network transfers
    for staging in staging_events:
        staging_time = staging["event"].timestamp

        for flow in flow_events:
            time_diff = (flow.timestamp - staging_time).total_seconds()

            if 0 < time_diff <= 1800:
                bytes_out = flow.flow_event.get("bytes_out", 0)

                # Large transfer after staging
                if bytes_out > 10 * 1024 * 1024:  # 10MB
                    exfil_events.append(
                        {
                            "staging_event": staging,
                            "exfil_event": flow,
                            "bytes_out": bytes_out,
                        }
                    )

    if not exfil_events:
        return None

    # Build incident
    event_ids = []
    for exfil in exfil_events:
        event_ids.append(exfil["staging_event"]["event"].event_id)
        event_ids.append(exfil["exfil_event"].event_id)

    event_ids = list(set(event_ids))

    incident = Incident(
        incident_id=f"staged_exfil_{device_id}_{int(staging_events[0]['event'].timestamp.timestamp())}",
        device_id=device_id,
        severity=Severity.CRITICAL,
        tactics=[
            MitreTactic.COLLECTION.value,
            MitreTactic.EXFILTRATION.value,
        ],
        techniques=[
            "T1560.001",  # Archive via Utility
            "T1048",  # Exfiltration Over Alternative Protocol
        ],
        rule_name="staged_exfiltration",
        summary=f"Data staging and exfiltration: "
        f"{len(staging_events)} archive(s), {len(exfil_events)} transfers",
        event_ids=event_ids,
        metadata={
            "staging_count": str(len(staging_events)),
            "exfil_count": str(len(exfil_events)),
            "archive_types": ", ".join(s["type"] for s in staging_events),
        },
    )

    incident.start_ts = staging_events[0]["event"].timestamp
    incident.end_ts = exfil_events[-1]["exfil_event"].timestamp

    logger.critical(f"Staged exfiltration detected on {device_id}")
    return incident


def rule_dns_exfiltration(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect DNS-based data exfiltration

    Pattern:
        - High volume of DNS queries
        - Queries with unusually long subdomains (encoded data)
        - Queries to suspicious TLDs

    DNS exfil is often used to bypass firewalls.
    """
    flow_events = [e for e in events if e.event_type == "FLOW" and e.flow_event]

    # DNS flows (port 53)
    dns_flows = [f for f in flow_events if f.flow_event.get("dst_port") == 53]

    if len(dns_flows) < 50:  # Need significant DNS activity
        return None

    # Check for unusual patterns
    # In a real implementation, we'd analyze actual DNS queries
    # For now, check volume and timing patterns

    # High DNS rate
    if len(dns_flows) >= 100:
        time_span = (dns_flows[-1].timestamp - dns_flows[0].timestamp).total_seconds()

        if time_span > 0:
            dns_rate = len(dns_flows) / time_span

            if dns_rate > 10:  # More than 10 DNS queries per second
                incident = Incident(
                    incident_id=f"dns_exfil_{device_id}_{int(dns_flows[0].timestamp.timestamp())}",
                    device_id=device_id,
                    severity=Severity.HIGH,
                    tactics=[MitreTactic.EXFILTRATION.value],
                    techniques=["T1048.003"],  # Exfiltration Over DNS
                    rule_name="dns_exfiltration",
                    summary=f"Possible DNS exfiltration: {len(dns_flows)} queries "
                    f"({dns_rate:.1f}/sec)",
                    event_ids=[f.event_id for f in dns_flows[:10]],
                    metadata={
                        "dns_query_count": str(len(dns_flows)),
                        "queries_per_second": f"{dns_rate:.2f}",
                        "time_span_seconds": str(int(time_span)),
                    },
                )

                incident.start_ts = dns_flows[0].timestamp
                incident.end_ts = dns_flows[-1].timestamp

                logger.warning(f"Possible DNS exfiltration on {device_id}")
                return incident

    return None


# =============================================================================
# FILE INTEGRITY & ROOTKIT DETECTION RULES
# =============================================================================


def rule_binary_replacement_attack(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect system binary replacement attacks (rootkit installation)

    Pattern:
        - FIM event showing modification to /bin/, /usr/bin/, /sbin/
        - Especially dangerous: common commands like ls, ps, netstat
        - Often followed by attempts to hide the change

    This is a critical indicator of rootkit installation.
    """
    # Look for FIM events on critical binaries
    fim_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "FILE_INTEGRITY"
    ]

    critical_binaries = {
        "ls",
        "ps",
        "netstat",
        "ss",
        "top",
        "login",
        "passwd",
        "sudo",
        "su",
        "ssh",
        "sshd",
        "bash",
        "sh",
        "zsh",
        "cron",
        "at",
        "find",
        "grep",
        "awk",
        "sed",
        "cat",
        "kill",
        "pkill",
        "ifconfig",
        "ip",
        "iptables",
    }

    modified_criticals = []

    for event in fim_events:
        sec = event.security_event
        if not sec:
            continue

        outcome = sec.get("event_outcome", "")
        path = sec.get("process_path", "")

        # Check if it's a modification to a critical binary
        if outcome == "MODIFIED":
            for binary in critical_binaries:
                if path.endswith(f"/{binary}"):
                    modified_criticals.append(
                        {"event": event, "binary": binary, "path": path}
                    )
                    break

    if len(modified_criticals) >= 1:
        # Even one critical binary modification is severe
        incident = Incident(
            incident_id=f"rootkit_{device_id}_{int(datetime.now().timestamp())}",
            device_id=device_id,
            severity=Severity.CRITICAL,
            tactics=[
                MitreTactic.DEFENSE_EVASION.value,
                MitreTactic.PERSISTENCE.value,
            ],
            techniques=["T1014", "T1574.010"],  # Rootkit, Services File Permissions
            rule_name="binary_replacement_attack",
            summary=f"CRITICAL: System binary replacement detected - "
            f"{len(modified_criticals)} binaries modified: "
            f"{', '.join(m['binary'] for m in modified_criticals[:5])}",
            event_ids=[m["event"].event_id for m in modified_criticals],
            metadata={
                "modified_binaries": ",".join(m["binary"] for m in modified_criticals),
                "paths": ",".join(m["path"] for m in modified_criticals),
            },
        )

        logger.critical(f"ROOTKIT DETECTED on {device_id}")
        return incident

    return None


def rule_suid_privilege_escalation(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect SUID bit manipulation for privilege escalation

    Pattern:
        - FIM event showing permission change with SUID/SGID bit set
        - Especially on newly created files or non-standard locations
        - Often precedes privilege escalation exploitation

    MITRE: T1548.001 - Setuid and Setgid
    """
    fim_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "FILE_INTEGRITY"
    ]

    suid_changes = []

    for event in fim_events:
        sec = event.security_event
        if not sec:
            continue

        details = sec.get("details", "{}")
        if isinstance(details, str):
            try:
                import json

                details = json.loads(details)
            except Exception:
                details = {}

        description = details.get("description", "")

        # Look for SUID indicators
        if "NEW SUID BIT" in description or "NEW SGID BIT" in description:
            suid_changes.append({"event": event, "path": sec.get("process_path", "")})

    if suid_changes:
        incident = Incident(
            incident_id=f"suid_privesc_{device_id}_{int(datetime.now().timestamp())}",
            device_id=device_id,
            severity=Severity.CRITICAL,
            tactics=[MitreTactic.PRIVILEGE_ESCALATION.value],
            techniques=["T1548.001"],  # Setuid and Setgid
            rule_name="suid_privilege_escalation",
            summary=f"SUID/SGID bit set on {len(suid_changes)} file(s) - "
            f"possible privilege escalation preparation",
            event_ids=[s["event"].event_id for s in suid_changes],
            metadata={
                "suid_files": ",".join(s["path"] for s in suid_changes),
            },
        )

        logger.warning(f"SUID privilege escalation prep on {device_id}")
        return incident

    return None


def rule_webshell_deployment(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect webshell deployment to web server directories

    Pattern:
        - FIM event showing new file in web root
        - File has executable extension (.php, .jsp, .aspx, etc.)
        - May be followed by web server access to that file

    MITRE: T1505.003 - Web Shell
    """
    fim_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "FILE_INTEGRITY"
        and e.security_event.get("event_outcome") == "CREATED"
    ]

    webshell_extensions = {".php", ".jsp", ".jspx", ".asp", ".aspx", ".cfm"}
    web_roots = ["/var/www", "/usr/share/nginx", "/Library/WebServer"]

    potential_webshells = []

    for event in fim_events:
        sec = event.security_event
        if not sec:
            continue

        path = sec.get("process_path", "")

        # Check if in web root
        in_webroot = any(path.startswith(root) for root in web_roots)
        if not in_webroot:
            continue

        # Check extension
        ext = ""
        if "." in path:
            ext = "." + path.rsplit(".", 1)[-1].lower()

        if ext in webshell_extensions:
            potential_webshells.append({"event": event, "path": path, "ext": ext})

    if potential_webshells:
        incident = Incident(
            incident_id=f"webshell_{device_id}_{int(datetime.now().timestamp())}",
            device_id=device_id,
            severity=Severity.CRITICAL,
            tactics=[MitreTactic.PERSISTENCE.value, MitreTactic.INITIAL_ACCESS.value],
            techniques=["T1505.003"],  # Web Shell
            rule_name="webshell_deployment",
            summary=f"Potential webshell deployed: "
            f"{', '.join(w['path'] for w in potential_webshells[:3])}",
            event_ids=[w["event"].event_id for w in potential_webshells],
            metadata={
                "webshell_paths": ",".join(w["path"] for w in potential_webshells),
            },
        )

        logger.critical(f"WEBSHELL deployment detected on {device_id}")
        return incident

    return None


# =============================================================================
# DNS THREAT CORRELATION RULES
# =============================================================================


def rule_dns_c2_beaconing(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect C2 beaconing through regular DNS query patterns

    Pattern:
        - Regular interval DNS queries to same domain
        - Low query interval variance (beaconing)
        - May use TXT records for data transfer
        - Domain may have high entropy (DGA-generated)

    MITRE: T1071.004 - DNS, T1573 - Encrypted Channel
    """
    dns_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "DNS_THREAT"
        and e.security_event.get("event_outcome") == "C2_BEACON"
    ]

    if not dns_events:
        return None

    # Group by domain
    domains = set()
    for event in dns_events:
        sec = event.security_event
        if sec:
            details = sec.get("details", "{}")
            if isinstance(details, str):
                try:
                    import json

                    details = json.loads(details)
                except Exception:
                    details = {}
            domain = details.get("domain", "")
            if domain:
                domains.add(domain)

    if domains:
        incident = Incident(
            incident_id=f"dns_c2_{device_id}_{int(datetime.now().timestamp())}",
            device_id=device_id,
            severity=Severity.CRITICAL,
            tactics=[MitreTactic.COMMAND_AND_CONTROL.value],
            techniques=["T1071.004", "T1573"],  # DNS, Encrypted Channel
            rule_name="dns_c2_beaconing",
            summary=f"DNS C2 beaconing detected to {len(domains)} domain(s): "
            f"{', '.join(list(domains)[:3])}",
            event_ids=[e.event_id for e in dns_events],
            metadata={
                "c2_domains": ",".join(domains),
                "beacon_count": str(len(dns_events)),
            },
        )

        logger.critical(f"DNS C2 beaconing on {device_id}")
        return incident

    return None


def rule_dga_malware_activity(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect Domain Generation Algorithm (DGA) malware activity

    Pattern:
        - Multiple DNS queries to high-entropy domains
        - Often many NXDOMAIN responses (failed lookups)
        - Indicates malware trying to find active C2 server

    MITRE: T1568.002 - Domain Generation Algorithms
    """
    dns_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "DNS_THREAT"
        and e.security_event.get("event_outcome") == "DGA"
    ]

    if len(dns_events) < 3:  # Need multiple DGA domains
        return None

    dga_domains = []
    for event in dns_events:
        sec = event.security_event
        if sec:
            details = sec.get("details", "{}")
            if isinstance(details, str):
                try:
                    import json

                    details = json.loads(details)
                except Exception:
                    details = {}
            domain = details.get("domain", "")
            if domain:
                dga_domains.append(domain)

    incident = Incident(
        incident_id=f"dga_{device_id}_{int(datetime.now().timestamp())}",
        device_id=device_id,
        severity=Severity.HIGH,
        tactics=[MitreTactic.COMMAND_AND_CONTROL.value],
        techniques=["T1568.002"],  # DGA
        rule_name="dga_malware_activity",
        summary=f"DGA malware activity: {len(dga_domains)} algorithmically "
        f"generated domains queried",
        event_ids=[e.event_id for e in dns_events],
        metadata={
            "dga_domains": ",".join(dga_domains[:10]),
            "total_count": str(len(dga_domains)),
        },
    )

    logger.warning(f"DGA malware activity on {device_id}")
    return incident


# =============================================================================
# KERNEL-LEVEL THREAT RULES
# =============================================================================


def rule_kernel_privilege_escalation(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect kernel-level privilege escalation

    Pattern:
        - Kernel audit event showing unexpected UID transition
        - Process gains root without using known SUID binaries
        - May indicate kernel exploit or misconfigured service

    MITRE: T1068 - Exploitation for Privilege Escalation
    """
    kernel_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "KERNEL_THREAT"
        and e.security_event.get("event_outcome") == "PRIVILEGE_ESCALATION"
    ]

    if not kernel_events:
        return None

    processes = []
    for event in kernel_events:
        sec = event.security_event
        if sec:
            processes.append(sec.get("process_name", "unknown"))

    incident = Incident(
        incident_id=f"kernel_privesc_{device_id}_{int(datetime.now().timestamp())}",
        device_id=device_id,
        severity=Severity.CRITICAL,
        tactics=[MitreTactic.PRIVILEGE_ESCALATION.value],
        techniques=["T1068"],  # Exploitation for Privilege Escalation
        rule_name="kernel_privilege_escalation",
        summary=f"Kernel-level privilege escalation by: {', '.join(set(processes))}",
        event_ids=[e.event_id for e in kernel_events],
        metadata={
            "processes": ",".join(set(processes)),
        },
    )

    logger.critical(f"Kernel privilege escalation on {device_id}")
    return incident


def rule_container_escape(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect container escape attempts

    Pattern:
        - Access to Docker socket, cgroup, or namespace files
        - Attempts to mount host filesystem
        - Breaking out of container isolation

    MITRE: T1611 - Escape to Host
    """
    kernel_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "KERNEL_THREAT"
        and e.security_event.get("event_outcome") == "CONTAINER_ESCAPE"
    ]

    if not kernel_events:
        return None

    incident = Incident(
        incident_id=f"container_escape_{device_id}_{int(datetime.now().timestamp())}",
        device_id=device_id,
        severity=Severity.CRITICAL,
        tactics=[MitreTactic.PRIVILEGE_ESCALATION.value],
        techniques=["T1611"],  # Escape to Host
        rule_name="container_escape",
        summary=f"Container escape attempt detected - "
        f"{len(kernel_events)} suspicious access(es)",
        event_ids=[e.event_id for e in kernel_events],
    )

    logger.critical(f"Container escape attempt on {device_id}")
    return incident


def rule_process_injection(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect process injection attacks

    Pattern:
        - ptrace syscall targeting another process
        - memory mapping with executable permissions in foreign process
        - Classic technique for code injection

    MITRE: T1055 - Process Injection
    """
    kernel_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "KERNEL_THREAT"
        and e.security_event.get("event_outcome") == "PROCESS_INJECTION"
    ]

    if not kernel_events:
        return None

    incident = Incident(
        incident_id=f"proc_inject_{device_id}_{int(datetime.now().timestamp())}",
        device_id=device_id,
        severity=Severity.CRITICAL,
        tactics=[
            MitreTactic.DEFENSE_EVASION.value,
            MitreTactic.PRIVILEGE_ESCALATION.value,
        ],
        techniques=["T1055", "T1055.008"],  # Process Injection, Ptrace
        rule_name="process_injection",
        summary=f"Process injection detected - {len(kernel_events)} injection event(s)",
        event_ids=[e.event_id for e in kernel_events],
    )

    logger.critical(f"Process injection on {device_id}")
    return incident


# =============================================================================
# ADVANCED RULE REGISTRY
# =============================================================================

ADVANCED_RULES = [
    # APT Detection
    rule_apt_initial_access_chain,
    rule_fileless_attack,
    # Defense Evasion
    rule_log_tampering,
    rule_security_tool_disable,
    # Credential Theft
    rule_credential_dumping_chain,
    # Lateral Movement
    rule_ssh_key_theft_and_pivot,
    rule_internal_reconnaissance,
    # Exfiltration
    rule_staged_exfiltration,
    rule_dns_exfiltration,
    # File Integrity / Rootkit Detection (NEW)
    rule_binary_replacement_attack,
    rule_suid_privilege_escalation,
    rule_webshell_deployment,
    # DNS Threat Detection (NEW)
    rule_dns_c2_beaconing,
    rule_dga_malware_activity,
    # Kernel-level Threats (NEW)
    rule_kernel_privilege_escalation,
    rule_container_escape,
    rule_process_injection,
]


def evaluate_advanced_rules(
    events: List[TelemetryEventView], device_id: str
) -> List[Incident]:
    """Evaluate all advanced correlation rules

    Args:
        events: List of TelemetryEventView objects
        device_id: Device being evaluated

    Returns:
        List of detected Incidents
    """
    incidents = []

    for rule_fn in ADVANCED_RULES:
        try:
            incident = rule_fn(events, device_id)
            if incident:
                incidents.append(incident)
                logger.info(
                    f"Advanced rule fired: {incident.rule_name} → {incident.incident_id}"
                )
        except Exception as e:
            logger.error(f"Advanced rule {rule_fn.__name__} failed: {e}", exc_info=True)

    return incidents
