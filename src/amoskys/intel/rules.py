"""
Correlation Rules for Incident Detection

Implements hand-written correlation rules that detect attack patterns
across multiple telemetry events. Each rule examines a sliding window
of events and fires an Incident when a suspicious pattern is detected.

Rules:
1. SSH Brute Force → Compromise
2. New Persistence After Auth/Sudo
3. Suspicious Sudo Command
4. Multi-Tactic Attack (Flow + Process + Persistence)
5. SSH Lateral Movement (Pivot Detection)
6. Data Exfiltration Spike
7. Suspicious Process Tree
"""

import logging
from typing import List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from amoskys.intel.models import Incident, Severity, MitreTactic, TelemetryEventView

logger = logging.getLogger(__name__)


def rule_ssh_brute_force(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect SSH brute force followed by successful login

    Pattern:
        - ≥ 3 failed SSH authentication attempts from same source IP
        - Followed by successful SSH login from that IP within 30 minutes

    Signals:
        - SECURITY events with event_action='SSH', event_outcome='FAILURE'/'SUCCESS'

    Returns:
        Incident if pattern detected, None otherwise
    """
    # Extract SSH events
    ssh_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "SSH"
    ]

    if len(ssh_events) < 4:  # Need at least 3 failures + 1 success
        return None

    # Group by source IP
    ip_timeline = defaultdict(list)
    for event in ssh_events:
        source_ip = event.security_event.get("source_ip", "unknown")
        outcome = event.security_event.get("event_outcome")
        ip_timeline[source_ip].append(
            {
                "event": event,
                "outcome": outcome,
                "timestamp": event.timestamp,
                "user": event.security_event.get("user_name", "unknown"),
            }
        )

    # Check each IP for brute force pattern
    for source_ip, timeline in ip_timeline.items():
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])

        # Look for failures followed by success
        failures = []
        for entry in timeline:
            if entry["outcome"] == "FAILURE":
                failures.append(entry)
            elif entry["outcome"] == "SUCCESS" and len(failures) >= 3:
                # Check if success is within 30 minutes of first failure
                first_failure_time = failures[0]["timestamp"]
                success_time = entry["timestamp"]
                time_diff = (success_time - first_failure_time).total_seconds()

                if time_diff <= 1800:  # 30 minutes
                    # Pattern detected!
                    event_ids = [f["event"].event_id for f in failures]
                    event_ids.append(entry["event"].event_id)

                    incident = Incident(
                        incident_id=f"ssh_bf_{device_id}_{int(success_time.timestamp())}",
                        device_id=device_id,
                        severity=Severity.HIGH,
                        tactics=[MitreTactic.INITIAL_ACCESS.value],
                        techniques=["T1110", "T1021.004"],  # Brute Force, SSH
                        rule_name="ssh_brute_force",
                        summary=f"SSH brute force from {source_ip}: {len(failures)} failed attempts "
                        f"followed by successful login as {entry['user']}",
                        event_ids=event_ids,
                        metadata={
                            "source_ip": source_ip,
                            "target_user": entry["user"],
                            "failed_attempts": str(len(failures)),
                            "time_to_compromise_seconds": str(int(time_diff)),
                        },
                    )

                    # Set time bounds
                    incident.start_ts = first_failure_time
                    incident.end_ts = success_time

                    logger.warning(
                        f"SSH brute force detected: {source_ip} → {entry['user']}"
                    )
                    return incident

    return None


def rule_persistence_after_auth(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect persistence mechanism created shortly after authentication

    Pattern:
        - Successful SSH login or sudo command execution
        - Followed by CREATED persistence (LaunchAgent/Daemon, cron, SSH key) within 10 minutes

    Signals:
        - SECURITY events: auth_type='SSH' or 'SUDO', result='SUCCESS'
        - AUDIT events: action='CREATED', object_type in persistence types

    Returns:
        Incident if pattern detected, None otherwise
    """
    # Extract auth events (SSH success or sudo)
    auth_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_outcome") == "SUCCESS"
        and e.security_event.get("event_action") in ["SSH", "SUDO"]
    ]

    # Extract persistence creation events
    persistence_events = [
        e
        for e in events
        if e.event_type == "AUDIT"
        and e.audit_event
        and e.audit_event.get("action_performed") == "CREATED"
        and e.audit_event.get("object_type")
        in ["LAUNCH_AGENT", "LAUNCH_DAEMON", "CRON", "SSH_KEYS"]
    ]

    if not auth_events or not persistence_events:
        return None

    # Look for persistence created within 10 minutes after auth
    for auth_event in auth_events:
        for persist_event in persistence_events:
            time_diff = (persist_event.timestamp - auth_event.timestamp).total_seconds()

            # Check if persistence happened after auth, within 10 minutes
            if 0 < time_diff <= 600:  # 10 minutes
                # Check if persistence is in user directory (more suspicious)
                file_path = persist_event.attributes.get("file_path", "")
                in_user_dir = "/Users/" in file_path

                severity = Severity.CRITICAL if in_user_dir else Severity.HIGH
                persist_type = persist_event.audit_event.get("object_type")

                incident = Incident(
                    incident_id=f"persist_after_auth_{device_id}_{int(persist_event.timestamp.timestamp())}",
                    device_id=device_id,
                    severity=severity,
                    tactics=[
                        MitreTactic.PERSISTENCE.value,
                        MitreTactic.PRIVILEGE_ESCALATION.value,
                    ],
                    techniques=_get_persistence_techniques(persist_type),
                    rule_name="persistence_after_auth",
                    summary=f"New {persist_type} created {int(time_diff)}s after "
                    f"{auth_event.security_event.get('event_action')} login",
                    event_ids=[auth_event.event_id, persist_event.event_id],
                    metadata={
                        "auth_type": auth_event.security_event.get("event_action"),
                        "auth_user": auth_event.security_event.get(
                            "user_name", "unknown"
                        ),
                        "persistence_type": persist_type,
                        "persistence_path": file_path,
                        "time_delta_seconds": str(int(time_diff)),
                    },
                )

                incident.start_ts = auth_event.timestamp
                incident.end_ts = persist_event.timestamp

                logger.warning(
                    f"Persistence after auth detected: {persist_type} at {file_path}"
                )
                return incident

    return None


def rule_suspicious_sudo(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect suspicious sudo command execution

    Pattern:
        - Sudo command containing dangerous patterns:
          - rm -rf with system paths
          - Modification of /etc/sudoers
          - Writing to LaunchAgents/Daemons directories
          - Installing kernel extensions

    Signals:
        - SECURITY events: auth_type='SUDO', attributes['sudo_command']

    Returns:
        Incident if pattern detected, None otherwise
    """
    sudo_events = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "SUDO"
    ]

    if not sudo_events:
        return None

    # Dangerous command patterns
    dangerous_patterns = [
        ("rm -rf /", "recursive delete of root", Severity.CRITICAL),
        ("rm -rf /etc", "delete system config", Severity.CRITICAL),
        ("rm -rf /var", "delete system data", Severity.CRITICAL),
        ("/etc/sudoers", "sudoers modification", Severity.CRITICAL),
        ("visudo", "sudoers editor", Severity.HIGH),
        ("LaunchAgents", "launch agent manipulation", Severity.HIGH),
        ("LaunchDaemons", "launch daemon manipulation", Severity.HIGH),
        ("/Library/Extensions", "kernel extension install", Severity.HIGH),
        ("kextload", "kernel extension load", Severity.HIGH),
    ]

    for event in sudo_events:
        command = event.attributes.get("sudo_command", "")

        for pattern, description, severity in dangerous_patterns:
            if pattern in command:
                incident = Incident(
                    incident_id=f"suspicious_sudo_{device_id}_{int(event.timestamp.timestamp())}",
                    device_id=device_id,
                    severity=severity,
                    tactics=[MitreTactic.PRIVILEGE_ESCALATION.value],
                    techniques=["T1548.003"],  # Sudo abuse
                    rule_name="suspicious_sudo",
                    summary=f"Dangerous sudo command detected: {description}",
                    event_ids=[event.event_id],
                    metadata={
                        "user": event.security_event.get("user_name", "unknown"),
                        "command": command,
                        "pattern_matched": pattern,
                        "description": description,
                    },
                )

                incident.start_ts = event.timestamp
                incident.end_ts = event.timestamp

                logger.warning(f"Suspicious sudo detected: {command}")
                return incident

    return None


def rule_multi_tactic_attack(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect complex multi-stage attack involving network, process, and persistence

    Pattern:
        - New outbound network connection to uncommon port or IP
        - New suspicious process (in /tmp, ~/Downloads, or unusual path)
        - New persistence mechanism
        All within 15 minutes

    Signals:
        - FLOW events: new outbound connections
        - PROCESS events: new processes with suspicious paths
        - AUDIT events: new persistence mechanisms

    Returns:
        Incident if pattern detected, None otherwise
    """
    # Extract flow events (outbound connections)
    flow_events = [e for e in events if e.event_type == "FLOW" and e.flow_event]

    # Extract process events with suspicious paths
    suspicious_paths = ["/tmp/", "/var/tmp/", "Downloads/", ".Trash/"]
    process_events = [
        e
        for e in events
        if e.event_type == "PROCESS"
        and e.process_event
        and any(
            path in e.process_event.get("executable_path", "")
            for path in suspicious_paths
        )
    ]

    # Extract persistence events
    persistence_events = [
        e
        for e in events
        if e.event_type == "AUDIT"
        and e.audit_event
        and e.audit_event.get("action_performed") == "CREATED"
        and e.audit_event.get("object_type")
        in ["LAUNCH_AGENT", "LAUNCH_DAEMON", "SSH_KEYS"]
    ]

    # Need all three signal types
    if not (flow_events and process_events and persistence_events):
        return None

    # Look for temporal correlation (all within 15 minutes)
    for flow_event in flow_events:
        for process_event in process_events:
            for persist_event in persistence_events:
                # Get time range
                all_events = [flow_event, process_event, persist_event]
                timestamps = [e.timestamp for e in all_events]
                time_span = (max(timestamps) - min(timestamps)).total_seconds()

                if time_span <= 900:  # 15 minutes
                    # Multi-tactic attack detected!
                    incident = Incident(
                        incident_id=f"multi_tactic_{device_id}_{int(min(timestamps).timestamp())}",
                        device_id=device_id,
                        severity=Severity.CRITICAL,
                        tactics=[
                            MitreTactic.COMMAND_AND_CONTROL.value,
                            MitreTactic.EXECUTION.value,
                            MitreTactic.PERSISTENCE.value,
                        ],
                        techniques=[
                            "T1071",  # Application Layer Protocol (C2)
                            "T1059",  # Command and Scripting Interpreter
                            "T1543.001",  # Launch Agent
                        ],
                        rule_name="multi_tactic_attack",
                        summary=f"Multi-stage attack detected: suspicious process + network connection + persistence",
                        event_ids=[e.event_id for e in all_events],
                        metadata={
                            "dst_ip": flow_event.flow_event.get("dst_ip", "unknown"),
                            "dst_port": str(flow_event.flow_event.get("dst_port", 0)),
                            "process_path": process_event.process_event.get(
                                "executable_path", "unknown"
                            ),
                            "persistence_type": persist_event.audit_event.get(
                                "object_type", "unknown"
                            ),
                            "time_span_seconds": str(int(time_span)),
                        },
                    )

                    incident.start_ts = min(timestamps)
                    incident.end_ts = max(timestamps)

                    logger.critical(f"Multi-tactic attack detected on {device_id}")
                    return incident

    return None


def rule_ssh_lateral_movement(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect SSH-based lateral movement (pivot behavior)

    Pattern:
        - Inbound SSH success from external source
        - Followed by outbound SSH connection to different IP within 5 minutes
        - Indicates this host is being used as a pivot point

    Signals:
        - SECURITY events: SSH success (inbound)
        - FLOW events: outbound SSH (port 22) connection

    Returns:
        Incident if pattern detected, None otherwise
    """
    # Extract inbound SSH successes
    ssh_successes = [
        e
        for e in events
        if e.event_type == "SECURITY"
        and e.security_event
        and e.security_event.get("event_action") == "SSH"
        and e.security_event.get("event_outcome") == "SUCCESS"
    ]

    # Extract outbound SSH flows (port 22)
    ssh_flows = [
        e
        for e in events
        if e.event_type == "FLOW"
        and e.flow_event
        and e.flow_event.get("dst_port") == 22
        and e.flow_event.get("direction") == "OUTBOUND"
    ]

    if not (ssh_successes and ssh_flows):
        return None

    # Look for SSH success followed by outbound SSH within 5 minutes
    for ssh_event in ssh_successes:
        if not ssh_event.security_event:
            continue

        source_ip = ssh_event.security_event.get("source_ip", "unknown")

        for flow_event in ssh_flows:
            if not flow_event.flow_event:
                continue

            dest_ip = flow_event.flow_event.get("dst_ip", "unknown")

            # Skip if outbound SSH is to the same IP that logged in (not lateral)
            if dest_ip == source_ip:
                continue

            time_diff = (flow_event.timestamp - ssh_event.timestamp).total_seconds()

            # Check if outbound SSH happened after inbound SSH, within 5 minutes
            if 0 < time_diff <= 300:  # 5 minutes
                incident = Incident(
                    incident_id=f"ssh_lateral_{device_id}_{int(flow_event.timestamp.timestamp())}",
                    device_id=device_id,
                    severity=Severity.HIGH,
                    tactics=[MitreTactic.LATERAL_MOVEMENT.value],
                    techniques=["T1021.004"],  # Remote Services: SSH
                    rule_name="ssh_lateral_movement",
                    summary=f"SSH lateral movement detected: inbound from {source_ip}, "
                    f"then outbound to {dest_ip} within {int(time_diff)}s",
                    event_ids=[ssh_event.event_id, flow_event.event_id],
                    metadata={
                        "inbound_source": source_ip,
                        "outbound_dest": dest_ip,
                        "time_delta_seconds": str(int(time_diff)),
                        "user": ssh_event.security_event.get("user_name", "unknown"),
                    },
                )

                incident.start_ts = ssh_event.timestamp
                incident.end_ts = flow_event.timestamp

                logger.warning(
                    f"SSH lateral movement: {source_ip} → {device_id} → {dest_ip}"
                )
                return incident

    return None


def rule_data_exfiltration_spike(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect large data exfiltration to rare/new destinations

    Pattern:
        - Large outbound data volume (>10MB within 5 minutes)
        - To external IP not seen in baseline (rare destination)
        - Or sudden spike in bytes_out compared to recent activity

    Signals:
        - FLOW events: outbound connections with bytes_out

    Returns:
        Incident if pattern detected, None otherwise
    """
    # Extract outbound flows with data transfer
    outbound_flows = [
        e
        for e in events
        if e.event_type == "FLOW"
        and e.flow_event
        and e.flow_event.get("direction") == "OUTBOUND"
        and e.flow_event.get("bytes_out", 0) > 0
    ]

    if not outbound_flows:
        return None

    # Group flows by destination IP and calculate total bytes within 5-minute windows
    dest_volumes = {}

    for flow_event in outbound_flows:
        if not flow_event.flow_event:
            continue

        dest_ip = flow_event.flow_event.get("dst_ip", "unknown")
        bytes_out = flow_event.flow_event.get("bytes_out", 0)

        if dest_ip not in dest_volumes:
            dest_volumes[dest_ip] = {
                "bytes": 0,
                "flows": [],
                "first_seen": flow_event.timestamp,
                "last_seen": flow_event.timestamp,
            }

        dest_volumes[dest_ip]["bytes"] += bytes_out
        dest_volumes[dest_ip]["flows"].append(flow_event)
        dest_volumes[dest_ip]["last_seen"] = flow_event.timestamp

    # Check for suspicious volume spikes
    EXFIL_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10MB

    for dest_ip, stats in dest_volumes.items():
        time_span = (stats["last_seen"] - stats["first_seen"]).total_seconds()

        # Check if high volume transferred in short time
        if stats["bytes"] >= EXFIL_THRESHOLD_BYTES and time_span <= 300:  # 5 minutes
            # Calculate bytes per second for context
            bytes_per_sec = stats["bytes"] / max(time_span, 1)
            mb_transferred = stats["bytes"] / (1024 * 1024)

            incident = Incident(
                incident_id=f"data_exfil_{device_id}_{int(stats['last_seen'].timestamp())}",
                device_id=device_id,
                severity=Severity.CRITICAL,
                tactics=[MitreTactic.EXFILTRATION.value],
                techniques=["T1041"],  # Exfiltration Over C2 Channel
                rule_name="data_exfiltration_spike",
                summary=f"Large data exfiltration detected: {mb_transferred:.1f}MB to {dest_ip} "
                f"in {int(time_span)}s",
                event_ids=[flow.event_id for flow in stats["flows"]],
                metadata={
                    "destination_ip": dest_ip,
                    "bytes_transferred": str(stats["bytes"]),
                    "megabytes_transferred": f"{mb_transferred:.2f}",
                    "time_span_seconds": str(int(time_span)),
                    "bytes_per_second": str(int(bytes_per_sec)),
                    "flow_count": str(len(stats["flows"])),
                },
            )

            incident.start_ts = stats["first_seen"]
            incident.end_ts = stats["last_seen"]

            logger.critical(
                f"Data exfiltration spike: {mb_transferred:.1f}MB → {dest_ip}"
            )
            return incident

    return None


def rule_suspicious_process_tree(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect suspicious process execution from user-interactive shells

    Pattern:
        - Parent process is Terminal, iTerm, SSH, or sshd
        - Child process located in /tmp, /private/tmp, or ~/Downloads
        - Indicates potential malware execution from interactive session

    Signals:
        - PROCESS events with parent_executable_name and executable_path

    Returns:
        Incident if pattern detected, None otherwise
    """
    process_events = [
        e for e in events if e.event_type == "PROCESS" and e.process_event
    ]

    if not process_events:
        return None

    # Suspicious parent processes (user-interactive shells)
    suspicious_parents = [
        "Terminal",
        "iTerm",
        "iTerm2",
        "sshd",
        "ssh",
        "bash",
        "zsh",
        "sh",
    ]

    # Suspicious child paths
    suspicious_paths = ["/tmp/", "/private/tmp/", "/var/tmp/", "Downloads/"]

    for event in process_events:
        if not event.process_event:
            continue

        parent_name = event.process_event.get("parent_executable_name", "")
        child_path = event.process_event.get("executable_path", "")

        # Check if parent is interactive shell
        is_suspicious_parent = any(
            parent in parent_name for parent in suspicious_parents
        )

        # Check if child is in suspicious location
        is_suspicious_path = any(path in child_path for path in suspicious_paths)

        if is_suspicious_parent and is_suspicious_path:
            # Additional risk: check if process also made network connection
            pid = event.process_event.get("pid", 0)

            # Look for flow events from same timeframe (within 60s)
            has_network = False
            network_dest = None

            for flow_event in [
                e for e in events if e.event_type == "FLOW" and e.flow_event
            ]:
                time_diff = abs(
                    (flow_event.timestamp - event.timestamp).total_seconds()
                )
                if time_diff <= 60:  # Within 1 minute
                    has_network = True
                    network_dest = flow_event.flow_event.get("dst_ip", "unknown")
                    break

            severity = Severity.CRITICAL if has_network else Severity.HIGH

            incident = Incident(
                incident_id=f"suspicious_proc_tree_{device_id}_{int(event.timestamp.timestamp())}",
                device_id=device_id,
                severity=severity,
                tactics=[MitreTactic.EXECUTION.value],
                techniques=["T1059"],  # Command and Scripting Interpreter
                rule_name="suspicious_process_tree",
                summary=f"Suspicious process execution: {parent_name} spawned {child_path.split('/')[-1]} "
                f"from untrusted location"
                + (" with network activity" if has_network else ""),
                event_ids=[event.event_id],
                metadata={
                    "parent_process": parent_name,
                    "child_path": child_path,
                    "child_name": child_path.split("/")[-1],
                    "pid": str(pid),
                    "has_network_activity": str(has_network),
                    "network_destination": network_dest or "none",
                },
            )

            incident.start_ts = event.timestamp
            incident.end_ts = event.timestamp

            logger.warning(f"Suspicious process tree: {parent_name} → {child_path}")
            return incident

    return None


def _get_persistence_techniques(persist_type: str) -> List[str]:
    """Map persistence type to MITRE ATT&CK techniques

    Args:
        persist_type: Type of persistence (LAUNCH_AGENT, SSH_KEYS, etc.)

    Returns:
        List of MITRE technique IDs
    """
    mapping = {
        "LAUNCH_AGENT": ["T1543.001"],
        "LAUNCH_DAEMON": ["T1543.004"],
        "CRON": ["T1053.003"],
        "SSH_KEYS": ["T1098.004"],
    }
    return mapping.get(persist_type, ["T1543"])  # Generic persistence


# Rule registry - add new rules here
ALL_RULES = [
    rule_ssh_brute_force,
    rule_persistence_after_auth,
    rule_suspicious_sudo,
    rule_multi_tactic_attack,
    rule_ssh_lateral_movement,
    rule_data_exfiltration_spike,
    rule_suspicious_process_tree,
]


def evaluate_rules(events: List[TelemetryEventView], device_id: str) -> List[Incident]:
    """Evaluate all correlation rules against event window

    Args:
        events: List of TelemetryEventView objects to correlate
        device_id: Device being evaluated

    Returns:
        List of Incident objects (may be empty if no rules fire)
    """
    incidents = []

    for rule_fn in ALL_RULES:
        try:
            incident = rule_fn(events, device_id)
            if incident:
                incidents.append(incident)
                logger.info(
                    f"Rule fired: {incident.rule_name} → {incident.incident_id}"
                )
        except Exception as e:
            logger.error(f"Rule {rule_fn.__name__} failed: {e}", exc_info=True)

    return incidents
