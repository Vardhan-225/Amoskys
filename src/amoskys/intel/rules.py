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

import json
import logging
from collections import defaultdict
from typing import Dict, List, Optional

from amoskys.intel.models import Incident, MitreTactic, Severity, TelemetryEventView

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
        sec_event = event.security_event
        assert sec_event is not None  # Guaranteed by filter above
        source_ip = sec_event.get("source_ip", "unknown")
        outcome = sec_event.get("event_outcome")
        ip_timeline[source_ip].append(
            {
                "event": event,
                "outcome": outcome,
                "timestamp": event.timestamp,
                "user": sec_event.get("user_name", "unknown"),
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
        if e.audit_event
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
    flow_events = [e for e in events if e.flow_event]

    # Extract process events with suspicious paths
    suspicious_paths = ["/tmp/", "/var/tmp/", "Downloads/", ".Trash/"]
    process_events = [
        e
        for e in events
        if e.process_event
        and any(
            path in e.process_event.get("executable_path", "")
            for path in suspicious_paths
        )
    ]

    # Extract persistence events
    persistence_events = [
        e
        for e in events
        if e.audit_event
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
                        summary="Multi-stage attack detected: suspicious process + network connection + persistence",
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
        e for e in events if e.process_event
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
                e for e in events if e.flow_event
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


# ── NetworkSentinel event categories ──────────────────────────────────────
_NETWORK_SENTINEL_CATEGORIES = {
    "http_scan_storm",
    "directory_brute_force",
    "sqli_payload_detected",
    "xss_payload_detected",
    "path_traversal_detected",
    "attack_tool_detected",
    "rate_anomaly",
    "admin_path_enumeration",
    "credential_spray_detected",
    "connection_flood_detected",
}

# Kill-chain stage mapping for network attack events
_KILL_CHAIN_STAGES = {
    "http_scan_storm": ("reconnaissance", 1),
    "directory_brute_force": ("reconnaissance", 1),
    "attack_tool_detected": ("weaponization", 2),
    "rate_anomaly": ("delivery", 3),
    "sqli_payload_detected": ("exploitation", 4),
    "xss_payload_detected": ("exploitation", 4),
    "path_traversal_detected": ("exploitation", 4),
    "admin_path_enumeration": ("installation", 5),
    "credential_spray_detected": ("exploitation", 4),
    "connection_flood_detected": ("actions_on_objectives", 7),
}


def _get_event_category(event: TelemetryEventView) -> Optional[str]:
    """Extract event category from a TelemetryEventView.

    NetworkSentinel events store category in security_event['event_category'].
    Falls back to event_type for non-security events.
    """
    if event.security_event:
        return event.security_event.get("event_category")
    return event.event_type


def _extract_attacker_ip(event: TelemetryEventView) -> Optional[str]:
    """Extract attacker IP from any event type.

    NetworkSentinel stores it in attributes['attacker_ip'].
    Auth events store it in security_event['source_ip'].
    Flow events store it in flow_event['src_ip'].
    """
    ip = event.attributes.get("attacker_ip")
    if ip:
        return ip
    if event.security_event:
        ip = event.security_event.get("source_ip")
        if ip:
            return ip
    if event.flow_event:
        return event.flow_event.get("src_ip")
    return None


def rule_coordinated_reconnaissance(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect coordinated multi-vector attack from a single source IP.

    Pattern:
        - 3+ distinct NetworkSentinel probe detections from the same attacker IP
        - within the correlation window (30 minutes)

    This connects scan storm + directory brute force + SQLi + XSS +
    path traversal + tool fingerprint + rate anomaly + admin enum
    into ONE incident: "Coordinated Attack from X.X.X.X"

    Returns:
        Incident if pattern detected, None otherwise
    """
    # Collect NetworkSentinel events by attacker IP
    ip_events: Dict[str, List[TelemetryEventView]] = defaultdict(list)
    for event in events:
        cat = _get_event_category(event)
        if cat not in _NETWORK_SENTINEL_CATEGORIES:
            continue
        ip = _extract_attacker_ip(event)
        if ip:
            ip_events[ip].append(event)

    for attacker_ip, attack_events in ip_events.items():
        categories: set[str] = {
            c for e in attack_events if (c := _get_event_category(e)) is not None
        }
        if len(categories) < 3:
            continue

        # Determine kill chain stages hit and collect MITRE techniques
        stages_hit: set[str] = set()
        techniques_all: set[str] = set()
        for e in attack_events:
            cat = _get_event_category(e)
            stage_info = _KILL_CHAIN_STAGES.get(cat or "")
            if stage_info:
                stages_hit.add(stage_info[0])
            mitre_raw = e.attributes.get("mitre_techniques", "")
            if mitre_raw:
                try:
                    techniques_all.update(json.loads(mitre_raw))
                except (json.JSONDecodeError, TypeError):
                    pass

        # Severity based on attack breadth
        if len(categories) >= 6:
            severity = Severity.CRITICAL
        elif len(categories) >= 4:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        # Sort by kill chain stage for narrative
        sorted_events = sorted(
            attack_events,
            key=lambda ev: _KILL_CHAIN_STAGES.get(
                _get_event_category(ev) or "", ("unknown", 99)
            )[1],
        )

        # Build attack narrative
        narrative_lines = []
        for e in sorted_events:
            cat = _get_event_category(e) or "unknown"
            stage = _KILL_CHAIN_STAGES.get(cat, ("unknown", 99))
            desc = e.attributes.get("verdict", cat)
            if len(desc) > 60:
                desc = desc[:57] + "..."
            narrative_lines.append(f"  [{stage[0].upper()}] {desc}")

        timestamps = [e.timestamp for e in attack_events]
        start_ts = min(timestamps)
        end_ts = max(timestamps)
        duration = (end_ts - start_ts).total_seconds()

        incident = Incident(
            incident_id=f"coordinated_recon_{device_id}_{attacker_ip}_{int(end_ts.timestamp())}",
            device_id=device_id,
            severity=severity,
            tactics=[
                MitreTactic.DISCOVERY.value,  # TA0007 (closest to Reconnaissance)
                MitreTactic.INITIAL_ACCESS.value,
            ],
            techniques=sorted(techniques_all) if techniques_all else ["T1595", "T1190"],
            rule_name="coordinated_reconnaissance",
            summary=(
                f"COORDINATED ATTACK from {attacker_ip}: "
                f"{len(categories)} attack vectors, "
                f"{len(stages_hit)} kill chain stages hit in {int(duration)}s"
            ),
            event_ids=[e.event_id for e in attack_events],
            metadata={
                "attacker_ip": attacker_ip,
                "attack_categories": str(sorted(categories)),
                "category_count": str(len(categories)),
                "kill_chain_stages": str(sorted(stages_hit)),
                "stages_hit": str(len(stages_hit)),
                "duration_seconds": str(int(duration)),
                "total_events": str(len(attack_events)),
                "attack_narrative": "\n".join(narrative_lines),
            },
        )

        incident.start_ts = start_ts
        incident.end_ts = end_ts

        logger.critical(
            "COORDINATED ATTACK: %s → %d vectors, %d kill chain stages",
            attacker_ip,
            len(categories),
            len(stages_hit),
        )
        return incident

    return None


def rule_web_attack_chain(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect kill chain progression: recon → exploitation → post-exploitation.

    Pattern:
        - Scan/recon event (http_scan_storm, directory_brute_force)
        - FOLLOWED BY injection attempt (sqli, xss, path_traversal)
        - FOLLOWED BY enumeration (admin_path_enumeration)
        - All from same IP within window

    Differs from coordinated_reconnaissance by requiring
    temporal PROGRESSION through kill chain stages.

    Returns:
        Incident if kill chain progression detected, None otherwise
    """
    RECON = {"http_scan_storm", "directory_brute_force", "attack_tool_detected"}
    EXPLOIT = {
        "sqli_payload_detected",
        "xss_payload_detected",
        "path_traversal_detected",
    }
    POST_EXPLOIT = {"admin_path_enumeration", "credential_spray_detected"}

    ip_events: Dict[str, List[TelemetryEventView]] = defaultdict(list)
    for event in events:
        cat = _get_event_category(event)
        if cat not in _NETWORK_SENTINEL_CATEGORIES:
            continue
        ip = _extract_attacker_ip(event)
        if ip:
            ip_events[ip].append(event)

    for attacker_ip, attack_events in ip_events.items():
        categories: set[str] = {
            c for e in attack_events if (c := _get_event_category(e)) is not None
        }

        has_recon = bool(categories & RECON)
        has_exploit = bool(categories & EXPLOIT)
        has_post = bool(categories & POST_EXPLOIT)

        if not (has_recon and has_exploit):
            continue

        chain_stages = []
        if has_recon:
            chain_stages.append("RECON")
        if has_exploit:
            chain_stages.append("EXPLOIT")
        if has_post:
            chain_stages.append("POST-EXPLOIT")

        severity = Severity.CRITICAL if has_post else Severity.HIGH

        timestamps = [e.timestamp for e in attack_events]
        start_ts = min(timestamps)
        end_ts = max(timestamps)
        duration = (end_ts - start_ts).total_seconds()

        incident = Incident(
            incident_id=f"web_attack_chain_{device_id}_{attacker_ip}_{int(end_ts.timestamp())}",
            device_id=device_id,
            severity=severity,
            tactics=[
                MitreTactic.DISCOVERY.value,
                MitreTactic.INITIAL_ACCESS.value,
                MitreTactic.EXECUTION.value,
            ],
            techniques=["T1595", "T1190", "T1059.007"],
            rule_name="web_attack_chain",
            summary=(
                f"KILL CHAIN: {attacker_ip} progressed through "
                f"{' → '.join(chain_stages)} "
                f"({len(categories)} techniques in {int(duration)}s)"
            ),
            event_ids=[e.event_id for e in attack_events],
            metadata={
                "attacker_ip": attacker_ip,
                "chain_stages": str(chain_stages),
                "chain_depth": str(len(chain_stages)),
                "recon_techniques": str(sorted(categories & RECON)),
                "exploit_techniques": str(sorted(categories & EXPLOIT)),
                "post_exploit_techniques": str(sorted(categories & POST_EXPLOIT)),
                "duration_seconds": str(int(duration)),
            },
        )

        incident.start_ts = start_ts
        incident.end_ts = end_ts

        logger.critical(
            "KILL CHAIN: %s → %s",
            attacker_ip,
            " → ".join(chain_stages),
        )
        return incident

    return None


# ── macOS Shield Fusion Rules ──────────────────────────────────────────

# Infostealer kill chain stages (event_category values from probes)
_STEALER_STAGES = {
    "dialog": {"fake_password_dialog", "fake_dialog"},
    "credential_access": {
        "keychain_access",
        "browser_cred_theft",
        "browser_credential_theft",  # actual probe event_category
        "crypto_wallet_theft",
        "session_cookie_theft",
        "stealer_sequence",
        "clipboard_harvest",
        "screen_capture_abuse",
    },
    "staging": {"credential_archive"},
    "exfil": {
        "sensitive_file_exfil",
        "exfil_detected",
        "cloud_exfil_detected",  # internet_activity probe category
        "execute_to_exfil",
        "pid_network_anomaly",
    },
}

# ClickFix-related event categories
_CLICKFIX_CATEGORIES = {
    "clickfix_detected",
    "browser_to_terminal",
    "rapid_app_switch",
    "msg_to_download",
    "download_to_execute",
}

# Download/execute chain categories
_DOWNLOAD_EXECUTE_CATEGORIES = {
    "quarantine_bypass",
    "dmg_mount_execute",
    "unsigned_download_exec",
    "cli_download_execute",
    "quarantine_evasion",
    "installer_script_abuse",
    "download_to_execute",
    "suspicious_download_source",
}

# Persistence categories (from existing persistence agent)
_PERSISTENCE_CATEGORIES = {
    "launch_agent_created",
    "launch_daemon_created",
    "cron_modified",
    "ssh_key_added",
    "login_item_added",
    "shell_profile_modified",
    "persistence_detected",
    "folder_action_created",
}


def rule_infostealer_kill_chain(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect macOS infostealer kill chain: dialog → credential access → archive → exfil.

    Pattern:
        - Fake password dialog (osascript display dialog with password keywords)
        - Credential store access (keychain, browser, crypto wallet, cookies)
        - Credential archiving (zip/tar/ditto with sensitive paths)
        - Network exfiltration (sensitive file access + external connection)

    Fires when 2+ distinct stages are detected from the same device.
    """
    stage_events: Dict[str, List[TelemetryEventView]] = defaultdict(list)

    for event in events:
        category = _get_event_category(event)
        if not category:
            continue
        for stage_name, stage_categories in _STEALER_STAGES.items():
            if category in stage_categories:
                stage_events[stage_name].append(event)

    if len(stage_events) < 2:
        return None

    # Build evidence
    all_event_ids = []
    stage_summary = []
    techniques = set()

    for stage_name, stage_evts in sorted(stage_events.items()):
        for e in stage_evts:
            all_event_ids.append(e.event_id)
            if e.security_event and e.security_event.get("mitre_techniques"):
                try:
                    techs = json.loads(e.security_event["mitre_techniques"])
                    techniques.update(techs)
                except (json.JSONDecodeError, TypeError):
                    pass
        stage_summary.append(f"{stage_name}: {len(stage_evts)} events")

    stages_hit = len(stage_events)
    severity = Severity.CRITICAL if stages_hit >= 3 else Severity.HIGH

    timestamps = [
        e.timestamp
        for e in events
        if _get_event_category(e)
        in {c for cats in _STEALER_STAGES.values() for c in cats}
    ]
    start_ts = min(timestamps) if timestamps else events[0].timestamp
    end_ts = max(timestamps) if timestamps else events[-1].timestamp

    return Incident(
        incident_id=f"infostealer_chain_{device_id}_{int(start_ts.timestamp())}",
        device_id=device_id,
        severity=severity,
        tactics=[MitreTactic.CREDENTIAL_ACCESS.value, MitreTactic.COLLECTION.value],
        techniques=sorted(techniques) or ["T1555", "T1056.002"],
        rule_name="infostealer_kill_chain",
        summary=(
            f"INFOSTEALER KILL CHAIN on {device_id}: {stages_hit} stages detected "
            f"({', '.join(stage_summary)})"
        ),
        event_ids=all_event_ids,
        metadata={
            "stages_hit": str(stages_hit),
            "stage_breakdown": str(stage_summary),
            "kill_chain_type": "macos_infostealer",
        },
        start_ts=start_ts,
        end_ts=end_ts,
    )


def rule_clickfix_attack(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect ClickFix social engineering attack chain.

    Pattern:
        - Messaging app activity detected
        - Terminal spawned with suspicious command (curl, bash -c, wget)
        - Possible execution or exfiltration follows

    This is the primary post-Sequoia stealer delivery mechanism.
    """
    clickfix_events = []

    for event in events:
        category = _get_event_category(event)
        if category and category in _CLICKFIX_CATEGORIES:
            clickfix_events.append(event)

    if not clickfix_events:
        return None

    # Check for the key indicators
    has_clickfix = any(
        _get_event_category(e) in {"clickfix_detected", "browser_to_terminal"}
        for e in clickfix_events
    )
    has_chain = any(
        _get_event_category(e) in {"msg_to_download", "download_to_execute"}
        for e in clickfix_events
    )

    if not has_clickfix and not has_chain:
        return None

    all_event_ids = [e.event_id for e in clickfix_events]
    techniques = set()
    for e in clickfix_events:
        if e.security_event and e.security_event.get("mitre_techniques"):
            try:
                techs = json.loads(e.security_event["mitre_techniques"])
                techniques.update(techs)
            except (json.JSONDecodeError, TypeError):
                pass

    start_ts = min(e.timestamp for e in clickfix_events)
    end_ts = max(e.timestamp for e in clickfix_events)

    return Incident(
        incident_id=f"clickfix_{device_id}_{int(start_ts.timestamp())}",
        device_id=device_id,
        severity=Severity.CRITICAL,
        tactics=[MitreTactic.EXECUTION.value, MitreTactic.INITIAL_ACCESS.value],
        techniques=sorted(techniques) or ["T1204.001", "T1059"],
        rule_name="clickfix_attack",
        summary=(
            f"CLICKFIX ATTACK on {device_id}: messaging app → Terminal → suspicious "
            f"command chain ({len(clickfix_events)} indicators)"
        ),
        event_ids=all_event_ids,
        metadata={
            "indicator_count": str(len(clickfix_events)),
            "categories": str(
                sorted(
                    {
                        _get_event_category(e)
                        for e in clickfix_events
                        if _get_event_category(e)
                    }
                )
            ),
        },
        start_ts=start_ts,
        end_ts=end_ts,
    )


def rule_download_execute_persist(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect download → execute → persist chain.

    Pattern:
        - Download event (quarantine, DMG mount, CLI download)
        - Execution from downloaded file
        - Persistence mechanism created (LaunchAgent, cron, etc.)

    Links quarantine_guard events with persistence agent events.
    """
    download_events = []
    persist_events = []

    for event in events:
        category = _get_event_category(event)
        if not category:
            continue
        if category in _DOWNLOAD_EXECUTE_CATEGORIES:
            download_events.append(event)
        elif category in _PERSISTENCE_CATEGORIES:
            persist_events.append(event)

    if not download_events or not persist_events:
        return None

    all_event_ids = [e.event_id for e in download_events + persist_events]
    techniques = {"T1204.002", "T1543"}

    start_ts = min(e.timestamp for e in download_events + persist_events)
    end_ts = max(e.timestamp for e in download_events + persist_events)

    return Incident(
        incident_id=f"download_persist_{device_id}_{int(start_ts.timestamp())}",
        device_id=device_id,
        severity=Severity.HIGH,
        tactics=[
            MitreTactic.INITIAL_ACCESS.value,
            MitreTactic.EXECUTION.value,
            MitreTactic.PERSISTENCE.value,
        ],
        techniques=sorted(techniques),
        rule_name="download_execute_persist",
        summary=(
            f"DOWNLOAD → EXECUTE → PERSIST on {device_id}: "
            f"{len(download_events)} download/execute events + "
            f"{len(persist_events)} persistence events"
        ),
        event_ids=all_event_ids,
        metadata={
            "download_count": str(len(download_events)),
            "persistence_count": str(len(persist_events)),
        },
        start_ts=start_ts,
        end_ts=end_ts,
    )


def rule_credential_harvest_exfil(
    events: List[TelemetryEventView], device_id: str
) -> Optional[Incident]:
    """Detect credential harvesting followed by exfiltration.

    Pattern:
        - 3+ credential store access events (keychain + browser + wallet)
        - Network exfiltration event within the same window

    The cumulative credential access from multiple stores is the key signal —
    legitimate processes only access their own store.
    """
    cred_categories_seen: Dict[str, List[TelemetryEventView]] = defaultdict(list)
    exfil_events = []

    for event in events:
        category = _get_event_category(event)
        if not category:
            continue
        # Check if this is a credential access event
        if category in _STEALER_STAGES.get("credential_access", set()):
            cred_categories_seen[category].append(event)
        elif category in {
            "sensitive_file_exfil",
            "exfil_detected",
            "execute_to_exfil",
            "pid_network_anomaly",
        }:
            exfil_events.append(event)

    # Need 2+ distinct credential categories
    if len(cred_categories_seen) < 2:
        return None

    all_cred_events = [e for evts in cred_categories_seen.values() for e in evts]
    all_event_ids = [e.event_id for e in all_cred_events + exfil_events]

    severity = Severity.CRITICAL if exfil_events else Severity.HIGH
    category_names = sorted(cred_categories_seen.keys())

    all_events_combined = all_cred_events + exfil_events
    start_ts = min(e.timestamp for e in all_events_combined)
    end_ts = max(e.timestamp for e in all_events_combined)

    exfil_note = f" + {len(exfil_events)} exfil events" if exfil_events else ""

    return Incident(
        incident_id=f"cred_harvest_{device_id}_{int(start_ts.timestamp())}",
        device_id=device_id,
        severity=severity,
        tactics=[MitreTactic.CREDENTIAL_ACCESS.value, MitreTactic.EXFILTRATION.value],
        techniques=["T1555", "T1041"],
        rule_name="credential_harvest_exfil",
        summary=(
            f"CREDENTIAL HARVESTING on {device_id}: {len(cred_categories_seen)} "
            f"credential stores accessed ({', '.join(category_names)})"
            f"{exfil_note}"
        ),
        event_ids=all_event_ids,
        metadata={
            "credential_categories": str(category_names),
            "category_count": str(len(cred_categories_seen)),
            "total_access_events": str(len(all_cred_events)),
            "exfil_events": str(len(exfil_events)),
        },
        start_ts=start_ts,
        end_ts=end_ts,
    )


# Rule registry - add new rules here
ALL_RULES = [
    rule_ssh_brute_force,
    rule_persistence_after_auth,
    rule_suspicious_sudo,
    rule_multi_tactic_attack,
    rule_ssh_lateral_movement,
    rule_data_exfiltration_spike,
    rule_suspicious_process_tree,
    rule_coordinated_reconnaissance,
    rule_web_attack_chain,
    # macOS Shield rules
    rule_infostealer_kill_chain,
    rule_clickfix_attack,
    rule_download_execute_persist,
    rule_credential_harvest_exfil,
]


def evaluate_rules(
    events: List[TelemetryEventView],
    device_id: str,
    weights: Optional[dict] = None,
) -> List[Incident]:
    """Evaluate all correlation rules against event window

    Args:
        events: List of TelemetryEventView objects to correlate
        device_id: Device being evaluated
        weights: Optional AMRDR fusion weights {agent_id: weight}.
            When provided, incidents are annotated with agent_weights,
            weighted_confidence, and contributing_agents.

    Returns:
        List of Incident objects (may be empty if no rules fire)
    """
    incidents = []

    for rule_fn in ALL_RULES:
        try:
            incident = rule_fn(events, device_id)
            if incident:
                # Annotate with AMRDR weights if available
                if weights:
                    _annotate_incident_weights(incident, events, weights)
                incidents.append(incident)
                logger.info(
                    f"Rule fired: {incident.rule_name} → {incident.incident_id}"
                )
        except Exception as e:
            logger.error(f"Rule {rule_fn.__name__} failed: {e}", exc_info=True)

    return incidents


def _annotate_incident_weights(
    incident: Incident,
    events: List[TelemetryEventView],
    weights: dict,
) -> None:
    """Annotate an incident with AMRDR reliability weights.

    Determines which agents contributed to the incident's events and
    computes a weighted confidence score based on their fusion weights.

    Args:
        incident: Incident to annotate (modified in place)
        events: Event window (used to determine agent sources)
        weights: AMRDR fusion weights {agent_id: weight}
    """
    # Determine contributing agents from incident event IDs
    incident_event_ids = set(incident.event_ids)
    contributing = set()

    for event in events:
        if event.event_id in incident_event_ids:
            # Derive agent from event attributes or event_type
            agent_id = event.attributes.get("agent_id", event.event_type)
            contributing.add(agent_id)

    incident.contributing_agents = sorted(contributing)

    # Collect weights for contributing agents
    agent_w = {}
    for agent_id in incident.contributing_agents:
        agent_w[agent_id] = weights.get(agent_id, 1.0)

    incident.agent_weights = agent_w

    # Compute weighted confidence from AMRDR weights + event risk scores
    # AMRDR weight = agent reliability, risk_score = signal strength
    amrdr_conf = sum(agent_w.values()) / len(agent_w) if agent_w else 1.0

    # Blend in signal strength from contributing events
    risk_scores = []
    for event in events:
        if event.event_id in incident_event_ids and event.security_event:
            r = event.security_event.get("risk_score", 0)
            try:
                risk_scores.append(float(r))
            except (TypeError, ValueError):
                pass

    if risk_scores:
        avg_risk = sum(risk_scores) / len(risk_scores)
        # 70% AMRDR reliability + 30% signal strength
        incident.weighted_confidence = round(0.7 * amrdr_conf + 0.3 * avg_risk, 3)
    else:
        incident.weighted_confidence = amrdr_conf
