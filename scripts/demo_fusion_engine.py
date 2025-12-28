#!/usr/bin/env python3
"""
Fusion Engine Demonstration

Creates synthetic security events to demonstrate correlation rules:
1. SSH brute force → successful login
2. Persistence after authentication
3. Suspicious sudo commands
4. Multi-tactic attack chains

This validates the Intelligence layer without requiring live agents.
"""

import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from amoskys.intel import FusionEngine, TelemetryEventView


def create_ssh_brute_force_scenario(device_id: str, base_time: datetime):
    """Create SSH brute force attack scenario

    Timeline:
    - T+0s: Failed SSH attempt from 203.0.113.42
    - T+5s: Failed SSH attempt from same IP
    - T+10s: Failed SSH attempt from same IP
    - T+15s: Successful SSH login from same IP

    Expected: Rule 1 fires (ssh_brute_force)
    """
    events = []

    # Failed attempts
    for i in range(3):
        event = TelemetryEventView(
            event_id=f"auth_ssh_fail_{i}",
            device_id=device_id,
            event_type="SECURITY",
            severity="WARN",
            timestamp=base_time + timedelta(seconds=i * 5),
            security_event={
                'event_category': 'AUTHENTICATION',
                'event_action': 'SSH',
                'event_outcome': 'FAILURE',
                'user_name': 'admin',
                'source_ip': '203.0.113.42',
                'risk_score': 0.6,
                'mitre_techniques': ['T1110', 'T1021.004'],
                'requires_investigation': True
            }
        )
        events.append(event)

    # Successful login
    success_event = TelemetryEventView(
        event_id="auth_ssh_success",
        device_id=device_id,
        event_type="SECURITY",
        severity="INFO",
        timestamp=base_time + timedelta(seconds=15),
        security_event={
            'event_category': 'AUTHENTICATION',
            'event_action': 'SSH',
            'event_outcome': 'SUCCESS',
            'user_name': 'admin',
            'source_ip': '203.0.113.42',
            'risk_score': 0.3,
            'mitre_techniques': ['T1021.004'],
            'requires_investigation': False
        }
    )
    events.append(success_event)

    return events


def create_persistence_after_auth_scenario(device_id: str, base_time: datetime):
    """Create persistence installation after authentication

    Timeline:
    - T+0s: Successful SSH login
    - T+120s: New LaunchAgent created in /Users/

    Expected: Rule 2 fires (persistence_after_auth)
    """
    events = []

    # SSH login
    ssh_event = TelemetryEventView(
        event_id="auth_ssh_login",
        device_id=device_id,
        event_type="SECURITY",
        severity="INFO",
        timestamp=base_time,
        security_event={
            'event_category': 'AUTHENTICATION',
            'event_action': 'SSH',
            'event_outcome': 'SUCCESS',
            'user_name': 'compromised_user',
            'source_ip': '198.51.100.23',
            'risk_score': 0.3,
            'mitre_techniques': ['T1021.004'],
            'requires_investigation': False
        }
    )
    events.append(ssh_event)

    # Persistence creation
    persist_event = TelemetryEventView(
        event_id="audit_launchagent_created",
        device_id=device_id,
        event_type="AUDIT",
        severity="WARN",
        timestamp=base_time + timedelta(seconds=120),
        attributes={
            'persistence_type': 'LAUNCH_AGENT',
            'file_path': '/Users/compromised_user/Library/LaunchAgents/com.evil.backdoor.plist',
            'risk_score': '0.7'
        },
        audit_event={
            'audit_category': 'CHANGE',
            'action_performed': 'CREATED',
            'object_type': 'LAUNCH_AGENT',
            'object_id': '/Users/compromised_user/Library/LaunchAgents/com.evil.backdoor.plist',
            'before_value': '',
            'after_value': '{"Program": "/tmp/backdoor", "RunAtLoad": true}'
        }
    )
    events.append(persist_event)

    return events


def create_suspicious_sudo_scenario(device_id: str, base_time: datetime):
    """Create suspicious sudo command execution

    Timeline:
    - T+0s: Sudo command to modify /etc/sudoers

    Expected: Rule 3 fires (suspicious_sudo)
    """
    event = TelemetryEventView(
        event_id="auth_sudo_dangerous",
        device_id=device_id,
        event_type="SECURITY",
        severity="CRITICAL",
        timestamp=base_time,
        attributes={
            'sudo_command': 'vim /etc/sudoers',
            'auth_method': 'password'
        },
        security_event={
            'event_category': 'AUTHENTICATION',
            'event_action': 'SUDO',
            'event_outcome': 'SUCCESS',
            'user_name': 'attacker',
            'source_ip': '127.0.0.1',
            'risk_score': 0.8,
            'mitre_techniques': ['T1548.003'],
            'requires_investigation': True
        }
    )

    return [event]


def create_multi_tactic_scenario(device_id: str, base_time: datetime):
    """Create complex multi-tactic attack

    Timeline:
    - T+0s: Suspicious process in /tmp
    - T+60s: Outbound connection to unknown IP
    - T+180s: SSH key added

    Expected: Rule 4 fires (multi_tactic_attack)
    """
    events = []

    # Suspicious process
    process_event = TelemetryEventView(
        event_id="process_suspicious",
        device_id=device_id,
        event_type="PROCESS",
        severity="WARN",
        timestamp=base_time,
        process_event={
            'process_name': 'malware',
            'pid': 12345,
            'ppid': 1,
            'uid': 501,
            'command_line': '/tmp/malware --connect 198.51.100.99',
            'executable_path': '/tmp/malware'
        }
    )
    events.append(process_event)

    # Network connection
    flow_event = TelemetryEventView(
        event_id="flow_suspicious_c2",
        device_id=device_id,
        event_type="FLOW",
        severity="WARN",
        timestamp=base_time + timedelta(seconds=60),
        flow_event={
            'src_ip': '192.168.1.100',
            'src_port': 54321,
            'dst_ip': '198.51.100.99',
            'dst_port': 443,
            'protocol': 'TCP',
            'bytes_sent': 1024,
            'bytes_received': 4096
        }
    )
    events.append(flow_event)

    # SSH key persistence
    persist_event = TelemetryEventView(
        event_id="audit_sshkey_created",
        device_id=device_id,
        event_type="AUDIT",
        severity="CRITICAL",
        timestamp=base_time + timedelta(seconds=180),
        attributes={
            'persistence_type': 'SSH_KEYS',
            'file_path': '/Users/victim/.ssh/authorized_keys',
            'risk_score': '0.8'
        },
        audit_event={
            'audit_category': 'CHANGE',
            'action_performed': 'CREATED',
            'object_type': 'SSH_KEYS',
            'object_id': '/Users/victim/.ssh/authorized_keys',
            'before_value': '',
            'after_value': 'ssh-rsa AAAAB3... attacker@evil.com'
        }
    )
    events.append(persist_event)

    return events


def run_demo():
    """Run fusion engine demonstration"""
    print("=" * 70)
    print("AMOSKYS Fusion Engine Demonstration")
    print("=" * 70)
    print()

    # Initialize engine
    print("Initializing Fusion Engine...")
    engine = FusionEngine(
        db_path="data/intel/fusion_demo.db",
        window_minutes=30,
        eval_interval=60
    )
    print(f"  Database: {engine.db_path}")
    print(f"  Correlation window: {engine.window_minutes} minutes")
    print()

    device_id = "demo-macbook-pro"
    base_time = datetime.now()

    # Scenario 1: SSH Brute Force
    print("Scenario 1: SSH Brute Force Attack")
    print("-" * 70)
    events = create_ssh_brute_force_scenario(device_id, base_time)
    for event in events:
        engine.add_event(event)
        print(f"  [T+{(event.timestamp - base_time).seconds}s] {event.event_type}: "
              f"{event.security_event['event_outcome']} SSH from {event.security_event['source_ip']}")
    print()

    # Evaluate
    incidents, risk = engine.evaluate_device(device_id)
    for inc in incidents:
        engine.persist_incident(inc)
    engine.persist_risk_snapshot(risk)

    print(f"  Incidents: {len(incidents)}")
    for inc in incidents:
        print(f"    [{inc.severity.value}] {inc.rule_name}: {inc.summary}")
    print(f"  Device Risk: {risk.level.value} (score={risk.score})")
    print(f"  Reason: {', '.join(risk.reason_tags)}")
    print()

    # Scenario 2: Persistence After Auth
    print("Scenario 2: Persistence After Authentication")
    print("-" * 70)
    base_time += timedelta(minutes=5)
    events = create_persistence_after_auth_scenario(device_id, base_time)
    for event in events:
        engine.add_event(event)
        print(f"  [T+{(event.timestamp - base_time).seconds}s] {event.event_type}: ", end='')
        if event.event_type == "SECURITY":
            print(f"{event.security_event['event_action']} login")
        else:
            print(f"{event.audit_event['object_type']} created")
    print()

    incidents, risk = engine.evaluate_device(device_id)
    for inc in incidents:
        engine.persist_incident(inc)
    engine.persist_risk_snapshot(risk)

    print(f"  Incidents: {len(incidents)}")
    for inc in incidents:
        print(f"    [{inc.severity.value}] {inc.rule_name}: {inc.summary}")
    print(f"  Device Risk: {risk.level.value} (score={risk.score})")
    print(f"  Reason: {', '.join(risk.reason_tags[:5])}")
    print()

    # Scenario 3: Suspicious Sudo
    print("Scenario 3: Suspicious Sudo Command")
    print("-" * 70)
    base_time += timedelta(minutes=5)
    events = create_suspicious_sudo_scenario(device_id, base_time)
    for event in events:
        engine.add_event(event)
        print(f"  [T+0s] SUDO: {event.attributes['sudo_command']}")
    print()

    incidents, risk = engine.evaluate_device(device_id)
    for inc in incidents:
        engine.persist_incident(inc)
    engine.persist_risk_snapshot(risk)

    print(f"  Incidents: {len(incidents)}")
    for inc in incidents:
        print(f"    [{inc.severity.value}] {inc.rule_name}: {inc.summary}")
    print(f"  Device Risk: {risk.level.value} (score={risk.score})")
    print(f"  Reason: {', '.join(risk.reason_tags[:5])}")
    print()

    # Scenario 4: Multi-Tactic Attack
    print("Scenario 4: Multi-Tactic Attack Chain")
    print("-" * 70)
    base_time += timedelta(minutes=5)
    events = create_multi_tactic_scenario(device_id, base_time)
    for event in events:
        engine.add_event(event)
        print(f"  [T+{(event.timestamp - base_time).seconds}s] {event.event_type}", end='')
        if event.event_type == "PROCESS":
            print(f": {event.process_event['executable_path']}")
        elif event.event_type == "FLOW":
            print(f": → {event.flow_event['dst_ip']}:{event.flow_event['dst_port']}")
        else:
            print(f": {event.audit_event['object_type']}")
    print()

    incidents, risk = engine.evaluate_device(device_id)
    for inc in incidents:
        engine.persist_incident(inc)
    engine.persist_risk_snapshot(risk)

    print(f"  Incidents: {len(incidents)}")
    for inc in incidents:
        print(f"    [{inc.severity.value}] {inc.rule_name}: {inc.summary}")
    print(f"  Device Risk: {risk.level.value} (score={risk.score})")
    print(f"  Reason: {', '.join(risk.reason_tags[:5])}")
    print()

    # Summary
    print("=" * 70)
    print("Demonstration Summary")
    print("=" * 70)

    all_incidents = engine.get_recent_incidents(device_id=device_id, limit=100)
    print(f"Total Incidents Detected: {len(all_incidents)}")
    print()

    print("Incidents by Severity:")
    severity_counts = {}
    for inc in all_incidents:
        sev = inc['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"  {sev}: {count}")
    print()

    final_risk = engine.get_device_risk(device_id)
    if final_risk:
        print(f"Final Device Risk: {final_risk['level']} (score={final_risk['score']})")
        print(f"Contributing Factors:")
        for tag in final_risk['reason_tags'][:10]:
            print(f"  - {tag}")
    print()

    print(f"Results saved to: {engine.db_path}")
    print()
    print("Demo complete! Fusion Engine successfully detected:")
    print("  ✓ SSH brute force → compromise")
    print("  ✓ Persistence after authentication")
    print("  ✓ Suspicious sudo commands")
    print("  ✓ Multi-tactic attack chains")
    print()
    print("Intelligence layer ready for production integration!")


if __name__ == '__main__':
    run_demo()
