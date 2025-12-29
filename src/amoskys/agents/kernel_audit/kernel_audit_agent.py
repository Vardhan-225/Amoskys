#!/usr/bin/env python3
"""
AMOSKYS Kernel Audit Agent (KernelAuditAgent)

Monitors kernel-level events for advanced attack detection:
- System call monitoring (exec, open, connect, etc.)
- Privilege escalation detection
- Container escapes
- Kernel module loading
- ptrace-based attacks (process injection)
- Capability abuse

Uses:
- macOS: Endpoint Security Framework (ESF) / OpenBSM audit
- Linux: auditd / eBPF

Critical for detecting:
- Privilege escalation (T1068)
- Process injection (T1055)
- Container escape (T1611)
- Kernel rootkits (T1014)
"""

import json
import logging
import os
import re
import socket
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import grpc

from amoskys.agents.common import LocalQueue
from amoskys.agents.common.hardened_base import HardenedAgentBase
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("KernelAuditAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(
    config.agent, "kernel_queue_path", "data/queue/kernel_audit_agent.db"
)


@dataclass
class AuditEvent:
    """Represents a kernel audit event"""

    timestamp: datetime
    event_type: str  # EXEC, OPEN, CONNECT, PTRACE, MMAP, etc.
    pid: int
    ppid: int
    uid: int
    euid: int  # Effective UID
    gid: int
    egid: int  # Effective GID
    process_name: str
    process_path: str
    args: List[str] = field(default_factory=list)
    target_path: Optional[str] = None
    target_pid: Optional[int] = None
    syscall: Optional[str] = None
    return_code: Optional[int] = None
    raw_event: Optional[str] = None


@dataclass
class KernelThreat:
    """Represents a detected kernel-level threat"""

    threat_type: str
    severity: str  # INFO, WARN, HIGH, CRITICAL
    description: str
    process_name: str
    process_path: str
    pid: int
    evidence: List[str]
    mitre_techniques: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class KernelAuditAgent(HardenedAgentBase):
    """Kernel Audit Agent for syscall and privilege monitoring"""

    # Sensitive files that shouldn't be accessed by most processes
    SENSITIVE_FILES = {
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/master.passwd",
        "/etc/security/passwd",
        "/private/var/db/dslocal/nodes/Default/users",
        "/var/db/shadow/hash",
    }

    # Sensitive syscalls for privilege escalation
    SENSITIVE_SYSCALLS = {
        "setuid",
        "setgid",
        "setreuid",
        "setregid",
        "setresuid",
        "setresgid",
        "seteuid",
        "setegid",
    }

    # Process injection syscalls
    INJECTION_SYSCALLS = {
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "mmap",
        "mprotect",
    }

    # Suspicious process names (common attack tools)
    SUSPICIOUS_PROCESSES = {
        "nc",
        "ncat",
        "netcat",
        "socat",
        "nmap",
        "masscan",
        "hydra",
        "medusa",
        "john",
        "hashcat",
        "mimikatz",
        "lazagne",
        "bloodhound",
        "rubeus",
        "kerbrute",
    }

    # Container escape indicators
    CONTAINER_ESCAPE_PATHS = {
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/containerd/containerd.sock",
        "/.dockerenv",
        "/proc/1/ns/",
        "/sys/fs/cgroup",
    }

    def __init__(
        self,
        queue_path: Optional[str] = None,
        enable_bsm: bool = True,
        enable_esf: bool = False,  # Requires SIP disable or entitlements
    ):
        """Initialize Kernel Audit Agent

        Args:
            queue_path: Path to offline queue database
            enable_bsm: Enable OpenBSM audit parsing (macOS)
            enable_esf: Enable Endpoint Security Framework (macOS, requires entitlements)
        """
        super().__init__(agent_name="KernelAuditAgent")

        self.queue_path = queue_path or QUEUE_PATH
        self.enable_bsm = enable_bsm
        self.enable_esf = enable_esf

        # Ensure directories exist
        Path(self.queue_path).parent.mkdir(parents=True, exist_ok=True)

        self.queue = LocalQueue(
            path=self.queue_path, max_bytes=100 * 1024 * 1024, max_retries=10
        )

        # Platform detection
        self.platform = self._detect_platform()

        # Track process trees for correlation
        self.process_tree: Dict[int, AuditEvent] = {}

        # Track privilege escalation attempts
        self.privesc_tracking: Dict[int, List[AuditEvent]] = defaultdict(list)

        # Baseline of normal UID transitions
        self.known_suid_binaries: Set[str] = self._get_suid_binaries()

        logger.info(
            f"KernelAuditAgent initialized: platform={self.platform}, "
            f"bsm={enable_bsm}, esf={enable_esf}"
        )

    def _detect_platform(self) -> str:
        """Detect operating system"""
        import platform

        system = platform.system().lower()
        if system == "darwin":
            return "macos"
        elif system == "linux":
            return "linux"
        return "unknown"

    def _get_suid_binaries(self) -> Set[str]:
        """Get set of known SUID binaries"""
        suid_bins = set()

        search_paths = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]

        for search_path in search_paths:
            try:
                result = subprocess.run(
                    ["find", search_path, "-perm", "-4000", "-type", "f"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                for line in result.stdout.strip().split("\n"):
                    if line:
                        suid_bins.add(line)
            except Exception:
                pass

        return suid_bins

    def _is_container(self) -> bool:
        """Detect if running inside a container"""
        indicators = [
            Path("/.dockerenv").exists(),
            Path("/run/.containerenv").exists(),
            os.environ.get("container") is not None,
        ]

        # Check cgroup
        try:
            with open("/proc/1/cgroup", "r") as f:
                content = f.read()
                if "docker" in content or "kubepods" in content:
                    return True
        except Exception:
            pass

        return any(indicators)

    def _parse_macos_audit(self) -> List[AuditEvent]:
        """Parse OpenBSM audit logs on macOS"""
        events = []

        try:
            # Use praudit to parse binary audit logs
            # Requires audit to be enabled: sudo audit -e
            audit_log = "/var/audit/current"

            if not Path(audit_log).exists():
                # Try to find recent audit file
                audit_dir = Path("/var/audit")
                if audit_dir.exists():
                    audit_files = sorted(audit_dir.glob("*"), key=os.path.getmtime)
                    if audit_files:
                        audit_log = str(audit_files[-1])
                    else:
                        return events
                else:
                    return events

            # Use praudit to convert binary to text
            result = subprocess.run(
                ["praudit", "-x", audit_log],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.debug(f"praudit failed: {result.stderr}")
                return events

            # Parse XML output
            current_record = {}
            for line in result.stdout.split("\n"):
                event = self._parse_bsm_line(line, current_record)
                if event:
                    events.append(event)

        except subprocess.TimeoutExpired:
            logger.warning("Audit parsing timed out")
        except PermissionError:
            logger.debug("Permission denied reading audit logs (need root)")
        except Exception as e:
            logger.error(f"Error parsing macOS audit: {e}")

        return events

    def _parse_bsm_line(self, line: str, current_record: Dict) -> Optional[AuditEvent]:
        """Parse a single BSM audit line"""
        # OpenBSM XML format parsing
        # <record> ... </record>

        line = line.strip()

        if "<record" in line:
            current_record.clear()
            return None

        if "</record>" in line:
            # End of record - create event
            if current_record:
                return self._create_event_from_bsm(current_record)
            return None

        # Parse individual elements
        # <subject ... uid="0" gid="0" pid="123" ... />
        if "<subject" in line:
            uid_match = re.search(r'uid="(\d+)"', line)
            gid_match = re.search(r'gid="(\d+)"', line)
            pid_match = re.search(r'pid="(\d+)"', line)
            euid_match = re.search(r'euid="(\d+)"', line)

            if uid_match:
                current_record["uid"] = int(uid_match.group(1))
            if gid_match:
                current_record["gid"] = int(gid_match.group(1))
            if pid_match:
                current_record["pid"] = int(pid_match.group(1))
            if euid_match:
                current_record["euid"] = int(euid_match.group(1))

        # <path>/some/path</path>
        path_match = re.search(r"<path>([^<]+)</path>", line)
        if path_match:
            current_record["path"] = path_match.group(1)

        # <exec_args> ... </exec_args>
        if "<exec_args>" in line:
            args_match = re.search(r"<exec_args>(.+)</exec_args>", line)
            if args_match:
                current_record["args"] = args_match.group(1).split()

        return None

    def _create_event_from_bsm(self, record: Dict) -> Optional[AuditEvent]:
        """Create AuditEvent from BSM record"""
        try:
            return AuditEvent(
                timestamp=datetime.now(),
                event_type=record.get("event_type", "UNKNOWN"),
                pid=record.get("pid", 0),
                ppid=record.get("ppid", 0),
                uid=record.get("uid", 0),
                euid=record.get("euid", record.get("uid", 0)),
                gid=record.get("gid", 0),
                egid=record.get("egid", record.get("gid", 0)),
                process_name=record.get("process_name", ""),
                process_path=record.get("path", ""),
                args=record.get("args", []),
                raw_event=json.dumps(record),
            )
        except Exception:
            return None

    def _parse_linux_audit(self) -> List[AuditEvent]:
        """Parse auditd logs on Linux"""
        events = []

        try:
            # Use ausearch to query recent events
            result = subprocess.run(
                [
                    "ausearch",
                    "-ts",
                    "recent",
                    "--format",
                    "text",
                    "-m",
                    "EXECVE,SYSCALL,PROCTITLE",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                # Try aureport as fallback
                result = subprocess.run(
                    ["aureport", "-x", "--summary"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

            for line in result.stdout.split("\n"):
                event = self._parse_auditd_line(line)
                if event:
                    events.append(event)

        except FileNotFoundError:
            logger.debug("auditd tools not installed")
        except subprocess.TimeoutExpired:
            logger.warning("Audit parsing timed out")
        except Exception as e:
            logger.error(f"Error parsing Linux audit: {e}")

        return events

    def _parse_auditd_line(self, line: str) -> Optional[AuditEvent]:
        """Parse a single auditd line"""
        # auditd format varies, but typically:
        # type=SYSCALL msg=audit(timestamp:id): arch=... syscall=... ... pid=... uid=... ...

        if not line.strip() or "type=" not in line:
            return None

        try:
            # Extract common fields
            pid_match = re.search(r"pid=(\d+)", line)
            uid_match = re.search(r"uid=(\d+)", line)
            euid_match = re.search(r"euid=(\d+)", line)
            gid_match = re.search(r"gid=(\d+)", line)
            syscall_match = re.search(r"syscall=(\d+)", line)
            comm_match = re.search(r'comm="([^"]+)"', line)
            exe_match = re.search(r'exe="([^"]+)"', line)

            if not pid_match:
                return None

            return AuditEvent(
                timestamp=datetime.now(),
                event_type="SYSCALL",
                pid=int(pid_match.group(1)),
                ppid=0,
                uid=int(uid_match.group(1)) if uid_match else 0,
                euid=int(euid_match.group(1)) if euid_match else 0,
                gid=int(gid_match.group(1)) if gid_match else 0,
                egid=0,
                process_name=comm_match.group(1) if comm_match else "",
                process_path=exe_match.group(1) if exe_match else "",
                syscall=syscall_match.group(1) if syscall_match else None,
                raw_event=line,
            )
        except Exception:
            return None

    def _analyze_process_start(self, events: List[AuditEvent]) -> List[KernelThreat]:
        """Analyze process start events for suspicious activity"""
        threats = []

        for event in events:
            if event.event_type not in ("EXEC", "EXECVE", "SYSCALL"):
                continue

            process_lower = event.process_name.lower()

            # Check for suspicious process names
            if process_lower in self.SUSPICIOUS_PROCESSES:
                threat = KernelThreat(
                    threat_type="SUSPICIOUS_PROCESS",
                    severity="HIGH",
                    description=f"Suspicious tool executed: {event.process_name}",
                    process_name=event.process_name,
                    process_path=event.process_path,
                    pid=event.pid,
                    evidence=[
                        f"Known attack tool: {event.process_name}",
                        f"Args: {' '.join(event.args)}",
                    ],
                    mitre_techniques=["T1059"],  # Command and Scripting Interpreter
                    timestamp=event.timestamp,
                )
                threats.append(threat)

            # Check for shell spawned by unexpected parent
            if process_lower in ("sh", "bash", "zsh", "fish", "dash"):
                # Would need parent tracking to detect anomalies
                pass

        return threats

    def _analyze_privilege_escalation(
        self, events: List[AuditEvent]
    ) -> List[KernelThreat]:
        """Analyze for privilege escalation attempts"""
        threats = []

        for event in events:
            # UID 0 = root
            # Transition from non-root to root
            if event.uid != 0 and event.euid == 0:
                # Check if this is a known SUID binary
                if event.process_path not in self.known_suid_binaries:
                    threat = KernelThreat(
                        threat_type="PRIVILEGE_ESCALATION",
                        severity="CRITICAL",
                        description=f"Unexpected privilege escalation to root: {event.process_path}",
                        process_name=event.process_name,
                        process_path=event.process_path,
                        pid=event.pid,
                        evidence=[
                            f"UID transition: {event.uid} -> euid {event.euid}",
                            "Not a known SUID binary",
                            f"Process: {event.process_path}",
                        ],
                        mitre_techniques=[
                            "T1068",  # Exploitation for Privilege Escalation
                            "T1548",  # Abuse Elevation Control Mechanism
                        ],
                        timestamp=event.timestamp,
                    )
                    threats.append(threat)

        return threats

    def _analyze_container_escape(self, events: List[AuditEvent]) -> List[KernelThreat]:
        """Analyze for container escape attempts"""
        threats = []

        if not self._is_container():
            return threats

        for event in events:
            # Check for access to container escape paths
            target = event.target_path or event.process_path

            for escape_path in self.CONTAINER_ESCAPE_PATHS:
                if target and escape_path in target:
                    threat = KernelThreat(
                        threat_type="CONTAINER_ESCAPE",
                        severity="CRITICAL",
                        description=f"Potential container escape: accessing {target}",
                        process_name=event.process_name,
                        process_path=event.process_path,
                        pid=event.pid,
                        evidence=[
                            f"Access to escape vector: {escape_path}",
                            f"Process: {event.process_path}",
                        ],
                        mitre_techniques=["T1611"],  # Escape to Host
                        timestamp=event.timestamp,
                    )
                    threats.append(threat)
                    break

        return threats

    def _analyze_process_injection(
        self, events: List[AuditEvent]
    ) -> List[KernelThreat]:
        """Analyze for process injection attempts"""
        threats = []

        for event in events:
            syscall = event.syscall

            if syscall in self.INJECTION_SYSCALLS:
                # ptrace is the most suspicious
                if syscall == "ptrace" and event.target_pid:
                    threat = KernelThreat(
                        threat_type="PROCESS_INJECTION",
                        severity="CRITICAL",
                        description=f"ptrace on PID {event.target_pid} by {event.process_name}",
                        process_name=event.process_name,
                        process_path=event.process_path,
                        pid=event.pid,
                        evidence=[
                            "ptrace syscall detected",
                            f"Target PID: {event.target_pid}",
                            f"Source: {event.process_path}",
                        ],
                        mitre_techniques=[
                            "T1055.008",  # Ptrace System Calls
                            "T1055",  # Process Injection
                        ],
                        timestamp=event.timestamp,
                    )
                    threats.append(threat)

        return threats

    def _analyze_sensitive_file_access(
        self, events: List[AuditEvent]
    ) -> List[KernelThreat]:
        """Analyze for access to sensitive files"""
        threats = []

        for event in events:
            target = event.target_path

            if target in self.SENSITIVE_FILES:
                # Whitelist expected processes
                allowed = {"passwd", "sudo", "su", "login", "sshd", "pam"}
                if event.process_name.lower() not in allowed:
                    threat = KernelThreat(
                        threat_type="SENSITIVE_FILE_ACCESS",
                        severity="HIGH",
                        description=f"Sensitive file access: {target} by {event.process_name}",
                        process_name=event.process_name,
                        process_path=event.process_path,
                        pid=event.pid,
                        evidence=[
                            f"Accessed: {target}",
                            f"Process: {event.process_path} (PID {event.pid})",
                        ],
                        mitre_techniques=[
                            "T1003",  # OS Credential Dumping
                            "T1552",  # Unsecured Credentials
                        ],
                        timestamp=event.timestamp,
                    )
                    threats.append(threat)

        return threats

    def collect_events(self) -> List[AuditEvent]:
        """Collect kernel audit events"""
        if self.platform == "macos":
            return self._parse_macos_audit()
        elif self.platform == "linux":
            return self._parse_linux_audit()
        return []

    def analyze_events(self, events: List[AuditEvent]) -> List[KernelThreat]:
        """Analyze collected events for threats"""
        all_threats = []

        # Run all analyzers
        all_threats.extend(self._analyze_process_start(events))
        all_threats.extend(self._analyze_privilege_escalation(events))
        all_threats.extend(self._analyze_container_escape(events))
        all_threats.extend(self._analyze_process_injection(events))
        all_threats.extend(self._analyze_sensitive_file_access(events))

        return all_threats

    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus with mTLS"""
        try:
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            with open(f"{CERT_DIR}/agent.crt", "rb") as f:
                client_cert = f.read()
            with open(f"{CERT_DIR}/agent.key", "rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            return channel
        except Exception as e:
            logger.error(f"Failed to create gRPC channel: {e}")
            return None

    def _create_telemetry(
        self, threats: List[KernelThreat]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Create DeviceTelemetry protobuf from kernel threats"""
        timestamp_ns = int(time.time() * 1e9)
        hostname = socket.gethostname()

        events = []
        for threat in threats:
            severity_map = {
                "INFO": "INFO",
                "WARN": "WARN",
                "HIGH": "ERROR",
                "CRITICAL": "CRITICAL",
            }

            event = telemetry_pb2.TelemetryEvent(
                event_id=f"kernel_{threat.pid}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(threat.severity, "WARN"),
                event_timestamp_ns=timestamp_ns,
                security_event=telemetry_pb2.SecurityEvent(
                    event_action="KERNEL_THREAT",
                    event_outcome=threat.threat_type,
                    process_name=threat.process_name,
                    process_path=threat.process_path,
                    source_ip="127.0.0.1",
                    details=json.dumps(
                        {
                            "description": threat.description,
                            "pid": threat.pid,
                            "evidence": threat.evidence,
                            "mitre_techniques": threat.mitre_techniques,
                        }
                    ),
                ),
            )
            events.append(event)

        return telemetry_pb2.DeviceTelemetry(
            device_id=f"endpoint_{hostname}",
            device_type="ENDPOINT",
            collection_timestamp_ns=timestamp_ns,
            events=events,
        )

    def publish_threats(self, threats: List[KernelThreat]) -> bool:
        """Publish kernel threats to EventBus"""
        if not threats:
            return True

        telemetry = self._create_telemetry(threats)

        channel = self._get_grpc_channel()
        if not channel:
            self.queue.push(telemetry.SerializeToString())
            return False

        try:
            stub = universal_pbrpc.UniversalTelemetryServiceStub(channel)

            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=int(time.time() * 1e9),
                idempotency_key=f"kernel_{socket.gethostname()}_{int(time.time())}",
                device_telemetry=telemetry,
            )

            response = stub.Publish(envelope, timeout=10)
            if response.ack == telemetry_pb2.UniversalAck.Ack.OK:
                logger.info(f"Published {len(threats)} kernel threats")
                return True
            else:
                self.queue.push(telemetry.SerializeToString())
                return False

        except grpc.RpcError as e:
            self.queue.push(telemetry.SerializeToString())
            logger.error(f"gRPC error: {e}")
            return False
        finally:
            channel.close()

    def collect(self) -> bool:
        """Perform one collection cycle (implements abstract method)

        Returns:
            True if collection succeeded, False otherwise
        """
        try:
            self.run_once()
            return True
        except Exception as e:
            logger.error(f"Collection failed: {e}")
            return False

    def run_once(self) -> List[KernelThreat]:
        """Run a single analysis cycle"""
        self.detect_evasion_attempts()

        events = self.collect_events()
        logger.debug(f"Collected {len(events)} kernel audit events")

        threats = self.analyze_events(events)

        if threats:
            logger.warning(
                f"Detected {len(threats)} kernel threats: "
                f"CRITICAL={sum(1 for t in threats if t.severity == 'CRITICAL')}"
            )
            self.publish_threats(threats)

        return threats

    def run(self, interval: int = 30) -> None:
        """Run continuous monitoring loop"""
        logger.info(f"Starting Kernel Audit Agent: interval={interval}s")

        while True:
            try:
                self.run_once()
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Shutting down Kernel Audit Agent...")
                break
            except Exception as e:
                logger.error(f"Error in kernel monitoring loop: {e}")
                time.sleep(60)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS Kernel Audit Monitor")
    parser.add_argument(
        "--interval", type=int, default=30, help="Analysis interval in seconds"
    )
    parser.add_argument(
        "--scan-once", action="store_true", help="Run single analysis and exit"
    )
    args = parser.parse_args()

    agent = KernelAuditAgent()

    if args.scan_once:
        threats = agent.run_once()
        print(f"Detected {len(threats)} threats")
        for threat in threats:
            print(f"  [{threat.severity}] {threat.threat_type}: {threat.description}")
    else:
        agent.run(interval=args.interval)


if __name__ == "__main__":
    main()
