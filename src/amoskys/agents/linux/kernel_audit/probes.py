#!/usr/bin/env python3
"""KernelAudit Micro-Probes - Syscall & Kernel-Level Threat Detection.

This module provides 8 specialized micro-probes for kernel audit plane monitoring:
    1. ExecveHighRiskProbe - suspicious process exec from risky locations
    2. PrivEscSyscallProbe - setuid/seteuid by non-root
    3. KernelModuleLoadProbe - init_module from suspicious paths
    4. PtraceAbuseProbe - ptrace on sensitive processes
    5. FilePermissionTamperProbe - chmod/chown on /etc/sudoers, /etc/shadow
    6. AuditTamperProbe - attempts to blind audit subsystem
    7. SyscallFloodProbe - abnormal syscall patterns
    8. CredentialDumpProbe - T1003 credential dumping (macOS + Linux)

Architecture:
    - KernelAuditEvent: Normalized kernel audit event from collector
    - Probes analyze events via context.shared_data["kernel_events"]
    - Each probe focuses on ONE attack vector

MITRE ATT&CK Coverage:
    - T1068: Exploitation for Privilege Escalation
    - T1055: Process Injection (via ptrace)
    - T1547: Boot or Logon Autostart Execution
    - T1222: File and Directory Permissions Modification
    - T1562: Impair Defenses
    - T1014: Rootkit
    - T1003: OS Credential Dumping
    - T1555: Credentials from Password Stores
    - T1555.001: Keychain
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from .agent_types import (
    MODULE_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
    KernelAuditEvent,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Detection Constants
# =============================================================================

# Correlation group tags for fusion-engine kill-chain linking
_TAG_EXECUTION = "correlation_group:execution"
_TAG_PRIVESC = "correlation_group:privilege_escalation"
_TAG_PERSISTENCE = "correlation_group:persistence"
_TAG_DEFENSE_EVASION = "correlation_group:defense_evasion"
_TAG_CRED_ACCESS = "correlation_group:credential_access"

# High-risk directories for process execution
HIGH_RISK_EXEC_PATHS: frozenset[str] = frozenset(
    {
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/user",
        "/home",  # subdirs like ~/.local, ~/.cache
        "/Users",  # macOS home
        "/Users/Shared",
    }
)

# Sensitive files that should not be chmod/chowned
SENSITIVE_FILES: frozenset[str] = frozenset(
    {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/group",
        "/etc/gshadow",
        "/etc/master.passwd",  # BSD
        "/etc/security/passwd",  # AIX
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
        "/root/.ssh/authorized_keys",
    }
)

# Sensitive processes that shouldn't be ptraced
PROTECTED_PROCESSES: frozenset[str] = frozenset(
    {
        "sshd",
        "sudo",
        "su",
        "passwd",
        "login",
        "cron",
        "systemd",
        "init",
        "klogd",
        "syslogd",
        "rsyslogd",
        "journald",
        "auditd",
        "polkitd",
        "dbus-daemon",
        "gdm",
        "lightdm",
        "sddm",
        "Xorg",
        "gnome-shell",
    }
)

# Paths indicating module load from suspicious locations
SUSPICIOUS_MODULE_PATHS: frozenset[str] = frozenset(
    {
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/home",
        "/root",
        "/Users",
    }
)

# Audit-related processes and files
AUDIT_BINARIES: frozenset[str] = frozenset(
    {
        "auditd",
        "auditctl",
        "ausearch",
        "aureport",
        "augenrules",
        "audispd",
    }
)

AUDIT_FILES: frozenset[str] = frozenset(
    {
        "/etc/audit",
        "/etc/audit/audit.rules",
        "/etc/audit/auditd.conf",
        "/var/log/audit",
        "/var/log/audit/audit.log",
    }
)


def _path_starts_with_any(path: Optional[str], prefixes: frozenset[str]) -> bool:
    """Check if path starts with any of the given prefixes."""
    if not path:
        return False
    return any(path.startswith(prefix) for prefix in prefixes)


def _is_sensitive_file(path: Optional[str]) -> bool:
    """Check if path is a sensitive system file."""
    if not path:
        return False
    # Exact match or prefix match for directories
    return path in SENSITIVE_FILES or any(
        path.startswith(f"{sf}/") for sf in SENSITIVE_FILES if sf.endswith("d")
    )


# =============================================================================
# Probe 1: ExecveHighRiskProbe
# =============================================================================


class ExecveHighRiskProbe(MicroProbe):
    """Detects process execution from high-risk directories.

    Flags execve/execveat syscalls where the executable path is in
    /tmp, /var/tmp, /dev/shm, user home directories, etc.

    These locations are commonly used by attackers for:
        - Staging malware after initial access
        - Downloading and running payloads
        - Living off the land binaries dropped to temp dirs

    MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
    """

    name = "execve_high_risk"
    description = "Detect process execution from high-risk directories"
    mitre_techniques = ["T1059", "T1204.002"]
    mitre_tactics = ["Execution", "Defense Evasion"]
    platforms = ["linux"]
    requires_fields = ["kernel_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan kernel events for high-risk execve calls."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        for ke in kernel_events:
            # Only process execve/execveat
            if ke.syscall not in ("execve", "execveat"):
                continue

            # Check if executable path is in high-risk location
            exe_path = ke.exe or ke.path
            if not exe_path:
                continue

            if not _path_starts_with_any(exe_path, HIGH_RISK_EXEC_PATHS):
                continue

            # Determine severity based on context
            severity = Severity.MEDIUM
            reason = f"Process executed from high-risk location: {exe_path}"

            # Escalate if running as root or setuid
            if ke.euid == 0 and ke.uid != 0:
                severity = Severity.HIGH
                reason = f"Setuid execution from high-risk location: {exe_path}"
            elif ke.euid == 0:
                severity = Severity.HIGH
                reason = f"Root execution from high-risk location: {exe_path}"

            events.append(
                TelemetryEvent(
                    event_type="kernel_execve_high_risk",
                    severity=severity,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "syscall": ke.syscall,
                        "exe": exe_path,
                        "pid": ke.pid,
                        "ppid": ke.ppid,
                        "uid": ke.uid,
                        "euid": ke.euid,
                        "comm": ke.comm,
                        "cwd": ke.cwd,
                        "cmdline": ke.cmdline,
                        "reason": reason,
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.75,
                    tags=[_TAG_EXECUTION],
                )
            )

        return events


# =============================================================================
# Probe 2: PrivEscSyscallProbe
# =============================================================================


class PrivEscSyscallProbe(MicroProbe):
    """Detects privilege escalation via setuid/setgid syscalls.

    Monitors for:
        - setuid/seteuid/setreuid/setresuid by non-root
        - Transitions from non-root UID to root EUID
        - capset calls modifying capabilities

    MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
    """

    name = "privesc_syscall"
    description = "Detect privilege escalation via setuid/setgid syscalls"
    mitre_techniques = ["T1068", "T1548.001"]
    mitre_tactics = ["Privilege Escalation"]
    platforms = ["linux"]
    requires_fields = ["kernel_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan kernel events for privilege escalation syscalls."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        for ke in kernel_events:
            if ke.syscall not in PRIVESC_SYSCALLS:
                continue

            # Only flag if result was success
            if ke.result != "success":
                continue

            # Detect privilege gain: non-root UID -> root EUID
            severity = Severity.MEDIUM
            reason = f"Privilege escalation syscall: {ke.syscall}"

            if ke.uid != 0 and ke.euid == 0:
                severity = Severity.CRITICAL
                reason = (
                    f"Privilege escalation: UID {ke.uid} gained EUID 0 via {ke.syscall}"
                )
            elif ke.uid != ke.euid:
                severity = Severity.HIGH
                reason = f"UID/EUID mismatch after {ke.syscall}: uid={ke.uid}, euid={ke.euid}"

            events.append(
                TelemetryEvent(
                    event_type="kernel_privesc_syscall",
                    severity=severity,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "syscall": ke.syscall,
                        "exe": ke.exe,
                        "pid": ke.pid,
                        "ppid": ke.ppid,
                        "uid": ke.uid,
                        "euid": ke.euid,
                        "gid": ke.gid,
                        "egid": ke.egid,
                        "comm": ke.comm,
                        "reason": reason,
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.9,
                    tags=[_TAG_PRIVESC],
                )
            )

        return events


# =============================================================================
# Probe 3: KernelModuleLoadProbe
# =============================================================================


class KernelModuleLoadProbe(MicroProbe):
    """Detects kernel module loading, especially from suspicious paths.

    Monitors:
        - init_module / finit_module syscalls
        - Module loads from /tmp, /home, other non-standard locations
        - delete_module for rootkit cleanup detection

    MITRE ATT&CK: T1014 (Rootkit), T1547.006 (Kernel Modules and Extensions)
    """

    name = "kernel_module_load"
    description = "Detect kernel module loading from suspicious locations"
    mitre_techniques = ["T1014", "T1547.006"]
    mitre_tactics = ["Persistence", "Defense Evasion"]
    platforms = ["linux"]
    requires_fields = ["kernel_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan kernel events for module load/unload syscalls."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        for ke in kernel_events:
            if ke.syscall not in MODULE_SYSCALLS:
                continue

            severity = Severity.HIGH
            event_type = "kernel_module_loaded"

            if ke.syscall == "delete_module":
                severity = Severity.MEDIUM
                event_type = "kernel_module_unloaded"
                reason = f"Kernel module unloaded by {ke.exe or ke.comm}"
            else:
                reason = f"Kernel module loaded via {ke.syscall}"

                # Escalate if loaded from suspicious path
                if _path_starts_with_any(ke.path, SUSPICIOUS_MODULE_PATHS):
                    severity = Severity.CRITICAL
                    reason = f"Kernel module loaded from suspicious path: {ke.path}"
                elif _path_starts_with_any(ke.cwd, SUSPICIOUS_MODULE_PATHS):
                    severity = Severity.CRITICAL
                    reason = f"Kernel module loaded from suspicious cwd: {ke.cwd}"
                # Any module load by non-root is suspicious
                elif ke.uid != 0:
                    severity = Severity.CRITICAL
                    reason = f"Kernel module load attempted by non-root uid={ke.uid}"

            events.append(
                TelemetryEvent(
                    event_type=event_type,
                    severity=severity,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "syscall": ke.syscall,
                        "exe": ke.exe,
                        "path": ke.path,
                        "cwd": ke.cwd,
                        "pid": ke.pid,
                        "uid": ke.uid,
                        "comm": ke.comm,
                        "reason": reason,
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.85,
                    tags=[_TAG_PERSISTENCE],
                )
            )

        return events


# =============================================================================
# Probe 4: PtraceAbuseProbe
# =============================================================================


class PtraceAbuseProbe(MicroProbe):
    """Detects ptrace abuse for process injection or debugging protected processes.

    Monitors:
        - ptrace syscalls on sensitive processes (sshd, sudo, etc.)
        - PTRACE_ATTACH/PTRACE_SEIZE on system daemons
        - process_vm_readv/writev for memory manipulation

    MITRE ATT&CK: T1055 (Process Injection)
    """

    name = "ptrace_abuse"
    description = "Detect ptrace abuse for process injection"
    mitre_techniques = ["T1055", "T1055.008"]
    mitre_tactics = ["Defense Evasion", "Privilege Escalation"]
    platforms = ["linux"]
    requires_fields = ["kernel_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan kernel events for suspicious ptrace activity."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        # Build a map of PIDs to process names for target lookup
        pid_to_comm: Dict[int, str] = {}
        for ke in kernel_events:
            if ke.pid and ke.comm:
                pid_to_comm[ke.pid] = ke.comm

        for ke in kernel_events:
            if ke.syscall not in ("ptrace", "process_vm_readv", "process_vm_writev"):
                continue

            severity = Severity.MEDIUM
            reason = f"Process debugging/injection via {ke.syscall}"

            # Check if target is a protected process
            target_comm = None
            if ke.dest_pid:
                target_comm = pid_to_comm.get(ke.dest_pid)

            if target_comm and target_comm in PROTECTED_PROCESSES:
                severity = Severity.CRITICAL
                reason = (
                    f"ptrace on protected process: {target_comm} (pid={ke.dest_pid})"
                )
            elif ke.dest_pid == 1:
                severity = Severity.CRITICAL
                reason = "ptrace on init/systemd (pid=1)"
            elif ke.uid != 0:
                # Non-root ptracing is suspicious
                severity = Severity.HIGH
                reason = f"Non-root process {ke.comm} using {ke.syscall}"

            events.append(
                TelemetryEvent(
                    event_type="kernel_ptrace_abuse",
                    severity=severity,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "syscall": ke.syscall,
                        "attacker_exe": ke.exe,
                        "attacker_pid": ke.pid,
                        "attacker_comm": ke.comm,
                        "target_pid": ke.dest_pid,
                        "target_comm": target_comm,
                        "uid": ke.uid,
                        "reason": reason,
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.85,
                    tags=[_TAG_CRED_ACCESS],
                )
            )

        return events


# =============================================================================
# Probe 5: FilePermissionTamperProbe
# =============================================================================


class FilePermissionTamperProbe(MicroProbe):
    """Detects chmod/chown on sensitive system files.

    Monitors:
        - chmod/fchmod on /etc/shadow, /etc/sudoers, SSH keys
        - chown/fchown on authentication-related files
        - Permission changes that could enable privilege escalation

    MITRE ATT&CK: T1222 (File and Directory Permissions Modification)
    """

    name = "file_permission_tamper"
    description = "Detect permission tampering on sensitive files"
    mitre_techniques = ["T1222", "T1222.002"]
    mitre_tactics = ["Defense Evasion", "Credential Access"]
    platforms = ["linux"]
    requires_fields = ["kernel_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan kernel events for sensitive file permission changes."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        for ke in kernel_events:
            if ke.syscall not in PERMISSION_SYSCALLS:
                continue

            target_path = ke.path
            if not target_path:
                continue

            if not _is_sensitive_file(target_path):
                continue

            severity = Severity.HIGH
            reason = f"Permission change on sensitive file: {target_path}"

            # Escalate for shadow/sudoers
            if "shadow" in target_path or "sudoers" in target_path:
                severity = Severity.CRITICAL
                reason = f"Permission change on critical auth file: {target_path}"

            # Non-root modifying sensitive files is very suspicious
            if ke.uid != 0 and ke.euid != 0:
                severity = Severity.CRITICAL
                reason = f"Non-root ({ke.uid}) modifying {target_path}"

            events.append(
                TelemetryEvent(
                    event_type="kernel_file_permission_tamper",
                    severity=severity,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "syscall": ke.syscall,
                        "target_path": target_path,
                        "exe": ke.exe,
                        "pid": ke.pid,
                        "uid": ke.uid,
                        "euid": ke.euid,
                        "dest_uid": ke.dest_uid,  # For chown
                        "comm": ke.comm,
                        "reason": reason,
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.9,
                    tags=[_TAG_DEFENSE_EVASION],
                )
            )

        return events


# =============================================================================
# Probe 6: AuditTamperProbe
# =============================================================================


class AuditTamperProbe(MicroProbe):
    """Detects attempts to blind or tamper with the audit subsystem.

    Monitors:
        - Killing/stopping auditd process
        - Modifying audit rules or config
        - Clearing audit logs

    MITRE ATT&CK: T1562.001 (Disable or Modify Tools)
    """

    name = "audit_tamper"
    description = "Detect attempts to disable or tamper with audit"
    mitre_techniques = ["T1562.001", "T1070.002"]
    mitre_tactics = ["Defense Evasion"]
    platforms = ["linux"]
    requires_fields = ["kernel_events"]

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan kernel events for audit tampering attempts."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        for ke in kernel_events:
            # Check for kill/signal on auditd
            if ke.syscall == "kill" and ke.dest_pid:
                # We'd need to track auditd's PID - for now flag any kill
                # that comes from suspicious context
                pass

            # Check for access to audit files
            if ke.path and _path_starts_with_any(ke.path, AUDIT_FILES):
                # Writing to audit logs or config
                if ke.syscall in ("open", "openat", "write", "unlink", "truncate"):
                    # Check if it's not auditd itself
                    if ke.comm not in AUDIT_BINARIES:
                        severity = Severity.CRITICAL
                        reason = f"Non-audit process accessing audit file: {ke.path}"

                        events.append(
                            TelemetryEvent(
                                event_type="kernel_audit_tamper",
                                severity=severity,
                                probe_name=self.name,
                                timestamp_ns=ke.timestamp_ns,
                                data={
                                    "host": ke.host,
                                    "syscall": ke.syscall,
                                    "target_path": ke.path,
                                    "exe": ke.exe,
                                    "pid": ke.pid,
                                    "uid": ke.uid,
                                    "comm": ke.comm,
                                    "reason": reason,
                                },
                                mitre_techniques=self.mitre_techniques,
                                mitre_tactics=self.mitre_tactics,
                                confidence=0.95,
                                tags=[_TAG_DEFENSE_EVASION],
                            )
                        )

            # Check for execve of audit tools by non-root
            if ke.syscall in ("execve", "execveat"):
                exe_name = ke.exe.split("/")[-1] if ke.exe else ""
                if exe_name in AUDIT_BINARIES and ke.uid != 0:
                    severity = Severity.HIGH
                    reason = f"Non-root executing audit tool: {exe_name}"

                    events.append(
                        TelemetryEvent(
                            event_type="kernel_audit_tool_exec",
                            severity=severity,
                            probe_name=self.name,
                            timestamp_ns=ke.timestamp_ns,
                            data={
                                "host": ke.host,
                                "syscall": ke.syscall,
                                "exe": ke.exe,
                                "pid": ke.pid,
                                "uid": ke.uid,
                                "comm": ke.comm,
                                "reason": reason,
                            },
                            mitre_techniques=self.mitre_techniques,
                            mitre_tactics=self.mitre_tactics,
                            confidence=0.85,
                            tags=[_TAG_DEFENSE_EVASION],
                        )
                    )

        return events


# =============================================================================
# Probe 7: SyscallFloodProbe
# =============================================================================


class SyscallFloodProbe(MicroProbe):
    """Detects abnormal syscall patterns indicating attacks or enumeration.

    Monitors for:
        - High volume of failed syscalls (brute force)
        - Rapid privilege escalation attempts
        - Scanning patterns (openat floods, connect floods)

    MITRE ATT&CK: T1592 (Gather Victim Host Information)
    """

    name = "syscall_flood"
    description = "Detect abnormal syscall patterns"
    mitre_techniques = ["T1592", "T1083"]
    mitre_tactics = ["Reconnaissance", "Discovery"]
    platforms = ["linux", "darwin"]
    requires_fields = ["kernel_events"]

    # Thresholds
    FLOOD_THRESHOLD = 100  # syscalls per window
    FAILURE_THRESHOLD = 50  # failed syscalls per window

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Scan for syscall flooding patterns."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )

        # Aggregate by process
        process_syscalls: Dict[int, List[KernelAuditEvent]] = defaultdict(list)
        process_failures: Dict[int, int] = defaultdict(int)

        for ke in kernel_events:
            if ke.pid:
                process_syscalls[ke.pid].append(ke)
                if ke.result == "failed":
                    process_failures[ke.pid] += 1

        # Check for floods
        for pid, syscalls in process_syscalls.items():
            count = len(syscalls)
            failures = process_failures[pid]

            # Get representative event for metadata
            sample = syscalls[0]

            if count >= self.FLOOD_THRESHOLD:
                severity = Severity.MEDIUM
                reason = f"High syscall volume from pid {pid}: {count} syscalls"

                if failures >= self.FAILURE_THRESHOLD:
                    severity = Severity.HIGH
                    reason = f"Syscall flood with many failures: {count} total, {failures} failed"

                events.append(
                    TelemetryEvent(
                        event_type="kernel_syscall_flood",
                        severity=severity,
                        probe_name=self.name,
                        timestamp_ns=sample.timestamp_ns,
                        data={
                            "host": sample.host,
                            "pid": pid,
                            "exe": sample.exe,
                            "comm": sample.comm,
                            "uid": sample.uid,
                            "syscall_count": count,
                            "failure_count": failures,
                            "reason": reason,
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                        confidence=0.7,
                    )
                )

        return events


# =============================================================================
# Probe 8: CredentialDumpProbe — T1003 / T1555 / T1555.001
# =============================================================================

# macOS: only these daemons legitimately access the user DB plist and Keychain
_CRED_FILE_ACCESS_WHITELIST: frozenset[str] = frozenset(
    {
        "opendirectoryd",
        "DirectoryService",
        "SecurityAgent",
        "accountsd",
        "secd",  # macOS Keychain daemon
        "trustd",  # Trust policy daemon
        "cloudd",  # iCloud sync — accesses Keychain legitimately
        "nsurlsessiond",  # Network sessions — uses Keychain
        "securityd",  # Legacy Keychain daemon (older macOS)
    }
)

# Root-run tools that may legitimately access credential files
_CRED_ROOT_WHITELIST: frozenset[str] = frozenset(
    {
        "dsimport",  # macOS directory data import
        "sysadminctl",  # System admin CLI
    }
)

# Expected exe paths for whitelisted daemons (P1.1: masquerade detection)
# Maps comm name → expected absolute exe path. If a process claims the comm of a
# whitelisted daemon but runs from a different binary, it is likely spoofing via prctl().
_CRED_WHITELIST_EXE_PATHS: dict[str, str] = {
    "opendirectoryd": "/usr/libexec/opendirectoryd",
    "DirectoryService": (
        "/System/Library/CoreServices/DirectoryService.bundle"
        "/Contents/MacOS/DirectoryService"
    ),
    "SecurityAgent": (
        "/System/Library/Frameworks/Security.framework/Versions/A"
        "/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent"
    ),
    "accountsd": "/System/Library/Accounts/Executables/accountsd",
    "secd": "/usr/libexec/secd",
    "trustd": "/usr/libexec/trustd",
    "cloudd": (
        "/System/Library/PrivateFrameworks/CloudKitDaemon.framework"
        "/Versions/A/Support/cloudd"
    ),
    "nsurlsessiond": "/usr/libexec/nsurlsessiond",
    "securityd": "/usr/libexec/securityd",
}

# Process names that are unambiguously credential dump tools
_KNOWN_CRED_DUMP_TOOLS: frozenset[str] = frozenset(
    {
        "mimikatz",
        "lazagne",
        "gsecdump",
        "pwdump7",
        "fgdump",
        "wce",
        "creddump",
        "lsadump",
        "hashdump",
        "xcredz",
        "keychaindumper",  # macOS-specific open-source tool
        "chainbreaker",  # macOS Keychain forensic tool, abused in attacks
    }
)

# macOS `security` subcommands that access credentials
_SECURITY_CRED_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "find-generic-password",
        "find-internet-password",
        "find-certificate",
        "dump-keychain",
        "dump-trust-settings",
        "export",
    }
)

# Subcommands that dump entire keystores (higher severity than single lookups)
_SECURITY_DUMP_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "dump-keychain",
        "dump-trust-settings",
        "export",
    }
)

# Linux/BSD shadow password files
_LINUX_SHADOW_PATHS: frozenset[str] = frozenset(
    {
        "/etc/shadow",
        "/etc/master.passwd",  # BSD
        "/etc/security/passwd",  # AIX
    }
)

# P0.1: Shell interpreters that may wrap credential commands
_SHELL_INTERPRETERS: frozenset[str] = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "fish",
        "csh",
        "tcsh",
        "ksh",
        "osascript",
    }
)

# P0.1: Script interpreters that execute credential dump scripts
_SCRIPT_INTERPRETERS: frozenset[str] = frozenset(
    {
        "python",
        "python3",
        "python2",
        "perl",
        "ruby",
        "node",
        "nodejs",
    }
)

# P0.1: Script filenames strongly associated with credential dump tools
_KNOWN_TOOL_SCRIPT_NAMES: frozenset[str] = frozenset(
    {
        "lazagne",
        "lazagne.py",
        "chainbreaker",
        "chainbreaker.py",
        "keychaindumper",
        "keychaindumper.py",
        "mimikatz",
        "mimikatz.py",
        "keychainstealer",
        "cred_dump",
    }
)


def _is_interpreter_exe(exe_name: str) -> bool:
    """Return True if exe is a shell or script interpreter (P0.1)."""
    return (
        exe_name in _SHELL_INTERPRETERS
        or exe_name in _SCRIPT_INTERPRETERS
        or exe_name.startswith("python")  # python3.11, python2.7, etc.
    )


def _is_temp_db_path(cmdline: str) -> bool:
    """Return True if cmdline references a .db/.sqlite file in a temp directory (P1.2)."""
    _TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/")
    _DB_EXTS = (".db", ".sqlite", ".sqlite3")
    for part in cmdline.split():
        if any(part.startswith(td) for td in _TEMP_DIRS):
            if any(part.endswith(ext) for ext in _DB_EXTS):
                return True
    return False


def _is_keychain_db_path(path: str) -> bool:
    """Return True if path is a Keychain database file."""
    # User keychain: /Users/<name>/Library/Keychains/login.keychain-db
    # System keychain: /Library/Keychains/System.keychain
    if "/Library/Keychains/" not in path:
        return False
    return path.endswith((".keychain-db", ".keychain", ".db"))


def _is_dscl_cred_query(cmdline: str) -> bool:
    """Return True if a dscl invocation is querying credential attributes."""
    # dscl . -list /Users
    if "-list" in cmdline and "/Users" in cmdline:
        return True
    # dscl . -read /Users/<user> AuthenticationAuthority
    if "-read" in cmdline and "AuthenticationAuthority" in cmdline:
        return True
    # dscl . -read /Users/<user> ShadowHashData  (macOS password hash)
    if "ShadowHashData" in cmdline:
        return True
    return False


class CredentialDumpProbe(MicroProbe):
    """Detects credential dumping techniques (T1003 / T1555).

    Covers three attack vectors — macOS-first, Linux secondary:

    Vector 1 — Direct credential store access (open/openat syscall):
        - /var/db/dslocal/nodes/Default/users/*.plist  (macOS user DB)
        - /Library/Keychains/*.keychain-db             (System Keychain)
        - ~/Library/Keychains/login.keychain-db        (User Keychain)
        - /etc/shadow, /etc/master.passwd              (Linux/BSD shadow)

    Vector 2 — Known tool execution (execve syscall):
        - mimikatz, lazagne, keychaindumper, chainbreaker  → CRITICAL
        - `security dump-keychain` / `security export`     → HIGH
        - `security find-generic-password`                 → MEDIUM
        - `dscl . -read /Users/<u> ShadowHashData`         → MEDIUM
        - `sqlite3` invoked on a Keychain DB path          → HIGH

    Vector 3 — Keychain access burst (stateful, per-process):
        - >10 `security find-*` calls from the same PID within 60 seconds
        - Indicates automated credential harvesting (LaZagne-style loop)
        - Fires once per burst; window resets after firing

    MITRE ATT&CK:
        T1003   — OS Credential Dumping
        T1555   — Credentials from Password Stores
        T1555.001 — Keychain
    """

    name = "credential_dump"
    description = "Detect OS credential dumping (T1003, T1555)"
    mitre_techniques = ["T1003", "T1555", "T1555.001"]
    mitre_tactics = ["Credential Access"]
    platforms = ["linux"]
    requires_fields = ["kernel_events"]

    KEYCHAIN_BURST_THRESHOLD: int = 10
    KEYCHAIN_BURST_WINDOW_SECONDS: float = 60.0

    def __init__(self) -> None:
        super().__init__()
        # pid → deque of event timestamps (seconds) for `security find-*` calls
        self._keychain_calls: Dict[int, Deque[float]] = defaultdict(deque)
        # uid → deque of (timestamp_s, pid) tuples for cross-PID burst detection (P0.2)
        self._uid_cred_calls: Dict[int, Deque[tuple]] = defaultdict(deque)

    def scan(self, context: ProbeContext) -> List[TelemetryEvent]:
        """Run all three detection vectors across the current event batch."""
        events: List[TelemetryEvent] = []
        kernel_events: List[KernelAuditEvent] = context.shared_data.get(
            "kernel_events", []
        )
        now_s: float = (
            context.now_ns if context.now_ns is not None else int(time.time() * 1e9)
        ) / 1e9

        for ke in kernel_events:
            if ke.syscall in ("open", "openat"):
                ev = self._check_file_access(ke)
                if ev:
                    events.append(ev)

            elif ke.syscall in ("execve", "execveat"):
                events.extend(self._check_tool_exec(ke))

        # Burst checks run once per scan cycle, not per event
        events.extend(self._check_keychain_burst(now_s))
        events.extend(self._check_cross_pid_burst(now_s))  # P0.2
        return events

    # ------------------------------------------------------------------
    # Vector 1: Direct credential file access
    # ------------------------------------------------------------------

    def _check_file_access(self, ke: KernelAuditEvent) -> Optional[TelemetryEvent]:
        """Flag open/openat on credential stores by non-system processes."""
        path = ke.path
        if not path:
            return None

        comm = ke.comm or ""

        # System daemons always allowed — but check for comm spoofing (P1.1)
        if comm in _CRED_FILE_ACCESS_WHITELIST:
            expected_exe = _CRED_WHITELIST_EXE_PATHS.get(comm)
            if expected_exe and ke.exe and ke.exe != expected_exe:
                # comm matches whitelist but exe doesn't — likely prctl() comm spoofing
                return TelemetryEvent(
                    event_type="masquerade_whitelist_break",
                    severity=Severity.CRITICAL,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "syscall": ke.syscall,
                        "path": path,
                        "comm": comm,
                        "exe": ke.exe,
                        "expected_exe": expected_exe,
                        "pid": ke.pid,
                        "uid": ke.uid,
                        "reason": (
                            f"Process comm='{comm}' matches whitelist but "
                            f"exe='{ke.exe}' != expected='{expected_exe}' "
                            "— possible comm spoofing"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.92,
                    tags=[_TAG_CRED_ACCESS],
                )
            return None  # Legitimate daemon
        # Root-run admin tools allowed
        if ke.uid == 0 and comm in _CRED_ROOT_WHITELIST:
            return None

        severity: Optional[Severity] = None
        reason: str = ""

        # macOS: user DB plist — only opendirectoryd should touch this
        if path.startswith("/var/db/dslocal/nodes/Default/users/") and path.endswith(
            ".plist"
        ):
            severity = Severity.CRITICAL
            reason = f"Direct read of macOS user database: {path}"

        # macOS/Linux: Keychain database files
        elif _is_keychain_db_path(path):
            severity = Severity.HIGH
            reason = f"Direct read of Keychain database: {path}"

        # Linux/BSD: shadow password files
        elif path in _LINUX_SHADOW_PATHS:
            severity = Severity.CRITICAL
            reason = f"Direct read of shadow password file: {path}"

        if severity is None:
            return None

        return TelemetryEvent(
            event_type="credential_file_access",
            severity=severity,
            probe_name=self.name,
            timestamp_ns=ke.timestamp_ns,
            data={
                "host": ke.host,
                "syscall": ke.syscall,
                "path": path,
                "exe": ke.exe,
                "pid": ke.pid,
                "uid": ke.uid,
                "comm": comm,
                "reason": reason,
            },
            mitre_techniques=self.mitre_techniques,
            mitre_tactics=self.mitre_tactics,
            confidence=0.9,
            tags=[_TAG_CRED_ACCESS],
        )

    # ------------------------------------------------------------------
    # Vector 2: Credential tool execution
    # ------------------------------------------------------------------

    def _check_tool_exec(self, ke: KernelAuditEvent) -> List[TelemetryEvent]:
        """Dispatch execve events to per-tool detection helpers."""
        exe = ke.exe or ""
        exe_name = exe.rsplit("/", 1)[-1] if "/" in exe else (ke.comm or exe)

        if exe_name.lower() in _KNOWN_CRED_DUMP_TOOLS:
            return [self._event_known_tool(ke, exe, exe_name)]

        dispatch = {
            "security": self._check_security_cli,
            "dscl": self._check_dscl_cli,
            "sqlite3": self._check_sqlite3,
        }
        handler = dispatch.get(exe_name)
        if handler:
            return handler(ke, exe)

        # P0.1: interpreter wrapping — sh -c 'security dump-keychain', python3 lazagne.py
        if _is_interpreter_exe(exe_name):
            return self._check_interpreter_cmdline(ke, exe)
        return []

    def _event_known_tool(
        self, ke: KernelAuditEvent, exe: str, exe_name: str
    ) -> TelemetryEvent:
        """Build CRITICAL event for a known credential dump tool."""
        return TelemetryEvent(
            event_type="known_cred_dump_tool",
            severity=Severity.CRITICAL,
            probe_name=self.name,
            timestamp_ns=ke.timestamp_ns,
            data={
                "host": ke.host,
                "tool": exe_name,
                "exe": exe,
                "pid": ke.pid,
                "uid": ke.uid,
                "cmdline": ke.cmdline or "",
                "reason": f"Known credential dump tool executed: {exe_name}",
            },
            mitre_techniques=self.mitre_techniques,
            mitre_tactics=self.mitre_tactics,
            confidence=0.98,
            tags=[_TAG_CRED_ACCESS],
        )

    def _check_security_cli(
        self, ke: KernelAuditEvent, exe: str
    ) -> List[TelemetryEvent]:
        """Detect macOS `security` CLI credential subcommands."""
        cmdline = ke.cmdline or ""
        if not cmdline:
            return []
        matched = next((sc for sc in _SECURITY_CRED_SUBCOMMANDS if sc in cmdline), None)
        if not matched:
            return []

        is_dump = matched in _SECURITY_DUMP_SUBCOMMANDS
        ts_s = ke.timestamp_ns / 1e9
        if ke.pid is not None:
            self._keychain_calls[ke.pid].append(ts_s)
        # P0.2: also track by UID for cross-PID burst detection
        if ke.uid is not None and ke.pid is not None:
            self._uid_cred_calls[ke.uid].append((ts_s, ke.pid))

        return [
            TelemetryEvent(
                event_type="keychain_security_exec",
                severity=Severity.HIGH if is_dump else Severity.MEDIUM,
                probe_name=self.name,
                timestamp_ns=ke.timestamp_ns,
                data={
                    "host": ke.host,
                    "subcommand": matched,
                    "exe": exe,
                    "pid": ke.pid,
                    "uid": ke.uid,
                    "cmdline": cmdline,
                    "reason": f"security {matched} executed",
                },
                mitre_techniques=self.mitre_techniques,
                mitre_tactics=self.mitre_tactics,
                confidence=0.85 if is_dump else 0.70,
                tags=[_TAG_CRED_ACCESS],
            )
        ]

    def _check_dscl_cli(self, ke: KernelAuditEvent, exe: str) -> List[TelemetryEvent]:
        """Detect macOS `dscl` credential attribute enumeration."""
        cmdline = ke.cmdline or ""
        if not cmdline or not _is_dscl_cred_query(cmdline):
            return []
        return [
            TelemetryEvent(
                event_type="dscl_credential_query",
                severity=Severity.MEDIUM,
                probe_name=self.name,
                timestamp_ns=ke.timestamp_ns,
                data={
                    "host": ke.host,
                    "exe": exe,
                    "pid": ke.pid,
                    "uid": ke.uid,
                    "cmdline": cmdline,
                    "reason": "dscl queried credential attributes",
                },
                mitre_techniques=self.mitre_techniques,
                mitre_tactics=self.mitre_tactics,
                confidence=0.75,
                tags=[_TAG_CRED_ACCESS],
            )
        ]

    def _check_sqlite3(self, ke: KernelAuditEvent, exe: str) -> List[TelemetryEvent]:
        """Detect `sqlite3` invoked on a Keychain database or temp DB files.

        PRIMARY (HIGH): sqlite3 on a keychain path — direct keychain read.
        P1.2 (LOW): sqlite3 on a /tmp/*.db — possible copy-then-query pattern;
            low confidence, tagged correlation_needed=True for FusionEngine.
        """
        cmdline = ke.cmdline or ""
        if not cmdline:
            return []

        # Primary: sqlite3 on a keychain path → HIGH
        if "Keychain" in cmdline or "keychain" in cmdline:
            return [
                TelemetryEvent(
                    event_type="sqlite3_keychain_access",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "exe": exe,
                        "pid": ke.pid,
                        "uid": ke.uid,
                        "cmdline": cmdline,
                        "reason": "sqlite3 opened a Keychain database directly",
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.90,
                    tags=[_TAG_CRED_ACCESS],
                )
            ]

        # P1.2: sqlite3 on a temp .db file → LOW signal for correlation
        if _is_temp_db_path(cmdline):
            return [
                TelemetryEvent(
                    event_type="sqlite3_temp_db_access",
                    severity=Severity.LOW,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "exe": exe,
                        "pid": ke.pid,
                        "uid": ke.uid,
                        "cmdline": cmdline,
                        "correlation_needed": True,
                        "reason": (
                            "sqlite3 opened a temp .db file "
                            "— possible keychain copy-then-query pattern"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.40,
                    tags=[_TAG_CRED_ACCESS],
                )
            ]

        return []

    def _check_interpreter_cmdline(
        self, ke: KernelAuditEvent, exe: str
    ) -> List[TelemetryEvent]:
        """Detect credential tools launched via shell/script interpreter wrapping (P0.1).

        Catches:
            sh -c 'security dump-keychain'
            bash -c 'security find-generic-password -s ...'
            python3 lazagne.py all
            osascript -e 'do shell script "security dump-keychain"'

        Lower confidence than direct detection (interpreter wrapping adds uncertainty).
        Priority order: known tool script > security subcommand > dscl query.
        """
        cmdline = ke.cmdline or ""
        if not cmdline:
            return []

        cmdline_lower = cmdline.lower()

        # Priority 1: known credential dump script name present → HIGH
        for script_name in _KNOWN_TOOL_SCRIPT_NAMES:
            if script_name in cmdline_lower:
                return [
                    TelemetryEvent(
                        event_type="interpreter_cred_tool_exec",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        timestamp_ns=ke.timestamp_ns,
                        data={
                            "host": ke.host,
                            "interpreter": exe,
                            "script": script_name,
                            "pid": ke.pid,
                            "uid": ke.uid,
                            "cmdline": cmdline,
                            "reason": (
                                f"Credential dump script '{script_name}' "
                                f"executed via {exe}"
                            ),
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                        confidence=0.85,
                        tags=[_TAG_CRED_ACCESS],
                    )
                ]

        # Priority 2: `security` credential subcommand in cmdline → HIGH/MEDIUM
        matched_sc = next(
            (sc for sc in _SECURITY_CRED_SUBCOMMANDS if sc in cmdline), None
        )
        if matched_sc:
            is_dump = matched_sc in _SECURITY_DUMP_SUBCOMMANDS
            return [
                TelemetryEvent(
                    event_type="interpreter_security_exec",
                    severity=Severity.HIGH if is_dump else Severity.MEDIUM,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "interpreter": exe,
                        "subcommand": matched_sc,
                        "pid": ke.pid,
                        "uid": ke.uid,
                        "cmdline": cmdline,
                        "reason": (
                            f"security {matched_sc} invoked via {exe} interpreter"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.75 if is_dump else 0.65,
                    tags=[_TAG_CRED_ACCESS],
                )
            ]

        # Priority 3: `dscl` credential query in cmdline → MEDIUM
        if _is_dscl_cred_query(cmdline):
            return [
                TelemetryEvent(
                    event_type="interpreter_dscl_query",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    timestamp_ns=ke.timestamp_ns,
                    data={
                        "host": ke.host,
                        "interpreter": exe,
                        "pid": ke.pid,
                        "uid": ke.uid,
                        "cmdline": cmdline,
                        "reason": (
                            f"dscl credential query invoked via {exe} interpreter"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.65,
                    tags=[_TAG_CRED_ACCESS],
                )
            ]

        return []

    # ------------------------------------------------------------------
    # Vector 3: Keychain access burst
    # ------------------------------------------------------------------

    def _check_cross_pid_burst(self, now_s: float) -> List[TelemetryEvent]:
        """Detect Keychain harvesting spread across multiple PIDs by the same UID (P0.2).

        Catches the evasion pattern where an attacker spawns N short-lived processes
        (each making <THRESHOLD calls) to stay under the per-PID burst detector.
        Fires when a single UID exceeds the call threshold across ≥2 distinct PIDs.
        """
        events: List[TelemetryEvent] = []
        cutoff = now_s - self.KEYCHAIN_BURST_WINDOW_SECONDS

        for uid, entries in self._uid_cred_calls.items():
            # Evict entries outside the sliding window
            while entries and entries[0][0] < cutoff:
                entries.popleft()

            if len(entries) < self.KEYCHAIN_BURST_THRESHOLD:
                continue

            # Require ≥2 distinct PIDs — single PID is handled by _check_keychain_burst
            pids: Set[int] = {pid for _, pid in entries}
            if len(pids) < 2:
                continue

            count = len(entries)
            entries.clear()  # Prevent re-firing until new calls accumulate

            events.append(
                TelemetryEvent(
                    event_type="keychain_cross_pid_burst",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    timestamp_ns=int(now_s * 1e9),
                    data={
                        "uid": uid,
                        "pid_count": len(pids),
                        "call_count": count,
                        "window_seconds": self.KEYCHAIN_BURST_WINDOW_SECONDS,
                        "reason": (
                            f"Cross-PID Keychain harvesting: {count} credential "
                            f"lookups across {len(pids)} PIDs in "
                            f"{self.KEYCHAIN_BURST_WINDOW_SECONDS:.0f}s by uid {uid}"
                        ),
                    },
                    mitre_techniques=self.mitre_techniques,
                    mitre_tactics=self.mitre_tactics,
                    confidence=0.88,
                    tags=[_TAG_CRED_ACCESS],
                )
            )

        return events

    def _check_keychain_burst(self, now_s: float) -> List[TelemetryEvent]:
        """Fire when a single PID exceeds the lookup burst threshold."""
        events: List[TelemetryEvent] = []
        cutoff = now_s - self.KEYCHAIN_BURST_WINDOW_SECONDS

        for pid, timestamps in self._keychain_calls.items():
            # Evict entries outside the sliding window
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.KEYCHAIN_BURST_THRESHOLD:
                count = len(timestamps)
                timestamps.clear()  # Prevent re-firing until new calls accumulate

                events.append(
                    TelemetryEvent(
                        event_type="keychain_access_burst",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        timestamp_ns=int(now_s * 1e9),
                        data={
                            "pid": pid,
                            "call_count": count,
                            "window_seconds": self.KEYCHAIN_BURST_WINDOW_SECONDS,
                            "reason": (
                                f"Automated Keychain harvesting: {count} credential "
                                f"lookups in {self.KEYCHAIN_BURST_WINDOW_SECONDS:.0f}s "
                                f"from pid {pid}"
                            ),
                        },
                        mitre_techniques=self.mitre_techniques,
                        mitre_tactics=self.mitre_tactics,
                        confidence=0.90,
                        tags=[_TAG_CRED_ACCESS],
                    )
                )

        return events


# =============================================================================
# Probe Registry
# =============================================================================

# All probes for this agent
KERNEL_AUDIT_PROBES = [
    ExecveHighRiskProbe,
    PrivEscSyscallProbe,
    KernelModuleLoadProbe,
    PtraceAbuseProbe,
    FilePermissionTamperProbe,
    AuditTamperProbe,
    SyscallFloodProbe,
    CredentialDumpProbe,
]


def create_kernel_audit_probes() -> List[MicroProbe]:
    """Create instances of all kernel audit probes.

    Returns:
        List of instantiated probes
    """
    return [probe_class() for probe_class in KERNEL_AUDIT_PROBES]


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "ExecveHighRiskProbe",
    "PrivEscSyscallProbe",
    "KernelModuleLoadProbe",
    "PtraceAbuseProbe",
    "FilePermissionTamperProbe",
    "AuditTamperProbe",
    "SyscallFloodProbe",
    "CredentialDumpProbe",
    "KERNEL_AUDIT_PROBES",
    "create_kernel_audit_probes",
]
