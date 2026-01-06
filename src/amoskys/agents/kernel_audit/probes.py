#!/usr/bin/env python3
"""KernelAudit Micro-Probes - Syscall & Kernel-Level Threat Detection.

This module provides 7 specialized micro-probes for kernel audit plane monitoring:
    1. ExecveHighRiskProbe - suspicious process exec from risky locations
    2. PrivEscSyscallProbe - setuid/seteuid by non-root
    3. KernelModuleLoadProbe - init_module from suspicious paths
    4. PtraceAbuseProbe - ptrace on sensitive processes
    5. FilePermissionTamperProbe - chmod/chown on /etc/sudoers, /etc/shadow
    6. AuditTamperProbe - attempts to blind audit subsystem
    7. SyscallFloodProbe - abnormal syscall patterns

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
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.kernel_audit.types import (
    KernelAuditEvent,
    MODULE_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Detection Constants
# =============================================================================

# High-risk directories for process execution
HIGH_RISK_EXEC_PATHS: frozenset[str] = frozenset({
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/user",
    "/home",  # subdirs like ~/.local, ~/.cache
    "/Users",  # macOS home
    "/Users/Shared",
})

# Sensitive files that should not be chmod/chowned
SENSITIVE_FILES: frozenset[str] = frozenset({
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
})

# Sensitive processes that shouldn't be ptraced
PROTECTED_PROCESSES: frozenset[str] = frozenset({
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
})

# Paths indicating module load from suspicious locations
SUSPICIOUS_MODULE_PATHS: frozenset[str] = frozenset({
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
    "/root",
    "/Users",
})

# Audit-related processes and files
AUDIT_BINARIES: frozenset[str] = frozenset({
    "auditd",
    "auditctl",
    "ausearch",
    "aureport",
    "augenrules",
    "audispd",
})

AUDIT_FILES: frozenset[str] = frozenset({
    "/etc/audit",
    "/etc/audit/audit.rules",
    "/etc/audit/auditd.conf",
    "/var/log/audit",
    "/var/log/audit/audit.log",
})


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
                reason = f"Privilege escalation: UID {ke.uid} gained EUID 0 via {ke.syscall}"
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
                reason = f"ptrace on protected process: {target_comm} (pid={ke.dest_pid})"
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
    platforms = ["linux"]

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
    "KERNEL_AUDIT_PROBES",
    "create_kernel_audit_probes",
]
