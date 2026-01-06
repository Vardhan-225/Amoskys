"""Kernel Audit Event Types - Normalized representation of audit records.

This module provides the core data structures for kernel audit events,
normalized from various sources (auditd, eBPF, BSM, ETW).

Design:
    - Platform-agnostic normalized format
    - All fields optional to handle varying source richness
    - Raw dict preserved for deep inspection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class KernelAuditEvent:
    """Normalized kernel/auditd event.

    This is the canonical format passed to micro-probes for analysis.
    Collectors parse platform-specific audit logs into this format.

    Attributes:
        event_id: Stable per-audit-record identifier
        timestamp_ns: Event timestamp in nanoseconds
        host: Hostname where event occurred

        syscall: Syscall name (execve, ptrace, init_module, setuid, etc.)
        exe: Executable path (/usr/bin/bash, /usr/bin/sudo)
        pid: Process ID
        ppid: Parent process ID
        uid: Real user ID
        euid: Effective user ID
        gid: Real group ID
        egid: Effective group ID

        tty: TTY device
        cwd: Current working directory
        path: Target path (file being accessed, module being loaded)
        dest_pid: Destination process ID (for ptrace, kill, etc.)
        dest_uid: Destination user ID (for chown, etc.)

        audit_user: Audit user ID (auid)
        session: Session ID

        action: High-level action type ("EXEC", "MODULE_LOAD", "PTRACE", etc.)
        result: Syscall result ("success", "failed")

        cmdline: Full command line (if available)
        comm: Short process name (comm field)

        raw: Full key=value map for deeper inspection
    """

    event_id: str
    timestamp_ns: int
    host: str

    # Process context
    syscall: Optional[str] = None
    exe: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    euid: Optional[int] = None
    gid: Optional[int] = None
    egid: Optional[int] = None

    # Execution context
    tty: Optional[str] = None
    cwd: Optional[str] = None
    path: Optional[str] = None
    dest_pid: Optional[int] = None
    dest_uid: Optional[int] = None

    # Audit metadata
    audit_user: Optional[str] = None
    session: Optional[str] = None

    # Derived/high-level
    action: Optional[str] = None
    result: Optional[str] = None

    # Extended fields
    cmdline: Optional[str] = None
    comm: Optional[str] = None

    # Raw audit record for deep inspection
    raw: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp_ns": self.timestamp_ns,
            "host": self.host,
            "syscall": self.syscall,
            "exe": self.exe,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "euid": self.euid,
            "gid": self.gid,
            "egid": self.egid,
            "tty": self.tty,
            "cwd": self.cwd,
            "path": self.path,
            "dest_pid": self.dest_pid,
            "dest_uid": self.dest_uid,
            "audit_user": self.audit_user,
            "session": self.session,
            "action": self.action,
            "result": self.result,
            "cmdline": self.cmdline,
            "comm": self.comm,
        }


# =============================================================================
# Syscall Constants
# =============================================================================

# Privilege escalation syscalls
PRIVESC_SYSCALLS = frozenset({
    "setuid",
    "seteuid",
    "setreuid",
    "setresuid",
    "setgid",
    "setegid",
    "setregid",
    "setresgid",
    "setfsuid",
    "setfsgid",
    "capset",
})

# Process manipulation syscalls
PROCESS_SYSCALLS = frozenset({
    "execve",
    "execveat",
    "fork",
    "vfork",
    "clone",
    "clone3",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
})

# Module/driver syscalls
MODULE_SYSCALLS = frozenset({
    "init_module",
    "finit_module",
    "delete_module",
})

# File permission syscalls
PERMISSION_SYSCALLS = frozenset({
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
})

# Memory mapping syscalls (relevant for injection)
MEMORY_SYSCALLS = frozenset({
    "mmap",
    "mprotect",
    "mremap",
})

# Network syscalls
NETWORK_SYSCALLS = frozenset({
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
})


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "KernelAuditEvent",
    "PRIVESC_SYSCALLS",
    "PROCESS_SYSCALLS",
    "MODULE_SYSCALLS",
    "PERMISSION_SYSCALLS",
    "MEMORY_SYSCALLS",
    "NETWORK_SYSCALLS",
]
