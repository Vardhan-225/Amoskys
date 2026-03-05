"""macOS Security Monitor — Event Types.

Uses the same schema as KernelAuditEvent (shared across Linux and macOS agents)
but with macOS-specific field semantics:

    syscall     → always None (unified log has no syscall field)
    exe         → processImagePath from unified log (full path, reliable)
    pid         → processID from unified log (reliable)
    uid         → None (not available from unified log messages)
    euid        → None (not available)
    ppid        → None (not available)
    comm        → basename of processImagePath (reliable)
    action      → derived from log message category/subsystem (broad classification)
    result      → inferred from message keywords (limited reliability)
    cmdline     → None (not available)
    path        → None (not available from this collector)
    raw         → full unified log JSON entry as str dict

MacOS Security Monitor watches the Apple security framework layer:
    - com.apple.securityd   (PKI, trust, keychain operations)
    - com.apple.authd       (authentication daemon)
    - com.apple.sandbox     (sandbox policy enforcement)
    - com.apple.kernel      (kernel-level events where available)

This is distinct from kernel syscall monitoring — it observes the security
framework's view of the system, not kernel primitive calls.
"""

from amoskys.agents.linux.kernel_audit.agent_types import (  # noqa: F401
    KernelAuditEvent,
    MEMORY_SYSCALLS,
    MODULE_SYSCALLS,
    NETWORK_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
)

# Alias — MacOSSecurityEvent uses identical schema to KernelAuditEvent.
# Fields are populated differently (see module docstring), but the data
# contract (probes, serialization, WAL) stays uniform across platforms.
MacOSSecurityEvent = KernelAuditEvent

__all__ = [
    "MacOSSecurityEvent",
    "KernelAuditEvent",
    "PRIVESC_SYSCALLS",
    "PROCESS_SYSCALLS",
    "MODULE_SYSCALLS",
    "PERMISSION_SYSCALLS",
    "MEMORY_SYSCALLS",
    "NETWORK_SYSCALLS",
]
