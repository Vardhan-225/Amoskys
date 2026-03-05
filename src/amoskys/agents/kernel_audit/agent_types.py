"""Backward-compatibility re-export — moved to agents.linux.kernel_audit.agent_types."""
from amoskys.agents.linux.kernel_audit.agent_types import (  # noqa: F401
    KernelAuditEvent,
    MEMORY_SYSCALLS,
    MODULE_SYSCALLS,
    NETWORK_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
)

__all__ = [
    "KernelAuditEvent",
    "PRIVESC_SYSCALLS",
    "PROCESS_SYSCALLS",
    "MODULE_SYSCALLS",
    "PERMISSION_SYSCALLS",
    "MEMORY_SYSCALLS",
    "NETWORK_SYSCALLS",
]
