"""AMOSKYS Kernel Audit Agent - Syscall & Kernel-Level Monitoring.

Micro-probe architecture with specialized probes.
Uses lazy imports to avoid circular import issues.
"""

# Collectors - minimal dependencies
from amoskys.agents.kernel_audit.collector import (
    AuditdLogCollector,
    BaseKernelAuditCollector,
    StubKernelAuditCollector,
    create_kernel_audit_collector,
)

# Types - no dependencies, safe to import directly
from amoskys.agents.kernel_audit.agent_types import (
    MODULE_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
    KernelAuditEvent,
)


def __getattr__(name: str):
    """Lazy import for components that depend on common.probes."""
    if name in ("KernelAuditAgent", "KernelAuditAgentV2"):
        from amoskys.agents.kernel_audit.kernel_audit_agent import KernelAuditAgent

        return KernelAuditAgent

    if name in (
        "ExecveHighRiskProbe",
        "PrivEscSyscallProbe",
        "KernelModuleLoadProbe",
        "PtraceAbuseProbe",
        "FilePermissionTamperProbe",
        "AuditTamperProbe",
        "SyscallFloodProbe",
        "create_kernel_audit_probes",
    ):
        from amoskys.agents.kernel_audit import probes as _probes

        return getattr(_probes, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "KernelAuditAgent",
    "KernelAuditAgentV2",
    "KernelAuditEvent",
    "PRIVESC_SYSCALLS",
    "PROCESS_SYSCALLS",
    "MODULE_SYSCALLS",
    "PERMISSION_SYSCALLS",
    "BaseKernelAuditCollector",
    "AuditdLogCollector",
    "StubKernelAuditCollector",
    "create_kernel_audit_collector",
    "ExecveHighRiskProbe",
    "PrivEscSyscallProbe",
    "KernelModuleLoadProbe",
    "PtraceAbuseProbe",
    "FilePermissionTamperProbe",
    "AuditTamperProbe",
    "SyscallFloodProbe",
    "create_kernel_audit_probes",
]
