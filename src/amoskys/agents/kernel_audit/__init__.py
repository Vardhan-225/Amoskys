"""Backward-compatibility shim — kernel_audit moved to agents.linux.kernel_audit.

All imports from amoskys.agents.kernel_audit.* continue to work unchanged.
New code should import from amoskys.agents.linux.kernel_audit directly.
"""

from amoskys.agents.linux.kernel_audit.agent_types import (  # noqa: F401
    MODULE_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
    KernelAuditEvent,
)
from amoskys.agents.linux.kernel_audit.collector import (  # noqa: F401
    AuditdLogCollector,
    BaseKernelAuditCollector,
    StubKernelAuditCollector,
    create_kernel_audit_collector,
)


def __getattr__(name: str):
    """Lazy import for components that depend on common.probes."""
    if name == "KernelAuditAgent":
        from amoskys.agents.linux.kernel_audit.kernel_audit_agent import KernelAuditAgent
        return KernelAuditAgent

    if name in (
        "ExecveHighRiskProbe",
        "PrivEscSyscallProbe",
        "KernelModuleLoadProbe",
        "PtraceAbuseProbe",
        "FilePermissionTamperProbe",
        "AuditTamperProbe",
        "SyscallFloodProbe",
        "CredentialDumpProbe",
        "create_kernel_audit_probes",
    ):
        from amoskys.agents.linux.kernel_audit import probes as _probes
        return getattr(_probes, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "KernelAuditAgent",
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
    "CredentialDumpProbe",
    "create_kernel_audit_probes",
]
