"""AMOSKYS Linux Kernel Audit Agent — Syscall & Kernel-Level Monitoring.

Primary sensor for Linux: reads auditd SYSCALL records from /var/log/audit/audit.log.
Provides: exec detection, privilege escalation, module load, ptrace, chmod/chown,
audit tamper, credential dump, and syscall flood probes.
"""

from .agent_types import (
    MODULE_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
    KernelAuditEvent,
)
from .collector import (
    AuditdLogCollector,
    BaseKernelAuditCollector,
    StubKernelAuditCollector,
    create_kernel_audit_collector,
)


def __getattr__(name: str):
    """Lazy import for components that depend on common.probes."""
    if name == "KernelAuditAgent":
        from .kernel_audit_agent import KernelAuditAgent

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
        from . import probes as _probes

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
