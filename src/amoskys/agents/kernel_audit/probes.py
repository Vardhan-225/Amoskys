"""Backward-compatibility re-export — moved to agents.linux.kernel_audit.probes."""
from amoskys.agents.linux.kernel_audit.probes import (  # noqa: F401
    AuditTamperProbe,
    CredentialDumpProbe,
    ExecveHighRiskProbe,
    FilePermissionTamperProbe,
    KernelModuleLoadProbe,
    PrivEscSyscallProbe,
    PtraceAbuseProbe,
    SyscallFloodProbe,
    create_kernel_audit_probes,
)

__all__ = [
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
