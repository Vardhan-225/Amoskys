"""AMOSKYS Kernel Audit Agent - Syscall & Kernel-Level Monitoring.

This module provides two generations of kernel audit agents:

v1 (Legacy):
    - KernelAuditAgent: Monolithic agent with inline detection
    - AuditEvent, KernelThreat: v1 data types

v2 (Micro-Probe Architecture):
    - KernelAuditAgentV2: Micro-probe based agent
    - KernelAuditEvent: Normalized event type
    - 7 specialized probes for different attack vectors
    - Pluggable collectors (auditd, stub for testing)

Note: v2 components use lazy imports to avoid circular import issues
with the main agents __init__.py module.
"""

from typing import TYPE_CHECKING

# v1 exports (legacy, still functional) - always loaded
from amoskys.agents.kernel_audit.kernel_audit_agent import (
    AuditEvent,
    KernelAuditAgent,
    KernelThreat,
)

# v2 types - no dependencies, safe to import directly
from amoskys.agents.kernel_audit.types import (
    KernelAuditEvent,
    MODULE_SYSCALLS,
    PERMISSION_SYSCALLS,
    PRIVESC_SYSCALLS,
    PROCESS_SYSCALLS,
)

# v2 collectors - minimal dependencies
from amoskys.agents.kernel_audit.collector import (
    AuditdLogCollector,
    BaseKernelAuditCollector,
    StubKernelAuditCollector,
    create_kernel_audit_collector,
)


def __getattr__(name: str):
    """Lazy import for v2 components that depend on common.probes.

    This avoids circular imports when agents/__init__.py loads kernel_audit.
    """
    # v2 agent - depends on MicroProbeAgentMixin
    if name == "KernelAuditAgentV2":
        from amoskys.agents.kernel_audit.kernel_audit_agent_v2 import KernelAuditAgentV2
        return KernelAuditAgentV2

    # v2 probes
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
    # v1 (legacy)
    "KernelAuditAgent",
    "AuditEvent",
    "KernelThreat",
    # v2 agent
    "KernelAuditAgentV2",
    # v2 types
    "KernelAuditEvent",
    "PRIVESC_SYSCALLS",
    "PROCESS_SYSCALLS",
    "MODULE_SYSCALLS",
    "PERMISSION_SYSCALLS",
    # v2 collectors
    "BaseKernelAuditCollector",
    "AuditdLogCollector",
    "StubKernelAuditCollector",
    "create_kernel_audit_collector",
    # v2 probes
    "ExecveHighRiskProbe",
    "PrivEscSyscallProbe",
    "KernelModuleLoadProbe",
    "PtraceAbuseProbe",
    "FilePermissionTamperProbe",
    "AuditTamperProbe",
    "SyscallFloodProbe",
    "create_kernel_audit_probes",
]
