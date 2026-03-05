"""Backward-compatibility re-export — moved to agents.linux.kernel_audit.collector."""
from amoskys.agents.linux.kernel_audit.collector import (  # noqa: F401
    AuditdLogCollector,
    BaseKernelAuditCollector,
    MacOSAuditCollector,
    MacOSUnifiedLogCollector,
    StubKernelAuditCollector,
    create_kernel_audit_collector,
)

__all__ = [
    "BaseKernelAuditCollector",
    "AuditdLogCollector",
    "MacOSAuditCollector",
    "MacOSUnifiedLogCollector",
    "StubKernelAuditCollector",
    "create_kernel_audit_collector",
]
