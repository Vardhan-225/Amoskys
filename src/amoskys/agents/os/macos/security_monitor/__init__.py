"""AMOSKYS macOS Security Monitor Agent.

Monitors the macOS security framework layer (Gatekeeper, PKI, trustd, syspolicyd)
via the Unified Logging system. Same probe architecture as linux.kernel_audit
but positioned for macOS security framework events, not kernel syscalls.

Sensor truth: see docs/Engineering/kernel_audit/macos_reality_matrix.md
"""

from .agent_types import KernelAuditEvent, MacOSSecurityEvent
from .collector import (
    BaseKernelAuditCollector,
    MacOSUnifiedLogCollector,
    StubKernelAuditCollector,
    create_macos_security_collector,
)


def __getattr__(name: str):
    if name == "MacOSSecurityMonitorAgent":
        from .security_monitor_agent import MacOSSecurityMonitorAgent

        return MacOSSecurityMonitorAgent

    if name in (
        "SecurityFrameworkFloodProbe",
        "GatekeeperAnomalyProbe",
        "CertificateAnomalyProbe",
        "SecurityFrameworkHealthProbe",
        "create_macos_security_probes",
    ):
        from . import probes as _probes

        return getattr(_probes, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "MacOSSecurityMonitorAgent",
    "MacOSSecurityEvent",
    "KernelAuditEvent",
    "BaseKernelAuditCollector",
    "MacOSUnifiedLogCollector",
    "StubKernelAuditCollector",
    "create_macos_security_collector",
    "SecurityFrameworkFloodProbe",
    "GatekeeperAnomalyProbe",
    "CertificateAnomalyProbe",
    "SecurityFrameworkHealthProbe",
    "create_macos_security_probes",
]
