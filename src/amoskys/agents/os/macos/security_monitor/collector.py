"""macOS Security Monitor — Collector.

Provides collectors for macOS security framework events via the Unified Logging
system. The primary collector queries security-relevant subsystems and converts
entries into MacOSSecurityEvent (KernelAuditEvent-compatible) objects.

Reality (as measured on macOS 26.0, 2026-03-04):
    - com.apple.securityd: 10-19 events per 10s — PKI/cert infrastructure
    - com.apple.authd:     0 events (silent on modern macOS)
    - com.apple.sandbox:   0 events (silent)
    - com.apple.kernel:    0 events (silent)
    - syscall field:       ALWAYS None (unified log has no syscall primitive)
    - uid/euid/ppid:       ALWAYS None
    - exe/pid/comm:        Reliable

See docs/Engineering/kernel_audit/macos_reality_matrix.md for full evidence.
"""

from amoskys.agents.os.linux.kernel_audit.collector import (  # noqa: F401
    BaseKernelAuditCollector,
    MacOSAuditCollector,
    MacOSUnifiedLogCollector,
    StubKernelAuditCollector,
)


def create_macos_security_collector(
    use_stub: bool = False,
    use_bsm_fallback: bool = False,
) -> BaseKernelAuditCollector:
    """Create the appropriate macOS security collector.

    Args:
        use_stub: Return a StubKernelAuditCollector for testing.
        use_bsm_fallback: Use OpenBSM collector (broken on macOS 10.15+,
            present only for completeness — returns 0 events on macOS 26.0).

    Returns:
        Collector instance ready for collect_batch() calls.
    """
    if use_stub:
        return StubKernelAuditCollector()

    if use_bsm_fallback:
        return MacOSAuditCollector()

    return MacOSUnifiedLogCollector()


__all__ = [
    "BaseKernelAuditCollector",
    "MacOSUnifiedLogCollector",
    "MacOSAuditCollector",
    "StubKernelAuditCollector",
    "create_macos_security_collector",
]
