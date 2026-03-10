"""AMOSKYS macOS Unified Log Observatory.

Monitors the macOS Unified Logging system (log stream / log show) for security-
relevant events across multiple subsystems. Uses targeted predicates to observe
securityd, Gatekeeper, TCC, XPC, installer, and sharing activity without
requiring Full Disk Access for most subsystems.

Data sources:
    - log show --predicate '...' --last Ns --style json
    - Predicate groups: securityd, syspolicyd/GatekeeperXPC, TCC, XPC,
      installer, sharingd/AirDrop

Ground truth (macOS 26.0, uid=501):
    - Security subsystem: PKI/certificate/trust events visible without FDA
    - Gatekeeper: syspolicyd assessment and quarantine visible
    - TCC: permission grant/deny events (DEGRADED without FDA for full history)
    - XPC: connection lifecycle and error events
    - Installer: package install activity
    - Sharing: AirDrop/sharingd transfer events

Coverage: T1553, T1553.001, T1204.002, T1559, T1548, T1105
"""

from amoskys.agents.os.macos.unified_log.agent import MacOSUnifiedLogAgent

__all__ = ["MacOSUnifiedLogAgent"]
