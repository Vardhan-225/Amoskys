"""AMOSKYS macOS Auth Observatory.

Monitors authentication events on macOS via Unified Logging (log show).
Collects SSH, sudo, loginwindow, and screensaver events and runs 6 detection
probes for brute-force, privilege escalation, off-hours login, impossible
travel, account lockout, and credential access.

Data sources:
    - macOS Unified Logging: process == "sshd" | "sudo" | "loginwindow" | "screensaverengine"
    - security CLI (Keychain) usage via process enumeration

Coverage: T1110, T1548.003, T1078, T1555.001
"""

from amoskys.agents.os.macos.auth.agent import MacOSAuthAgent

__all__ = ["MacOSAuthAgent"]
