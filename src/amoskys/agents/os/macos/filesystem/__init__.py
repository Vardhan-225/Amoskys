"""AMOSKYS macOS File Observatory.

Monitors critical macOS filesystem paths for integrity violations, unauthorized
modifications, SUID abuse, webshells, quarantine bypass, and SIP status changes.

Ground truth (macOS 26.0, uid=501):
    - /etc: system configuration files (hosts, resolv.conf, sudoers, etc.)
    - /usr/bin, /usr/sbin, /usr/lib: SIP-protected system binaries
    - ~/Library: user-level config, preferences, application support
    - /Library: system-level frameworks, preferences, extensions
    - SIP status: csrutil status readable without root
    - SUID binaries: stat() accessible on known paths

Coverage: T1565, T1548.001, T1070, T1505.003, T1553.001, T1562.001, T1564.001, T1204
"""

from amoskys.agents.os.macos.filesystem.agent import MacOSFileAgent

__all__ = ["MacOSFileAgent"]
