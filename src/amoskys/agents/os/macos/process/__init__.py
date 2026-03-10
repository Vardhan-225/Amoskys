"""AMOSKYS macOS Process Observatory.

Purpose-built process monitoring for macOS (Darwin 25.0.0+, Apple Silicon).
Built from live device ground truth on uid=501 non-root.

Ground truth (measured):
    - 652 total processes visible via psutil
    - 398 own-user processes with full detail (cmdline, cpu, memory, environ)
    - 254 other-user processes with pid/name/exe only (permission boundary)
    - 60.8% cmdline coverage across all processes
    - 5ms full process enumeration time
    - AppTranslocation paths in /private/var/folders/*/T/ (false positive source)
    - codesign --verify works for most binaries (some Permission denied)

Coverage: T1059, T1218, T1055, T1496, T1036, T1204, T1078
"""

from amoskys.agents.os.macos.process.agent import MacOSProcessAgent

__all__ = ["MacOSProcessAgent"]
