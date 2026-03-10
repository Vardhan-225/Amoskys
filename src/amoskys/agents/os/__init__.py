"""AMOSKYS OS Arsenal — platform-specific security modules.

Each OS module provides a self-contained view of what AMOSKYS can actually
detect on that platform. Built from live device ground truth, not assumptions.

Usage:
    from amoskys.agents.os.macos import MacOSArsenal
    arsenal = MacOSArsenal()
    arsenal.status()       # What's REAL, what's DEGRADED, what's BLIND
    arsenal.run_audit()    # Live capability check against the device
"""

import sys
from typing import Optional


def get_arsenal(platform: Optional[str] = None):
    """Get the OS arsenal for the current or specified platform."""
    if platform is None:
        platform = sys.platform

    if platform == "darwin":
        from amoskys.agents.os.macos import MacOSArsenal

        return MacOSArsenal()
    elif platform.startswith("linux"):
        from amoskys.agents.os.linux import LinuxArsenal

        return LinuxArsenal()
    elif platform == "win32":
        from amoskys.agents.os.windows import WindowsArsenal

        return WindowsArsenal()
    else:
        raise ValueError(f"Unsupported platform: {platform}")
