"""AMOSKYS macOS Arsenal — Darwin security capabilities.

Built from live device ground truth on macOS 26.0 (Darwin 25.0.0), Apple Silicon.
Every capability documented with its reality status.

Ground truth methodology:
    1. Run the actual tool/API on the device
    2. Record what fields are present, what's missing, what's permission-gated
    3. Badge each capability: REAL / DEGRADED / BLIND / STUB
    4. Document false-positive sources and evasion vectors

Device tested: Mac, uid=501, non-root, admin group.
"""

from amoskys.agents.os.macos.arsenal import MacOSArsenal

__all__ = ["MacOSArsenal"]
