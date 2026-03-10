"""AMOSKYS macOS Network Observatory.

Network flow monitoring via lsof and nettop. Detects C2 beaconing,
data exfiltration, lateral movement, and anomalous connections.

Ground truth (macOS 26.0, uid=501):
    - lsof -i -nP: 37 connections visible, ~200ms
    - nettop: per-process bandwidth available, ~1s
    - No root required for connection listing
    - No DPI capability (tcpdump requires root)

Coverage: T1071, T1573, T1572, T1571, T1048, T1570, T1021
"""

from amoskys.agents.os.macos.network.agent import MacOSNetworkAgent

__all__ = ["MacOSNetworkAgent"]
