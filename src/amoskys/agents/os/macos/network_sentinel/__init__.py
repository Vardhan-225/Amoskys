"""NetworkSentinel — HTTP access log analysis, scan detection, payload inspection.

Built because 17,273 malicious requests went undetected. Never again.
"""

from amoskys.agents.os.macos.network_sentinel.agent import NetworkSentinelAgent
from amoskys.agents.os.macos.network_sentinel.probes import (
    create_network_sentinel_probes,
)

__all__ = ["NetworkSentinelAgent", "create_network_sentinel_probes"]
