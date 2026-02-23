"""Backward-compatibility shim — use protocol_collectors.py instead.

Deprecated in v0.9.0-beta.1 (B5.1). Will be removed in v1.0.
"""

from amoskys.agents.protocol_collectors.protocol_collectors import *  # noqa: F401,F403
from amoskys.agents.protocol_collectors.protocol_collectors import ProtocolCollectors

ProtocolCollectorsV2 = ProtocolCollectors
