"""ProtocolCollectors Agent v2 - Protocol Plane Threat Detection.

This module provides micro-probe based protocol monitoring:
    - HTTP suspicious headers
    - TLS/SSL anomalies
    - SSH brute force detection
    - DNS tunneling
    - SQL injection
    - RDP suspicious activity
    - FTP cleartext credentials
    - SMTP spam/phishing
    - IRC/P2P C2 detection
    - Protocol anomalies
"""

from amoskys.agents.protocol_collectors.protocol_collectors_v2 import (
    ProtocolCollectorsV2,
)

__all__ = ["ProtocolCollectorsV2"]
