"""AMOSKYS macOS Internet Activity Observatory.

Purpose-built internet connection threat detection for macOS (Darwin 25.0.0+, Apple Silicon).
Monitors active network connections via lsof -i with PID-to-process correlation and
IP classification (private, cloud provider, CDN, TOR exit node ranges).

Probes:
    - Cloud exfiltration (S3/GCS/Azure Blob endpoint detection)
    - TOR/VPN usage (exit node + VPN port detection)
    - Crypto mining (stratum pool port patterns)
    - Geo-anomaly (unusual IP range heuristics)
    - Long-lived connections (persistent non-CDN connections)
    - Data exfil timing (late-night + burst pattern detection)
    - Shadow IT (unauthorized cloud service usage)
    - CDN masquerade (C2 hiding behind CDN infrastructure)

Coverage: T1567, T1090.003, T1496, T1071, T1571, T1048, T1567.002, T1090.002
"""

from amoskys.agents.os.macos.internet_activity.agent import MacOSInternetActivityAgent

__all__ = ["MacOSInternetActivityAgent"]
