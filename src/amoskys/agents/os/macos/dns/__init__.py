"""AMOSKYS macOS DNS Observatory.

Purpose-built DNS threat detection for macOS (Darwin 25.0.0+, Apple Silicon).
Monitors mDNSResponder via Unified Logging and scutil --dns for DNS config.

Probes:
    - DGA detection (Shannon entropy + n-gram scoring)
    - DNS tunneling (TXT record anomaly, high frequency single domain)
    - Beaconing patterns (periodic queries with jitter analysis)
    - DNS-over-HTTPS detection (DoH provider IP matching)
    - New/first-seen domain baseline-diff
    - Fast-flux detection (rapid IP rotation)
    - Reverse DNS reconnaissance (internal PTR queries)
    - Cache poison indicators (TTL anomalies)

Coverage: T1568.002, T1071.004, T1572, T1583, T1568.001, T1046, T1557.002
"""

from amoskys.agents.os.macos.dns.agent import MacOSDNSAgent

__all__ = ["MacOSDNSAgent"]
