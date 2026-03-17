"""macOS Real-Time Sensor — Event-driven kernel event monitoring.

Replaces polling-based detection with real-time event streams using
macOS kernel APIs that require NO entitlements:

  1. FSEvents     — Real-time filesystem change notifications
  2. kqueue       — Process lifecycle events (fork/exec/exit)
  3. Log Stream   — Unified logging events (TCC, auth, security)

This agent eliminates the 60-second polling gap that the peer review
identified as a fundamental evasion window. Detection latency drops
from polling_interval (30-60s) to event delivery latency (<100ms).

Addresses peer review criticism #8 (no evasion discussion) by making
the collection interval irrelevant — events arrive as they happen.
"""

from .agent import MacOSRealtimeSensorAgent

__all__ = ["MacOSRealtimeSensorAgent"]
