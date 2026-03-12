"""AMOSKYS macOS InfostealerGuard Observatory.

Purpose-built infostealer detection for macOS (Darwin 25.0.0+, Apple Silicon).
Detects the AMOS/Poseidon/Banshee infostealer kill chain: credential harvesting,
fake password dialogs, browser data theft, crypto wallet theft, and exfiltration.

Ground truth (measured on macOS 26.0, uid=501):
    - 13 sensitive file categories monitored (keychain, browsers, wallets, messaging)
    - lsof +D per category with 5s timeout, filtered against expected accessor sets
    - psutil process scan for osascript dialog phishing, security CLI, archive staging
    - lsof -i -n -P for per-PID network connections (exfil correlation)
    - Expected false positive rate < 2% (aggressive benign-process filtering)
    - 10 detection probes covering T1555.001, T1555.003, T1005, T1056.002,
      T1560.001, T1539, T1115, T1113, T1041

Coverage: T1555.001, T1555.003, T1005, T1056.002, T1560.001, T1539, T1115, T1113, T1041
"""

from amoskys.agents.os.macos.infostealer_guard.agent import MacOSInfostealerGuardAgent

__all__ = ["MacOSInfostealerGuardAgent"]
