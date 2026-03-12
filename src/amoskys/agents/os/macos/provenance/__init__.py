"""AMOSKYS macOS Provenance Observatory.

Cross-application attack chain correlation — the killer differentiator that
no competitor has.  Traditional EDR monitors processes in isolation; AMOSKYS
Provenance tracks the *causal chain* across application boundaries:

    Slack message -> Safari download -> Terminal execute -> curl exfiltrate

The agent maintains rolling state across collection cycles.  A stateful
collector tracks process baselines and download directories, while eight
detection probes maintain sliding temporal windows to correlate events that
span minutes and multiple applications.

Data sources (measured on macOS 26.0, Apple Silicon, uid=501):
    - psutil process enumeration: ~650 processes in 5ms
    - ~/Downloads directory scan: <1ms for typical user
    - lsof -i -n -P: ~50ms for established TCP connections
    - Active app detection: derived from process list (zero cost)

Kill chain stages tracked:
    1. Message delivery (Slack, Teams, Discord, Signal, Telegram)
    2. Browser activity (Safari, Chrome, Firefox, Arc, Brave, Edge)
    3. File download (new files in ~/Downloads)
    4. Execution (new process from downloaded file)
    5. Credential access (sensitive file in cmdline/name)
    6. Network exfiltration (new process with external connections)

Coverage: T1566.002, T1204.001, T1204.002, T1041, T1071.001, T1005
"""

from amoskys.agents.os.macos.provenance.agent import MacOSProvenanceAgent

__all__ = ["MacOSProvenanceAgent"]
