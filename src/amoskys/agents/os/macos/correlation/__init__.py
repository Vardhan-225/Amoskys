"""AMOSKYS macOS Correlation Engine — cross-agent intelligence layer.

The 8th macOS Observatory agent. Aggregates data from all 7 domain collectors
(process, network, persistence, filesystem, auth, unified_log, peripheral)
and runs 18 correlation probes (12 snapshot + 6 temporal) that detect
cross-domain attack patterns invisible to any single agent.

Closes 17 + 11 = 28 evasion gaps:
    Snapshot (17): Whitelist abuse (wl1-wl6), Threshold evasion (th1-th4),
                   Coverage gaps (cg1-cg6), Naming tricks (nt1-nt3)
    Temporal (11): T1-T4, E2, E5, F1-F3, S1-S5, ab2

Architecture:
    CorrelationCollector → merged shared_data (all 7 domains + PID indexes)
    12 Snapshot Probes → cross-domain TelemetryEvents (same-scan patterns)
    6 Temporal Probes → timestamp-driven TelemetryEvents (sequences + timing)
    RollingWindowAggregator → cumulative + temporal metrics (rate, burst, jitter)
"""

from amoskys.agents.os.macos.correlation.probes import create_correlation_probes
from amoskys.agents.os.macos.correlation.temporal_probes import create_temporal_probes

__all__ = ["create_correlation_probes", "create_temporal_probes"]
