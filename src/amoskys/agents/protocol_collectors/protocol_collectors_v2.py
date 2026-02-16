#!/usr/bin/env python3
"""ProtocolCollectors Agent v2 - Micro-Probe Based Protocol Monitoring.

This is the v2 implementation using the micro-probe architecture.
Each probe focuses on a specific protocol-level threat vector:

    1. HTTPSuspiciousHeadersProbe - Suspicious HTTP headers (T1071.001)
    2. TLSSSLAnomalyProbe - TLS/SSL anomalies (T1573.002)
    3. SSHBruteForceProbe - SSH brute force (T1110, T1021.004)
    4. DNSTunnelingProbe - DNS exfiltration (T1048.003)
    5. SQLInjectionProbe - SQL injection (T1190)
    6. RDPSuspiciousProbe - RDP suspicious activity (T1021.001)
    7. FTPCleartextCredsProbe - FTP credential exposure (T1552.001)
    8. SMTPSpamPhishProbe - SMTP spam/phishing (T1566.001)
    9. IRCP2PC2Probe - IRC/P2P C2 (T1071.001)
    10. ProtocolAnomalyProbe - Protocol anomalies (T1205)

Architecture:
    - Uses ProtocolCollector to gather protocol events
    - Events passed to probes via context.shared_data["protocol_events"]
    - Each probe returns TelemetryEvents for detected threats
    - Inherits metrics/observability from HardenedAgentBase

Usage:
    >>> from amoskys.agents.protocol_collectors import ProtocolCollectorsV2
    >>> agent = ProtocolCollectorsV2(device_id="host-001")
    >>> agent.run_forever()
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    TelemetryEvent,
)

# Use relative imports to avoid triggering amoskys.agents.__init__
from .collector import (
    BaseProtocolCollector,
    create_protocol_collector,
)
from .probes import PROTOCOL_PROBES
from .types import ProtocolEvent

logger = logging.getLogger(__name__)


class ProtocolCollectorsV2(MicroProbeAgentMixin, HardenedAgentBase):
    """Protocol plane threat detection using micro-probe architecture.
    
    Monitors network protocol traffic for security threats across
    multiple protocol types (HTTP, DNS, SSH, etc.).
    
    Attributes:
        collector: Protocol event collector instance
        log_path: Path to network/protocol log file
        use_stub: Use stub collector for testing
    """

    def __init__(
        self,
        device_id: str,
        agent_name: str = "protocol_collectors_v2",
        collection_interval: float = 5.0,
        log_path: str = "/var/log/syslog",
        collector: Optional[BaseProtocolCollector] = None,
        use_stub: bool = False,
        queue_adapter: Optional[Any] = None,
        metrics_interval: float = 60.0,
        probes: Optional[Sequence[MicroProbe]] = None,
    ):
        """Initialize ProtocolCollectorsV2.
        
        Args:
            device_id: Unique device identifier
            agent_name: Agent name for logging/metrics
            collection_interval: Seconds between collection cycles
            log_path: Path to network log file
            collector: Custom collector (overrides log_path)
            use_stub: Use stub collector for testing
            queue_adapter: Queue adapter for event persistence
            metrics_interval: Seconds between metrics emissions
            probes: Custom probes (overrides defaults)
        """
        # Initialize using super() for proper MRO handling
        super().__init__(
            agent_name=agent_name,
            device_id=device_id,
            collection_interval=collection_interval,
            probes=probes,
            queue_adapter=queue_adapter,
            metrics_interval=metrics_interval,
        )
        
        self.log_path = log_path
        self.use_stub = use_stub
        self._collector = collector

    def setup(self) -> bool:
        """Initialize collector and register probes.
        
        Returns:
            True if setup succeeded, False otherwise
        """
        logger.info(f"Setting up {self.agent_name} for device {self.device_id}")

        # Initialize collector
        if self._collector is None:
            self._collector = create_protocol_collector(
                use_stub=self.use_stub,
                log_path=self.log_path,
            )
        logger.info(f"Initialized collector: {type(self._collector).__name__}")

        # Register default probes if none were provided
        if not self.probes:
            self._register_default_probes()

        logger.info(f"{self.agent_name} setup complete: {len(self.probes)} probes active")
        return True

    def _register_default_probes(self) -> None:
        """Register all default protocol collector probes."""
        for probe_class in PROTOCOL_PROBES:
            probe = probe_class()
            self.register_probe(probe)
        logger.info(f"Registered {len(PROTOCOL_PROBES)} default protocol_collectors probes")

    def collect_data(self) -> List[Dict[str, Any]]:
        """Collect protocol events and run through probes.
        
        This implements the abstract method from HardenedAgentBase.
        
        Returns:
            List of telemetry dictionaries from probe analysis
        """
        results: List[Dict[str, Any]] = []
        
        # Collect raw protocol events
        try:
            protocol_events = self._collector.collect()
            logger.debug(f"Collected {len(protocol_events)} protocol events")
        except Exception as e:
            logger.error(f"Error collecting protocol events: {e}")
            return results

        # Create probe context with events
        context = ProbeContext(
            device_id=self.device_id,
            agent_name=self.agent_name,
            shared_data={"protocol_events": protocol_events},
        )

        # Run all probes
        telemetry_events = self.run_probes(context)
        
        # Convert to dictionaries
        # NOTE: Do not enqueue here — base class run() handles queue_adapter.enqueue()
        for event in telemetry_events:
            event_dict = event.to_dict()
            event_dict["device_id"] = self.device_id
            event_dict["agent"] = self.agent_name
            results.append(event_dict)

        return results

    def cleanup(self) -> None:
        """Clean up resources."""
        logger.info(f"Cleaning up {self.agent_name}")
        # Collector cleanup if needed
        if hasattr(self._collector, 'cleanup'):
            self._collector.cleanup()


# Convenience factory function
def create_protocol_collectors_v2(
    device_id: str,
    **kwargs,
) -> ProtocolCollectorsV2:
    """Create and configure a ProtocolCollectorsV2 agent.
    
    Args:
        device_id: Unique device identifier
        **kwargs: Additional configuration options
        
    Returns:
        Configured ProtocolCollectorsV2 instance
    """
    return ProtocolCollectorsV2(device_id=device_id, **kwargs)
