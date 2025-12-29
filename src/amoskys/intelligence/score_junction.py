"""
AMOSKYS Score Junction
Neural synapse for correlating multi-agent telemetry and computing unified threat scores

Architecture:
    Multiple Agents → DeviceTelemetry → ScoreJunction → ThreatScore → Intelligence Layer

Agents feed in:
- SNMPAgent: Device health, network stats
- ProcAgent: Process behavior, resource usage
- FlowAgent: Network flows
- Future: SyscallAgent, ProfileAgent, etc.

ScoreJunction performs:
1. Temporal correlation (events within time window)
2. Entity correlation (same device/IP/user)
3. Anomaly scoring
4. Threat aggregation
5. Confidence calculation
"""

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

# Use canonical ThreatLevel from intel.models
from amoskys.intel.models import ThreatLevel

logger = logging.getLogger("ScoreJunction")


@dataclass
class CorrelatedEvent:
    """Event with correlation metadata"""

    event_id: str
    device_id: str
    timestamp_ns: int
    agent_source: str  # snmp_agent, proc_agent, flow_agent
    event_type: str
    severity: str
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    alert_type: Optional[str] = None
    additional_context: Dict[str, str] = field(default_factory=dict)

    # Correlation fields
    correlation_score: float = 0.0
    correlated_with: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)


@dataclass
class ThreatScore:
    """Unified threat score for an entity"""

    entity_id: str  # device_id, IP, user, etc.
    entity_type: str  # device, ip, user, process
    score: float  # 0.0 - 100.0
    threat_level: ThreatLevel
    confidence: float  # 0.0 - 1.0
    contributing_events: List[str]  # Event IDs
    indicators: List[str]  # Human-readable indicators
    timestamp_ns: int
    time_window_seconds: int

    # Note: ThreatScore protobuf message doesn't exist in current schema
    # This would need to be added to universal_telemetry.proto if needed
    # def to_protobuf(self) -> telemetry_pb2.ThreatScore:
    #     """Convert to protobuf message"""
    #     pass


class EventBuffer:
    """Time-windowed buffer for event correlation"""

    def __init__(self, window_seconds: int = 300):
        """Initialize event buffer

        Args:
            window_seconds: Time window for correlation (default 5 minutes)
        """
        self.window_seconds = window_seconds
        self.window_ns = window_seconds * 1_000_000_000

        # Buffer organized by entity (device_id, IP, etc.)
        self.events_by_entity: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # Global event index
        self.all_events: deque = deque(maxlen=10000)

    def add_event(self, event: CorrelatedEvent):
        """Add event to buffer

        Args:
            event: Event to add
        """
        self.all_events.append(event)
        self.events_by_entity[event.device_id].append(event)

    def get_events_in_window(
        self, entity_id: str, current_time_ns: int
    ) -> List[CorrelatedEvent]:
        """Get events within time window for an entity

        Args:
            entity_id: Entity to query
            current_time_ns: Current timestamp

        Returns:
            List of events within window
        """
        entity_events = self.events_by_entity.get(entity_id, deque())
        window_start = current_time_ns - self.window_ns

        return [e for e in entity_events if e.timestamp_ns >= window_start]

    def cleanup_old_events(self, current_time_ns: int):
        """Remove events outside time window

        Args:
            current_time_ns: Current timestamp
        """
        window_start = current_time_ns - self.window_ns

        # Cleanup per-entity buffers
        for entity_id, events in list(self.events_by_entity.items()):
            while events and events[0].timestamp_ns < window_start:
                events.popleft()

            # Remove empty entity buffers
            if not events:
                del self.events_by_entity[entity_id]


class CorrelationEngine:
    """Correlate events across agents and time"""

    def __init__(self):
        self.rules = self._load_correlation_rules()

    def _load_correlation_rules(self) -> List[Dict]:
        """Load correlation rules

        Returns:
            List of correlation rules
        """
        # Simple rule-based correlation
        # In production, this would be loaded from config or ML model
        return [
            {
                "name": "high_cpu_suspicious_process",
                "description": "High CPU usage + suspicious process",
                "conditions": [
                    {"agent": "proc_agent", "metric": "cpu_percent", "threshold": 80},
                    {
                        "agent": "proc_agent",
                        "event_type": "ALERT",
                        "alert_type": "SUSPICIOUS_PROCESS",
                    },
                ],
                "score_weight": 0.7,
                "threat_level": ThreatLevel.HIGH,
            },
            {
                "name": "memory_spike_new_process",
                "description": "Memory spike correlated with new process",
                "conditions": [
                    {
                        "agent": "snmp_agent",
                        "metric": "hrStorageUsed",
                        "change": "spike",
                    },
                    {
                        "agent": "proc_agent",
                        "event_type": "EVENT",
                        "event_action": "PROCESS_START",
                    },
                ],
                "score_weight": 0.5,
                "threat_level": ThreatLevel.MEDIUM,
            },
            {
                "name": "network_spike_suspicious",
                "description": "Network traffic spike + suspicious activity",
                "conditions": [
                    {"agent": "snmp_agent", "metric": "ifInOctets", "change": "spike"},
                    {"agent": "proc_agent", "metric": "connections", "threshold": 50},
                ],
                "score_weight": 0.6,
                "threat_level": ThreatLevel.HIGH,
            },
        ]

    def correlate_events(
        self, events: List[CorrelatedEvent]
    ) -> List[Tuple[str, float, List[CorrelatedEvent]]]:
        """Find correlated event patterns

        Args:
            events: List of events to correlate

        Returns:
            List of (rule_name, correlation_score, matching_events)
        """
        correlations = []

        for rule in self.rules:
            matching_events = []
            score = 0.0

            # Check if rule conditions are met
            for condition in rule["conditions"]:
                for event in events:
                    if self._matches_condition(event, condition):
                        matching_events.append(event)
                        score += rule["score_weight"] / len(rule["conditions"])

            # If enough conditions met, record correlation
            if (
                len(matching_events) >= len(rule["conditions"]) * 0.5
            ):  # At least 50% of conditions
                correlations.append((rule["name"], score, matching_events))

        return correlations

    def _matches_condition(self, event: CorrelatedEvent, condition: Dict) -> bool:
        """Check if event matches a condition

        Args:
            event: Event to check
            condition: Condition to match

        Returns:
            True if event matches
        """
        # Check agent source
        if "agent" in condition and event.agent_source != condition["agent"]:
            return False

        # Check event type
        if "event_type" in condition and event.event_type != condition["event_type"]:
            return False

        # Check metric name
        if "metric" in condition and event.metric_name != f"proc_{condition['metric']}":
            return False

        # Check threshold
        if "threshold" in condition and event.metric_value:
            if event.metric_value < condition["threshold"]:
                return False

        # Check alert type
        if "alert_type" in condition and event.alert_type != condition["alert_type"]:
            return False

        return True


class ScoreJunction:
    """Main score junction for multi-agent telemetry correlation"""

    def __init__(self, config: Optional[Dict] = None):
        """Initialize score junction

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}

        # Time window for correlation (5 minutes default)
        self.correlation_window = self.config.get("correlation_window_seconds", 300)

        # Event buffer
        self.event_buffer = EventBuffer(self.correlation_window)

        # Correlation engine
        self.correlation_engine = CorrelationEngine()

        # Threat scores by entity
        self.threat_scores: Dict[str, ThreatScore] = {}

        # Statistics
        self.stats = {
            "events_processed": 0,
            "correlations_found": 0,
            "threats_detected": 0,
            "last_update": datetime.now(),
        }

    async def process_telemetry(
        self, envelope: telemetry_pb2.UniversalEnvelope
    ) -> Optional[ThreatScore]:
        """Process incoming telemetry and compute threat score

        Args:
            envelope: UniversalEnvelope from any agent

        Returns:
            ThreatScore if threats detected, None otherwise
        """
        # Extract device telemetry
        if not envelope.HasField("device_telemetry"):
            logger.warning("Envelope has no device_telemetry")
            return None

        device_telemetry = envelope.device_telemetry
        device_id = device_telemetry.device_id
        agent_source = device_telemetry.collection_agent

        # Convert events to CorrelatedEvent objects
        for event in device_telemetry.events:
            corr_event = self._convert_to_correlated_event(
                event, device_id, agent_source
            )

            self.event_buffer.add_event(corr_event)
            self.stats["events_processed"] += 1

        # Get events in correlation window
        current_time_ns = int(datetime.now().timestamp() * 1e9)
        recent_events = self.event_buffer.get_events_in_window(
            device_id, current_time_ns
        )

        if len(recent_events) < 2:
            # Not enough events to correlate
            return None

        # Perform correlation
        correlations = self.correlation_engine.correlate_events(recent_events)

        if correlations:
            self.stats["correlations_found"] += len(correlations)

            # Compute threat score
            threat_score = self._compute_threat_score(
                device_id, correlations, recent_events, current_time_ns
            )

            # Store and return
            self.threat_scores[device_id] = threat_score

            if threat_score.threat_level.value >= ThreatLevel.MEDIUM.value:
                self.stats["threats_detected"] += 1
                logger.warning(
                    f"🚨 Threat detected: {device_id} - Score {threat_score.score:.1f} ({threat_score.threat_level.name})"
                )
                return threat_score

        # Cleanup old events
        self.event_buffer.cleanup_old_events(current_time_ns)

        return None

    def _convert_to_correlated_event(
        self, event: telemetry_pb2.TelemetryEvent, device_id: str, agent_source: str
    ) -> CorrelatedEvent:
        """Convert protobuf event to CorrelatedEvent

        Args:
            event: TelemetryEvent from protobuf
            device_id: Device identifier
            agent_source: Source agent name

        Returns:
            CorrelatedEvent object
        """
        # Extract metric data if present
        metric_name = None
        metric_value = None
        if event.HasField("metric_data"):
            metric_name = event.metric_data.metric_name
            metric_value = (
                event.metric_data.numeric_value
                if event.metric_data.HasField("numeric_value")
                else None
            )

        # Extract alert data if present
        alert_type = None
        if event.HasField("alert_data"):
            alert_type = event.alert_data.alert_type

        return CorrelatedEvent(
            event_id=event.event_id,
            device_id=device_id,
            timestamp_ns=event.event_timestamp_ns,
            agent_source=agent_source,
            event_type=event.event_type,
            severity=event.severity,
            metric_name=metric_name,
            metric_value=metric_value,
            alert_type=alert_type,
            additional_context=(
                dict(event.additional_context) if event.additional_context else {}
            ),
        )

    def _compute_threat_score(
        self,
        entity_id: str,
        correlations: List[Tuple[str, float, List[CorrelatedEvent]]],
        all_events: List[CorrelatedEvent],
        timestamp_ns: int,
    ) -> ThreatScore:
        """Compute unified threat score from correlations

        Args:
            entity_id: Entity being scored
            correlations: List of correlations found
            all_events: All events in window
            timestamp_ns: Current timestamp

        Returns:
            ThreatScore object
        """
        # Aggregate scores
        total_score = 0.0
        contributing_events = []
        indicators = []

        for rule_name, score, events in correlations:
            total_score += score * 100  # Convert to 0-100 scale
            contributing_events.extend([e.event_id for e in events])
            indicators.append(rule_name)

        # Normalize score
        if correlations:
            total_score = min(100.0, total_score)

        # Determine threat level
        if total_score >= 80:
            threat_level = ThreatLevel.CRITICAL
        elif total_score >= 60:
            threat_level = ThreatLevel.HIGH
        elif total_score >= 40:
            threat_level = ThreatLevel.MEDIUM
        elif total_score >= 20:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.BENIGN

        # Confidence based on number of correlated events
        confidence = min(1.0, len(contributing_events) / 10.0)

        return ThreatScore(
            entity_id=entity_id,
            entity_type="device",
            score=total_score,
            threat_level=threat_level,
            confidence=confidence,
            contributing_events=list(set(contributing_events)),
            indicators=indicators,
            timestamp_ns=timestamp_ns,
            time_window_seconds=self.correlation_window,
        )

    def get_entity_score(self, entity_id: str) -> Optional[ThreatScore]:
        """Get current threat score for an entity

        Args:
            entity_id: Entity to query

        Returns:
            ThreatScore if available, None otherwise
        """
        return self.threat_scores.get(entity_id)

    def get_statistics(self) -> Dict:
        """Get junction statistics

        Returns:
            Dictionary of statistics
        """
        self.stats["last_update"] = datetime.now()
        self.stats["entities_tracked"] = len(self.threat_scores)
        return self.stats.copy()


# Example usage
async def main():
    """Example of using ScoreJunction"""
    logging.basicConfig(level=logging.INFO)

    logger.info("🧠⚡ AMOSKYS Score Junction Starting...")

    junction = ScoreJunction()

    # In production, this would receive envelopes from EventBus
    # For demo, we'll just show the structure

    logger.info(f"✅ Junction initialized with {junction.correlation_window}s window")
    logger.info(f"📊 Loaded {len(junction.correlation_engine.rules)} correlation rules")

    # Get statistics
    stats = junction.get_statistics()
    logger.info(f"📈 Statistics: {stats}")


if __name__ == "__main__":
    asyncio.run(main())


# Export public API
__all__ = [
    "ScoreJunction",
    "ThreatScore",
    "ThreatLevel",
    "CorrelatedEvent",
    "EventBuffer",
    "CorrelationEngine",
]
