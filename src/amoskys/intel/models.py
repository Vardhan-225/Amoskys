"""
Intelligence Layer Data Models

Defines core objects emitted by the Fusion correlation engine:
- DeviceRiskSnapshot: Current security posture of a device
- Incident: Correlated attack chain detected across multiple events
- ThreatLevel: Canonical threat severity levels (used across all agents)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatLevel(Enum):
    """Canonical threat severity levels - single source of truth

    Used across all agents and intelligence modules for consistent
    threat classification.

    Values:
        BENIGN (0): No threat detected
        LOW (1): Minor concern, routine monitoring
        MEDIUM (2): Notable activity, enhanced monitoring
        HIGH (3): Significant threat, investigation needed
        CRITICAL (4): Active attack, immediate response required
        UNDER_ATTACK (5): Confirmed breach, incident response active
    """

    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    UNDER_ATTACK = 5


class RiskLevel(Enum):
    """Device risk classification levels"""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(Enum):
    """Incident severity levels"""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MitreTactic(Enum):
    """MITRE ATT&CK Tactics (high-level attack stages)"""

    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class DeviceRiskSnapshot:
    """Current security posture of a device

    Aggregates recent risky events into a unified risk score and level.
    Updated continuously as new events arrive.

    Attributes:
        device_id: Unique device identifier (hostname)
        score: Risk score 0-100 (higher = more risky)
        level: Categorical risk level (LOW/MEDIUM/HIGH/CRITICAL)
        reason_tags: Human-readable tags explaining the score
        supporting_events: Event IDs contributing to this score
        updated_at: Timestamp of last update
        metadata: Additional context (event counts, source IPs, etc.)
    """

    device_id: str
    score: int
    level: RiskLevel
    reason_tags: List[str] = field(default_factory=list)
    supporting_events: List[str] = field(default_factory=list)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "device_id": self.device_id,
            "score": self.score,
            "level": self.level.value,
            "reason_tags": self.reason_tags,
            "supporting_events": self.supporting_events,
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def score_to_level(cls, score: int) -> RiskLevel:
        """Map numeric score to risk level

        Args:
            score: Risk score 0-100

        Returns:
            RiskLevel enum value
        """
        if score <= 30:
            return RiskLevel.LOW
        elif score <= 60:
            return RiskLevel.MEDIUM
        elif score <= 80:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL


@dataclass
class Incident:
    """Correlated attack chain detected across multiple events

    Represents a meaningful security incident - a sequence of events
    that together tell an attack story (e.g., brute force → compromise → persistence).

    Attributes:
        incident_id: Unique identifier for this incident
        device_id: Device where incident occurred
        severity: How serious this incident is
        tactics: MITRE ATT&CK tactics involved (list of TA#### codes)
        techniques: MITRE ATT&CK techniques involved (list of T#### codes)
        rule_name: Which correlation rule fired
        summary: Human-readable description
        start_ts: When the incident started (earliest event)
        end_ts: When the incident ended (latest event)
        event_ids: List of TelemetryEvent IDs involved
        metadata: Additional context (user, source IP, commands, etc.)
        created_at: When this incident was first detected
    """

    incident_id: str
    device_id: str
    severity: Severity
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    rule_name: str = ""
    summary: str = ""
    start_ts: Optional[datetime] = None
    end_ts: Optional[datetime] = None
    event_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "incident_id": self.incident_id,
            "device_id": self.device_id,
            "severity": self.severity.value,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "rule_name": self.rule_name,
            "summary": self.summary,
            "start_ts": self.start_ts.isoformat() if self.start_ts else None,
            "end_ts": self.end_ts.isoformat() if self.end_ts else None,
            "event_ids": self.event_ids,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    def add_event(self, event_id: str, event_ts: datetime) -> None:
        """Add event to this incident and update time bounds

        Args:
            event_id: Event identifier to add
            event_ts: Timestamp of the event
        """
        if event_id not in self.event_ids:
            self.event_ids.append(event_id)

        if self.start_ts is None or event_ts < self.start_ts:
            self.start_ts = event_ts

        if self.end_ts is None or event_ts > self.end_ts:
            self.end_ts = event_ts


@dataclass
class TelemetryEventView:
    """Normalized view of a TelemetryEvent for correlation

    Extracts relevant fields from protobuf TelemetryEvent into
    a simpler Python structure for rule evaluation.

    Attributes:
        event_id: Unique event identifier
        device_id: Device that generated this event
        event_type: Type of event (SECURITY, AUDIT, PROCESS, FLOW, etc.)
        severity: Event severity
        timestamp: When the event occurred
        attributes: Key-value attributes from the event

        # Typed event bodies (only one will be populated)
        security_event: SecurityEvent details (auth, privilege escalation)
        audit_event: AuditEvent details (persistence changes)
        process_event: ProcessEvent details (new processes)
        flow_event: FlowEvent details (network connections)
    """

    event_id: str
    device_id: str
    event_type: str  # SECURITY, AUDIT, PROCESS, FLOW, METRIC
    severity: str
    timestamp: datetime
    attributes: Dict[str, str] = field(default_factory=dict)

    # Typed event bodies
    security_event: Optional[Dict] = None  # auth_type, result, user, source_ip, etc.
    audit_event: Optional[Dict] = None  # audit_category, action, object_type, etc.
    process_event: Optional[Dict] = None  # process_name, pid, ppid, etc.
    flow_event: Optional[Dict] = None  # src_ip, dst_ip, dst_port, protocol, etc.

    @classmethod
    def from_protobuf(cls, pb_event: Any, device_id: str) -> "TelemetryEventView":
        """Create TelemetryEventView from protobuf TelemetryEvent

        Args:
            pb_event: TelemetryEvent protobuf message
            device_id: Device ID from parent DeviceTelemetry

        Returns:
            TelemetryEventView instance
        """
        timestamp = datetime.fromtimestamp(pb_event.event_timestamp_ns / 1e9)

        # Extract attributes
        attributes = dict(pb_event.attributes) if pb_event.attributes else {}

        # Extract typed event body
        security_event = None
        audit_event = None
        process_event = None
        flow_event = None

        if pb_event.event_type == "SECURITY" and pb_event.HasField("security_event"):
            se = pb_event.security_event
            security_event = {
                "event_category": se.event_category,
                "event_action": se.event_action,
                "event_outcome": se.event_outcome,
                "user_name": se.user_name,
                "source_ip": se.source_ip,
                "risk_score": se.risk_score,
                "mitre_techniques": list(se.mitre_techniques),
                "requires_investigation": se.requires_investigation,
            }

        elif pb_event.event_type == "AUDIT" and pb_event.HasField("audit_event"):
            ae = pb_event.audit_event
            audit_event = {
                "audit_category": ae.audit_category,
                "action_performed": ae.action_performed,
                "object_type": ae.object_type,
                "object_id": ae.object_id,
                "before_value": ae.before_value,
                "after_value": ae.after_value,
            }

        elif pb_event.event_type == "PROCESS" and pb_event.HasField("process_event"):
            pe = pb_event.process_event
            process_event = {
                "process_name": pe.process_name,
                "pid": pe.pid,
                "ppid": pe.ppid,
                "uid": pe.uid,
                "command_line": pe.command_line,
                "executable_path": pe.executable_path,
            }

        elif pb_event.event_type == "FLOW" and pb_event.HasField("flow_event"):
            fe = pb_event.flow_event
            flow_event = {
                "src_ip": fe.src_ip,
                "src_port": fe.src_port,
                "dst_ip": fe.dst_ip,
                "dst_port": fe.dst_port,
                "protocol": fe.protocol,
                "bytes_sent": fe.bytes_sent,
                "bytes_received": fe.bytes_received,
            }

        return cls(
            event_id=pb_event.event_id,
            device_id=device_id,
            event_type=pb_event.event_type,
            severity=pb_event.severity,
            timestamp=timestamp,
            attributes=attributes,
            security_event=security_event,
            audit_event=audit_event,
            process_event=process_event,
            flow_event=flow_event,
        )
