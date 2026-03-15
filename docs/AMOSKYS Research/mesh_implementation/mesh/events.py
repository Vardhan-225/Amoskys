"""
SecurityEvent — the atomic unit of communication in the Agent Mesh.

Every mesh event has:
  - event_type: what happened (enum)
  - source_agent: who detected it (string)
  - severity: how serious (enum)
  - payload: structured data (dict)
  - timestamp_ns: when (nanoseconds since epoch)
  - event_id: unique identifier (uuid)
  - signature: Ed25519 signature (bytes, optional)
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class EventType(str, enum.Enum):
    """Types of events that flow through the Agent Mesh."""

    # Detection events (published by Observatory agents)
    SUSPICIOUS_DOMAIN = "suspicious_domain"
    BEACONING_DETECTED = "beaconing_detected"
    CREDENTIAL_FILE_ACCESS = "credential_file_access"
    SUSPICIOUS_PROCESS = "suspicious_process"
    OUTBOUND_EXFIL_ATTEMPT = "outbound_exfil_attempt"
    STAGING_ARCHIVE = "staging_archive"
    CLEANUP_DETECTED = "cleanup_detected"
    AUTH_ANOMALY = "auth_anomaly"
    PERSISTENCE_INSTALLED = "persistence_installed"

    # Correlation events (published by KillChainTracker / FusionEngine)
    KILL_CHAIN_ESCALATION = "kill_chain_escalation"
    FUSION_INCIDENT = "fusion_incident"

    # Directive events (published by IGRIS Orchestrator)
    DIRECTED_WATCH = "directed_watch"
    ADAPTIVE_MODE_CHANGE = "adaptive_mode_change"

    # Action events (published by ActionExecutor)
    ACTION_TAKEN = "action_taken"
    ACTION_FAILED = "action_failed"

    # System events
    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"
    MESH_HEARTBEAT = "mesh_heartbeat"


class Severity(str, enum.Enum):
    """Event severity levels, aligned with the confidence ladder."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> float:
        """Numeric value for comparison and scoring."""
        return {
            "info": 0.0,
            "low": 0.3,
            "medium": 0.5,
            "high": 0.7,
            "critical": 0.9,
        }[self.value]


@dataclass
class SecurityEvent:
    """Atomic unit of communication in the Agent Mesh.

    Immutable after creation. Signed for forensic integrity.
    """

    event_type: EventType
    source_agent: str
    severity: Severity = Severity.INFO
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp_ns: int = field(default_factory=lambda: time.time_ns())
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    signature: Optional[bytes] = None

    # Optional correlation fields
    related_pid: Optional[int] = None
    related_ip: Optional[str] = None
    related_domain: Optional[str] = None
    related_path: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage and transport."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "source_agent": self.source_agent,
            "severity": self.severity.value,
            "payload": self.payload,
            "timestamp_ns": self.timestamp_ns,
            "related_pid": self.related_pid,
            "related_ip": self.related_ip,
            "related_domain": self.related_domain,
            "related_path": self.related_path,
            "mitre_technique": self.mitre_technique,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityEvent:
        """Deserialize from storage."""
        return cls(
            event_id=data["event_id"],
            event_type=EventType(data["event_type"]),
            source_agent=data["source_agent"],
            severity=Severity(data["severity"]),
            payload=data.get("payload", {}),
            timestamp_ns=data.get("timestamp_ns", time.time_ns()),
            related_pid=data.get("related_pid"),
            related_ip=data.get("related_ip"),
            related_domain=data.get("related_domain"),
            related_path=data.get("related_path"),
            mitre_technique=data.get("mitre_technique"),
            confidence=data.get("confidence", 0.0),
        )

    def __str__(self) -> str:
        parts = [
            f"[{self.severity.value.upper()}]",
            f"{self.event_type.value}",
            f"from={self.source_agent}",
        ]
        if self.related_pid:
            parts.append(f"pid={self.related_pid}")
        if self.related_ip:
            parts.append(f"ip={self.related_ip}")
        if self.related_domain:
            parts.append(f"domain={self.related_domain}")
        if self.mitre_technique:
            parts.append(f"mitre={self.mitre_technique}")
        return " ".join(parts)
