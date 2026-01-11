"""Type definitions for ProtocolCollectors agent."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ProtocolType(str, Enum):
    """Supported protocol types."""
    HTTP = "http"
    HTTPS = "https"
    TLS = "tls"
    SSH = "ssh"
    DNS = "dns"
    SQL = "sql"
    RDP = "rdp"
    FTP = "ftp"
    SMTP = "smtp"
    IRC = "irc"
    P2P = "p2p"
    UNKNOWN = "unknown"


class ThreatCategory(str, Enum):
    """Protocol threat categories mapped to MITRE ATT&CK."""
    HTTP_SUSPICIOUS = "http_suspicious"           # T1071.001
    TLS_ANOMALY = "tls_anomaly"                   # T1573.002
    SSH_BRUTE_FORCE = "ssh_brute_force"           # T1110, T1021.004
    DNS_TUNNELING = "dns_tunneling"               # T1048.003
    SQL_INJECTION = "sql_injection"               # T1190
    RDP_SUSPICIOUS = "rdp_suspicious"             # T1021.001
    FTP_CLEARTEXT = "ftp_cleartext"               # T1552.001
    SMTP_SPAM_PHISH = "smtp_spam_phish"           # T1566.001
    IRC_P2P_C2 = "irc_p2p_c2"                     # T1071.001
    PROTOCOL_ANOMALY = "protocol_anomaly"         # T1205


@dataclass
class ProtocolEvent:
    """Represents a protocol-level event for analysis.
    
    Attributes:
        timestamp: When the event occurred
        protocol: Protocol type (http, dns, ssh, etc.)
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port
        dst_port: Destination port
        payload_size: Size of payload in bytes
        flags: Protocol-specific flags
        metadata: Additional protocol-specific metadata
        raw_data: Raw event data for debugging
    """
    timestamp: datetime
    protocol: ProtocolType
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload_size: int = 0
    flags: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "protocol": self.protocol.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "payload_size": self.payload_size,
            "flags": self.flags,
            "metadata": self.metadata,
        }


@dataclass  
class ProtocolThreat:
    """Represents a detected protocol-level threat.
    
    Attributes:
        category: Threat category
        severity: Severity level (1-10)
        confidence: Detection confidence (0.0-1.0)
        description: Human-readable description
        mitre_techniques: List of MITRE ATT&CK technique IDs
        source_event: Original event that triggered detection
        indicators: Specific indicators of compromise
    """
    category: ThreatCategory
    severity: int
    confidence: float
    description: str
    mitre_techniques: List[str]
    source_event: ProtocolEvent
    indicators: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "category": self.category.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
            "source_event": self.source_event.to_dict(),
            "indicators": self.indicators,
        }
