"""Unit tests for ProtocolCollectorsV2 agent and protocol collector components.

Tests cover:
    - ProtocolType and ThreatCategory enum types
    - ProtocolEvent and ProtocolThreat data structures
    - NetworkLogCollector log parsing and rotation handling
    - StubProtocolCollector event generation
    - create_protocol_collector factory function
    - All 10 micro-probes with crafted protocol events
    - create_protocol_collector_probes factory
    - ProtocolCollectorsV2 agent initialization, setup, collect_data cycle
    - Health metrics and probe management
    - Error handling for missing files and permission errors
    - Probe error isolation and independence
"""

import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List
from unittest.mock import MagicMock, Mock, patch

import pytest

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.protocol_collectors.collector import (
    BaseProtocolCollector,
    NetworkLogCollector,
    StubProtocolCollector,
    create_protocol_collector,
)
from amoskys.agents.protocol_collectors.probes import (
    PROTOCOL_PROBES,
    DNSTunnelingProbe,
    FTPCleartextCredsProbe,
    HTTPSuspiciousHeadersProbe,
    IRCP2PC2Probe,
    ProtocolAnomalyProbe,
    RDPSuspiciousProbe,
    SMTPSpamPhishProbe,
    SQLInjectionProbe,
    SSHBruteForceProbe,
    TLSSSLAnomalyProbe,
    create_protocol_collector_probes,
)
from amoskys.agents.protocol_collectors.protocol_collectors_v2 import (
    ProtocolCollectorsV2,
    create_protocol_collectors,
)
from amoskys.agents.protocol_collectors.agent_types import (
    ProtocolEvent,
    ProtocolThreat,
    ProtocolType,
    ThreatCategory,
)

# =============================================================================
# Helpers
# =============================================================================


def _make_protocol_event(**overrides) -> ProtocolEvent:
    """Helper: create ProtocolEvent with sensible defaults."""
    defaults = dict(
        timestamp=datetime.now(),
        protocol=ProtocolType.HTTP,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=80,
        payload_size=0,
        metadata={},
        raw_data=None,
    )
    defaults.update(overrides)
    return ProtocolEvent(**defaults)


def _make_context(protocol_events: List[ProtocolEvent] = None) -> ProbeContext:
    """Helper: create ProbeContext with protocol events in shared_data."""
    return ProbeContext(
        device_id="host-001",
        agent_name="protocol_collectors",
        shared_data={"protocol_events": protocol_events or []},
    )


# =============================================================================
# Test: ProtocolType and ThreatCategory Enums
# =============================================================================


class TestProtocolType:
    """Test ProtocolType enum values and behavior."""

    def test_all_protocol_values(self):
        """Verify all expected protocol types exist."""
        expected = {
            "http",
            "https",
            "tls",
            "ssh",
            "dns",
            "sql",
            "rdp",
            "ftp",
            "smtp",
            "irc",
            "p2p",
            "unknown",
        }
        actual = {pt.value for pt in ProtocolType}
        assert expected == actual

    def test_string_enum_behavior(self):
        """ProtocolType is a str enum and can be compared to strings."""
        assert ProtocolType.HTTP == "http"
        assert ProtocolType.SSH == "ssh"
        assert ProtocolType.UNKNOWN == "unknown"

    def test_protocol_type_from_value(self):
        """Verify ProtocolType can be constructed from value."""
        assert ProtocolType("http") is ProtocolType.HTTP
        assert ProtocolType("dns") is ProtocolType.DNS


class TestThreatCategory:
    """Test ThreatCategory enum values."""

    def test_all_threat_categories(self):
        """Verify all threat categories exist."""
        expected = {
            "http_suspicious",
            "tls_anomaly",
            "ssh_brute_force",
            "dns_tunneling",
            "sql_injection",
            "rdp_suspicious",
            "ftp_cleartext",
            "smtp_spam_phish",
            "irc_p2p_c2",
            "protocol_anomaly",
        }
        actual = {tc.value for tc in ThreatCategory}
        assert expected == actual


# =============================================================================
# Test: ProtocolEvent and ProtocolThreat Data Structures
# =============================================================================


class TestProtocolEvent:
    """Test ProtocolEvent dataclass."""

    def test_basic_creation(self):
        """Test creating a ProtocolEvent with required fields."""
        pe = _make_protocol_event()
        assert pe.protocol == ProtocolType.HTTP
        assert pe.src_ip == "192.168.1.10"
        assert pe.dst_ip == "10.0.0.1"
        assert pe.src_port == 50000
        assert pe.dst_port == 80

    def test_default_fields(self):
        """Test default values for optional fields."""
        pe = _make_protocol_event()
        assert pe.payload_size == 0
        assert pe.flags == {}
        assert pe.metadata == {}
        assert pe.raw_data is None

    def test_to_dict(self):
        """Test ProtocolEvent serialization."""
        pe = _make_protocol_event(
            protocol=ProtocolType.SSH,
            src_port=22,
            metadata={"auth_result": "failed"},
        )
        d = pe.to_dict()
        assert d["protocol"] == "ssh"
        assert d["src_ip"] == "192.168.1.10"
        assert d["dst_ip"] == "10.0.0.1"
        assert d["metadata"] == {"auth_result": "failed"}
        assert "timestamp" in d
        assert isinstance(d["timestamp"], str)

    def test_with_metadata_and_raw_data(self):
        """Test creating event with metadata and raw data."""
        pe = _make_protocol_event(
            metadata={"user_agent": "curl/7.64"},
            raw_data="GET /index.html HTTP/1.1",
        )
        assert pe.metadata["user_agent"] == "curl/7.64"
        assert pe.raw_data == "GET /index.html HTTP/1.1"


class TestProtocolThreat:
    """Test ProtocolThreat dataclass."""

    def test_basic_creation(self):
        """Test ProtocolThreat instantiation and to_dict."""
        source_event = _make_protocol_event()
        threat = ProtocolThreat(
            category=ThreatCategory.SSH_BRUTE_FORCE,
            severity=8,
            confidence=0.95,
            description="SSH brute force from 192.168.1.10",
            mitre_techniques=["T1110"],
            source_event=source_event,
            indicators={"failed_count": 20},
        )
        assert threat.category == ThreatCategory.SSH_BRUTE_FORCE
        assert threat.severity == 8
        assert threat.confidence == 0.95

        d = threat.to_dict()
        assert d["category"] == "ssh_brute_force"
        assert d["severity"] == 8
        assert d["mitre_techniques"] == ["T1110"]
        assert d["indicators"]["failed_count"] == 20
        assert "source_event" in d


# =============================================================================
# Test: NetworkLogCollector
# =============================================================================


class TestNetworkLogCollector:
    """Test log-based protocol event collection."""

    def test_init_defaults(self):
        """Test default initialization."""
        collector = NetworkLogCollector()
        assert collector.log_path == "/var/log/syslog"
        assert collector.tail_lines == 1000
        assert collector._last_position == 0
        assert collector._last_inode == 0

    def test_init_custom_params(self):
        """Test custom initialization."""
        collector = NetworkLogCollector(
            log_path="/tmp/test.log",
            tail_lines=500,
        )
        assert collector.log_path == "/tmp/test.log"
        assert collector.tail_lines == 500

    def test_collect_missing_file(self):
        """Collector returns empty list for nonexistent log file."""
        collector = NetworkLogCollector(log_path="/nonexistent/path/log.txt")
        events = collector.collect()
        assert events == []

    def test_collect_empty_file(self, tmp_path):
        """Collector returns empty list for empty log file."""
        log_file = tmp_path / "empty.log"
        log_file.write_text("")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()
        assert events == []

    def test_collect_ssh_log_lines(self, tmp_path):
        """Collector parses SSH log lines into ProtocolEvents."""
        log_file = tmp_path / "syslog"
        log_file.write_text(
            "Dec 10 10:00:01 host sshd[1234]: Failed password for root from 192.168.1.5 port 22\n"
            "Dec 10 10:00:02 host sshd[1234]: Accepted publickey for admin from 10.0.0.1 port 22\n"
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 2
        assert all(e.protocol == ProtocolType.SSH for e in events)
        # First event should have failed auth
        assert events[0].metadata.get("auth_result") == "failed"
        # Second event should have accepted auth
        assert events[1].metadata.get("auth_result") == "accepted"

    def test_collect_http_log_lines(self, tmp_path):
        """Collector parses HTTP log lines."""
        log_file = tmp_path / "access.log"
        log_file.write_text(
            '10.0.0.5 - - [10/Dec/2025] "GET /api HTTP/1.1" 200 1234\n'
            '10.0.0.6 - - [10/Dec/2025] "POST /login HTTPS/1.1" 401 56\n'
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 2
        # First is HTTP (no "https" keyword)
        assert events[0].protocol == ProtocolType.HTTP
        assert events[0].metadata.get("method") == "GET"
        assert events[0].metadata.get("status_code") == 200
        # Second has HTTPS keyword
        assert events[1].protocol == ProtocolType.HTTPS
        assert events[1].metadata.get("method") == "POST"
        assert events[1].metadata.get("status_code") == 401

    def test_collect_dns_log_lines(self, tmp_path):
        """Collector parses DNS log lines."""
        log_file = tmp_path / "dns.log"
        # Use " A " (space-delimited query type) format that _extract_metadata matches
        log_file.write_text(
            "query dns 192.168.1.50:53000 -> 8.8.8.8:53 A example.com\n"
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.DNS
        assert events[0].metadata.get("query_type") == "A"

    def test_collect_smtp_log_lines(self, tmp_path):
        """Collector parses SMTP log lines."""
        log_file = tmp_path / "mail.log"
        log_file.write_text(
            "postfix/smtp[999]: connect from 172.16.0.1:40000 to 10.0.0.25:25\n"
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.SMTP

    def test_collect_ftp_log_lines(self, tmp_path):
        """Collector parses FTP log lines."""
        log_file = tmp_path / "ftp.log"
        log_file.write_text(
            "vsftpd: connection from 192.168.2.1:55000 to 10.0.0.21:21\n"
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.FTP

    def test_collect_rdp_log_lines(self, tmp_path):
        """Collector parses RDP log lines."""
        log_file = tmp_path / "rdp.log"
        log_file.write_text("rdp session from 203.0.113.5:60000 to 10.0.0.50:3389\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.RDP

    def test_collect_sql_mysql_log_lines(self, tmp_path):
        """Collector parses MySQL log lines."""
        log_file = tmp_path / "mysql.log"
        log_file.write_text(
            "mysql connection from 192.168.1.10:45000 to 10.0.0.5:3306\n"
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.SQL

    def test_collect_sql_postgres_log_lines(self, tmp_path):
        """Collector parses PostgreSQL log lines."""
        log_file = tmp_path / "pg.log"
        log_file.write_text(
            "postgres connection from 192.168.1.10:45000 to 10.0.0.5:5432\n"
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.SQL

    def test_collect_irc_log_lines(self, tmp_path):
        """Collector parses IRC log lines."""
        log_file = tmp_path / "irc.log"
        log_file.write_text("irc connection from 192.168.1.100:40000 to 1.2.3.4:6667\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.IRC

    def test_collect_tls_log_lines(self, tmp_path):
        """Collector parses TLS/SSL log lines."""
        log_file = tmp_path / "tls.log"
        log_file.write_text("tls handshake from 192.168.1.10:55000 to 10.0.0.1:443\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()

        assert len(events) == 1
        assert events[0].protocol == ProtocolType.TLS

    def test_collect_unknown_protocol_skipped(self, tmp_path):
        """Lines with unknown protocol are skipped."""
        log_file = tmp_path / "unknown.log"
        log_file.write_text(
            "some random line with no protocol markers at all\n"
            "another generic line with just numbers 123 456\n"
        )
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()
        assert events == []

    def test_collect_empty_lines_skipped(self, tmp_path):
        """Empty lines are skipped."""
        log_file = tmp_path / "mixed.log"
        log_file.write_text("\n" "sshd failed from 192.168.1.1 port 22\n" "\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()
        assert len(events) == 1

    def test_collect_truncates_raw_data(self, tmp_path):
        """Raw data is truncated to 500 chars."""
        long_line = "ssh " + "A" * 600 + " from 192.168.1.1 port 22"
        log_file = tmp_path / "long.log"
        log_file.write_text(long_line + "\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()
        assert len(events) == 1
        assert len(events[0].raw_data) == 500

    def test_collect_incremental_reading(self, tmp_path):
        """Collector tracks file position for incremental reads."""
        log_file = tmp_path / "incremental.log"
        log_file.write_text("sshd connection from 1.2.3.4 port 22\n")

        collector = NetworkLogCollector(log_path=str(log_file))

        # First collect should get 1 event
        events1 = collector.collect()
        assert len(events1) == 1

        # Second collect with no new data should get 0 events
        events2 = collector.collect()
        assert len(events2) == 0

        # Append new data
        with open(str(log_file), "a") as f:
            f.write("sshd connection from 5.6.7.8 port 22\n")

        # Third collect should get 1 new event
        events3 = collector.collect()
        assert len(events3) == 1

    def test_collect_handles_log_rotation(self, tmp_path):
        """Collector resets position on inode change (log rotation)."""
        log_file = tmp_path / "rotate.log"
        log_file.write_text("ssh login from 1.2.3.4 port 22\n")

        collector = NetworkLogCollector(log_path=str(log_file))
        events1 = collector.collect()
        assert len(events1) == 1

        # Simulate log rotation: delete and recreate
        os.unlink(str(log_file))
        log_file.write_text("ssh login from 5.6.7.8 port 22\n")

        events2 = collector.collect()
        assert len(events2) == 1

    def test_collect_permission_error(self, tmp_path):
        """Collector handles PermissionError gracefully."""
        log_file = tmp_path / "protected.log"
        log_file.write_text("ssh from 1.2.3.4 port 22\n")

        collector = NetworkLogCollector(log_path=str(log_file))
        with patch("builtins.open", side_effect=PermissionError("denied")):
            # Need to also patch os.stat and os.path.exists
            with patch("os.path.exists", return_value=True):
                with patch("os.stat") as mock_stat:
                    mock_stat.return_value.st_ino = 12345
                    events = collector.collect()
                    assert events == []

    def test_collect_general_exception(self, tmp_path):
        """Collector handles unexpected exceptions gracefully."""
        collector = NetworkLogCollector(log_path=str(tmp_path / "exists.log"))
        with patch("os.path.exists", return_value=True):
            with patch("os.stat", side_effect=OSError("disk error")):
                events = collector.collect()
                assert events == []

    def test_detect_protocol_ssh_keywords(self):
        """Test SSH detection by keyword."""
        collector = NetworkLogCollector()
        assert collector._detect_protocol("sshd[1234]: connection") == ProtocolType.SSH
        assert collector._detect_protocol("SSH session opened") == ProtocolType.SSH

    def test_detect_protocol_https_before_http(self):
        """HTTPS should be detected before HTTP when both present."""
        collector = NetworkLogCollector()
        assert (
            collector._detect_protocol("HTTPS request to server") == ProtocolType.HTTPS
        )
        assert collector._detect_protocol("HTTP GET /index.html") == ProtocolType.HTTP

    def test_detect_protocol_dns_by_port(self):
        """DNS detected by port :53."""
        collector = NetworkLogCollector()
        assert (
            collector._detect_protocol("connection to 8.8.8.8:53") == ProtocolType.DNS
        )

    def test_detect_protocol_smtp_by_port(self):
        """SMTP detected by port :25 or :587."""
        collector = NetworkLogCollector()
        assert collector._detect_protocol("connection to mail:25") == ProtocolType.SMTP
        assert collector._detect_protocol("connection to mail:587") == ProtocolType.SMTP

    def test_detect_protocol_ftp_by_port(self):
        """FTP detected by port :21."""
        collector = NetworkLogCollector()
        assert collector._detect_protocol("connection to server:21") == ProtocolType.FTP

    def test_detect_protocol_rdp_by_port(self):
        """RDP detected by port :3389."""
        collector = NetworkLogCollector()
        assert (
            collector._detect_protocol("connection to server:3389") == ProtocolType.RDP
        )

    def test_detect_protocol_sql_mysql_by_port(self):
        """SQL detected by MySQL port :3306."""
        collector = NetworkLogCollector()
        assert collector._detect_protocol("connection to db:3306") == ProtocolType.SQL

    def test_detect_protocol_sql_postgres_by_port(self):
        """SQL detected by Postgres port :5432."""
        collector = NetworkLogCollector()
        assert collector._detect_protocol("connection to db:5432") == ProtocolType.SQL

    def test_detect_protocol_irc_by_port(self):
        """IRC detected by port :6667."""
        collector = NetworkLogCollector()
        assert (
            collector._detect_protocol("connection to server:6667") == ProtocolType.IRC
        )

    def test_detect_protocol_tls_ssl(self):
        """TLS/SSL detected by keywords."""
        collector = NetworkLogCollector()
        assert collector._detect_protocol("TLS handshake complete") == ProtocolType.TLS
        assert collector._detect_protocol("SSL certificate error") == ProtocolType.TLS

    def test_detect_protocol_unknown(self):
        """Unknown protocol for unrecognized lines."""
        collector = NetworkLogCollector()
        assert collector._detect_protocol("just a random line") == ProtocolType.UNKNOWN

    def test_extract_metadata_ssh_invalid_user(self):
        """SSH metadata extracts invalid user flag."""
        collector = NetworkLogCollector()
        meta = collector._extract_metadata(
            "invalid user attacker from 1.2.3.4", ProtocolType.SSH
        )
        assert meta.get("invalid_user") is True

    def test_extract_metadata_http_methods(self):
        """HTTP metadata extracts method and status."""
        collector = NetworkLogCollector()
        meta = collector._extract_metadata("GET /api/v1 200 OK", ProtocolType.HTTP)
        assert meta.get("method") == "GET"
        assert meta.get("status_code") == 200

    def test_extract_metadata_dns_query_types(self):
        """DNS metadata extracts query types."""
        collector = NetworkLogCollector()
        for qtype in ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "PTR"]:
            meta = collector._extract_metadata(
                f"query {qtype} example.com", ProtocolType.DNS
            )
            assert meta.get("query_type") == qtype

    def test_ip_extraction_from_log_line(self, tmp_path):
        """IP addresses are correctly extracted from log lines."""
        log_file = tmp_path / "ip.log"
        log_file.write_text("sshd: from 10.20.30.40:12345 to 192.168.0.1:22\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()
        assert len(events) == 1
        assert events[0].src_ip == "10.20.30.40"
        assert events[0].dst_ip == "192.168.0.1"

    def test_ip_extraction_single_ip(self, tmp_path):
        """Single IP defaults dst_ip to 0.0.0.0."""
        log_file = tmp_path / "single_ip.log"
        log_file.write_text("sshd: connection from 10.20.30.40\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()
        assert len(events) == 1
        assert events[0].src_ip == "10.20.30.40"
        assert events[0].dst_ip == "0.0.0.0"

    def test_port_extraction_single_port(self, tmp_path):
        """Single port defaults dst_port to 0."""
        log_file = tmp_path / "single_port.log"
        log_file.write_text("ssh from 10.0.0.1:22\n")
        collector = NetworkLogCollector(log_path=str(log_file))
        events = collector.collect()
        assert len(events) == 1
        assert events[0].src_port == 22
        assert events[0].dst_port == 0


# =============================================================================
# Test: StubProtocolCollector
# =============================================================================


class TestStubProtocolCollector:
    """Test stub/simulated protocol event generation."""

    def test_init_defaults(self):
        """Test default stub initialization."""
        stub = StubProtocolCollector()
        assert stub.events_per_cycle == 5
        assert stub._cycle_count == 0

    def test_init_custom_count(self):
        """Test custom events per cycle."""
        stub = StubProtocolCollector(events_per_cycle=10)
        assert stub.events_per_cycle == 10

    def test_collect_returns_correct_count(self):
        """collect() returns events_per_cycle events."""
        stub = StubProtocolCollector(events_per_cycle=5)
        events = stub.collect()
        assert len(events) == 5

    def test_collect_increments_cycle(self):
        """collect() increments cycle count."""
        stub = StubProtocolCollector()
        stub.collect()
        assert stub._cycle_count == 1
        stub.collect()
        assert stub._cycle_count == 2

    def test_collect_generates_varied_protocols(self):
        """collect() generates events for multiple protocol types."""
        stub = StubProtocolCollector(events_per_cycle=5)
        events = stub.collect()
        protocols = {e.protocol for e in events}
        # Should have SSH, HTTP, DNS, SMTP, FTP
        assert ProtocolType.SSH in protocols
        assert ProtocolType.HTTP in protocols
        assert ProtocolType.DNS in protocols
        assert ProtocolType.SMTP in protocols
        assert ProtocolType.FTP in protocols

    def test_collect_events_have_valid_structure(self):
        """All generated events have valid ProtocolEvent fields."""
        stub = StubProtocolCollector(events_per_cycle=10)
        events = stub.collect()
        for e in events:
            assert isinstance(e, ProtocolEvent)
            assert isinstance(e.timestamp, datetime)
            assert isinstance(e.protocol, ProtocolType)
            assert isinstance(e.src_ip, str) and len(e.src_ip) > 0
            assert isinstance(e.dst_ip, str) and len(e.dst_ip) > 0
            assert isinstance(e.src_port, int)
            assert isinstance(e.dst_port, int)
            assert isinstance(e.metadata, dict)

    def test_ssh_event_auth_result(self):
        """SSH events have auth_result metadata."""
        stub = StubProtocolCollector(events_per_cycle=1)
        events = stub.collect()
        ssh_event = events[0]  # First scenario is SSH
        assert ssh_event.protocol == ProtocolType.SSH
        assert "auth_result" in ssh_event.metadata
        assert ssh_event.metadata["auth_result"] in ("failed", "accepted")

    def test_dns_event_query_type(self):
        """DNS events have query_type metadata."""
        stub = StubProtocolCollector(events_per_cycle=5)
        events = stub.collect()
        dns_events = [e for e in events if e.protocol == ProtocolType.DNS]
        assert len(dns_events) >= 1
        assert "query_type" in dns_events[0].metadata

    def test_ftp_event_command(self):
        """FTP events have command metadata."""
        stub = StubProtocolCollector(events_per_cycle=5)
        events = stub.collect()
        ftp_events = [e for e in events if e.protocol == ProtocolType.FTP]
        assert len(ftp_events) >= 1
        assert "command" in ftp_events[0].metadata
        assert ftp_events[0].metadata["command"] in ("RETR", "STOR")

    def test_single_event_cycle(self):
        """Test with events_per_cycle=1."""
        stub = StubProtocolCollector(events_per_cycle=1)
        events = stub.collect()
        assert len(events) == 1
        assert events[0].protocol == ProtocolType.SSH

    def test_more_events_than_scenarios(self):
        """Test with events_per_cycle > number of scenarios (wraps)."""
        stub = StubProtocolCollector(events_per_cycle=12)
        events = stub.collect()
        assert len(events) == 12


# =============================================================================
# Test: create_protocol_collector Factory
# =============================================================================


class TestCreateProtocolCollector:
    """Test factory function for protocol collectors."""

    def test_creates_stub_collector(self):
        """Factory with use_stub=True creates StubProtocolCollector."""
        collector = create_protocol_collector(use_stub=True)
        assert isinstance(collector, StubProtocolCollector)

    def test_creates_network_log_collector(self):
        """Factory with use_stub=False creates NetworkLogCollector."""
        collector = create_protocol_collector(use_stub=False)
        assert isinstance(collector, NetworkLogCollector)

    def test_passes_kwargs_to_stub(self):
        """Factory passes kwargs to StubProtocolCollector."""
        collector = create_protocol_collector(use_stub=True, events_per_cycle=20)
        assert isinstance(collector, StubProtocolCollector)
        assert collector.events_per_cycle == 20

    def test_passes_log_path_to_network(self):
        """Factory passes log_path to NetworkLogCollector."""
        collector = create_protocol_collector(use_stub=False, log_path="/custom/path")
        assert isinstance(collector, NetworkLogCollector)
        assert collector.log_path == "/custom/path"


# =============================================================================
# Test: HTTPSuspiciousHeadersProbe
# =============================================================================


class TestHTTPSuspiciousHeadersProbe:
    """Test HTTP suspicious header detection probe."""

    def test_probe_attributes(self):
        """Verify probe name, description, MITRE techniques."""
        probe = HTTPSuspiciousHeadersProbe()
        assert probe.name == "http_suspicious_headers"
        assert "T1071.001" in probe.mitre_techniques

    def test_no_http_events_returns_empty(self):
        """No HTTP events -> no alerts."""
        probe = HTTPSuspiciousHeadersProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.SSH),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_clean_http_no_alert(self):
        """Normal HTTP event with no suspicious indicators."""
        probe = HTTPSuspiciousHeadersProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    metadata={"user_agent": "Mozilla/5.0"},
                    raw_data="GET /index.html HTTP/1.1",
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_suspicious_user_agent_detected(self):
        """Suspicious user agents trigger alerts."""
        probe = HTTPSuspiciousHeadersProbe()
        for ua in ["python-requests/2.28", "curl/7.64", "nmap/7.92", "sqlmap/1.6"]:
            context = _make_context(
                [
                    _make_protocol_event(
                        protocol=ProtocolType.HTTP,
                        metadata={"user_agent": ua},
                    ),
                ]
            )
            events = probe.scan(context)
            assert len(events) == 1, f"Expected alert for user agent: {ua}"
            assert events[0].event_type == "protocol_threat"
            assert events[0].severity == Severity.MEDIUM
            assert any(
                "suspicious_user_agent" in i for i in events[0].data["indicators"]
            )

    def test_base64_in_headers_detected(self):
        """Base64-encoded content in headers triggers alert."""
        probe = HTTPSuspiciousHeadersProbe()
        long_b64 = "A" * 60  # 60 chars of [A-Za-z0-9+/]
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data=f"Authorization: Bearer {long_b64}",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert "base64_in_headers" in events[0].data["indicators"]

    def test_header_injection_detected(self):
        """Header injection (CRLF) triggers alert."""
        probe = HTTPSuspiciousHeadersProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="X-Forwarded-For: 1.2.3.4\\r\\nInjected: value",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert "header_injection_attempt" in events[0].data["indicators"]

    def test_header_injection_url_encoded(self):
        """URL-encoded CRLF triggers alert."""
        probe = HTTPSuspiciousHeadersProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="X-Forwarded-For: 1.2.3.4%0d%0aInjected: value",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert "header_injection_attempt" in events[0].data["indicators"]

    def test_https_events_also_scanned(self):
        """HTTPS events are also scanned for suspicious headers."""
        probe = HTTPSuspiciousHeadersProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTPS,
                    metadata={"user_agent": "python-requests/2.28"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_contains_base64_short_string(self):
        """Short strings are not flagged as base64."""
        probe = HTTPSuspiciousHeadersProbe()
        assert probe._contains_base64("short") is False

    def test_contains_base64_long_encoded(self):
        """Long base64-like strings are detected."""
        probe = HTTPSuspiciousHeadersProbe()
        assert probe._contains_base64("A" * 60) is True

    def test_empty_protocol_events(self):
        """Empty protocol events list produces no alerts."""
        probe = HTTPSuspiciousHeadersProbe()
        context = _make_context([])
        events = probe.scan(context)
        assert events == []

    def test_null_raw_data_and_user_agent(self):
        """Events with no raw_data or user_agent don't crash."""
        probe = HTTPSuspiciousHeadersProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    metadata={},
                    raw_data=None,
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []


# =============================================================================
# Test: TLSSSLAnomalyProbe
# =============================================================================


class TestTLSSSLAnomalyProbe:
    """Test TLS/SSL anomaly detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = TLSSSLAnomalyProbe()
        assert probe.name == "tls_ssl_anomaly"
        assert "T1573.002" in probe.mitre_techniques

    def test_clean_tls_no_alert(self):
        """Modern TLS with strong cipher produces no alert."""
        probe = TLSSSLAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.TLS,
                    metadata={
                        "tls_version": "TLSv1.3",
                        "cipher_suite": "TLS_AES_256_GCM_SHA384",
                    },
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_old_tls_version_detected(self):
        """Old TLS versions trigger alert."""
        probe = TLSSSLAnomalyProbe()
        for version in ["SSLv2", "SSLv3", "TLSv1.0"]:
            context = _make_context(
                [
                    _make_protocol_event(
                        protocol=ProtocolType.TLS,
                        metadata={"tls_version": version},
                    ),
                ]
            )
            events = probe.scan(context)
            assert len(events) == 1, f"Expected alert for {version}"
            assert any(
                f"old_tls_version:{version}" in a for a in events[0].data["anomalies"]
            )

    def test_weak_cipher_detected(self):
        """Weak ciphers trigger alert."""
        probe = TLSSSLAnomalyProbe()
        for cipher in ["RC4-SHA", "DES-CBC-SHA", "NULL-SHA", "EXPORT-AES128"]:
            context = _make_context(
                [
                    _make_protocol_event(
                        protocol=ProtocolType.TLS,
                        metadata={"cipher_suite": cipher},
                    ),
                ]
            )
            events = probe.scan(context)
            assert len(events) >= 1, f"Expected alert for cipher: {cipher}"

    def test_self_signed_cert_detected(self):
        """Self-signed certificate triggers alert."""
        probe = TLSSSLAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.TLS,
                    metadata={"self_signed": True},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert "self_signed_cert" in events[0].data["anomalies"]

    def test_expired_cert_detected(self):
        """Expired certificate triggers alert."""
        probe = TLSSSLAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.TLS,
                    metadata={"cert_expired": True},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert "expired_cert" in events[0].data["anomalies"]

    def test_https_events_also_scanned(self):
        """HTTPS events are scanned for TLS anomalies."""
        probe = TLSSSLAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTPS,
                    metadata={"tls_version": "SSLv3"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_non_tls_events_ignored(self):
        """Non-TLS/HTTPS events are skipped."""
        probe = TLSSSLAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.SSH),
                _make_protocol_event(protocol=ProtocolType.HTTP),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_multiple_anomalies_single_event(self):
        """Multiple anomalies on one event produce one alert with all anomalies."""
        probe = TLSSSLAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.TLS,
                    metadata={
                        "tls_version": "SSLv2",
                        "cipher_suite": "RC4-SHA",
                        "self_signed": True,
                        "cert_expired": True,
                    },
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        anomalies = events[0].data["anomalies"]
        assert any("old_tls_version" in a for a in anomalies)
        assert any("weak_cipher" in a for a in anomalies)
        assert "self_signed_cert" in anomalies
        assert "expired_cert" in anomalies


# =============================================================================
# Test: SSHBruteForceProbe
# =============================================================================


class TestSSHBruteForceProbe:
    """Test SSH brute force detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = SSHBruteForceProbe()
        assert probe.name == "ssh_brute_force"
        assert "T1110" in probe.mitre_techniques
        assert "T1021.004" in probe.mitre_techniques

    def test_no_ssh_events_no_alert(self):
        """No SSH events -> no alert."""
        probe = SSHBruteForceProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.HTTP),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_below_threshold_no_alert(self):
        """Failures below threshold produce no alert."""
        probe = SSHBruteForceProbe()
        # 4 failures (below default threshold of 5)
        pe_list = [
            _make_protocol_event(
                protocol=ProtocolType.SSH,
                src_ip="10.0.0.1",
                metadata={"auth_result": "failed"},
            )
            for _ in range(4)
        ]
        context = _make_context(pe_list)
        events = probe.scan(context)
        assert events == []

    def test_threshold_reached_alert(self):
        """Reaching failure threshold triggers alert."""
        probe = SSHBruteForceProbe()
        pe_list = [
            _make_protocol_event(
                protocol=ProtocolType.SSH,
                src_ip="10.0.0.1",
                metadata={"auth_result": "failed"},
            )
            for _ in range(5)
        ]
        context = _make_context(pe_list)
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert events[0].data["category"] == ThreatCategory.SSH_BRUTE_FORCE.value
        assert events[0].data["failed_count"] >= 5
        assert events[0].data["src_ip"] == "10.0.0.1"

    def test_accepted_auth_no_alert(self):
        """Accepted auth events do not trigger alerts."""
        probe = SSHBruteForceProbe()
        pe_list = [
            _make_protocol_event(
                protocol=ProtocolType.SSH,
                src_ip="10.0.0.1",
                metadata={"auth_result": "accepted"},
            )
            for _ in range(10)
        ]
        context = _make_context(pe_list)
        events = probe.scan(context)
        assert events == []

    def test_different_src_ips_no_alert(self):
        """Failures from different IPs don't accumulate."""
        probe = SSHBruteForceProbe()
        pe_list = [
            _make_protocol_event(
                protocol=ProtocolType.SSH,
                src_ip=f"10.0.0.{i}",
                metadata={"auth_result": "failed"},
            )
            for i in range(5)
        ]
        context = _make_context(pe_list)
        events = probe.scan(context)
        assert events == []

    def test_counter_resets_after_alert(self):
        """Counter resets after alert to prevent repeated alerts."""
        probe = SSHBruteForceProbe()
        pe_list = [
            _make_protocol_event(
                protocol=ProtocolType.SSH,
                src_ip="10.0.0.1",
                metadata={"auth_result": "failed"},
            )
            for _ in range(5)
        ]
        context = _make_context(pe_list)
        events1 = probe.scan(context)
        assert len(events1) == 1

        # Next scan with 1 more failure should NOT alert
        pe_list2 = [
            _make_protocol_event(
                protocol=ProtocolType.SSH,
                src_ip="10.0.0.1",
                metadata={"auth_result": "failed"},
            )
        ]
        context2 = _make_context(pe_list2)
        events2 = probe.scan(context2)
        assert events2 == []

    def test_invalid_user_flag_in_alert(self):
        """Invalid user flag is included in alert data."""
        probe = SSHBruteForceProbe()
        pe_list = [
            _make_protocol_event(
                protocol=ProtocolType.SSH,
                src_ip="10.0.0.1",
                metadata={"auth_result": "failed", "invalid_user": True},
            )
            for _ in range(5)
        ]
        context = _make_context(pe_list)
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].data["invalid_user"] is True


# =============================================================================
# Test: DNSTunnelingProbe
# =============================================================================


class TestDNSTunnelingProbe:
    """Test DNS tunneling / exfiltration detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = DNSTunnelingProbe()
        assert probe.name == "dns_tunneling"
        assert "T1048.003" in probe.mitre_techniques

    def test_normal_dns_no_alert(self):
        """Normal DNS queries produce no alert."""
        probe = DNSTunnelingProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.DNS,
                    metadata={"domain": "example.com", "query_type": "A"},
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_long_subdomain_detected(self):
        """Long subdomains (potential encoding) trigger alert."""
        probe = DNSTunnelingProbe()
        long_subdomain = "a" * 40  # > MAX_NORMAL_SUBDOMAIN_LENGTH
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.DNS,
                    metadata={
                        "domain": f"{long_subdomain}.evil.com",
                        "query_type": "A",
                    },
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) >= 1
        indicators = events[0].data["indicators"]
        assert any("long_subdomain" in i for i in indicators)

    def test_encoded_subdomain_detected(self):
        """Encoded-looking subdomains trigger alert."""
        probe = DNSTunnelingProbe()
        # High consonant/number ratio domain
        encoded_domain = "bcdfghjklmnpqrst.evil.com"
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.DNS,
                    metadata={"domain": encoded_domain, "query_type": "A"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) >= 1
        indicators = events[0].data["indicators"]
        assert any("encoded_subdomain" in i for i in indicators)

    def test_high_txt_query_volume_detected(self):
        """High volume of TXT queries to same domain triggers alert."""
        probe = DNSTunnelingProbe()
        pe_list = [
            _make_protocol_event(
                protocol=ProtocolType.DNS,
                metadata={"domain": f"sub{i}.evil.com", "query_type": "TXT"},
            )
            for i in range(12)
        ]
        context = _make_context(pe_list)
        events = probe.scan(context)
        # Should detect high TXT volume at threshold (10)
        txt_volume_events = [
            e
            for e in events
            if any("high_txt_volume" in i for i in e.data.get("indicators", []))
        ]
        assert len(txt_volume_events) >= 1

    def test_large_dns_payload_detected(self):
        """Large DNS payloads trigger alert."""
        probe = DNSTunnelingProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.DNS,
                    payload_size=300,
                    metadata={"domain": "normal.com", "query_type": "A"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) >= 1
        indicators = events[0].data["indicators"]
        assert any("large_dns_payload" in i for i in indicators)

    def test_non_dns_events_ignored(self):
        """Non-DNS events are skipped."""
        probe = DNSTunnelingProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.HTTP),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_looks_encoded_short_domain(self):
        """Short domains are not flagged as encoded."""
        probe = DNSTunnelingProbe()
        assert probe._looks_encoded("abc.com") is False

    def test_looks_encoded_normal_domain(self):
        """Normal domains with vowels are not flagged."""
        probe = DNSTunnelingProbe()
        assert probe._looks_encoded("example.com") is False

    def test_looks_encoded_high_consonant_ratio(self):
        """High consonant ratio subdomain is flagged as encoded."""
        probe = DNSTunnelingProbe()
        assert probe._looks_encoded("bcdfghjklmnpq.com") is True

    def test_domain_truncation(self):
        """Domain is truncated to 100 chars in alert data."""
        probe = DNSTunnelingProbe()
        long_domain = "a" * 40 + "." + "b" * 80 + ".evil.com"
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.DNS,
                    metadata={"domain": long_domain, "query_type": "A"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) >= 1
        assert len(events[0].data["domain"]) <= 100


# =============================================================================
# Test: SQLInjectionProbe
# =============================================================================


class TestSQLInjectionProbe:
    """Test SQL injection detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = SQLInjectionProbe()
        assert probe.name == "sql_injection"
        assert "T1190" in probe.mitre_techniques

    def test_clean_http_no_alert(self):
        """Normal HTTP request produces no alert."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="GET /api/users HTTP/1.1",
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_union_injection_detected(self):
        """UNION-based injection triggers alert."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="GET /users?id=1 UNION SELECT FROM users WHERE id=1",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["category"] == ThreatCategory.SQL_INJECTION.value

    def test_or_based_injection_detected(self):
        """OR 1=1 injection triggers alert."""
        probe = SQLInjectionProbe()
        # The regex pattern is: ('|")\s*(OR|AND)\s*('|")?\s*\d+\s*=\s*\d+
        # This matches: ' OR 1=1
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="POST /login: username=' OR 1=1 --",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_drop_table_detected(self):
        """DROP TABLE injection triggers alert."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="GET /delete?id=1; DROP TABLE users",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_sleep_injection_detected(self):
        """SLEEP-based blind injection triggers alert."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="GET /check?id=1 AND SLEEP(5)",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_hex_encoding_detected(self):
        """Hex-encoded payloads trigger alert."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data="GET /query?v=0x48656C6C6F",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_sql_protocol_events_scanned(self):
        """SQL protocol events are also scanned."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.SQL,
                    raw_data="SELECT * FROM users WHERE id=1; DROP TABLE users",
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_non_http_sql_events_ignored(self):
        """Non-HTTP/HTTPS/SQL events are skipped."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.SSH,
                    raw_data="SELECT * FROM users",
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_null_raw_data(self):
        """Events with no raw_data don't crash."""
        probe = SQLInjectionProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data=None,
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_payload_truncation_in_alert(self):
        """Sample payload is truncated to 200 chars in alert."""
        probe = SQLInjectionProbe()
        long_payload = "SELECT " + "A" * 300 + " FROM users WHERE id=1"
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.HTTP,
                    raw_data=long_payload,
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert len(events[0].data["sample_payload"]) <= 200


# =============================================================================
# Test: RDPSuspiciousProbe
# =============================================================================


class TestRDPSuspiciousProbe:
    """Test suspicious RDP activity detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = RDPSuspiciousProbe()
        assert probe.name == "rdp_suspicious"
        assert "T1021.001" in probe.mitre_techniques

    def test_normal_rdp_no_alert(self):
        """Internal RDP to standard port produces no alert."""
        probe = RDPSuspiciousProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.RDP,
                    src_ip="192.168.1.10",
                    dst_port=3389,
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_non_standard_port_detected(self):
        """RDP on non-standard port triggers alert."""
        probe = RDPSuspiciousProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.RDP,
                    src_ip="192.168.1.10",
                    dst_port=4444,
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert any("non_standard_port:4444" in i for i in events[0].data["indicators"])

    def test_external_source_detected(self):
        """External (non-RFC1918) source IP triggers alert."""
        probe = RDPSuspiciousProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.RDP,
                    src_ip="203.0.113.5",
                    dst_port=3389,
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert "external_source" in events[0].data["indicators"]

    def test_both_non_standard_port_and_external(self):
        """Both external + non-standard port produces single alert with both indicators."""
        probe = RDPSuspiciousProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.RDP,
                    src_ip="1.2.3.4",
                    dst_port=8888,
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert len(events[0].data["indicators"]) == 2

    def test_non_rdp_events_ignored(self):
        """Non-RDP events are skipped."""
        probe = RDPSuspiciousProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.SSH),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_internal_ips_not_flagged(self):
        """Internal (RFC1918) IPs are not flagged as external."""
        probe = RDPSuspiciousProbe()
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            context = _make_context(
                [
                    _make_protocol_event(
                        protocol=ProtocolType.RDP,
                        src_ip=ip,
                        dst_port=3389,
                    ),
                ]
            )
            events = probe.scan(context)
            assert events == [], f"Internal IP {ip} should not trigger alert"


# =============================================================================
# Test: FTPCleartextCredsProbe
# =============================================================================


class TestFTPCleartextCredsProbe:
    """Test FTP cleartext credential detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = FTPCleartextCredsProbe()
        assert probe.name == "ftp_cleartext_creds"
        assert "T1552.001" in probe.mitre_techniques

    def test_ftp_always_alerts(self):
        """Any FTP traffic always triggers alert (cleartext by nature)."""
        probe = FTPCleartextCredsProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.FTP,
                    metadata={"command": "RETR", "filename": "secrets.txt"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["category"] == ThreatCategory.FTP_CLEARTEXT.value
        assert events[0].data["command"] == "RETR"
        assert events[0].data["filename"] == "secrets.txt"

    def test_ftp_without_metadata(self):
        """FTP event without command/filename metadata still alerts."""
        probe = FTPCleartextCredsProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.FTP, metadata={}),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].data["command"] == "unknown"
        assert events[0].data["filename"] == ""

    def test_non_ftp_events_ignored(self):
        """Non-FTP events are skipped."""
        probe = FTPCleartextCredsProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.SSH),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_multiple_ftp_events(self):
        """Multiple FTP events produce multiple alerts."""
        probe = FTPCleartextCredsProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.FTP),
                _make_protocol_event(protocol=ProtocolType.FTP),
                _make_protocol_event(protocol=ProtocolType.FTP),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 3


# =============================================================================
# Test: SMTPSpamPhishProbe
# =============================================================================


class TestSMTPSpamPhishProbe:
    """Test SMTP spam/phishing detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = SMTPSpamPhishProbe()
        assert probe.name == "smtp_spam_phish"
        assert "T1566.001" in probe.mitre_techniques

    def test_clean_smtp_no_alert(self):
        """Normal SMTP from legitimate domain produces no alert."""
        probe = SMTPSpamPhishProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.SMTP,
                    metadata={"from": "user@company.com"},
                ),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_suspicious_domain_ru(self):
        """SMTP from .ru domain triggers alert."""
        probe = SMTPSpamPhishProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.SMTP,
                    metadata={"from": "attacker@evil.ru"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].data["category"] == ThreatCategory.SMTP_SPAM_PHISH.value

    def test_suspicious_domain_xyz(self):
        """SMTP from .xyz domain triggers alert."""
        probe = SMTPSpamPhishProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.SMTP,
                    metadata={"from": "phisher@scam.xyz"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_suspicious_domain_tk(self):
        """SMTP from .tk domain triggers alert."""
        probe = SMTPSpamPhishProbe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.SMTP,
                    metadata={"from": "spam@free.tk"},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1

    def test_non_smtp_events_ignored(self):
        """Non-SMTP events are skipped."""
        probe = SMTPSpamPhishProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.HTTP),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_sender_truncation(self):
        """Sender is truncated to 100 chars in alert data."""
        probe = SMTPSpamPhishProbe()
        long_sender = "user@" + "a" * 100 + ".ru"
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.SMTP,
                    metadata={"from": long_sender},
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert len(events[0].data["sender"]) <= 100


# =============================================================================
# Test: IRCP2PC2Probe
# =============================================================================


class TestIRCP2PC2Probe:
    """Test IRC/P2P C2 communication detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = IRCP2PC2Probe()
        assert probe.name == "irc_p2p_c2"
        assert "T1071.001" in probe.mitre_techniques

    def test_irc_traffic_always_alerts(self):
        """Any IRC traffic in enterprise env triggers alert."""
        probe = IRCP2PC2Probe()
        context = _make_context(
            [
                _make_protocol_event(
                    protocol=ProtocolType.IRC,
                    src_ip="192.168.1.100",
                    dst_ip="1.2.3.4",
                    dst_port=6667,
                ),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert events[0].data["category"] == ThreatCategory.IRC_P2P_C2.value

    def test_non_irc_events_ignored(self):
        """Non-IRC events are skipped."""
        probe = IRCP2PC2Probe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.HTTP),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_multiple_irc_events(self):
        """Multiple IRC events produce multiple alerts."""
        probe = IRCP2PC2Probe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.IRC, dst_port=6667),
                _make_protocol_event(protocol=ProtocolType.IRC, dst_port=6668),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 2


# =============================================================================
# Test: ProtocolAnomalyProbe
# =============================================================================


class TestProtocolAnomalyProbe:
    """Test general protocol anomaly detection probe."""

    def test_probe_attributes(self):
        """Verify probe metadata."""
        probe = ProtocolAnomalyProbe()
        assert probe.name == "protocol_anomaly"
        assert "T1205" in probe.mitre_techniques

    def test_standard_port_no_alert(self):
        """Protocol on standard port produces no alert."""
        probe = ProtocolAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.HTTP, dst_port=80),
                _make_protocol_event(protocol=ProtocolType.SSH, dst_port=22),
                _make_protocol_event(protocol=ProtocolType.DNS, dst_port=53),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_non_standard_port_detected(self):
        """Protocol on non-standard port triggers alert."""
        probe = ProtocolAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.SSH, dst_port=2222),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.LOW
        assert any("non_standard_port:2222" in a for a in events[0].data["anomalies"])

    def test_http_on_alternative_ports_ok(self):
        """HTTP on alternative standard ports (8080, 8000) produces no alert."""
        probe = ProtocolAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.HTTP, dst_port=8080),
                _make_protocol_event(protocol=ProtocolType.HTTP, dst_port=8000),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_https_on_8443_ok(self):
        """HTTPS on 8443 produces no alert."""
        probe = ProtocolAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.HTTPS, dst_port=8443),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_protocol_without_standard_ports_not_checked(self):
        """Protocols not in STANDARD_PORTS mapping are not flagged."""
        probe = ProtocolAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.IRC, dst_port=9999),
            ]
        )
        events = probe.scan(context)
        assert events == []

    def test_multiple_anomalies(self):
        """Multiple anomalous events produce multiple alerts."""
        probe = ProtocolAnomalyProbe()
        context = _make_context(
            [
                _make_protocol_event(protocol=ProtocolType.SSH, dst_port=2222),
                _make_protocol_event(protocol=ProtocolType.HTTP, dst_port=9999),
            ]
        )
        events = probe.scan(context)
        assert len(events) == 2


# =============================================================================
# Test: create_protocol_collector_probes Factory
# =============================================================================


class TestCreateProtocolCollectorProbes:
    """Test probe factory function."""

    def test_creates_all_probes(self):
        """Factory creates instances of all 10 probes."""
        probes = create_protocol_collector_probes()
        assert len(probes) == 10

    def test_probe_types(self):
        """Factory creates correct probe types."""
        probes = create_protocol_collector_probes()
        probe_names = {p.name for p in probes}
        expected_names = {
            "http_suspicious_headers",
            "tls_ssl_anomaly",
            "ssh_brute_force",
            "dns_tunneling",
            "sql_injection",
            "rdp_suspicious",
            "ftp_cleartext_creds",
            "smtp_spam_phish",
            "irc_p2p_c2",
            "protocol_anomaly",
        }
        assert probe_names == expected_names

    def test_all_probes_are_micro_probes(self):
        """All created probes inherit from MicroProbe."""
        probes = create_protocol_collector_probes()
        for probe in probes:
            assert isinstance(probe, MicroProbe)

    def test_protocol_probes_registry(self):
        """PROTOCOL_PROBES registry contains 10 classes."""
        assert len(PROTOCOL_PROBES) == 10


# =============================================================================
# Test: ProtocolCollectorsV2 Agent Initialization
# =============================================================================


class TestProtocolCollectorsV2Init:
    """Test agent initialization."""

    def test_default_init(self):
        """Test agent with default parameters."""
        agent = ProtocolCollectorsV2(device_id="host-001")
        assert agent.device_id == "host-001"
        assert agent.agent_name == "protocol_collectors"
        assert agent.collection_interval == 5.0
        assert agent.log_path == "/var/log/syslog"
        assert agent.use_stub is False
        assert agent._collector is None

    def test_custom_init(self):
        """Test agent with custom parameters."""
        agent = ProtocolCollectorsV2(
            device_id="mac-lab",
            agent_name="custom_name",
            collection_interval=30.0,
            log_path="/custom/log",
            use_stub=True,
            metrics_interval=120.0,
        )
        assert agent.device_id == "mac-lab"
        assert agent.agent_name == "custom_name"
        assert agent.collection_interval == 30.0
        assert agent.log_path == "/custom/log"
        assert agent.use_stub is True

    def test_isinstance_checks(self):
        """Agent inherits from HardenedAgentBase and MicroProbeAgentMixin."""
        agent = ProtocolCollectorsV2(device_id="host-001")
        assert isinstance(agent, HardenedAgentBase)
        assert isinstance(agent, MicroProbeAgentMixin)

    def test_custom_collector_injection(self):
        """Custom collector can be injected."""
        mock_collector = MagicMock(spec=BaseProtocolCollector)
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=mock_collector,
        )
        assert agent._collector is mock_collector

    def test_custom_probes_injection(self):
        """Custom probes can be injected."""
        probe1 = HTTPSuspiciousHeadersProbe()
        probe2 = SSHBruteForceProbe()
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            probes=[probe1, probe2],
        )
        assert len(agent.probes) == 2


# =============================================================================
# Test: ProtocolCollectorsV2 Setup
# =============================================================================


class TestProtocolCollectorsV2Setup:
    """Test agent setup lifecycle."""

    def test_setup_creates_stub_collector(self):
        """Setup with use_stub=True creates StubProtocolCollector."""
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            use_stub=True,
        )
        result = agent.setup()
        assert result is True
        assert isinstance(agent._collector, StubProtocolCollector)

    def test_setup_creates_network_collector(self):
        """Setup with use_stub=False creates NetworkLogCollector."""
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            use_stub=False,
            log_path="/tmp/test.log",
        )
        result = agent.setup()
        assert result is True
        assert isinstance(agent._collector, NetworkLogCollector)

    def test_setup_registers_default_probes(self):
        """Setup registers all 10 default probes when none provided."""
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            use_stub=True,
        )
        agent.setup()
        assert len(agent.probes) == 10

    def test_setup_preserves_custom_probes(self):
        """Setup preserves custom probes if provided."""
        probe = HTTPSuspiciousHeadersProbe()
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            use_stub=True,
            probes=[probe],
        )
        agent.setup()
        assert len(agent.probes) == 1
        assert agent.probes[0].name == "http_suspicious_headers"

    def test_setup_preserves_injected_collector(self):
        """Setup preserves an injected collector."""
        mock_collector = MagicMock(spec=BaseProtocolCollector)
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=mock_collector,
        )
        agent.setup()
        assert agent._collector is mock_collector

    def test_setup_returns_true(self):
        """Setup always returns True."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        assert agent.setup() is True


# =============================================================================
# Test: ProtocolCollectorsV2 Data Collection
# =============================================================================


class TestProtocolCollectorsV2Collection:
    """Test agent data collection cycle."""

    def test_collect_data_with_stub(self):
        """collect_data() returns results from stub collector + probes."""
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            use_stub=True,
        )
        agent.setup()
        results = agent.collect_data()
        assert isinstance(results, list)
        # Stub generates 5 events, probes run on them
        # At least some probes should trigger (FTP cleartext, protocol anomaly, etc.)
        assert len(results) >= 1

    def test_collect_data_results_have_device_id(self):
        """All result dicts contain device_id."""
        agent = ProtocolCollectorsV2(
            device_id="test-device",
            use_stub=True,
        )
        agent.setup()
        results = agent.collect_data()
        for r in results:
            assert r["device_id"] == "test-device"

    def test_collect_data_results_have_agent_name(self):
        """All result dicts contain agent name."""
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            use_stub=True,
        )
        agent.setup()
        results = agent.collect_data()
        for r in results:
            assert r["agent"] == "protocol_collectors"

    def test_collect_data_empty_collector(self):
        """collect_data() returns empty list when collector produces no events."""
        mock_collector = MagicMock(spec=BaseProtocolCollector)
        mock_collector.collect.return_value = []
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=mock_collector,
        )
        agent.setup()
        results = agent.collect_data()
        assert results == []

    def test_collect_data_collector_exception(self):
        """collect_data() returns empty list on collector error."""
        mock_collector = MagicMock(spec=BaseProtocolCollector)
        mock_collector.collect.side_effect = RuntimeError("collector failed")
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=mock_collector,
        )
        agent.setup()
        results = agent.collect_data()
        assert results == []

    def test_collect_data_calls_run_probes(self):
        """collect_data() runs probes with protocol events in context."""
        mock_collector = MagicMock(spec=BaseProtocolCollector)
        ftp_event = _make_protocol_event(
            protocol=ProtocolType.FTP,
            metadata={"command": "RETR"},
        )
        mock_collector.collect.return_value = [ftp_event]

        # Use only FTP probe for predictable results
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=mock_collector,
            probes=[FTPCleartextCredsProbe()],
        )
        agent.setup()
        results = agent.collect_data()

        # FTP probe always alerts on FTP traffic
        assert len(results) == 1
        assert results[0]["probe_name"] == "ftp_cleartext_creds"


# =============================================================================
# Test: ProtocolCollectorsV2 Cleanup
# =============================================================================


class TestProtocolCollectorsV2Cleanup:
    """Test agent cleanup."""

    def test_cleanup_with_stub(self):
        """Cleanup does not crash with stub collector."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()
        # Should not raise
        agent.cleanup()

    def test_cleanup_calls_collector_cleanup(self):
        """Cleanup calls collector.cleanup() if it exists."""
        mock_collector = MagicMock(spec=BaseProtocolCollector)
        mock_collector.cleanup = MagicMock()
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=mock_collector,
        )
        agent.setup()
        agent.cleanup()
        mock_collector.cleanup.assert_called_once()

    def test_cleanup_no_collector_cleanup(self):
        """Cleanup handles collector without cleanup method."""
        collector = NetworkLogCollector()
        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=collector,
        )
        agent.setup()
        # Should not raise (NetworkLogCollector has no cleanup method)
        agent.cleanup()


# =============================================================================
# Test: ProtocolCollectorsV2 Health
# =============================================================================


class TestProtocolCollectorsV2Health:
    """Test agent health metrics."""

    def test_health_summary(self):
        """health_summary() returns expected structure."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()
        health = agent.health_summary()
        assert health["agent_name"] == "protocol_collectors"
        assert health["device_id"] == "host-001"
        assert "uptime_seconds" in health
        assert "collection_count" in health
        assert "error_count" in health
        assert "circuit_breaker_state" in health
        assert health["circuit_breaker_state"] == "CLOSED"

    def test_probe_health(self):
        """get_probe_health() returns health for all probes."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()
        probe_health = agent.get_probe_health()
        assert len(probe_health) == 10
        for ph in probe_health:
            assert "name" in ph
            assert "enabled" in ph
            assert "scan_count" in ph

    def test_probe_listing(self):
        """list_probes() returns all probe names."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()
        probe_names = agent.list_probes()
        assert len(probe_names) == 10
        assert "http_suspicious_headers" in probe_names
        assert "ssh_brute_force" in probe_names

    def test_enable_disable_probe(self):
        """Probes can be individually enabled/disabled."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()

        # Disable a probe
        result = agent.disable_probe("sql_injection")
        assert result is True

        # Verify it's disabled
        for p in agent.probes:
            if p.name == "sql_injection":
                assert p.enabled is False

        # Re-enable
        result = agent.enable_probe("sql_injection")
        assert result is True
        for p in agent.probes:
            if p.name == "sql_injection":
                assert p.enabled is True

    def test_disable_nonexistent_probe(self):
        """Disabling nonexistent probe returns False."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()
        result = agent.disable_probe("nonexistent")
        assert result is False


# =============================================================================
# Test: ProtocolCollectorsV2 Probe Error Isolation
# =============================================================================


class TestProtocolCollectorsV2ProbeIsolation:
    """Test probe error isolation and independence."""

    def test_probe_exception_does_not_crash_agent(self):
        """A failing probe doesn't crash collect_data()."""

        class ExplodingProbe(MicroProbe):
            name = "exploding_probe"
            description = "Always raises"

            def scan(self, context: ProbeContext):
                raise RuntimeError("probe kaboom")

        mock_collector = MagicMock(spec=BaseProtocolCollector)
        mock_collector.collect.return_value = [
            _make_protocol_event(protocol=ProtocolType.FTP)
        ]

        agent = ProtocolCollectorsV2(
            device_id="host-001",
            collector=mock_collector,
            probes=[ExplodingProbe(), FTPCleartextCredsProbe()],
        )
        agent.setup()
        results = agent.collect_data()

        # FTP probe should still produce results despite exploding probe
        assert len(results) >= 1

    def test_probes_are_independent(self):
        """Each probe has unique name and description."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()
        names = [p.name for p in agent.probes]
        assert len(names) == len(set(names)), "Probe names should be unique"


# =============================================================================
# Test: create_protocol_collectors Factory
# =============================================================================


class TestCreateProtocolCollectorsV2:
    """Test convenience factory function."""

    def test_creates_agent(self):
        """Factory creates ProtocolCollectorsV2 instance."""
        agent = create_protocol_collectors(device_id="host-001")
        assert isinstance(agent, ProtocolCollectorsV2)
        assert agent.device_id == "host-001"

    def test_passes_kwargs(self):
        """Factory passes kwargs through."""
        agent = create_protocol_collectors(
            device_id="host-001",
            use_stub=True,
            collection_interval=60.0,
        )
        assert agent.use_stub is True
        assert agent.collection_interval == 60.0


# =============================================================================
# Test: Full Integration Cycle
# =============================================================================


class TestFullCycleIntegration:
    """Integration test: setup -> collect -> validate -> health."""

    def test_full_cycle_stub(self):
        """Full cycle with stub collector produces expected results."""
        agent = ProtocolCollectorsV2(
            device_id="integration-host",
            use_stub=True,
        )
        assert agent.setup() is True

        # First collection
        results1 = agent.collect_data()
        assert isinstance(results1, list)
        assert len(results1) >= 1

        # All results have expected fields
        for r in results1:
            assert "event_type" in r
            assert "severity" in r
            assert "probe_name" in r
            assert "device_id" in r
            assert r["device_id"] == "integration-host"

        # Health should reflect collection
        health = agent.health_summary()
        assert health["agent_name"] == "protocol_collectors"

        # Second collection should also work
        results2 = agent.collect_data()
        assert isinstance(results2, list)

    def test_full_cycle_with_log_file(self, tmp_path):
        """Full cycle with real log file collector."""
        log_file = tmp_path / "test_syslog"
        log_file.write_text(
            "sshd: Failed password from 10.0.0.1 port 22\n"
            "sshd: Failed password from 10.0.0.1 port 22\n"
            "sshd: Failed password from 10.0.0.1 port 22\n"
            "sshd: Failed password from 10.0.0.1 port 22\n"
            "sshd: Failed password from 10.0.0.1 port 22\n"
            "http GET /index.html 200 from 10.0.0.2 to 192.168.1.1\n"
            "ftp connection from 10.0.0.3:55000 to 10.0.0.21:21\n"
        )

        agent = ProtocolCollectorsV2(
            device_id="log-host",
            log_path=str(log_file),
            use_stub=False,
        )
        assert agent.setup() is True

        results = agent.collect_data()
        assert isinstance(results, list)
        # Should produce alerts from SSH brute force (5 failures), FTP cleartext, etc.
        assert len(results) >= 1

        # Check that probe names come from the actual probes
        probe_names = {r["probe_name"] for r in results}
        # At least FTP cleartext should fire
        assert "ftp_cleartext_creds" in probe_names

    def test_validate_event_default(self):
        """Default validate_event accepts all events."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        result = agent.validate_event({"any": "event"})
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True

    def test_cleanup_integration(self):
        """Cleanup does not raise after full lifecycle."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent.setup()
        agent.collect_data()
        agent.cleanup()  # Should not raise


# =============================================================================
# Test: Edge Cases and Robustness
# =============================================================================


class TestEdgeCases:
    """Test edge cases and robustness."""

    def test_empty_shared_data(self):
        """Probes handle missing protocol_events key gracefully."""
        probe = HTTPSuspiciousHeadersProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="test",
            shared_data={},
        )
        events = probe.scan(context)
        assert events == []

    def test_probe_scan_with_mixed_protocols(self):
        """Probes correctly filter events by protocol."""
        probes = create_protocol_collector_probes()
        mixed_events = [
            _make_protocol_event(
                protocol=ProtocolType.SSH, metadata={"auth_result": "accepted"}
            ),
            _make_protocol_event(protocol=ProtocolType.HTTP, dst_port=80),
            _make_protocol_event(
                protocol=ProtocolType.DNS,
                metadata={"domain": "safe.com", "query_type": "A"},
            ),
            _make_protocol_event(
                protocol=ProtocolType.FTP, metadata={"command": "RETR"}
            ),
        ]
        context = _make_context(mixed_events)

        # Run all probes
        all_events = []
        for probe in probes:
            all_events.extend(probe.scan(context))

        # FTP should always trigger ftp_cleartext_creds
        ftp_alerts = [e for e in all_events if e.probe_name == "ftp_cleartext_creds"]
        assert len(ftp_alerts) == 1

    def test_concurrent_agent_instances(self):
        """Multiple agent instances don't interfere."""
        agent1 = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        agent2 = ProtocolCollectorsV2(device_id="host-002", use_stub=True)
        agent1.setup()
        agent2.setup()

        results1 = agent1.collect_data()
        results2 = agent2.collect_data()

        # Both should produce results
        assert len(results1) >= 1
        assert len(results2) >= 1

        # Results should have correct device_ids
        for r in results1:
            assert r["device_id"] == "host-001"
        for r in results2:
            assert r["device_id"] == "host-002"

    def test_agent_metrics_object_exists(self):
        """Agent has metrics attribute from HardenedAgentBase."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        assert hasattr(agent, "metrics")

    def test_circuit_breaker_initial_state(self):
        """Circuit breaker starts in CLOSED state."""
        agent = ProtocolCollectorsV2(device_id="host-001", use_stub=True)
        assert agent.circuit_breaker.state == "CLOSED"


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "TestProtocolType",
    "TestThreatCategory",
    "TestProtocolEvent",
    "TestProtocolThreat",
    "TestNetworkLogCollector",
    "TestStubProtocolCollector",
    "TestCreateProtocolCollector",
    "TestHTTPSuspiciousHeadersProbe",
    "TestTLSSSLAnomalyProbe",
    "TestSSHBruteForceProbe",
    "TestDNSTunnelingProbe",
    "TestSQLInjectionProbe",
    "TestRDPSuspiciousProbe",
    "TestFTPCleartextCredsProbe",
    "TestSMTPSpamPhishProbe",
    "TestIRCP2PC2Probe",
    "TestProtocolAnomalyProbe",
    "TestCreateProtocolCollectorProbes",
    "TestProtocolCollectorsV2Init",
    "TestProtocolCollectorsV2Setup",
    "TestProtocolCollectorsV2Collection",
    "TestProtocolCollectorsV2Cleanup",
    "TestProtocolCollectorsV2Health",
    "TestProtocolCollectorsV2ProbeIsolation",
    "TestCreateProtocolCollectorsV2",
    "TestFullCycleIntegration",
    "TestEdgeCases",
]
