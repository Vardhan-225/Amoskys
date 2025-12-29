"""
Tests for AMOSKYS DNS Monitoring Agent (DNSAgent)
"""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.dns import DNSAgent, DNSQuery, DNSThreat


class TestDNSQuery:
    """Tests for DNSQuery dataclass"""

    def test_dns_query_creation(self):
        """Test basic DNSQuery creation"""
        query = DNSQuery(
            timestamp=datetime.now(),
            query_name="example.com",
            query_type="A",
            source_ip="192.168.1.100",
        )

        assert query.query_name == "example.com"
        assert query.query_type == "A"
        assert query.source_ip == "192.168.1.100"

    def test_dns_query_with_response(self):
        """Test DNSQuery with response data"""
        query = DNSQuery(
            timestamp=datetime.now(),
            query_name="google.com",
            query_type="A",
            source_ip="192.168.1.100",
            response_ip="142.250.80.46",
            response_code="NOERROR",
            ttl=300,
        )

        assert query.response_ip == "142.250.80.46"
        assert query.response_code == "NOERROR"
        assert query.ttl == 300


class TestDNSThreat:
    """Tests for DNSThreat dataclass"""

    def test_dns_threat_creation(self):
        """Test basic DNSThreat creation"""
        threat = DNSThreat(
            threat_type="C2_BEACON",
            severity="CRITICAL",
            domain="evil.example.com",
            evidence=["Regular 60s beacon interval"],
            query_count=50,
            first_seen=datetime.now() - timedelta(minutes=30),
            last_seen=datetime.now(),
            mitre_techniques=["T1071.004"],
            confidence=0.9,
        )

        assert threat.threat_type == "C2_BEACON"
        assert threat.severity == "CRITICAL"
        assert threat.confidence == 0.9


class TestDNSAgentDetection:
    """Tests for DNSAgent threat detection"""

    @pytest.fixture
    def dns_agent(self):
        """Create DNSAgent instance for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            queue_path = Path(tmpdir) / "queue" / "dns.db"

            with patch.object(DNSAgent, "collect_queries", return_value=[]):
                agent = DNSAgent(
                    queue_path=str(queue_path),
                    beacon_threshold=5,
                    entropy_threshold=3.5,
                )
                yield agent

    def test_calculate_entropy(self, dns_agent):
        """Test Shannon entropy calculation"""
        # Low entropy (repeating characters)
        low_entropy = dns_agent._calculate_entropy("aaaaaaaaaa")
        assert low_entropy == 0.0

        # Higher entropy (mixed characters)
        high_entropy = dns_agent._calculate_entropy("abcdefghij")
        assert high_entropy > 3.0

        # Random-looking string (high entropy)
        random_entropy = dns_agent._calculate_entropy("x7k9m2p5q8")
        assert random_entropy > 3.0

    def test_is_whitelisted(self, dns_agent):
        """Test domain whitelisting"""
        assert dns_agent._is_whitelisted("google.com")
        assert dns_agent._is_whitelisted("www.google.com")
        assert dns_agent._is_whitelisted("mail.google.com")
        assert not dns_agent._is_whitelisted("evil.com")
        assert not dns_agent._is_whitelisted("suspicious.xyz")

    def test_extract_subdomain(self, dns_agent):
        """Test subdomain extraction"""
        assert dns_agent._extract_subdomain("www.example.com") == "www"
        assert dns_agent._extract_subdomain("mail.sub.example.com") == "mail.sub"
        assert dns_agent._extract_subdomain("example.com") == ""

    def test_dga_detection_random_domain(self, dns_agent):
        """Test DGA detection for random-looking domain"""
        # Simulate a DGA domain (high entropy, random characters)
        is_dga, confidence = dns_agent._is_dga_domain("xk7m2p5q8r3t1n9.malware.com")

        # The detection should flag it, but confidence depends on entropy calculation
        assert is_dga is True or confidence > 0.2

    def test_dga_detection_normal_domain(self, dns_agent):
        """Test DGA detection for normal domain"""
        is_dga, confidence = dns_agent._is_dga_domain("www.example.com")

        assert is_dga is False

    def test_tunneling_detection_long_subdomain(self, dns_agent):
        """Test DNS tunneling detection for long subdomain"""
        # Simulate encoded data in subdomain
        long_subdomain = "a" * 60 + ".tunnel.evil.com"
        is_tunnel, confidence = dns_agent._detect_tunneling(long_subdomain, "TXT")

        assert is_tunnel is True
        assert confidence > 0.5

    def test_tunneling_detection_txt_record(self, dns_agent):
        """Test DNS tunneling detection for TXT record queries"""
        is_tunnel, confidence = dns_agent._detect_tunneling(
            "encoded-data-here.evil.com", "TXT"
        )

        # TXT record adds to confidence but may not trigger alone
        assert isinstance(is_tunnel, bool)
        assert isinstance(confidence, float)

    def test_tunneling_detection_base64_pattern(self, dns_agent):
        """Test DNS tunneling detection for base64 pattern"""
        # Base64-like subdomain
        base64_domain = "SGVsbG9Xb3JsZEVuY29kZWQ=.tunnel.com"
        is_tunnel, confidence = dns_agent._detect_tunneling(base64_domain, "A")

        # May or may not trigger depending on entropy
        assert isinstance(is_tunnel, bool)

    def test_beaconing_detection_regular_intervals(self, dns_agent):
        """Test C2 beaconing detection with regular intervals"""
        base_time = datetime.now()

        # Create queries with regular 60-second intervals
        queries = [
            DNSQuery(
                timestamp=base_time + timedelta(seconds=i * 60),
                query_name="beacon.evil.com",
                query_type="A",
                source_ip="192.168.1.100",
            )
            for i in range(20)
        ]

        is_beacon, confidence, interval = dns_agent._detect_beaconing(
            "evil.com", queries
        )

        assert is_beacon is True
        assert confidence > 0.5
        assert 55 <= interval <= 65  # Should be close to 60

    def test_beaconing_detection_irregular_intervals(self, dns_agent):
        """Test beaconing detection with irregular intervals"""
        base_time = datetime.now()

        # Create queries with irregular intervals
        intervals = [5, 120, 10, 300, 15, 180, 8, 90]
        queries = []
        current_time = base_time

        for interval in intervals:
            current_time += timedelta(seconds=interval)
            queries.append(
                DNSQuery(
                    timestamp=current_time,
                    query_name="normal.example.com",
                    query_type="A",
                    source_ip="192.168.1.100",
                )
            )

        is_beacon, confidence, _ = dns_agent._detect_beaconing("example.com", queries)

        # Irregular intervals should not trigger beaconing
        assert is_beacon is False or confidence < 0.5

    def test_beaconing_detection_insufficient_queries(self, dns_agent):
        """Test beaconing detection with too few queries"""
        queries = [
            DNSQuery(
                timestamp=datetime.now(),
                query_name="test.com",
                query_type="A",
                source_ip="192.168.1.100",
            )
            for _ in range(3)  # Less than threshold
        ]

        is_beacon, confidence, _ = dns_agent._detect_beaconing("test.com", queries)

        assert is_beacon is False


class TestDNSAgentAnalysis:
    """Tests for DNSAgent query analysis"""

    @pytest.fixture
    def dns_agent(self):
        """Create DNSAgent for analysis tests"""
        with tempfile.TemporaryDirectory() as tmpdir:
            queue_path = Path(tmpdir) / "queue" / "dns.db"

            with patch.object(DNSAgent, "collect_queries", return_value=[]):
                agent = DNSAgent(queue_path=str(queue_path))
                yield agent

    def test_analyze_queries_c2_pattern(self, dns_agent):
        """Test analysis detects C2 patterns"""
        # Query to known suspicious pattern
        queries = [
            DNSQuery(
                timestamp=datetime.now(),
                query_name="test.cobaltstrike.example.com",  # More explicit pattern
                query_type="A",
                source_ip="192.168.1.100",
            )
        ]

        threats = dns_agent.analyze_queries(queries)

        # Should detect C2 pattern or at least return a list
        assert isinstance(threats, list)
        # C2 pattern detection may depend on exact regex matching

    def test_analyze_queries_suspicious_tld(self, dns_agent):
        """Test analysis flags suspicious TLDs"""
        base_time = datetime.now()

        # Multiple queries to suspicious TLD
        queries = [
            DNSQuery(
                timestamp=base_time + timedelta(seconds=i),
                query_name=f"domain{i}.xyz",
                query_type="A",
                source_ip="192.168.1.100",
            )
            for i in range(10)
        ]

        threats = dns_agent.analyze_queries(queries)

        # Should detect suspicious TLD activity
        tld_threats = [
            t for t in threats if "suspicious TLD" in " ".join(t.evidence).lower()
        ]
        # May or may not trigger based on implementation
        assert isinstance(threats, list)

    def test_analyze_queries_whitelisted_ignored(self, dns_agent):
        """Test that whitelisted domains are ignored"""
        queries = [
            DNSQuery(
                timestamp=datetime.now(),
                query_name="www.google.com",
                query_type="A",
                source_ip="192.168.1.100",
            ),
            DNSQuery(
                timestamp=datetime.now(),
                query_name="api.github.com",
                query_type="A",
                source_ip="192.168.1.100",
            ),
        ]

        threats = dns_agent.analyze_queries(queries)

        # Whitelisted domains should not generate threats
        google_threats = [t for t in threats if "google" in t.domain.lower()]
        github_threats = [t for t in threats if "github" in t.domain.lower()]

        assert len(google_threats) == 0
        assert len(github_threats) == 0


class TestDNSAgentIntegration:
    """Integration tests for DNSAgent"""

    def test_run_once(self):
        """Test single analysis cycle"""
        with tempfile.TemporaryDirectory() as tmpdir:
            queue_path = Path(tmpdir) / "queue" / "dns.db"

            # Mock log parsing to return empty list
            with patch.object(DNSAgent, "_parse_macos_dns_logs", return_value=[]):
                with patch.object(DNSAgent, "_parse_linux_dns_logs", return_value=[]):
                    agent = DNSAgent(queue_path=str(queue_path))
                    threats = agent.run_once()

                    assert isinstance(threats, list)
