#!/usr/bin/env python3
"""Tests for FlowAgent micro-probes."""

import time

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity
from amoskys.agents.flow.probes import (
    C2BeaconFlowProbe,
    CleartextCredentialLeakProbe,
    DataExfilVolumeSpikeProbe,
    FlowEvent,
    InternalReconDNSFlowProbe,
    LateralSMBWinRMProbe,
    NewExternalServiceProbe,
    PortScanSweepProbe,
    SuspiciousTunnelProbe,
    create_flow_probes,
)


class TestFlowProbes:
    """Test suite for FlowAgent probes."""

    def test_create_flow_probes(self):
        """Test probe factory creates all 8 probes."""
        probes = create_flow_probes()
        assert len(probes) == 8

        probe_names = [p.name for p in probes]
        assert "port_scan_sweep" in probe_names
        assert "lateral_smb_winrm" in probe_names
        assert "data_exfil_volume_spike" in probe_names
        assert "c2_beacon_flow" in probe_names
        assert "cleartext_credential_leak" in probe_names
        assert "suspicious_tunnel" in probe_names
        assert "internal_recon_dns_flow" in probe_names
        assert "new_external_service" in probe_names

    def test_port_scan_sweep_vertical(self):
        """Test vertical port scan detection (many ports to same target)."""
        probe = PortScanSweepProbe()
        now_ns = int(time.time() * 1e9)

        # Create flows scanning ports 1-25 on same target
        flows = [
            FlowEvent(
                src_ip="10.0.0.100",
                dst_ip="10.0.0.200",
                src_port=50000 + i,
                dst_port=i,
                protocol="TCP",
                bytes_tx=64,
                bytes_rx=0,
                packet_count=1,
                first_seen_ns=now_ns + i * 1_000_000,
                last_seen_ns=now_ns + i * 1_000_000,
            )
            for i in range(1, 26)  # 25 ports
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "flow_portscan_vertical"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["src_ip"] == "10.0.0.100"
        assert events[0].data["dst_ip"] == "10.0.0.200"
        assert events[0].data["port_count"] == 25

    def test_lateral_smb_detection(self):
        """Test lateral movement detection via SMB."""
        probe = LateralSMBWinRMProbe()
        now_ns = int(time.time() * 1e9)

        # Internal SMB connection
        flows = [
            FlowEvent(
                src_ip="192.168.1.10",
                dst_ip="192.168.1.20",
                src_port=49152,
                dst_port=445,  # SMB
                protocol="TCP",
                bytes_tx=1024,
                bytes_rx=2048,
                packet_count=10,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns + 1_000_000_000,
                direction="LATERAL",
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        # Should detect new lateral edge
        assert len(events) == 1
        assert events[0].event_type == "flow_lateral_smb_winrm_detected"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["dst_port"] == 445
        assert events[0].data["app_protocol"] == "SMB"
        assert events[0].data["is_new_edge"] is True

    def test_lateral_rdp_detection(self):
        """Test lateral movement detection via RDP."""
        probe = LateralSMBWinRMProbe()
        now_ns = int(time.time() * 1e9)

        # Internal RDP connection
        flows = [
            FlowEvent(
                src_ip="10.10.10.5",
                dst_ip="10.10.10.15",
                src_port=50000,
                dst_port=3389,  # RDP
                protocol="TCP",
                bytes_tx=5000,
                bytes_rx=10000,
                packet_count=50,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns + 5_000_000_000,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "flow_lateral_smb_winrm_detected"
        assert events[0].data["app_protocol"] == "RDP"

    def test_data_exfil_volume_spike(self):
        """Test data exfiltration volume spike detection."""
        probe = DataExfilVolumeSpikeProbe()
        now_ns = int(time.time() * 1e9)

        # Large outbound transfer (100 MB)
        flows = [
            FlowEvent(
                src_ip="192.168.1.50",
                dst_ip="8.8.8.8",  # External
                src_port=50000,
                dst_port=443,
                protocol="TCP",
                bytes_tx=100 * 1024 * 1024,  # 100 MB
                bytes_rx=1024,
                packet_count=70000,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns + 60_000_000_000,  # 60 seconds
                direction="OUTBOUND",
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "flow_exfil_volume_spike"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["dst_ip"] == "8.8.8.8"
        assert events[0].data["total_bytes_tx"] == 100 * 1024 * 1024

    def test_c2_beaconing_pattern(self):
        """Test C2 beaconing pattern detection."""
        probe = C2BeaconFlowProbe()
        now_ns = int(time.time() * 1e9)

        # Create 5 flows with regular 60-second intervals
        flows = [
            FlowEvent(
                src_ip="192.168.1.100",
                dst_ip="203.0.113.50",  # External C2
                src_port=50000 + i,
                dst_port=443,
                protocol="TCP",
                bytes_tx=256,  # Small payload
                bytes_rx=128,
                packet_count=2,
                first_seen_ns=now_ns + i * 60_000_000_000,  # 60s intervals
                last_seen_ns=now_ns + i * 60_000_000_000 + 500_000_000,
            )
            for i in range(5)
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "flow_c2_beaconing_pattern"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["src_ip"] == "192.168.1.100"
        assert events[0].data["dst_ip"] == "203.0.113.50"
        assert 55 <= events[0].data["avg_interval_seconds"] <= 65  # ~60s with tolerance
        assert events[0].data["jitter_ratio"] < 0.2

    def test_cleartext_http_detection(self):
        """Test cleartext HTTP credential detection."""
        probe = CleartextCredentialLeakProbe()
        now_ns = int(time.time() * 1e9)

        # HTTP traffic on port 80
        flows = [
            FlowEvent(
                src_ip="192.168.1.75",
                dst_ip="198.51.100.10",
                src_port=50000,
                dst_port=80,  # HTTP
                protocol="TCP",
                bytes_tx=512,
                bytes_rx=1024,
                packet_count=10,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns + 1_000_000_000,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "flow_cleartext_credentials_detected"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["dst_port"] == 80
        assert events[0].data["app_protocol"] == "HTTP"

    def test_cleartext_ftp_detection(self):
        """Test cleartext FTP detection."""
        probe = CleartextCredentialLeakProbe()
        now_ns = int(time.time() * 1e9)

        # FTP traffic
        flows = [
            FlowEvent(
                src_ip="10.0.0.50",
                dst_ip="10.0.0.100",
                src_port=50000,
                dst_port=21,  # FTP
                protocol="TCP",
                bytes_tx=256,
                bytes_rx=512,
                packet_count=5,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns + 5_000_000_000,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].data["app_protocol"] == "FTP"
        # Internal FTP has lower severity
        assert events[0].severity == Severity.MEDIUM

    def test_suspicious_tunnel_detection(self):
        """Test suspicious tunnel detection."""
        probe = SuspiciousTunnelProbe()
        now_ns = int(time.time() * 1e9)

        # Long-lived connection with many small packets
        flows = [
            FlowEvent(
                src_ip="192.168.1.200",
                dst_ip="198.51.100.100",
                src_port=50000,
                dst_port=8443,  # Non-standard port
                protocol="TCP",
                bytes_tx=50000,  # 50 KB
                bytes_rx=45000,  # 45 KB
                packet_count=300,  # Many packets
                first_seen_ns=now_ns,
                last_seen_ns=now_ns + 700_000_000_000,  # 11+ minutes
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "flow_suspicious_tunnel_detected"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["dst_port"] == 8443
        assert events[0].data["duration_seconds"] > 600
        assert events[0].data["avg_packet_size"] < 500

    def test_internal_dns_recon(self):
        """Test internal DNS reconnaissance detection."""
        probe = InternalReconDNSFlowProbe()
        now_ns = int(time.time() * 1e9)

        # Create 120 DNS queries from same source
        flows = [
            FlowEvent(
                src_ip="10.0.0.50",
                dst_ip="10.0.0.1",  # Internal DNS server
                src_port=50000 + i,
                dst_port=53,  # DNS
                protocol="UDP",
                bytes_tx=64,
                bytes_rx=128,
                packet_count=1,
                first_seen_ns=now_ns + i * 100_000_000,  # 0.1s apart
                last_seen_ns=now_ns + i * 100_000_000,
                app_protocol="DNS",
            )
            for i in range(120)
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "flow_internal_dns_recon_suspected"
        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["src_ip"] == "10.0.0.50"
        assert events[0].data["unique_dns_queries"] == 120

    def test_new_external_service(self):
        """Test new external service detection."""
        probe = NewExternalServiceProbe()
        now_ns = int(time.time() * 1e9)

        # Connection to external service on non-standard port
        flows = [
            FlowEvent(
                src_ip="192.168.1.100",
                dst_ip="203.0.113.25",  # External
                src_port=50000,
                dst_port=8888,  # Non-standard
                protocol="TCP",
                bytes_tx=1024,
                bytes_rx=2048,
                packet_count=10,
                first_seen_ns=now_ns,
                last_seen_ns=now_ns + 5_000_000_000,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"flows": flows},
        )
        events = probe.scan(context)

        # Should detect first-time connection
        assert len(events) == 1
        assert events[0].event_type == "flow_new_external_service_seen"
        assert events[0].severity == Severity.INFO
        assert events[0].data["dst_ip"] == "203.0.113.25"
        assert events[0].data["dst_port"] == 8888

        # Second scan should not emit (already seen)
        events2 = probe.scan(context)
        assert len(events2) == 0

    def test_flow_event_helpers(self):
        """Test FlowEvent helper methods."""
        now_ns = int(time.time() * 1e9)

        flow = FlowEvent(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            src_port=50000,
            dst_port=445,
            protocol="TCP",
            bytes_tx=1000,
            bytes_rx=2000,
            packet_count=10,
            first_seen_ns=now_ns,
            last_seen_ns=now_ns + 5_000_000_000,  # 5 seconds later
        )

        # Test duration calculation
        assert 4.9 <= flow.duration_seconds() <= 5.1

        # Test total bytes
        assert flow.total_bytes() == 3000

        # Test is_internal for RFC1918
        assert flow.is_internal() is True

        # Test is_internal for external
        external_flow = FlowEvent(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",  # External
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            bytes_tx=100,
            bytes_rx=200,
            packet_count=5,
            first_seen_ns=now_ns,
            last_seen_ns=now_ns + 1_000_000_000,
        )
        assert external_flow.is_internal() is False

    def test_probe_mitre_coverage(self):
        """Test that all probes have MITRE technique mappings."""
        probes = create_flow_probes()

        for probe in probes:
            assert len(probe.mitre_techniques) > 0, f"{probe.name} missing MITRE techniques"
            assert len(probe.mitre_tactics) > 0, f"{probe.name} missing MITRE tactics"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
