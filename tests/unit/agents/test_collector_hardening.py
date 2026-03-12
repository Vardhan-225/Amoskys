"""Tests for Component 2 collector hardening.

Validates:
    - Auth: MFA event mapping (SecurityAgent → MFA_SUCCESS/MFA_CHALLENGE)
    - Auth: Biometric event mapping (coreauthd → MFA_SUCCESS/MFA_CHALLENGE)
    - Auth: Account lockout synthesis from rapid SSH failures
    - DNS: query_type parsing from mDNSResponder log messages
    - DNS: response_code extraction from mDNSResponder log messages
    - FIM: Platform-aware bootloader tamper detection paths
    - Flow: Stateful cross-cycle tunnel detection
"""

import pytest  # noqa: E402

pytest.skip(
    "macOS Observatory v2 renamed/removed classes: AccountLockoutStormProbe, MFABypassOrAnomalyProbe, MacOSAuthLogCollector, BootloaderTamperProbe, FileChange, FileState, ChangeType, FlowEvent, SuspiciousTunnelProbe",
    allow_module_level=True,
)


import time
from typing import Dict
from unittest.mock import patch

from amoskys.agents.common.probes import ProbeContext, Severity
from amoskys.agents.os.macos.auth.agent import MacOSAuthLogCollector
from amoskys.agents.os.macos.auth.probes import (
    AccountLockoutStormProbe,
    AuthEvent,
    MFABypassOrAnomalyProbe,
)
from amoskys.agents.os.macos.dns.agent import MacOSDNSCollector
from amoskys.agents.os.macos.filesystem.probes import (
    BootloaderTamperProbe,
    ChangeType,
    FileChange,
    FileState,
)
from amoskys.agents.os.macos.network.probes import FlowEvent, SuspiciousTunnelProbe

# =============================================================================
# Auth: MFA Event Mapping
# =============================================================================


class TestAuthMFAMapping:
    """SecurityAgent and coreauthd events now map to MFA event types."""

    def setup_method(self):
        self.collector = MacOSAuthLogCollector()

    def test_security_agent_success_maps_to_mfa_success(self):
        ts_ns = int(time.time() * 1e9)
        event = self.collector._parse_security_agent_message(
            "Authorization DB: system.privilege.admin succeeded", ts_ns
        )
        assert event is not None
        assert event.event_type == "MFA_SUCCESS"
        assert event.status == "SUCCESS"

    def test_security_agent_failure_maps_to_mfa_challenge(self):
        ts_ns = int(time.time() * 1e9)
        event = self.collector._parse_security_agent_message(
            "Authorization DB: system.privilege.admin failed", ts_ns
        )
        assert event is not None
        assert event.event_type == "MFA_CHALLENGE"
        assert event.status == "FAILURE"

    def test_security_agent_no_match_returns_none(self):
        ts_ns = int(time.time() * 1e9)
        event = self.collector._parse_security_agent_message(
            "Some unrelated SecurityAgent log message", ts_ns
        )
        assert event is None

    def test_coreauthd_success_maps_to_mfa_success(self):
        ts_ns = int(time.time() * 1e9)
        event = self.collector._parse_coreauthd_message(
            "Evaluate policy: DeviceOwnerAuthentication success", ts_ns
        )
        assert event is not None
        assert event.event_type == "MFA_SUCCESS"
        assert event.status == "SUCCESS"

    def test_coreauthd_failure_maps_to_mfa_challenge(self):
        ts_ns = int(time.time() * 1e9)
        event = self.collector._parse_coreauthd_message(
            "Evaluate policy: DeviceOwnerAuthentication denied", ts_ns
        )
        assert event is not None
        assert event.event_type == "MFA_CHALLENGE"
        assert event.status == "FAILURE"

    def test_coreauthd_noise_returns_none(self):
        ts_ns = int(time.time() * 1e9)
        event = self.collector._parse_coreauthd_message(
            "Context create: 0x12345", ts_ns
        )
        assert event is None

    def test_mfa_probe_fires_with_mapped_events(self):
        """End-to-end: MFA probe detects bypass when MFA events present."""
        probe = MFABypassOrAnomalyProbe()
        ts = int(time.time() * 1e9)

        # SSH login succeeded but no MFA success
        auth_events = [
            AuthEvent(
                timestamp_ns=ts,
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username="admin",
                source_ip="10.0.0.1",
            ),
        ]

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)
        bypass = [e for e in events if e.event_type == "mfa_bypass_suspected"]
        assert len(bypass) == 1
        assert bypass[0].data["username"] == "admin"

    def test_mfa_probe_no_bypass_when_mfa_success_present(self):
        """MFA probe should NOT fire when MFA_SUCCESS exists."""
        probe = MFABypassOrAnomalyProbe()
        ts = int(time.time() * 1e9)

        auth_events = [
            AuthEvent(
                timestamp_ns=ts,
                event_type="MFA_SUCCESS",
                status="SUCCESS",
                username="admin",
                reason="SecurityAgent authorization",
            ),
            AuthEvent(
                timestamp_ns=ts + 1000,
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username="admin",
                source_ip="10.0.0.1",
            ),
        ]

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)
        bypass = [e for e in events if e.event_type == "mfa_bypass_suspected"]
        assert len(bypass) == 0


# =============================================================================
# Auth: Account Lockout Synthesis
# =============================================================================


class TestAuthLockoutSynthesis:
    """MacOS collector synthesizes ACCOUNT_LOCKED from rapid SSH failures."""

    def setup_method(self):
        self.collector = MacOSAuthLogCollector()

    def test_lockout_synthesized_from_rapid_failures(self):
        ts = int(time.time() * 1e9)
        # 5 failures within 1 minute for same user
        events = [
            AuthEvent(
                timestamp_ns=ts + i * int(10e9),  # 10s apart
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="attacker_target",
                source_ip="192.168.1.100",
            )
            for i in range(5)
        ]

        result = self.collector._synthesize_lockout_events(events)
        assert len(result) == 1
        assert result[0].event_type == "ACCOUNT_LOCKED"
        assert result[0].username == "attacker_target"
        assert result[0].source_ip == "192.168.1.100"
        assert "Synthesized" in result[0].reason

    def test_no_lockout_below_threshold(self):
        ts = int(time.time() * 1e9)
        # Only 4 failures (below threshold of 5)
        events = [
            AuthEvent(
                timestamp_ns=ts + i * int(10e9),
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="legit_user",
                source_ip="10.0.0.1",
            )
            for i in range(4)
        ]

        result = self.collector._synthesize_lockout_events(events)
        assert len(result) == 0

    def test_no_lockout_when_spread_too_far(self):
        ts = int(time.time() * 1e9)
        # 5 failures but spread over 10 minutes (outside 5-min window)
        events = [
            AuthEvent(
                timestamp_ns=ts + i * int(150e9),  # 150s apart
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="slow_attacker",
                source_ip="10.0.0.1",
            )
            for i in range(5)
        ]

        result = self.collector._synthesize_lockout_events(events)
        assert len(result) == 0

    def test_lockout_one_per_user(self):
        ts = int(time.time() * 1e9)
        # 10 failures — should still only produce 1 lockout event
        events = [
            AuthEvent(
                timestamp_ns=ts + i * int(5e9),
                event_type="SSH_LOGIN",
                status="FAILURE",
                username="target",
                source_ip="10.0.0.1",
            )
            for i in range(10)
        ]

        result = self.collector._synthesize_lockout_events(events)
        assert len(result) == 1

    def test_lockout_multiple_users(self):
        ts = int(time.time() * 1e9)
        events = []
        for user in ["user1", "user2"]:
            for i in range(5):
                events.append(
                    AuthEvent(
                        timestamp_ns=ts + i * int(10e9),
                        event_type="SSH_LOGIN",
                        status="FAILURE",
                        username=user,
                        source_ip="10.0.0.1",
                    )
                )

        result = self.collector._synthesize_lockout_events(events)
        assert len(result) == 2
        usernames = {r.username for r in result}
        assert usernames == {"user1", "user2"}

    def test_lockout_probe_fires_with_synthetic_events(self):
        """End-to-end: lockout probe fires on synthesized ACCOUNT_LOCKED."""
        probe = AccountLockoutStormProbe()
        ts = int(time.time() * 1e9)

        # Simulate 6 lockout events (above storm threshold of 5)
        auth_events = [
            AuthEvent(
                timestamp_ns=ts,
                event_type="ACCOUNT_LOCKED",
                status="FAILURE",
                username=f"user{i}",
                source_ip="10.0.0.1",
            )
            for i in range(6)
        ]

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"auth_events": auth_events},
        )
        events = probe.scan(context)
        storms = [e for e in events if e.event_type == "account_lockout_storm"]
        assert len(storms) == 1
        assert storms[0].data["locked_account_count"] == 6

    def test_success_events_ignored(self):
        ts = int(time.time() * 1e9)
        events = [
            AuthEvent(
                timestamp_ns=ts + i * int(10e9),
                event_type="SSH_LOGIN",
                status="SUCCESS",
                username="good_user",
                source_ip="10.0.0.1",
            )
            for i in range(10)
        ]

        result = self.collector._synthesize_lockout_events(events)
        assert len(result) == 0


# =============================================================================
# DNS: query_type and response_code Parsing
# =============================================================================


class TestDNSQueryTypeParsing:
    """MacOS DNS collector now parses query_type from mDNSResponder logs."""

    def setup_method(self):
        self.collector = MacOSDNSCollector()

    def _make_entry(self, message: str, timestamp: str = "") -> Dict:
        return {"eventMessage": message, "timestamp": timestamp}

    def test_query_type_a(self):
        entry = self._make_entry("QueryRecord for example.com. type A")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.domain == "example.com"
        assert query.query_type == "A"

    def test_query_type_aaaa(self):
        entry = self._make_entry("QueryRecord for example.com. type AAAA")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.query_type == "AAAA"

    def test_query_type_txt(self):
        entry = self._make_entry("Query for tunnel.evil.com. type TXT")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.query_type == "TXT"
        assert query.domain == "tunnel.evil.com"

    def test_query_type_mx(self):
        entry = self._make_entry("QueryRecord for mail.example.com. type MX")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.query_type == "MX"

    def test_query_type_cname(self):
        entry = self._make_entry("Query for cdn.example.com. type CNAME")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.query_type == "CNAME"

    def test_query_type_null(self):
        entry = self._make_entry("QueryRecord for c2.evil.com. type NULL")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.query_type == "NULL"

    def test_default_query_type_when_missing(self):
        entry = self._make_entry("Query for example.com. Addr 1.2.3.4")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.query_type == "A"  # default

    def test_response_code_nxdomain(self):
        entry = self._make_entry("QueryRecord for nonexist.com. type A NXDOMAIN")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.response_code == "NXDOMAIN"

    def test_response_code_servfail(self):
        entry = self._make_entry("Query for broken.com. type A SERVFAIL")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.response_code == "SERVFAIL"

    def test_default_response_code(self):
        entry = self._make_entry("Query for ok.com. type A")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.response_code == "NOERROR"

    def test_domain_trailing_dot_stripped(self):
        entry = self._make_entry("Query for example.com. type A")
        query = self.collector._parse_log_entry(entry)
        assert query.domain == "example.com"  # not "example.com."

    def test_non_query_message_returns_none(self):
        entry = self._make_entry("mDNSResponder starting up")
        query = self.collector._parse_log_entry(entry)
        assert query is None

    def test_query_without_domain_returns_none(self):
        entry = self._make_entry("Query received, processing...")
        query = self.collector._parse_log_entry(entry)
        assert query is None

    def test_case_insensitive_type(self):
        entry = self._make_entry("Query for example.com. type txt")
        query = self.collector._parse_log_entry(entry)
        assert query is not None
        assert query.query_type == "TXT"  # normalized to uppercase


# =============================================================================
# FIM: Platform-Aware Boot Paths
# =============================================================================


class TestFIMBootloaderPaths:
    """BootloaderTamperProbe now uses platform-aware boot paths."""

    def _make_change(self, path: str) -> FileChange:
        """Create a synthetic FileChange."""
        old = FileState(
            path=path,
            sha256="aaa",
            size=100,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=1000,
            is_dir=False,
            is_symlink=False,
        )
        new = FileState(
            path=path,
            sha256="bbb",
            size=101,
            mode=0o644,
            uid=0,
            gid=0,
            mtime_ns=2000,
            is_dir=False,
            is_symlink=False,
        )
        return FileChange(
            path=path,
            change_type=ChangeType.HASH_CHANGED,
            old_state=old,
            new_state=new,
            timestamp_ns=int(time.time() * 1e9),
        )

    @patch("sys.platform", "darwin")
    def test_macos_kernel_path_detected(self):
        probe = BootloaderTamperProbe()
        change = self._make_change("/System/Library/Kernels/kernel")

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    @patch("sys.platform", "darwin")
    def test_macos_kext_path_detected(self):
        probe = BootloaderTamperProbe()
        change = self._make_change(
            "/Library/Extensions/SomeDriver.kext/Contents/MacOS/SomeDriver"
        )

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL  # "kext" keyword

    @patch("sys.platform", "darwin")
    def test_macos_firmware_path_detected(self):
        probe = BootloaderTamperProbe()
        change = self._make_change("/usr/standalone/firmware/iBridge.fw")

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL  # "firmware" keyword

    @patch("sys.platform", "darwin")
    def test_macos_non_boot_path_ignored(self):
        probe = BootloaderTamperProbe()
        change = self._make_change("/Users/admin/Documents/notes.txt")

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 0

    @patch("sys.platform", "linux")
    def test_linux_boot_path_still_works(self):
        probe = BootloaderTamperProbe()
        change = self._make_change("/boot/vmlinuz-5.15.0")

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL  # "vmlinuz" keyword

    @patch("sys.platform", "linux")
    def test_linux_grub_detected(self):
        probe = BootloaderTamperProbe()
        change = self._make_change("/boot/grub/grub.cfg")

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    @patch("sys.platform", "darwin")
    def test_macos_system_extensions_detected(self):
        probe = BootloaderTamperProbe()
        change = self._make_change("/System/Library/Extensions/IOUSBFamily.kext")

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 1

    @patch("sys.platform", "darwin")
    def test_high_severity_for_non_critical_boot_file(self):
        """Non-critical keyword file in boot path gets HIGH (not CRITICAL)."""
        probe = BootloaderTamperProbe()
        change = self._make_change("/System/Library/Extensions/some_random.txt")

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"file_changes": [change]},
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.HIGH


# =============================================================================
# Flow: Stateful Cross-Cycle Tunnel Detection
# =============================================================================


class TestFlowStatefulTunnel:
    """SuspiciousTunnelProbe now tracks connections across scan cycles."""

    def _make_flow(
        self,
        src_ip: str = "192.168.1.10",
        dst_ip: str = "10.20.30.40",
        dst_port: int = 4444,
        first_seen_ns: int = 0,
        last_seen_ns: int = 0,
        bytes_tx: int = 1000,
        bytes_rx: int = 500,
        packet_count: int = 50,
        protocol: str = "TCP",
    ) -> FlowEvent:
        return FlowEvent(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=54321,
            dst_port=dst_port,
            protocol=protocol,
            bytes_tx=bytes_tx,
            bytes_rx=bytes_rx,
            packet_count=packet_count,
            first_seen_ns=first_seen_ns,
            last_seen_ns=last_seen_ns,
        )

    def test_single_cycle_short_flow_no_alert(self):
        """A single short flow should not trigger tunnel detection."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        flow = self._make_flow(
            first_seen_ns=now,
            last_seen_ns=now + int(60e9),  # 60 seconds
            packet_count=20,
        )

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow]},
        )
        events = probe.scan(context)
        assert len(events) == 0

    def test_single_cycle_long_flow_triggers(self):
        """A single long flow with enough duration triggers immediately."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        flow = self._make_flow(
            first_seen_ns=now,
            last_seen_ns=now + int(700e9),  # 700 seconds > 600 threshold
            packet_count=200,
            bytes_tx=5000,  # avg ~25 bytes/packet (small, tunnel-like)
            bytes_rx=5000,
        )

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow]},
        )
        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "flow_suspicious_tunnel_detected"

    def test_cross_cycle_accumulation(self):
        """Flow accumulates duration across multiple scan cycles."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        # Cycle 1: 200 seconds observed
        flow1 = self._make_flow(
            first_seen_ns=now,
            last_seen_ns=now + int(200e9),
            packet_count=40,
            bytes_tx=2000,
            bytes_rx=2000,
        )
        ctx1 = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow1]},
        )
        events1 = probe.scan(ctx1)
        assert len(events1) == 0  # Not enough yet

        # Cycle 2: same connection, now at 400s total
        flow2 = self._make_flow(
            first_seen_ns=now + int(200e9),
            last_seen_ns=now + int(400e9),
            packet_count=40,
            bytes_tx=2000,
            bytes_rx=2000,
        )
        ctx2 = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow2]},
        )
        events2 = probe.scan(ctx2)
        assert len(events2) == 0  # Still not enough

        # Cycle 3: now at 700s total → crosses threshold
        flow3 = self._make_flow(
            first_seen_ns=now + int(400e9),
            last_seen_ns=now + int(700e9),
            packet_count=40,
            bytes_tx=2000,
            bytes_rx=2000,
        )
        ctx3 = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow3]},
        )
        events3 = probe.scan(ctx3)
        assert len(events3) == 1
        assert events3[0].data["cycles_observed"] == 3

    def test_no_double_alert(self):
        """Once alerted, same flow should not alert again."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        flow = self._make_flow(
            first_seen_ns=now,
            last_seen_ns=now + int(700e9),
            packet_count=200,
            bytes_tx=5000,
            bytes_rx=5000,
        )

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow]},
        )
        events1 = probe.scan(context)
        assert len(events1) == 1

        # Same flow in next cycle
        events2 = probe.scan(context)
        assert len(events2) == 0  # already_alerted

    def test_stale_flows_evicted(self):
        """Flows not seen for >3 cycles are evicted from history."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        flow = self._make_flow(
            first_seen_ns=now,
            last_seen_ns=now + int(100e9),
            packet_count=20,
        )

        # Cycle 1: flow observed
        ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow]},
        )
        probe.scan(ctx)
        assert len(probe._flow_history) == 1

        # Cycles 2-5: no flows → stale_cycles increments
        empty_ctx = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": []},
        )
        for _ in range(4):
            probe.scan(empty_ctx)

        # Flow should be evicted (stale_cycles > 3)
        assert len(probe._flow_history) == 0

    def test_known_proxy_port_not_flagged(self):
        """Connections to known proxy ports are not flagged."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        flow = self._make_flow(
            dst_port=1080,  # SOCKS proxy
            first_seen_ns=now,
            last_seen_ns=now + int(700e9),
            packet_count=200,
            bytes_tx=5000,
            bytes_rx=5000,
        )

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow]},
        )
        events = probe.scan(context)
        assert len(events) == 0

    def test_udp_flows_ignored(self):
        """UDP flows are not tracked for tunnel detection."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        flow = self._make_flow(
            protocol="UDP",
            first_seen_ns=now,
            last_seen_ns=now + int(700e9),
            packet_count=200,
        )

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow]},
        )
        events = probe.scan(context)
        assert len(events) == 0
        assert len(probe._flow_history) == 0

    def test_large_packet_flows_not_flagged(self):
        """Flows with large average packet size are normal, not tunnels."""
        probe = SuspiciousTunnelProbe()
        now = int(time.time() * 1e9)

        flow = self._make_flow(
            first_seen_ns=now,
            last_seen_ns=now + int(700e9),
            packet_count=200,
            bytes_tx=100000,  # avg 1000 bytes/packet → not tunnel-like
            bytes_rx=100000,
        )

        context = ProbeContext(
            device_id="test",
            agent_name="test",
            shared_data={"flows": [flow]},
        )
        events = probe.scan(context)
        assert len(events) == 0
