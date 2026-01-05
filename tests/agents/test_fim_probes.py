#!/usr/bin/env python3
"""Tests for FIM micro-probes."""

import stat
import time

import pytest

from amoskys.agents.fim.probes import (
    BootloaderTamperProbe,
    ChangeType,
    ConfigBackdoorProbe,
    CriticalSystemFileChangeProbe,
    FileChange,
    FileState,
    LibraryHijackProbe,
    ServiceCreationProbe,
    SUIDBitChangeProbe,
    WebShellDropProbe,
    WorldWritableSensitiveProbe,
    create_fim_probes,
)
from amoskys.agents.common.probes import ProbeContext, Severity


class TestFIMProbes:
    """Test suite for FIM probes."""

    def test_create_fim_probes(self):
        """Test probe factory creates all 8 probes."""
        probes = create_fim_probes()
        assert len(probes) == 8

        probe_names = [p.name for p in probes]
        assert "critical_system_file_change" in probe_names
        assert "suid_bit_change" in probe_names
        assert "service_creation" in probe_names
        assert "webshell_drop" in probe_names
        assert "config_backdoor" in probe_names
        assert "library_hijack" in probe_names
        assert "bootloader_tamper" in probe_names
        assert "world_writable_sensitive" in probe_names

    def test_critical_system_file_change(self):
        """Test detection of critical system file modifications."""
        probe = CriticalSystemFileChangeProbe()
        now_ns = int(time.time() * 1e9)

        # Mock file changes for /bin/sudo
        old_state = FileState(
            path="/bin/sudo",
            sha256="a" * 64,
            size=123456,
            mode=0o104755,  # Regular file, rwxr-xr-x
            uid=0,
            gid=0,
            mtime_ns=now_ns - 1000000000,
            is_dir=False,
            is_symlink=False,
        )

        new_state = FileState(
            path="/bin/sudo",
            sha256="b" * 64,  # Different hash
            size=123457,
            mode=0o104755,
            uid=0,
            gid=0,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/bin/sudo",
                change_type=ChangeType.HASH_CHANGED,
                old_state=old_state,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "critical_file_tampered"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["path"] == "/bin/sudo"
        assert events[0].data["old_hash"] == "a" * 64
        assert events[0].data["new_hash"] == "b" * 64

    def test_suid_bit_change_detection(self):
        """Test detection of SUID bit additions."""
        probe = SUIDBitChangeProbe()
        now_ns = int(time.time() * 1e9)

        # File without SUID
        old_state = FileState(
            path="/tmp/malware",
            sha256="a" * 64,
            size=1024,
            mode=0o100755,  # Regular file, rwxr-xr-x (no SUID)
            uid=1000,
            gid=1000,
            mtime_ns=now_ns - 1000000000,
            is_dir=False,
            is_symlink=False,
        )

        # File with SUID added
        new_state = FileState(
            path="/tmp/malware",
            sha256="a" * 64,
            size=1024,
            mode=0o104755,  # Regular file, rwsr-xr-x (SUID set)
            uid=1000,
            gid=1000,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/tmp/malware",
                change_type=ChangeType.PERM_CHANGED,
                old_state=old_state,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "suid_bit_added"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["path"] == "/tmp/malware"
        assert events[0].data["mode"] == oct(0o104755)

    def test_sgid_bit_change_detection(self):
        """Test detection of SGID bit additions."""
        probe = SUIDBitChangeProbe()
        now_ns = int(time.time() * 1e9)

        old_state = FileState(
            path="/tmp/backdoor",
            sha256="a" * 64,
            size=1024,
            mode=0o100755,  # No SGID
            uid=1000,
            gid=1000,
            mtime_ns=now_ns - 1000000000,
            is_dir=False,
            is_symlink=False,
        )

        new_state = FileState(
            path="/tmp/backdoor",
            sha256="a" * 64,
            size=1024,
            mode=0o102755,  # SGID set
            uid=1000,
            gid=1000,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/tmp/backdoor",
                change_type=ChangeType.PERM_CHANGED,
                old_state=old_state,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "sgid_bit_added"
        assert events[0].severity == Severity.HIGH

    def test_service_creation_launchagent(self):
        """Test detection of new LaunchAgent creation."""
        probe = ServiceCreationProbe()
        now_ns = int(time.time() * 1e9)

        new_state = FileState(
            path="/Library/LaunchAgents/com.evil.persistence.plist",
            sha256="a" * 64,
            size=512,
            mode=0o100644,
            uid=0,
            gid=0,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/Library/LaunchAgents/com.evil.persistence.plist",
                change_type=ChangeType.CREATED,
                old_state=None,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "service_created"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["path"] == "/Library/LaunchAgents/com.evil.persistence.plist"

    def test_service_creation_systemd(self):
        """Test detection of new systemd service creation."""
        probe = ServiceCreationProbe()
        now_ns = int(time.time() * 1e9)

        new_state = FileState(
            path="/etc/systemd/system/malware.service",
            sha256="a" * 64,
            size=256,
            mode=0o100644,
            uid=0,
            gid=0,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/etc/systemd/system/malware.service",
                change_type=ChangeType.CREATED,
                old_state=None,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "service_created"

    def test_webshell_detection_php(self):
        """Test detection of PHP webshell with obfuscated patterns."""
        import tempfile
        import os

        probe = WebShellDropProbe()
        now_ns = int(time.time() * 1e9)

        # Create actual webshell file with suspicious pattern in /var/www
        os.makedirs("/tmp/test_var_www", exist_ok=True)
        webshell_path = "/tmp/test_var_www/shell.php"

        with open(webshell_path, 'w') as f:
            f.write('<?php eval(base64_decode($_POST["cmd"])); ?>')

        try:
            new_state = FileState(
                path=webshell_path,
                sha256="a" * 64,
                size=1024,
                mode=0o100644,
                uid=33,  # www-data
                gid=33,
                mtime_ns=now_ns,
                is_dir=False,
                is_symlink=False,
            )

            # Temporarily override the path check by using the real test file
            # Since the probe checks if path starts with web roots, we need to mock it
            import amoskys.agents.fim.probes as probes_module
            original_web_roots = probes_module.WEB_ROOTS
            probes_module.WEB_ROOTS = {"/tmp/test_var_www"}

            context = ProbeContext(
                device_id="test-device",
                agent_name="test-agent",
                shared_data={"file_changes": [FileChange(
                    path=webshell_path,  # Use actual path for the test
                    change_type=ChangeType.CREATED,
                    old_state=None,
                    new_state=new_state,
                    timestamp_ns=now_ns,
                )]},
            )
            events = probe.scan(context)

            # Restore original web roots
            probes_module.WEB_ROOTS = original_web_roots

            # Should detect webshell pattern
            assert len(events) == 1
            assert events[0].event_type == "webshell_detected"
            assert events[0].severity == Severity.CRITICAL
            assert webshell_path in events[0].data["path"]
        finally:
            if os.path.exists(webshell_path):
                os.unlink(webshell_path)
            if os.path.exists("/tmp/test_var_www"):
                os.rmdir("/tmp/test_var_www")

    def test_config_backdoor_sshd(self):
        """Test detection of SSH config modifications."""
        import tempfile
        import os

        probe = ConfigBackdoorProbe()
        now_ns = int(time.time() * 1e9)

        # Create actual SSH config with dangerous setting
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sshd_config', delete=False) as f:
            f.write('PermitRootLogin yes\n')
            f.write('Port 22\n')
            config_path = f.name

        try:
            old_state = FileState(
                path=config_path,
                sha256="a" * 64,
                size=2048,
                mode=0o100644,
                uid=0,
                gid=0,
                mtime_ns=now_ns - 1000000000,
                is_dir=False,
                is_symlink=False,
            )

            new_state = FileState(
                path=config_path,
                sha256="b" * 64,  # Modified
                size=2100,
                mode=0o100644,
                uid=0,
                gid=0,
                mtime_ns=now_ns,
                is_dir=False,
                is_symlink=False,
            )

            changes = [
                FileChange(
                    path=config_path,
                    change_type=ChangeType.HASH_CHANGED,
                    old_state=old_state,
                    new_state=new_state,
                    timestamp_ns=now_ns,
                )
            ]

            context = ProbeContext(
                device_id="test-device",
                agent_name="test-agent",
                shared_data={"file_changes": changes},
            )
            events = probe.scan(context)

            assert len(events) == 1
            assert events[0].event_type == "ssh_config_backdoor"
            assert events[0].severity == Severity.CRITICAL
            assert config_path in events[0].data["path"]
            assert "PermitRootLogin enabled" in events[0].data["dangerous_settings"]
        finally:
            os.unlink(config_path)

    def test_config_backdoor_sudoers(self):
        """Test detection of sudoers file tampering."""
        import tempfile
        import os

        probe = ConfigBackdoorProbe()
        now_ns = int(time.time() * 1e9)

        # Create actual sudoers with dangerous directive
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sudoers', delete=False) as f:
            f.write('attacker ALL=(ALL) NOPASSWD: ALL\n')
            sudoers_path = f.name

        try:
            old_state = FileState(
                path=sudoers_path,
                sha256="a" * 64,
                size=1024,
                mode=0o100440,
                uid=0,
                gid=0,
                mtime_ns=now_ns - 1000000000,
                is_dir=False,
                is_symlink=False,
            )

            new_state = FileState(
                path=sudoers_path,
                sha256="b" * 64,
                size=1100,
                mode=0o100440,
                uid=0,
                gid=0,
                mtime_ns=now_ns,
                is_dir=False,
                is_symlink=False,
            )

            changes = [
                FileChange(
                    path=sudoers_path,
                    change_type=ChangeType.HASH_CHANGED,
                    old_state=old_state,
                    new_state=new_state,
                    timestamp_ns=now_ns,
                )
            ]

            context = ProbeContext(
                device_id="test-device",
                agent_name="test-agent",
                shared_data={"file_changes": changes},
            )
            events = probe.scan(context)

            assert len(events) == 1
            assert events[0].event_type == "sudoers_backdoor"
            assert events[0].severity == Severity.CRITICAL
            assert "NOPASSWD:ALL directive" in events[0].data["dangerous_settings"]
        finally:
            os.unlink(sudoers_path)

    def test_library_hijack_ld_preload(self):
        """Test detection of LD_PRELOAD rootkit."""
        probe = LibraryHijackProbe()
        now_ns = int(time.time() * 1e9)

        # New ld.so.preload file created
        new_state = FileState(
            path="/etc/ld.so.preload",
            sha256="a" * 64,
            size=128,
            mode=0o100644,
            uid=0,
            gid=0,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/etc/ld.so.preload",
                change_type=ChangeType.CREATED,
                old_state=None,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "linker_config_modified"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["path"] == "/etc/ld.so.preload"

    def test_library_hijack_shared_library_drop(self):
        """Test detection of suspicious .so file creation."""
        probe = LibraryHijackProbe()
        now_ns = int(time.time() * 1e9)

        new_state = FileState(
            path="/lib/x86_64-linux-gnu/evil.so",
            sha256="a" * 64,
            size=8192,
            mode=0o100755,
            uid=0,
            gid=0,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/lib/x86_64-linux-gnu/evil.so",
                change_type=ChangeType.CREATED,
                old_state=None,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "new_system_library"
        assert events[0].severity == Severity.HIGH

    def test_bootloader_tamper_detection(self):
        """Test detection of bootloader/kernel tampering."""
        probe = BootloaderTamperProbe()
        now_ns = int(time.time() * 1e9)

        old_state = FileState(
            path="/boot/vmlinuz-5.10.0",
            sha256="a" * 64,
            size=8388608,  # 8MB
            mode=0o100644,
            uid=0,
            gid=0,
            mtime_ns=now_ns - 1000000000,
            is_dir=False,
            is_symlink=False,
        )

        new_state = FileState(
            path="/boot/vmlinuz-5.10.0",
            sha256="b" * 64,  # Modified kernel!
            size=8388608,
            mode=0o100644,
            uid=0,
            gid=0,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/boot/vmlinuz-5.10.0",
                change_type=ChangeType.HASH_CHANGED,
                old_state=old_state,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "bootloader_modified"
        assert events[0].severity == Severity.CRITICAL
        assert events[0].data["path"] == "/boot/vmlinuz-5.10.0"

    def test_world_writable_sensitive_detection(self):
        """Test detection of world-writable permissions on sensitive files."""
        probe = WorldWritableSensitiveProbe()
        now_ns = int(time.time() * 1e9)

        old_state = FileState(
            path="/etc/passwd",
            sha256="a" * 64,
            size=2048,
            mode=0o100644,  # rw-r--r-- (safe)
            uid=0,
            gid=0,
            mtime_ns=now_ns - 1000000000,
            is_dir=False,
            is_symlink=False,
        )

        new_state = FileState(
            path="/etc/passwd",
            sha256="a" * 64,
            size=2048,
            mode=0o100666,  # rw-rw-rw- (world writable!)
            uid=0,
            gid=0,
            mtime_ns=now_ns,
            is_dir=False,
            is_symlink=False,
        )

        changes = [
            FileChange(
                path="/etc/passwd",
                change_type=ChangeType.PERM_CHANGED,
                old_state=old_state,
                new_state=new_state,
                timestamp_ns=now_ns,
            )
        ]

        context = ProbeContext(
            device_id="test-device",
            agent_name="test-agent",
            shared_data={"file_changes": changes},
        )
        events = probe.scan(context)

        assert len(events) == 1
        assert events[0].event_type == "world_writable_sensitive"
        assert events[0].severity == Severity.HIGH
        assert events[0].data["path"] == "/etc/passwd"
        assert events[0].data["new_mode"] == oct(0o100666)

    def test_probe_mitre_coverage(self):
        """Test that all probes have MITRE technique mappings."""
        probes = create_fim_probes()

        for probe in probes:
            assert len(probe.mitre_techniques) > 0, f"{probe.name} missing MITRE techniques"
            assert len(probe.mitre_tactics) > 0, f"{probe.name} missing MITRE tactics"

    def test_file_state_suid_check(self):
        """Test FileState SUID/SGID helper methods."""
        # File with SUID
        suid_state = FileState(
            path="/bin/sudo",
            sha256="a" * 64,
            size=1024,
            mode=0o104755,  # SUID set
            uid=0,
            gid=0,
            mtime_ns=0,
            is_dir=False,
            is_symlink=False,
        )
        assert suid_state.has_suid() is True
        assert suid_state.has_sgid() is False

        # File with SGID
        sgid_state = FileState(
            path="/usr/bin/wall",
            sha256="b" * 64,
            size=1024,
            mode=0o102755,  # SGID set
            uid=0,
            gid=0,
            mtime_ns=0,
            is_dir=False,
            is_symlink=False,
        )
        assert sgid_state.has_suid() is False
        assert sgid_state.has_sgid() is True

        # Regular file
        regular_state = FileState(
            path="/tmp/file",
            sha256="c" * 64,
            size=1024,
            mode=0o100644,
            uid=1000,
            gid=1000,
            mtime_ns=0,
            is_dir=False,
            is_symlink=False,
        )
        assert regular_state.has_suid() is False
        assert regular_state.has_sgid() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
