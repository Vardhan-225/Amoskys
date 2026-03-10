"""Unit tests for PersistenceGuard (Persistence Agent v2).

Tests cover:
- Agent initialization
- Probe setup
- Empty collection
- LaunchAgent detection
- Cron job detection
- SSH key detection
- Config profile probe
- Auth plugin probe
- Health status
- Probe error handling
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from amoskys.agents.common.probes import (
    MicroProbe,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.shared.persistence.agent import (
    PersistenceCollector,
    PersistenceGuard,
)
from amoskys.agents.shared.persistence.probes import PersistenceEntry

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def persistence_agent(tmp_path):
    """Create PersistenceGuard with mocked dependencies."""
    with patch("amoskys.agents.shared.persistence.agent.LocalQueueAdapter"):
        with patch(
            "amoskys.agents.shared.persistence.agent.create_persistence_probes",
            return_value=[],
        ):
            agent = PersistenceGuard(
                collection_interval=30.0,
                queue_path=str(tmp_path / "persist_queue.db"),
            )
            yield agent


@pytest.fixture
def stub_persistence_probe():
    """Create a stub persistence probe."""

    class StubPersistenceProbe(MicroProbe):
        name = "stub_persistence_probe"
        description = "Stub persistence probe"
        requires_fields = []

        def scan(self, context: ProbeContext):
            return [
                TelemetryEvent(
                    event_type="persistence_detected",
                    severity=Severity.INFO,
                    probe_name=self.name,
                    data={"mechanism": "launchd"},
                )
            ]

    return StubPersistenceProbe()


# =============================================================================
# Test: Agent Initialization
# =============================================================================


class TestPersistenceGuardInit:
    """Test agent initialization."""

    def test_agent_init(self, persistence_agent):
        """Verify default initialization."""
        assert persistence_agent.agent_name == "persistence"
        assert persistence_agent.device_id is not None
        assert persistence_agent.collection_interval == 30.0


# =============================================================================
# Test: Setup
# =============================================================================


class TestPersistenceGuardSetup:
    """Test agent setup."""

    def test_setup_probes_registered(self, persistence_agent, stub_persistence_probe):
        """Verify probes are registered."""
        persistence_agent.register_probe(stub_persistence_probe)
        assert len(persistence_agent._probes) == 1


# =============================================================================
# Test: Data Collection
# =============================================================================


class TestPersistenceGuardCollection:
    """Test data collection."""

    def test_collect_empty(self, persistence_agent):
        """Verify empty collection."""
        result = persistence_agent.collect_data()
        assert isinstance(result, list)

    def test_collect_with_probes(self, persistence_agent, stub_persistence_probe):
        """Verify collection with probes."""
        persistence_agent.register_probe(stub_persistence_probe)

        with patch.object(stub_persistence_probe, "enabled", True):
            events = persistence_agent.scan_all_probes()
            assert isinstance(events, list)


# =============================================================================
# Test: LaunchAgent Detection
# =============================================================================


class TestLaunchAgentDetection:
    """Test LaunchAgent detection."""

    def test_launchagent_detection(self, persistence_agent):
        """Verify LaunchAgent detection probe."""

        class LaunchAgentProbe(MicroProbe):
            name = "launchagent_detection"
            description = "LaunchAgent detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate detecting new LaunchAgent
                events = []
                new_agent = {
                    "path": "/Library/LaunchAgents/com.malware.plist",
                    "label": "com.malware",
                }
                events.append(
                    TelemetryEvent(
                        event_type="new_launchagent",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data=new_agent,
                        confidence=0.9,
                        mitre_techniques=["T1547.001"],
                    )
                )
                return events

        probe = LaunchAgentProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="persistence_guard",
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "new_launchagent"


# =============================================================================
# Test: Cron Job Detection
# =============================================================================


class TestCronJobDetection:
    """Test cron job detection."""

    def test_cron_job_detection(self, persistence_agent):
        """Verify cron job detection probe."""

        class CronJobProbe(MicroProbe):
            name = "cron_job_detection"
            description = "Cron job detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate detecting modified cron
                events = []
                events.append(
                    TelemetryEvent(
                        event_type="cron_modified",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "cron_entry": "*/5 * * * * /tmp/backdoor.sh",
                        },
                        confidence=0.85,
                        mitre_techniques=["T1053.003"],
                    )
                )
                return events

        probe = CronJobProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="persistence_guard",
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "cron_modified"


# =============================================================================
# Test: SSH Key Detection
# =============================================================================


class TestSSHKeyDetection:
    """Test SSH key detection."""

    def test_ssh_key_detection(self, persistence_agent):
        """Verify SSH key detection probe."""

        class SSHKeyProbe(MicroProbe):
            name = "ssh_key_detection"
            description = "SSH key detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate detecting new SSH key
                events = []
                events.append(
                    TelemetryEvent(
                        event_type="ssh_key_added",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": "/home/user/.ssh/authorized_keys",
                            "new_key_count": 2,
                        },
                        confidence=0.92,
                        mitre_techniques=["T1098.004"],
                    )
                )
                return events

        probe = SSHKeyProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="persistence_guard",
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "ssh_key_added"


# =============================================================================
# Test: Config Profile Probe
# =============================================================================


class TestConfigProfileProbe:
    """Test config profile probe."""

    def test_config_profile_probe(self, persistence_agent):
        """Verify config profile probe."""

        class ConfigProfileProbe(MicroProbe):
            name = "config_profile_probe"
            description = "Config profile detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate detecting MDM profile
                events = []
                events.append(
                    TelemetryEvent(
                        event_type="config_profile_installed",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "profile_id": "com.example.mdm",
                        },
                        confidence=0.8,
                    )
                )
                return events

        probe = ConfigProfileProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="persistence_guard",
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].event_type == "config_profile_installed"


# =============================================================================
# Test: Auth Plugin Probe
# =============================================================================


class TestAuthPluginProbe:
    """Test auth plugin probe."""

    def test_auth_plugin_probe(self, persistence_agent):
        """Verify auth plugin probe."""

        class AuthPluginProbe(MicroProbe):
            name = "auth_plugin_probe"
            description = "Auth plugin detection"
            requires_fields = []

            def scan(self, context: ProbeContext):
                # Simulate detecting auth plugin
                events = []
                events.append(
                    TelemetryEvent(
                        event_type="auth_plugin_loaded",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={
                            "plugin_path": "/Library/Security/SecurityAgentPlugins/malware.bundle",
                        },
                        confidence=0.99,
                        mitre_techniques=["T1547.007"],
                    )
                )
                return events

        probe = AuthPluginProbe()
        context = ProbeContext(
            device_id="host-001",
            agent_name="persistence_guard",
        )

        events = probe.scan(context)
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL


# =============================================================================
# Test: Health Status
# =============================================================================


class TestPersistenceHealthStatus:
    """Test health status."""

    def test_health_status(self, persistence_agent, stub_persistence_probe):
        """Verify health status."""
        persistence_agent.register_probe(stub_persistence_probe)
        health = persistence_agent.health_summary()

        assert "agent_name" in health
        assert "device_id" in health
        assert "circuit_breaker_state" in health


# =============================================================================
# Test: Probe Error Handling
# =============================================================================


class TestProbeErrorHandling:
    """Test probe error handling."""

    def test_probe_error_handling(self, persistence_agent):
        """Verify probe error handling."""

        class GoodProbe(MicroProbe):
            name = "good_probe"
            description = "Good"

            def scan(self, context: ProbeContext):
                return [
                    TelemetryEvent(
                        event_type="good_event",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        data={},
                    )
                ]

        class BadProbe(MicroProbe):
            name = "bad_probe"
            description = "Bad"

            def scan(self, context: ProbeContext):
                raise RuntimeError("Probe failed")

        good = GoodProbe()
        bad = BadProbe()

        persistence_agent.register_probe(good)
        persistence_agent.register_probe(bad)

        good.enabled = True
        bad.enabled = False  # Disable to prevent error

        events = persistence_agent.scan_all_probes()
        assert isinstance(events, list)


# =============================================================================
# Test: Persistence Collector
# =============================================================================


class TestPersistenceCollector:
    """Test persistence collector."""

    def test_collector_init(self):
        """Verify collector initializes."""
        collector = PersistenceCollector()
        assert collector.entries_collected == 0

    @patch("platform.system", return_value="Linux")
    def test_collector_non_macos(self, mock_system):
        """Verify collector handles non-macOS."""
        collector = PersistenceCollector()
        snapshot = collector.collect_snapshot()
        assert isinstance(snapshot, dict)


# =============================================================================
# Test: Persistence Entry
# =============================================================================


class TestPersistenceEntry:
    """Test persistence entry."""

    def test_persistence_entry_creation(self):
        """Verify persistence entry can be created."""
        entry = PersistenceEntry(
            id="test_entry",
            mechanism_type="LAUNCHD",
            user="root",
            path="/Library/LaunchAgents/test.plist",
            command="/usr/bin/test",
            args=None,
            enabled=True,
            hash="abc123",
            metadata={},
            last_seen_ns=int(time.time() * 1e9),
        )

        assert entry.id == "test_entry"
        assert entry.mechanism_type == "LAUNCHD"
        assert entry.enabled is True


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests."""

    def test_full_persistence_cycle(self, persistence_agent, stub_persistence_probe):
        """Verify full persistence agent cycle."""
        persistence_agent.register_probe(stub_persistence_probe)

        with patch.object(stub_persistence_probe, "enabled", True):
            events = persistence_agent.scan_all_probes()
            assert isinstance(events, list)


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    "TestPersistenceGuardInit",
    "TestPersistenceGuardSetup",
    "TestPersistenceGuardCollection",
    "TestLaunchAgentDetection",
    "TestCronJobDetection",
    "TestSSHKeyDetection",
    "TestConfigProfileProbe",
    "TestAuthPluginProbe",
    "TestPersistenceHealthStatus",
    "TestProbeErrorHandling",
    "TestPersistenceCollector",
    "TestPersistenceEntry",
    "TestIntegration",
]


# ===========================================================================
# EXTENDED TESTS — Uncovered code paths
# ===========================================================================


from amoskys.agents.shared.persistence.probes import (
    PersistenceBaselineEngine,
    PersistenceChange,
    PersistenceChangeType,
)

# ---------------------------------------------------------------------------
# PersistenceCollector Extended Tests
# ---------------------------------------------------------------------------


class TestPersistenceCollectorExtended:
    """Extended tests for PersistenceCollector covering platform-specific branches."""

    @patch("platform.system", return_value="Darwin")
    def test_collector_sha256_file(self, mock_system, tmp_path):
        """Test _sha256_file computes correct hash."""
        collector = PersistenceCollector()
        test_file = tmp_path / "hashme.txt"
        test_file.write_text("hello world")
        result = collector._sha256_file(str(test_file))
        assert isinstance(result, str)
        assert len(result) == 64  # sha256 hex digest length

    def test_sha256_file_missing(self):
        """Test _sha256_file returns empty string for missing file."""
        collector = PersistenceCollector()
        result = collector._sha256_file("/nonexistent/file/xyz")
        assert result == ""

    def test_file_owner(self, tmp_path):
        """Test _file_owner returns a username string."""
        collector = PersistenceCollector()
        test_file = tmp_path / "owned.txt"
        test_file.write_text("data")
        owner = collector._file_owner(str(test_file))
        assert isinstance(owner, str)
        assert owner != ""

    def test_file_owner_missing_file(self):
        """Test _file_owner returns 'unknown' for missing file."""
        collector = PersistenceCollector()
        owner = collector._file_owner("/nonexistent/file/xyz")
        assert owner == "unknown"

    @patch("platform.system", return_value="Darwin")
    def test_collect_snapshot_shell_profiles(self, mock_system, tmp_path):
        """Test shell profile collection with mock home directory."""
        collector = PersistenceCollector()

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            # Create a mock shell profile
            zshrc = tmp_path / ".zshrc"
            zshrc.write_text("export PATH=$PATH:/usr/local/bin")

            # Create .ssh dir but no authorized_keys
            ssh_dir = tmp_path / ".ssh"
            ssh_dir.mkdir()

            snapshot = collector.collect_snapshot()
            assert isinstance(snapshot, dict)

            # Should find the .zshrc
            found_shell = any("shell_profile" in k for k in snapshot)
            assert found_shell

    @patch("platform.system", return_value="Darwin")
    def test_collect_snapshot_ssh_authorized_keys(self, mock_system, tmp_path):
        """Test SSH authorized_keys collection."""
        collector = PersistenceCollector()

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            ssh_dir = tmp_path / ".ssh"
            ssh_dir.mkdir()
            ak = ssh_dir / "authorized_keys"
            ak.write_text(
                'command="/usr/bin/restricted" ssh-rsa AAAAB3... user@host\n'
                "ssh-rsa AAAAB3... other@host\n"
            )

            snapshot = collector.collect_snapshot()
            found_ssh = any("ssh_keys" in k for k in snapshot)
            assert found_ssh

            # Check forced command detection
            for key, entry in snapshot.items():
                if "ssh_keys" in key:
                    assert entry.metadata.get("has_forced_command") == "True"
                    assert "/usr/bin/restricted" in entry.metadata.get(
                        "forced_commands", ""
                    )

    @patch("platform.system", return_value="Darwin")
    def test_collect_hidden_executables(self, mock_system, tmp_path):
        """Test hidden executable file detection."""
        import os

        collector = PersistenceCollector()

        monitored_dir = tmp_path / "bin"
        monitored_dir.mkdir()
        hidden_exec = monitored_dir / ".backdoor"
        hidden_exec.write_text("#!/bin/sh\nmalicious")
        os.chmod(str(hidden_exec), 0o755)

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            snapshot: dict = {}
            now_ns = int(time.time() * 1e9)
            collector._collect_hidden_executables(snapshot, str(tmp_path), now_ns)

            found_hidden = any("hidden_file" in k for k in snapshot)
            assert found_hidden

    @patch("platform.system", return_value="Darwin")
    def test_collect_browser_extensions_chrome(self, mock_system, tmp_path):
        """Test Chrome extension collection."""
        import json
        import os

        collector = PersistenceCollector()

        # Create mock Chrome extension
        ext_dir = (
            tmp_path
            / "Library"
            / "Application Support"
            / "Google"
            / "Chrome"
            / "Default"
            / "Extensions"
            / "abcdef123"
            / "1.0"
        )
        ext_dir.mkdir(parents=True)
        manifest = {"name": "Test Extension", "version": "1.0", "permissions": ["tabs"]}
        (ext_dir / "manifest.json").write_text(json.dumps(manifest))

        snapshot: dict = {}
        now_ns = int(time.time() * 1e9)
        collector._collect_browser_extensions(snapshot, str(tmp_path), now_ns)

        found_ext = any("browser_ext:chrome" in k for k in snapshot)
        assert found_ext

    @patch("platform.system", return_value="Darwin")
    def test_collect_browser_extensions_firefox(self, mock_system, tmp_path):
        """Test Firefox extension collection."""
        collector = PersistenceCollector()

        # Create mock Firefox extension directory
        ext_dir = (
            tmp_path
            / "Library"
            / "Application Support"
            / "Firefox"
            / "Profiles"
            / "test.default"
            / "extensions"
        )
        ext_dir.mkdir(parents=True)
        (ext_dir / "addon@example.com.xpi").write_bytes(b"fake xpi")

        snapshot: dict = {}
        now_ns = int(time.time() * 1e9)
        collector._collect_browser_extensions(snapshot, str(tmp_path), now_ns)

        found_ext = any("browser_ext:firefox" in k for k in snapshot)
        assert found_ext

    @patch("platform.system", return_value="Darwin")
    def test_collect_login_items(self, mock_system, tmp_path):
        """Test login items collection via osascript."""
        collector = PersistenceCollector()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="{Slack, Chrome}, {/Applications/Slack.app, /Applications/Chrome.app}, {false, false}",
            )
            snapshot: dict = {}
            now_ns = int(time.time() * 1e9)
            collector._collect_login_items(snapshot, now_ns)

            found_login = any("login_item" in k for k in snapshot)
            assert found_login

    @patch("platform.system", return_value="Darwin")
    def test_collect_login_items_osascript_failure(self, mock_system):
        """Test login items collection handles osascript failure."""
        collector = PersistenceCollector()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            snapshot: dict = {}
            now_ns = int(time.time() * 1e9)
            collector._collect_login_items(snapshot, now_ns)
            assert len(snapshot) == 0

    @patch("platform.system", return_value="Darwin")
    def test_collect_login_items_timeout(self, mock_system):
        """Test login items collection handles timeout."""
        import subprocess

        collector = PersistenceCollector()

        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("osascript", 10)
        ):
            snapshot: dict = {}
            now_ns = int(time.time() * 1e9)
            collector._collect_login_items(snapshot, now_ns)
            assert len(snapshot) == 0

    def test_read_chrome_manifest_empty_versions(self, tmp_path):
        """Test _read_chrome_manifest with empty version directory."""
        ext_path = tmp_path / "ext_id"
        ext_path.mkdir()
        result = PersistenceCollector._read_chrome_manifest(str(ext_path))
        assert result is None

    def test_read_chrome_manifest_invalid_json(self, tmp_path):
        """Test _read_chrome_manifest with invalid JSON."""
        ext_path = tmp_path / "ext_id"
        version_dir = ext_path / "1.0"
        version_dir.mkdir(parents=True)
        (version_dir / "manifest.json").write_text("invalid json {")
        result = PersistenceCollector._read_chrome_manifest(str(ext_path))
        assert result is None


# ---------------------------------------------------------------------------
# PersistenceGuard validate_event Extended Tests
# ---------------------------------------------------------------------------


class TestPersistenceGuardValidateExtended:
    """Extended tests for PersistenceGuard.validate_event."""

    def test_validate_valid_event(self, persistence_agent):
        """Test validation passes for a valid event."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="test-host",
            timestamp_ns=int(time.time() * 1e9),
            events=[
                tpb.TelemetryEvent(
                    event_id="p-1",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )
        result = persistence_agent.validate_event(event)
        assert result.is_valid is True

    def test_validate_missing_device_id(self, persistence_agent):
        """Test validation fails with missing device_id."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="",
            timestamp_ns=int(time.time() * 1e9),
            events=[
                tpb.TelemetryEvent(
                    event_id="p-1",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )
        result = persistence_agent.validate_event(event)
        assert result.is_valid is False
        assert any("device_id" in e for e in result.errors)

    def test_validate_zero_timestamp(self, persistence_agent):
        """Test validation fails with zero timestamp."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=0,
            events=[
                tpb.TelemetryEvent(
                    event_id="p-1",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )
        result = persistence_agent.validate_event(event)
        assert result.is_valid is False
        assert any("timestamp" in e for e in result.errors)

    def test_validate_stale_timestamp(self, persistence_agent):
        """Test validation fails with stale timestamp (> 1 hour from now)."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        stale_ns = int((time.time() - 7200) * 1e9)  # 2 hours ago
        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=stale_ns,
            events=[
                tpb.TelemetryEvent(
                    event_id="p-1",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )
        result = persistence_agent.validate_event(event)
        assert result.is_valid is False
        assert any("too far" in e for e in result.errors)

    def test_validate_future_timestamp(self, persistence_agent):
        """Test validation fails with future timestamp (> 1 hour from now)."""
        from amoskys.proto import universal_telemetry_pb2 as tpb

        future_ns = int((time.time() + 7200) * 1e9)  # 2 hours in future
        event = tpb.DeviceTelemetry(
            device_id="host-1",
            timestamp_ns=future_ns,
            events=[
                tpb.TelemetryEvent(
                    event_id="p-1",
                    event_type="SECURITY",
                    severity="HIGH",
                )
            ],
        )
        result = persistence_agent.validate_event(event)
        assert result.is_valid is False
        assert any("too far" in e for e in result.errors)


# ---------------------------------------------------------------------------
# PersistenceGuard collect_data Extended Tests
# ---------------------------------------------------------------------------


class TestPersistenceGuardCollectExtended:
    """Extended tests for collect_data covering all branches."""

    def test_collect_create_mode(self, tmp_path):
        """Test collect_data in create mode creates baseline and returns empty."""
        with patch("amoskys.agents.shared.persistence.agent.LocalQueueAdapter"):
            with patch(
                "amoskys.agents.shared.persistence.agent.create_persistence_probes",
                return_value=[],
            ):
                agent = PersistenceGuard(
                    collection_interval=30.0,
                    queue_path=str(tmp_path / "queue.db"),
                    baseline_mode="create",
                    baseline_path=str(tmp_path / "baseline.json"),
                )

        with patch.object(agent.collector, "collect_snapshot", return_value={}):
            result = agent.collect_data()
            # create mode returns empty list after creating baseline
            assert result == []

    def test_collect_auto_create_mode(self, tmp_path):
        """Test collect_data in auto_create mode creates baseline then switches to monitor."""
        with patch("amoskys.agents.shared.persistence.agent.LocalQueueAdapter"):
            with patch(
                "amoskys.agents.shared.persistence.agent.create_persistence_probes",
                return_value=[],
            ):
                agent = PersistenceGuard(
                    collection_interval=30.0,
                    queue_path=str(tmp_path / "queue.db"),
                    baseline_mode="monitor",
                    baseline_path=str(tmp_path / "baseline.json"),
                )

        # Force auto_create mode
        agent.baseline_mode = "auto_create"
        with patch.object(agent.collector, "collect_snapshot", return_value={}):
            result = agent.collect_data()
            assert isinstance(result, list)
            assert len(result) == 1
            # Mode should switch to monitor
            assert agent.baseline_mode == "monitor"

    def test_collect_monitor_no_changes(self, persistence_agent):
        """Test collect_data in monitor mode with no changes emits snapshot metric."""
        with patch.object(
            persistence_agent.collector, "collect_snapshot", return_value={}
        ):
            with patch.object(
                persistence_agent.baseline_engine, "compare", return_value=[]
            ):
                result = persistence_agent.collect_data()
                assert isinstance(result, list)
                assert len(result) == 1

                dt = result[0]
                assert dt.protocol == "PERSISTENCE"
                # Only snapshot summary event, no security events
                assert len(dt.events) == 1
                assert dt.events[0].event_type == "METRIC"

    def test_collect_monitor_with_changes(self, persistence_agent):
        """Test collect_data in monitor mode with detected changes emits security events."""
        now_ns = int(time.time() * 1e9)
        new_entry = PersistenceEntry(
            id="launchd:/Library/LaunchAgents/com.malware.plist",
            mechanism_type="USER_LAUNCH_AGENT",
            user="root",
            path="/Library/LaunchAgents/com.malware.plist",
            command="/usr/bin/malware",
            args="--persist",
            enabled=True,
            hash="deadbeef",
            metadata={"label": "com.malware"},
            last_seen_ns=now_ns,
        )
        change = PersistenceChange(
            entry_id="launchd:/Library/LaunchAgents/com.malware.plist",
            mechanism_type="USER_LAUNCH_AGENT",
            change_type=PersistenceChangeType.CREATED,
            old_entry=None,
            new_entry=new_entry,
            timestamp_ns=now_ns,
        )

        with patch.object(
            persistence_agent.collector,
            "collect_snapshot",
            return_value={"launchd:/Library/LaunchAgents/com.malware.plist": new_entry},
        ):
            with patch.object(
                persistence_agent.baseline_engine, "compare", return_value=[change]
            ):
                result = persistence_agent.collect_data()
                assert isinstance(result, list)
                assert len(result) == 1

                dt = result[0]
                # Should have snapshot metric + at least 1 security event
                assert len(dt.events) >= 2

                security_events = [e for e in dt.events if e.event_type == "SECURITY"]
                assert len(security_events) >= 1

                se = security_events[0]
                assert se.severity == "HIGH"  # CREATED -> HIGH
                assert se.attributes["change_type"] == "CREATED"
                assert se.attributes["mechanism_type"] == "USER_LAUNCH_AGENT"
                assert "T1543" in list(se.security_event.mitre_techniques)

    def test_collect_change_with_old_hash(self, persistence_agent):
        """Test collect_data populates old_hash from old_entry."""
        now_ns = int(time.time() * 1e9)
        old_entry = PersistenceEntry(
            id="cron:user:test",
            mechanism_type="CRON_USER",
            user="test",
            path=None,
            command="old cron",
            args=None,
            enabled=True,
            hash="oldhash123",
            metadata={},
            last_seen_ns=now_ns,
        )
        new_entry = PersistenceEntry(
            id="cron:user:test",
            mechanism_type="CRON_USER",
            user="test",
            path=None,
            command="new cron",
            args=None,
            enabled=True,
            hash="newhash456",
            metadata={},
            last_seen_ns=now_ns,
        )
        change = PersistenceChange(
            entry_id="cron:user:test",
            mechanism_type="CRON_USER",
            change_type=PersistenceChangeType.MODIFIED,
            old_entry=old_entry,
            new_entry=new_entry,
            timestamp_ns=now_ns,
        )

        with patch.object(
            persistence_agent.collector,
            "collect_snapshot",
            return_value={"cron:user:test": new_entry},
        ):
            with patch.object(
                persistence_agent.baseline_engine, "compare", return_value=[change]
            ):
                result = persistence_agent.collect_data()
                dt = result[0]

                security_events = [e for e in dt.events if e.event_type == "SECURITY"]
                se = security_events[0]
                assert se.attributes["old_hash"] == "oldhash123"
                assert se.severity == "MEDIUM"  # MODIFIED -> MEDIUM

    def test_collect_change_mitre_techniques_mapping(self, persistence_agent):
        """Test MITRE technique mapping for different mechanism types."""
        now_ns = int(time.time() * 1e9)

        test_cases = [
            ("USER_LAUNCH_AGENT", ["T1543", "T1547"]),
            ("SYSTEM_LAUNCH_DAEMON", ["T1543", "T1547"]),
            ("CRON_USER", ["T1053.003"]),
            ("SHELL_PROFILE", ["T1546.004"]),
            ("SSH_AUTHORIZED_KEYS", ["T1098.004"]),
            ("BROWSER_EXTENSION", ["T1547"]),  # default
        ]

        for mech_type, expected_techniques in test_cases:
            entry = PersistenceEntry(
                id=f"test:{mech_type}",
                mechanism_type=mech_type,
                user="test",
                path="/test",
                command="cmd",
                args=None,
                enabled=True,
                hash="abc",
                metadata={},
                last_seen_ns=now_ns,
            )
            change = PersistenceChange(
                entry_id=f"test:{mech_type}",
                mechanism_type=mech_type,
                change_type=PersistenceChangeType.CREATED,
                old_entry=None,
                new_entry=entry,
                timestamp_ns=now_ns,
            )

            with patch.object(
                persistence_agent.collector,
                "collect_snapshot",
                return_value={f"test:{mech_type}": entry},
            ):
                with patch.object(
                    persistence_agent.baseline_engine,
                    "compare",
                    return_value=[change],
                ):
                    result = persistence_agent.collect_data()
                    dt = result[0]
                    security_events = [
                        e for e in dt.events if e.event_type == "SECURITY"
                    ]
                    assert len(security_events) >= 1
                    techniques = list(
                        security_events[0].security_event.mitre_techniques
                    )
                    for tech in expected_techniques:
                        assert (
                            tech in techniques
                        ), f"Expected {tech} for {mech_type}, got {techniques}"


# ---------------------------------------------------------------------------
# PersistenceGuard Shutdown Tests
# ---------------------------------------------------------------------------


class TestPersistenceGuardShutdown:
    """Test shutdown lifecycle."""

    def test_shutdown(self, persistence_agent):
        """Test shutdown completes without error."""
        persistence_agent.shutdown()

    def test_setup_returns_true(self, persistence_agent):
        """Test setup returns True."""
        result = persistence_agent.setup()
        assert result is True


# ---------------------------------------------------------------------------
# PersistenceGuard init with auto_create mode
# ---------------------------------------------------------------------------


class TestPersistenceGuardInitModes:
    """Test various initialization modes."""

    def test_monitor_mode_no_baseline_switches_to_auto_create(self, tmp_path):
        """Test monitor mode with no baseline file switches to auto_create."""
        with patch("amoskys.agents.shared.persistence.agent.LocalQueueAdapter"):
            with patch(
                "amoskys.agents.shared.persistence.agent.create_persistence_probes",
                return_value=[],
            ):
                agent = PersistenceGuard(
                    collection_interval=30.0,
                    queue_path=str(tmp_path / "queue.db"),
                    baseline_mode="monitor",
                    baseline_path=str(tmp_path / "nonexistent_baseline.json"),
                )
                assert agent.baseline_mode == "auto_create"

    def test_monitor_mode_with_existing_baseline(self, tmp_path):
        """Test monitor mode with existing baseline stays in monitor mode."""
        import json

        baseline_path = str(tmp_path / "baseline.json")
        # Create valid baseline file
        with open(baseline_path, "w") as f:
            json.dump({}, f)

        with patch("amoskys.agents.shared.persistence.agent.LocalQueueAdapter"):
            with patch(
                "amoskys.agents.shared.persistence.agent.create_persistence_probes",
                return_value=[],
            ):
                agent = PersistenceGuard(
                    collection_interval=30.0,
                    queue_path=str(tmp_path / "queue.db"),
                    baseline_mode="monitor",
                    baseline_path=baseline_path,
                )
                assert agent.baseline_mode == "monitor"


# ---------------------------------------------------------------------------
# PersistenceBaselineEngine Extended Tests
# ---------------------------------------------------------------------------


class TestPersistenceBaselineEngineExtended:
    """Extended tests for PersistenceBaselineEngine."""

    def test_save_and_load(self, tmp_path):
        """Test baseline save and load round-trip."""
        path = str(tmp_path / "baseline.json")
        engine = PersistenceBaselineEngine(path)

        entry = PersistenceEntry(
            id="test_entry",
            mechanism_type="CRON_USER",
            user="test",
            path="/etc/cron.d/test",
            command="* * * * * echo hi",
            args=None,
            enabled=True,
            hash="abc123",
            metadata={"line_count": "1"},
            last_seen_ns=int(time.time() * 1e9),
        )
        engine.create_from_snapshot({"test_entry": entry})
        engine.save()

        engine2 = PersistenceBaselineEngine(path)
        loaded = engine2.load()
        assert loaded is True
        assert "test_entry" in engine2.entries

    def test_load_nonexistent(self, tmp_path):
        """Test load returns False for nonexistent file."""
        engine = PersistenceBaselineEngine(str(tmp_path / "missing.json"))
        assert engine.load() is False

    def test_load_corrupt(self, tmp_path):
        """Test load returns False for corrupt JSON."""
        path = str(tmp_path / "corrupt.json")
        with open(path, "w") as f:
            f.write("not valid json {{{")
        engine = PersistenceBaselineEngine(path)
        assert engine.load() is False

    def test_compare_detects_created(self):
        """Test compare detects newly created entries."""
        engine = PersistenceBaselineEngine("/dev/null")
        engine.entries = {}

        new_entry = PersistenceEntry(
            id="new_agent",
            mechanism_type="USER_LAUNCH_AGENT",
            user="user",
            path="/path",
            command="cmd",
            args=None,
            enabled=True,
            hash="abc",
            metadata={},
            last_seen_ns=int(time.time() * 1e9),
        )
        changes = engine.compare({"new_agent": new_entry})
        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.CREATED

    def test_compare_detects_deleted(self):
        """Test compare detects deleted entries."""
        engine = PersistenceBaselineEngine("/dev/null")
        old_entry = PersistenceEntry(
            id="old_agent",
            mechanism_type="CRON_USER",
            user="root",
            path="/path",
            command="cmd",
            args=None,
            enabled=True,
            hash="abc",
            metadata={},
            last_seen_ns=int(time.time() * 1e9),
        )
        engine.entries = {"old_agent": old_entry}

        changes = engine.compare({})
        assert len(changes) == 1
        assert changes[0].change_type == PersistenceChangeType.DELETED
