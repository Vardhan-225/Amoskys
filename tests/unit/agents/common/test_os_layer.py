"""Comprehensive unit tests for os_layer.py.

Covers all three OSLayer implementations (MacOSLayer, LinuxLayer, StubOSLayer),
the factory function create_os_layer(), dataclass construction, and error paths
in list_processes, list_network_connections, get_file_info, list_usb_devices,
and query_security_logs.

Every test mocks OS/psutil dependencies so they run on any platform.
"""

import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

import psutil
import pytest

from amoskys.agents.common.metrics import SCHEMA_VERSION, SubprocessOutcome
from amoskys.agents.common.os_layer import (
    FileInfo,
    LinuxLayer,
    MacOSLayer,
    NetworkConnection,
    OSLayer,
    ProcessInfo,
    StubOSLayer,
    USBDevice,
    create_os_layer,
)

# ============================================================================
# Helper factories
# ============================================================================


def _make_process_info(**overrides):
    defaults = dict(
        pid=42,
        name="pytest",
        exe="/usr/bin/pytest",
        cmdline=["pytest", "-v"],
        uid=501,
        ppid=1,
        cpu_percent=2.5,
        memory_mb=64.0,
        status="running",
        create_time=1700000000.0,
    )
    defaults.update(overrides)
    return ProcessInfo(**defaults)


def _make_network_connection(**overrides):
    defaults = dict(
        pid=42,
        process_name="curl",
        local_addr="127.0.0.1",
        local_port=54321,
        remote_addr="93.184.216.34",
        remote_port=443,
        protocol="tcp",
        status="ESTABLISHED",
    )
    defaults.update(overrides)
    return NetworkConnection(**defaults)


def _make_file_info(**overrides):
    defaults = dict(
        path="/etc/hosts",
        size=512,
        mode=0o644,
        uid=0,
        gid=0,
        mtime=1700000000.0,
    )
    defaults.update(overrides)
    return FileInfo(**defaults)


def _make_usb_device(**overrides):
    defaults = dict(
        vendor_id="05ac",
        product_id="8511",
        name="Apple Keyboard",
    )
    defaults.update(overrides)
    return USBDevice(**defaults)


def _mock_psutil_module():
    """Create a MagicMock psutil that preserves real exception classes.

    When we patch amoskys.agents.common.os_layer.psutil, the except clauses
    inside the source code reference psutil.AccessDenied etc. via the module
    attribute.  If those are plain MagicMock objects the except clause will
    never match.  By attaching the *real* exception classes to the mock module
    the except clauses work correctly while all functions remain mockable.
    """
    mock = MagicMock()
    mock.AccessDenied = psutil.AccessDenied
    mock.NoSuchProcess = psutil.NoSuchProcess
    mock.ZombieProcess = psutil.ZombieProcess
    return mock


# ============================================================================
# Dataclass construction & schema version
# ============================================================================


class TestDataclassConstruction:
    """Verify all dataclass fields, defaults, and schema versioning."""

    def test_process_info_all_fields(self):
        p = _make_process_info(environ={"HOME": "/root"})
        assert p.pid == 42
        assert p.name == "pytest"
        assert p.environ == {"HOME": "/root"}
        assert p._schema_version == SCHEMA_VERSION

    def test_process_info_default_environ(self):
        p = _make_process_info()
        assert p.environ == {}

    def test_network_connection_schema(self):
        nc = _make_network_connection()
        assert nc._schema_version == SCHEMA_VERSION
        assert nc.protocol == "tcp"

    def test_file_info_optional_fields(self):
        fi = _make_file_info()
        assert fi.sha256 is None
        assert fi.xattrs is None
        assert fi._schema_version == SCHEMA_VERSION

    def test_file_info_with_hash_and_xattrs(self):
        fi = _make_file_info(sha256="abcd1234", xattrs={"com.apple.quarantine": "0"})
        assert fi.sha256 == "abcd1234"
        assert fi.xattrs == {"com.apple.quarantine": "0"}

    def test_usb_device_optional_serial_bus(self):
        usb = _make_usb_device()
        assert usb.serial is None
        assert usb.bus is None
        assert usb._schema_version == SCHEMA_VERSION

    def test_usb_device_with_serial(self):
        usb = _make_usb_device(serial="ABC123", bus="500mA")
        assert usb.serial == "ABC123"
        assert usb.bus == "500mA"


# ============================================================================
# StubOSLayer
# ============================================================================


class TestStubOSLayer:
    """StubOSLayer: injectable data, copy semantics, defaults."""

    def setup_method(self):
        self.layer = StubOSLayer()

    def test_default_platform_name(self):
        assert self.layer.get_platform_name() == "Stub"

    def test_set_platform_name(self):
        self.layer.set_platform_name("TestOS")
        assert self.layer.get_platform_name() == "TestOS"

    def test_list_processes_empty(self):
        assert self.layer.list_processes() == []

    def test_set_and_list_processes(self):
        procs = [_make_process_info(pid=1), _make_process_info(pid=2)]
        self.layer.set_processes(procs)
        result = self.layer.list_processes()
        assert len(result) == 2
        assert result[0].pid == 1

    def test_processes_returns_copy(self):
        procs = [_make_process_info()]
        self.layer.set_processes(procs)
        result = self.layer.list_processes()
        result.append(_make_process_info(pid=99))
        assert len(self.layer.list_processes()) == 1

    def test_list_connections_empty(self):
        assert self.layer.list_network_connections() == []

    def test_set_and_list_connections(self):
        conns = [_make_network_connection()]
        self.layer.set_connections(conns)
        assert len(self.layer.list_network_connections()) == 1

    def test_connections_returns_copy(self):
        self.layer.set_connections([_make_network_connection()])
        result = self.layer.list_network_connections()
        result.clear()
        assert len(self.layer.list_network_connections()) == 1

    def test_get_file_info_missing(self):
        assert self.layer.get_file_info("/nonexistent") is None

    def test_set_and_get_file_info(self):
        fi = _make_file_info(path="/etc/hosts")
        self.layer.set_file_info("/etc/hosts", fi)
        result = self.layer.get_file_info("/etc/hosts")
        assert result is not None
        assert result.path == "/etc/hosts"

    def test_list_usb_empty(self):
        assert self.layer.list_usb_devices() == []

    def test_set_and_list_usb(self):
        devs = [_make_usb_device(), _make_usb_device(name="Mouse")]
        self.layer.set_usb_devices(devs)
        assert len(self.layer.list_usb_devices()) == 2

    def test_usb_returns_copy(self):
        self.layer.set_usb_devices([_make_usb_device()])
        result = self.layer.list_usb_devices()
        result.clear()
        assert len(self.layer.list_usb_devices()) == 1

    def test_query_logs_empty(self):
        assert self.layer.query_security_logs(["auth"]) == []

    def test_set_and_query_logs(self):
        logs = [{"line": "test log entry", "raw": True}]
        self.layer.set_logs(logs)
        result = self.layer.query_security_logs(["auth"], last_seconds=5)
        assert len(result) == 1
        assert result[0]["line"] == "test log entry"

    def test_logs_returns_copy(self):
        self.layer.set_logs([{"msg": "hello"}])
        result = self.layer.query_security_logs(["auth"])
        result.clear()
        assert len(self.layer.query_security_logs(["auth"])) == 1


# ============================================================================
# MacOSLayer
# ============================================================================


class TestMacOSLayer:
    """MacOSLayer with psutil fully mocked."""

    # --- init / platform ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", False)
    def test_init_raises_without_psutil(self):
        with pytest.raises(RuntimeError, match="psutil is required"):
            MacOSLayer()

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_platform_name(self):
        layer = MacOSLayer()
        assert layer.get_platform_name() == "macOS"

    # --- list_processes ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_happy_path(self):
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.return_value = {
            "pid": 100,
            "name": "bash",
            "exe": "/bin/bash",
            "cmdline": ["bash"],
            "uid": 501,
            "ppid": 1,
            "status": "running",
            "create_time": 1700000000.0,
        }
        proc_mock.cpu_percent.return_value = 5.0
        mem_mock = MagicMock()
        mem_mock.rss = 50 * 1024 * 1024  # 50 MB
        proc_mock.memory_info.return_value = mem_mock
        proc_mock.environ.return_value = {"PATH": "/usr/bin"}
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            processes = layer.list_processes()

        assert len(processes) == 1
        p = processes[0]
        assert p.pid == 100
        assert p.name == "bash"
        assert p.cpu_percent == 5.0
        assert abs(p.memory_mb - 50.0) < 0.01
        assert p.environ == {"PATH": "/usr/bin"}

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_access_denied_sentinel(self):
        """CPU/memory AccessDenied -> -1.0 sentinel."""
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.return_value = {
            "pid": 1,
            "name": "restricted",
            "exe": None,
            "cmdline": None,
            "uid": None,
            "ppid": None,
            "status": None,
            "create_time": None,
        }
        proc_mock.cpu_percent.side_effect = psutil.AccessDenied(pid=1)
        proc_mock.memory_info.side_effect = psutil.AccessDenied(pid=1)
        proc_mock.environ.side_effect = psutil.AccessDenied(pid=1)
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            procs = layer.list_processes()

        assert len(procs) == 1
        assert procs[0].cpu_percent == -1.0
        assert procs[0].memory_mb == -1.0
        assert procs[0].environ == {}

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_no_such_process_zero(self):
        """CPU/memory NoSuchProcess -> 0.0."""
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.return_value = {
            "pid": 2,
            "name": "zombie",
            "exe": "/bin/zomb",
            "cmdline": [],
            "uid": 0,
            "ppid": 1,
            "status": "zombie",
            "create_time": 0.0,
        }
        proc_mock.cpu_percent.side_effect = psutil.NoSuchProcess(pid=2)
        proc_mock.memory_info.side_effect = psutil.NoSuchProcess(pid=2)
        proc_mock.environ.side_effect = psutil.NoSuchProcess(pid=2)
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            procs = layer.list_processes()

        assert len(procs) == 1
        assert procs[0].cpu_percent == 0.0
        assert procs[0].memory_mb == 0.0

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_skip_zombie(self):
        """ZombieProcess during as_dict -> skip, don't crash."""
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.side_effect = psutil.ZombieProcess(pid=99)
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            procs = layer.list_processes()

        assert len(procs) == 0

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_global_error(self):
        """Top-level exception in process_iter -> return empty list."""
        mock_ps = _mock_psutil_module()
        mock_ps.process_iter.side_effect = RuntimeError("oops")

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            assert layer.list_processes() == []

    # --- list_network_connections ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_tcp(self):
        mock_ps = _mock_psutil_module()
        conn = SimpleNamespace(
            pid=200,
            status="ESTABLISHED",
            type=1,  # SOCK_STREAM -> tcp
            laddr=SimpleNamespace(ip="127.0.0.1", port=8080),
            raddr=SimpleNamespace(ip="10.0.0.1", port=443),
        )
        proc = MagicMock()
        proc.name.return_value = "curl"
        mock_ps.Process.return_value = proc
        mock_ps.net_connections.return_value = [conn]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            conns = layer.list_network_connections()

        assert len(conns) == 1
        assert conns[0].protocol == "tcp"
        assert conns[0].process_name == "curl"
        assert conns[0].remote_port == 443

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_udp(self):
        mock_ps = _mock_psutil_module()
        conn = SimpleNamespace(
            pid=201,
            status="",
            type=2,  # SOCK_DGRAM -> udp
            laddr=SimpleNamespace(ip="0.0.0.0", port=53),
            raddr=None,
        )
        proc = MagicMock()
        proc.name.return_value = "dnsmasq"
        mock_ps.Process.return_value = proc
        mock_ps.net_connections.return_value = [conn]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            conns = layer.list_network_connections()

        assert len(conns) == 1
        assert conns[0].protocol == "udp"
        assert conns[0].status == "UNKNOWN"
        assert conns[0].remote_addr == "0.0.0.0"
        assert conns[0].remote_port == 0

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_no_pid(self):
        mock_ps = _mock_psutil_module()
        conn = SimpleNamespace(
            pid=None,
            status="LISTEN",
            type=1,
            laddr=SimpleNamespace(ip="0.0.0.0", port=22),
            raddr=None,
        )
        mock_ps.net_connections.return_value = [conn]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            conns = layer.list_network_connections()

        assert len(conns) == 1
        assert conns[0].process_name == ""
        assert conns[0].pid == 0

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_process_gone(self):
        mock_ps = _mock_psutil_module()
        conn = SimpleNamespace(
            pid=999,
            status="ESTABLISHED",
            type=1,
            laddr=SimpleNamespace(ip="127.0.0.1", port=5000),
            raddr=SimpleNamespace(ip="10.0.0.2", port=80),
        )
        mock_ps.Process.side_effect = psutil.NoSuchProcess(pid=999)
        mock_ps.net_connections.return_value = [conn]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            conns = layer.list_network_connections()

        assert len(conns) == 1
        assert conns[0].process_name == "unknown"

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_unknown_type(self):
        """Socket type not 1 or 2 -> protocol 'unknown'."""
        mock_ps = _mock_psutil_module()
        conn = SimpleNamespace(
            pid=300,
            status="NONE",
            type=5,
            laddr=SimpleNamespace(ip="::1", port=9999),
            raddr=None,
        )
        mock_ps.net_connections.return_value = [conn]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            conns = layer.list_network_connections()

        assert len(conns) == 1
        assert conns[0].protocol == "unknown"

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_global_error(self):
        mock_ps = _mock_psutil_module()
        mock_ps.net_connections.side_effect = RuntimeError("permission denied")

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = MacOSLayer()
            assert layer.list_network_connections() == []

    # --- get_file_info ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_happy(self):
        layer = MacOSLayer()
        stat_result = MagicMock()
        stat_result.st_size = 1024
        stat_result.st_mode = 0o644
        stat_result.st_uid = 0
        stat_result.st_gid = 0
        stat_result.st_mtime = 1700000000.0

        # The source does `import os` inside the method then calls
        # os.stat and os.listxattr.  We mock the module-level os that
        # the local import resolves to.
        fake_os = MagicMock()
        fake_os.stat.return_value = stat_result
        fake_os.listxattr.return_value = None

        with patch.dict("sys.modules", {"os": fake_os}):
            # get_file_info does `import os` locally, which will
            # look up sys.modules["os"].  But since os is already
            # imported we need to patch it at the point of use.
            pass

        # Simpler approach: patch os.stat at the real os module level.
        # The source does `import os` inside get_file_info; that resolves
        # the already-loaded os module.  listxattr may or may not exist.
        with patch("os.stat", return_value=stat_result):
            # Handle the xattr call: the source calls os.listxattr(path).
            # On macOS os.listxattr exists; we monkeypatch it if present
            # or add it if not.
            original = getattr(os, "listxattr", None)
            os.listxattr = lambda path: None
            try:
                result = layer.get_file_info("/etc/hosts")
            finally:
                if original is None:
                    if hasattr(os, "listxattr"):
                        delattr(os, "listxattr")
                else:
                    os.listxattr = original

        assert result is not None
        assert result.path == "/etc/hosts"
        assert result.size == 1024
        assert result.mode == 0o644

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_not_found(self):
        layer = MacOSLayer()

        with patch("os.stat", side_effect=FileNotFoundError()):
            result = layer.get_file_info("/nonexistent")

        assert result is None

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_other_error(self):
        layer = MacOSLayer()

        with patch("os.stat", side_effect=PermissionError("access denied")):
            result = layer.get_file_info("/root/secret")

        assert result is None

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_xattr_oserror(self):
        """xattr collection failing should not prevent file info return."""
        layer = MacOSLayer()
        stat_result = MagicMock()
        stat_result.st_size = 256
        stat_result.st_mode = 0o755
        stat_result.st_uid = 501
        stat_result.st_gid = 20
        stat_result.st_mtime = 1700000000.0

        with patch("os.stat", return_value=stat_result):
            original = getattr(os, "listxattr", None)
            os.listxattr = MagicMock(side_effect=OSError("not supported"))
            try:
                result = layer.get_file_info("/tmp/test")
            finally:
                if original is None:
                    if hasattr(os, "listxattr"):
                        delattr(os, "listxattr")
                else:
                    os.listxattr = original

        assert result is not None
        assert result.xattrs is None

    # --- list_usb_devices ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_happy(self, mock_run):
        layer = MacOSLayer()
        usb_json = json.dumps(
            {
                "SPUSBDataType": [
                    {
                        "_items": [
                            {
                                "_name": "Apple Keyboard",
                                "idVendor": "0x05ac",
                                "idProduct": "0x024f",
                                "serial_num": "ABC123",
                                "bus_power": "500mA",
                            },
                            {
                                "_name": "Mouse",
                                "idVendor": "0x046d",
                                "idProduct": "0xc077",
                            },
                        ]
                    }
                ]
            }
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=usb_json, stderr="")

        devices = layer.list_usb_devices()

        assert len(devices) == 2
        assert devices[0].name == "Apple Keyboard"
        assert devices[0].serial == "ABC123"
        assert devices[1].serial is None

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_nonzero(self, mock_run):
        layer = MacOSLayer()
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_bad_json(self, mock_run):
        layer = MacOSLayer()
        mock_run.return_value = MagicMock(returncode=0, stdout="NOT JSON", stderr="")

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_timeout(self, mock_run):
        layer = MacOSLayer()
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="system_profiler", timeout=10
        )

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_general_error(self, mock_run):
        layer = MacOSLayer()
        mock_run.side_effect = OSError("disk error")

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_empty_controller(self, mock_run):
        layer = MacOSLayer()
        usb_json = json.dumps({"SPUSBDataType": [{"_items": []}]})
        mock_run.return_value = MagicMock(returncode=0, stdout=usb_json, stderr="")

        devices = layer.list_usb_devices()
        assert devices == []

    # --- query_security_logs ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_happy(self, mock_run):
        layer = MacOSLayer()
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="2024-01-01 auth event\n2024-01-01 security event\n",
            stderr="",
        )

        logs = layer.query_security_logs(["auth", "security"], last_seconds=60)

        assert len(logs) == 2
        assert logs[0]["raw"] is True

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_empty_subsystems(self, mock_run):
        layer = MacOSLayer()

        logs = layer.query_security_logs([], last_seconds=10)

        assert logs == []
        mock_run.assert_not_called()

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_nonzero(self, mock_run):
        layer = MacOSLayer()
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="access denied"
        )

        logs = layer.query_security_logs(["auth"])
        assert logs == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_timeout(self, mock_run):
        layer = MacOSLayer()
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="log", timeout=10)

        logs = layer.query_security_logs(["auth"])
        assert logs == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_general_error(self, mock_run):
        layer = MacOSLayer()
        mock_run.side_effect = OSError("broken pipe")

        logs = layer.query_security_logs(["auth"])
        assert logs == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_predicate_building(self, mock_run):
        """Verify that the predicate is built correctly for multiple subsystems."""
        layer = MacOSLayer()
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        layer.query_security_logs(["auth", "security", "sudo"], last_seconds=30)

        call_args = mock_run.call_args
        cmd = call_args[0][0]
        # Find the predicate argument
        pred_idx = cmd.index("--predicate") + 1
        predicate = cmd[pred_idx]
        assert 'subsystem == "auth"' in predicate
        assert 'subsystem == "security"' in predicate
        assert 'subsystem == "sudo"' in predicate
        assert " OR " in predicate


# ============================================================================
# LinuxLayer
# ============================================================================


class TestLinuxLayer:
    """LinuxLayer with psutil fully mocked."""

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", False)
    def test_init_raises_without_psutil(self):
        with pytest.raises(RuntimeError, match="psutil is required"):
            LinuxLayer()

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_platform_name(self):
        layer = LinuxLayer()
        assert layer.get_platform_name() == "Linux"

    # --- list_processes ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_happy(self):
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.return_value = {
            "pid": 50,
            "name": "nginx",
            "exe": "/usr/sbin/nginx",
            "cmdline": ["nginx", "-g", "daemon off;"],
            "uid": 33,
            "ppid": 1,
            "status": "sleeping",
            "create_time": 1700000000.0,
        }
        proc_mock.cpu_percent.return_value = 0.5
        mem = MagicMock()
        mem.rss = 100 * 1024 * 1024
        proc_mock.memory_info.return_value = mem
        proc_mock.environ.return_value = {}
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = LinuxLayer()
            procs = layer.list_processes()

        assert len(procs) == 1
        assert procs[0].name == "nginx"
        assert abs(procs[0].memory_mb - 100.0) < 0.01

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_access_denied_sentinel(self):
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.return_value = {
            "pid": 1,
            "name": "kthreadd",
            "exe": None,
            "cmdline": None,
            "uid": None,
            "ppid": None,
            "status": None,
            "create_time": None,
        }
        proc_mock.cpu_percent.side_effect = psutil.AccessDenied(pid=1)
        proc_mock.memory_info.side_effect = psutil.AccessDenied(pid=1)
        proc_mock.environ.side_effect = psutil.AccessDenied(pid=1)
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = LinuxLayer()
            procs = layer.list_processes()

        assert len(procs) == 1
        assert procs[0].cpu_percent == -1.0
        assert procs[0].memory_mb == -1.0

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_no_such_process_zero(self):
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.return_value = {
            "pid": 2,
            "name": "gone",
            "exe": "",
            "cmdline": [],
            "uid": 0,
            "ppid": 0,
            "status": "zombie",
            "create_time": 0.0,
        }
        proc_mock.cpu_percent.side_effect = psutil.NoSuchProcess(pid=2)
        proc_mock.memory_info.side_effect = psutil.NoSuchProcess(pid=2)
        proc_mock.environ.side_effect = psutil.NoSuchProcess(pid=2)
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = LinuxLayer()
            procs = layer.list_processes()

        assert len(procs) == 1
        assert procs[0].cpu_percent == 0.0
        assert procs[0].memory_mb == 0.0

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_skip_exceptions(self):
        mock_ps = _mock_psutil_module()
        proc_mock = MagicMock()
        proc_mock.as_dict.side_effect = psutil.AccessDenied(pid=1)
        mock_ps.process_iter.return_value = [proc_mock]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = LinuxLayer()
            assert layer.list_processes() == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_processes_global_error(self):
        mock_ps = _mock_psutil_module()
        mock_ps.process_iter.side_effect = RuntimeError("proc error")

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = LinuxLayer()
            assert layer.list_processes() == []

    # --- list_network_connections ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_happy(self):
        mock_ps = _mock_psutil_module()
        conn = SimpleNamespace(
            pid=1000,
            status="LISTEN",
            type=1,
            laddr=SimpleNamespace(ip="0.0.0.0", port=80),
            raddr=None,
        )
        proc = MagicMock()
        proc.name.return_value = "apache2"
        mock_ps.Process.return_value = proc
        mock_ps.net_connections.return_value = [conn]

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = LinuxLayer()
            conns = layer.list_network_connections()

        assert len(conns) == 1
        assert conns[0].process_name == "apache2"
        assert conns[0].local_port == 80
        assert conns[0].remote_addr == "0.0.0.0"

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_list_network_connections_global_error(self):
        mock_ps = _mock_psutil_module()
        mock_ps.net_connections.side_effect = PermissionError("no access")

        with patch("amoskys.agents.common.os_layer.psutil", mock_ps):
            layer = LinuxLayer()
            assert layer.list_network_connections() == []

    # --- get_file_info ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_happy(self):
        layer = LinuxLayer()
        stat_result = MagicMock()
        stat_result.st_size = 4096
        stat_result.st_mode = 0o755
        stat_result.st_uid = 0
        stat_result.st_gid = 0
        stat_result.st_mtime = 1700000000.0

        with patch("os.stat", return_value=stat_result):
            original_listxattr = getattr(os, "listxattr", None)
            original_getxattr = getattr(os, "getxattr", None)
            os.listxattr = lambda path: []
            os.getxattr = lambda path, attr: b""
            try:
                result = layer.get_file_info("/usr/bin/ls")
            finally:
                if original_listxattr is None:
                    if hasattr(os, "listxattr"):
                        delattr(os, "listxattr")
                else:
                    os.listxattr = original_listxattr
                if original_getxattr is None:
                    if hasattr(os, "getxattr"):
                        delattr(os, "getxattr")
                else:
                    os.getxattr = original_getxattr

        assert result is not None
        assert result.path == "/usr/bin/ls"
        assert result.size == 4096

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_not_found(self):
        layer = LinuxLayer()

        with patch("os.stat", side_effect=FileNotFoundError()):
            result = layer.get_file_info("/nope")

        assert result is None

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_xattr_error(self):
        layer = LinuxLayer()
        stat_result = MagicMock()
        stat_result.st_size = 512
        stat_result.st_mode = 0o644
        stat_result.st_uid = 1000
        stat_result.st_gid = 1000
        stat_result.st_mtime = 1700000000.0

        with patch("os.stat", return_value=stat_result):
            original = getattr(os, "listxattr", None)
            os.listxattr = MagicMock(side_effect=OSError("not supported"))
            try:
                result = layer.get_file_info("/tmp/test")
            finally:
                if original is None:
                    if hasattr(os, "listxattr"):
                        delattr(os, "listxattr")
                else:
                    os.listxattr = original

        assert result is not None
        assert result.xattrs is None

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_get_file_info_permission_error(self):
        layer = LinuxLayer()

        with patch("os.stat", side_effect=PermissionError("denied")):
            result = layer.get_file_info("/root/.ssh/id_rsa")

        assert result is None

    # --- list_usb_devices ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_fallback_to_simple(self, mock_run):
        """lsusb -v -s fails -> fallback to simple lsusb."""
        layer = LinuxLayer()

        # First call (lsusb -v -s) fails, second call (lsusb) succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="error"),
            MagicMock(
                returncode=0,
                stdout="Bus 001 Device 002: ID 1234:5678 Test Device\nBus 002 Device 001: ID abcd:ef01 Another Device\n",
                stderr="",
            ),
        ]

        devices = layer.list_usb_devices()

        assert len(devices) == 2
        assert devices[0].vendor_id == "1234"
        assert devices[0].product_id == "5678"
        assert devices[0].name == "Test Device"
        assert devices[1].vendor_id == "abcd"

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_both_fail(self, mock_run):
        layer = LinuxLayer()
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr=""),
            MagicMock(returncode=1, stdout="", stderr=""),
        ]

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_timeout(self, mock_run):
        layer = LinuxLayer()
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="lsusb", timeout=10)

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_not_found(self, mock_run):
        layer = LinuxLayer()
        mock_run.side_effect = FileNotFoundError("lsusb not found")

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_general_error(self, mock_run):
        layer = LinuxLayer()
        mock_run.side_effect = OSError("disk error")

        devices = layer.list_usb_devices()
        assert devices == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_list_usb_devices_simple_parse_no_name(self, mock_run):
        """Line with ID but no name after it."""
        layer = LinuxLayer()
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr=""),
            MagicMock(
                returncode=0,
                stdout="Bus 001 Device 001: ID aaaa:bbbb\n",
                stderr="",
            ),
        ]

        devices = layer.list_usb_devices()
        assert len(devices) == 1
        assert devices[0].vendor_id == "aaaa"
        assert devices[0].product_id == "bbbb"
        assert devices[0].name == "Unknown"

    # --- query_security_logs ---

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_journalctl_json(self, mock_run):
        layer = LinuxLayer()
        json_lines = '{"MESSAGE": "auth event"}\n{"MESSAGE": "second"}\n'
        mock_run.return_value = MagicMock(returncode=0, stdout=json_lines, stderr="")

        logs = layer.query_security_logs(["sshd", "sudo"], last_seconds=30)

        assert len(logs) == 2
        assert logs[0]["MESSAGE"] == "auth event"

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_journalctl_bad_json_line(self, mock_run):
        """Non-JSON lines from journalctl get stored as raw."""
        layer = LinuxLayer()
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='not json line\n{"good": true}\n',
            stderr="",
        )

        logs = layer.query_security_logs(["auth"])

        assert len(logs) == 2
        assert logs[0] == {"raw": "not json line"}
        assert logs[1] == {"good": True}

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_fallback_to_var_log(self, mock_run):
        """journalctl fails -> read from /var/log/auth.log etc."""
        layer = LinuxLayer()
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="no journal")

        fake_log = "Jan 1 auth: login success\nJan 1 auth: login failed\n"
        m = mock_open(read_data=fake_log)

        with patch("builtins.open", m):
            logs = layer.query_security_logs(["auth"])

        assert len(logs) == 2
        assert logs[0]["file"] == "/var/log/auth.log"

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_fallback_missing_file(self, mock_run):
        """journalctl fails and /var/log file missing -> empty."""
        layer = LinuxLayer()
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

        with patch("builtins.open", side_effect=FileNotFoundError()):
            logs = layer.query_security_logs(["nosuchservice"])

        assert logs == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    def test_query_security_logs_empty_subsystems(self):
        layer = LinuxLayer()

        logs = layer.query_security_logs([])
        assert logs == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_timeout(self, mock_run):
        layer = LinuxLayer()
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="journalctl", timeout=10)

        logs = layer.query_security_logs(["auth"])
        assert logs == []

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("subprocess.run")
    def test_query_security_logs_general_error(self, mock_run):
        layer = LinuxLayer()
        mock_run.side_effect = OSError("broken")

        logs = layer.query_security_logs(["auth"])
        assert logs == []


# ============================================================================
# create_os_layer factory
# ============================================================================


class TestCreateOSLayer:
    """Factory function: platform detection and fallbacks."""

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("platform.system", return_value="Darwin")
    def test_darwin_returns_macos_layer(self, _mock_sys):
        layer = create_os_layer()
        assert isinstance(layer, MacOSLayer)

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", True)
    @patch("platform.system", return_value="Linux")
    def test_linux_returns_linux_layer(self, _mock_sys):
        layer = create_os_layer()
        assert isinstance(layer, LinuxLayer)

    @patch("platform.system", return_value="Windows")
    def test_unsupported_returns_stub(self, _mock_sys):
        layer = create_os_layer()
        assert isinstance(layer, StubOSLayer)

    @patch("platform.system", return_value="FreeBSD")
    def test_freebsd_returns_stub(self, _mock_sys):
        layer = create_os_layer()
        assert isinstance(layer, StubOSLayer)

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", False)
    @patch("platform.system", return_value="Darwin")
    def test_darwin_no_psutil_falls_back_to_stub(self, _mock_sys):
        layer = create_os_layer()
        assert isinstance(layer, StubOSLayer)

    @patch("amoskys.agents.common.os_layer.HAS_PSUTIL", False)
    @patch("platform.system", return_value="Linux")
    def test_linux_no_psutil_falls_back_to_stub(self, _mock_sys):
        layer = create_os_layer()
        assert isinstance(layer, StubOSLayer)


# ============================================================================
# _run_subprocess (inherited by all concrete layers)
# ============================================================================


class TestRunSubprocessExtended:
    """Extended tests for _run_subprocess beyond what test_os_layer_hardened covers."""

    def setup_method(self):
        self.layer = StubOSLayer()

    @patch("subprocess.run")
    def test_default_timeout(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        self.layer._run_subprocess(["echo", "hello"])

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 10

    @patch("subprocess.run")
    def test_custom_timeout(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        self.layer._run_subprocess(["slow_cmd"], timeout=60)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 60

    @patch("subprocess.run")
    def test_nonzero_exit_no_stderr(self, mock_run):
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="")
        stdout, outcome = self.layer._run_subprocess(["fail"], operation="test_op")

        assert outcome == SubprocessOutcome.NONZERO_EXIT
        assert stdout is None

    @patch("subprocess.run")
    def test_success_returns_stdout(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="line1\nline2\n", stderr=""
        )
        stdout, outcome = self.layer._run_subprocess(["cmd"])

        assert outcome == SubprocessOutcome.SUCCESS
        assert "line1" in stdout
        assert "line2" in stdout

    @patch("subprocess.run")
    def test_nonzero_with_long_stderr(self, mock_run):
        """Long stderr gets truncated in logging."""
        long_stderr = "x" * 500
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=long_stderr)
        stdout, outcome = self.layer._run_subprocess(["fail"])

        assert outcome == SubprocessOutcome.NONZERO_EXIT
        assert stdout is None


# ============================================================================
# OSLayer ABC enforcement
# ============================================================================


class TestOSLayerABC:
    """Verify that OSLayer cannot be instantiated without implementing abstract methods."""

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            OSLayer()

    def test_subclass_must_implement_all(self):
        class IncompleteLayer(OSLayer):
            def list_processes(self):
                return []

        with pytest.raises(TypeError):
            IncompleteLayer()
