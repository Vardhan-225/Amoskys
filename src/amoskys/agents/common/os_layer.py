"""OS Abstraction Layer for AMOSKYS agents.

Provides a unified interface for platform-specific operations.
Agents call the OS layer instead of platform-specific commands directly,
enabling easy expansion to Linux, Windows, and other platforms.

Current implementations:
    - macOS (Darwin): psutil + subprocess (system_profiler, log show, lsof, etc.)
    - Linux: psutil + subprocess (/proc, auditd, etc.)
    - Stub: For testing without OS-specific dependencies
"""

import json
import logging
import platform
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from amoskys.agents.common.metrics import SCHEMA_VERSION, SubprocessOutcome

logger = logging.getLogger(__name__)

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@dataclass
class ProcessInfo:
    """Information about a running process.

    P0-18: ``cpu_percent`` and ``memory_mb`` use ``-1.0`` as a sentinel
    when the process exists but access was denied (psutil.AccessDenied).
    ``0.0`` is reserved for processes that exited (NoSuchProcess) where
    zero is the accurate reading.  Consumers should treat ``< 0`` as
    "unknown due to access restriction".
    """

    pid: int
    name: str
    exe: str
    cmdline: List[str]
    uid: int
    ppid: int
    cpu_percent: float
    memory_mb: float
    status: str
    create_time: float
    environ: Dict[str, str] = field(default_factory=dict)
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class NetworkConnection:
    """Information about a network connection."""

    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str  # tcp, udp, tcp6, udp6
    status: str  # ESTABLISHED, LISTEN, etc.
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class FileInfo:
    """Information about a file."""

    path: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    sha256: Optional[str] = None
    xattrs: Optional[Dict[str, str]] = None
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class USBDevice:
    """Information about a USB device."""

    vendor_id: str
    product_id: str
    name: str
    serial: Optional[str] = None
    bus: Optional[str] = None
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


class OSLayer(ABC):
    """Abstract OS layer interface.

    Defines the contract for platform-specific operations.
    Implementations should override these methods for their target OS.
    """

    def _run_subprocess(
        self,
        cmd: List[str],
        timeout: int = 10,
        operation: str = "subprocess",
    ) -> Tuple[Optional[str], SubprocessOutcome]:
        """P0-17: Typed subprocess wrapper with structured failure reporting.

        Args:
            cmd: Command and arguments to execute.
            timeout: Maximum seconds to wait.
            operation: Human-readable label for logging.

        Returns:
            (stdout_text, outcome) — stdout is None on any failure.
        """
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return result.stdout, SubprocessOutcome.SUCCESS
            logger.warning(
                "SUBPROCESS_NONZERO: op=%s cmd=%s rc=%d stderr=%s",
                operation,
                cmd[0],
                result.returncode,
                result.stderr[:200] if result.stderr else "",
            )
            return None, SubprocessOutcome.NONZERO_EXIT
        except subprocess.TimeoutExpired:
            logger.warning(
                "SUBPROCESS_TIMEOUT: op=%s cmd=%s timeout=%ds",
                operation,
                cmd[0],
                timeout,
            )
            return None, SubprocessOutcome.TIMEOUT
        except PermissionError:
            logger.warning("SUBPROCESS_ACCESS_DENIED: op=%s cmd=%s", operation, cmd[0])
            return None, SubprocessOutcome.ACCESS_DENIED
        except FileNotFoundError:
            logger.warning("SUBPROCESS_NOT_FOUND: op=%s cmd=%s", operation, cmd[0])
            return None, SubprocessOutcome.NOT_FOUND
        except Exception as exc:
            logger.warning(
                "SUBPROCESS_EXCEPTION: op=%s cmd=%s error=%s",
                operation,
                cmd[0],
                exc,
            )
            return None, SubprocessOutcome.EXCEPTION

    @abstractmethod
    def list_processes(self) -> List[ProcessInfo]:
        """List all running processes.

        Returns:
            List of ProcessInfo objects for all running processes.
        """
        ...

    @abstractmethod
    def list_network_connections(self) -> List[NetworkConnection]:
        """List all network connections.

        Returns:
            List of NetworkConnection objects for all open connections.
        """
        ...

    @abstractmethod
    def get_file_info(self, path: str) -> Optional[FileInfo]:
        """Get information about a file.

        Args:
            path: Path to the file.

        Returns:
            FileInfo object if file exists, None otherwise.
        """
        ...

    @abstractmethod
    def list_usb_devices(self) -> List[USBDevice]:
        """List all connected USB devices.

        Returns:
            List of USBDevice objects for all connected USB devices.
        """
        ...

    @abstractmethod
    def query_security_logs(
        self, subsystems: List[str], last_seconds: int = 10
    ) -> List[Dict]:
        """Query security-related system logs.

        Args:
            subsystems: List of subsystems to query (e.g., ['auth', 'security', 'sudo']).
            last_seconds: How many seconds back to query.

        Returns:
            List of log event dictionaries.
        """
        ...

    @abstractmethod
    def get_platform_name(self) -> str:
        """Get the platform name (macOS, Linux, Windows, etc.).

        Returns:
            String identifier for the platform.
        """
        ...


class MacOSLayer(OSLayer):
    """macOS implementation using psutil + subprocess.

    Uses psutil for processes and network connections, and subprocess
    for macOS-specific tools like system_profiler, log show, lsof, codesign, etc.
    """

    def __init__(self):
        if not HAS_PSUTIL:
            raise RuntimeError("psutil is required for MacOSLayer")

    def get_platform_name(self) -> str:
        """Return 'macOS'."""
        return "macOS"

    def list_processes(self) -> List[ProcessInfo]:
        """List all running processes on macOS using psutil."""
        processes = []
        try:
            for proc in psutil.process_iter(
                [
                    "pid",
                    "name",
                    "exe",
                    "cmdline",
                    "uid",
                    "ppid",
                    "status",
                    "create_time",
                ]
            ):
                try:
                    info = proc.as_dict(
                        attrs=[
                            "pid",
                            "name",
                            "exe",
                            "cmdline",
                            "uid",
                            "ppid",
                            "status",
                            "create_time",
                        ]
                    )

                    # P0-18: Get CPU and memory — AccessDenied → -1.0 sentinel
                    try:
                        cpu_percent = proc.cpu_percent(interval=0.01)
                    except psutil.AccessDenied:
                        cpu_percent = -1.0
                    except psutil.NoSuchProcess:
                        cpu_percent = 0.0

                    try:
                        memory_info = proc.memory_info()
                        memory_mb = memory_info.rss / (1024 * 1024)
                    except psutil.AccessDenied:
                        memory_mb = -1.0
                    except psutil.NoSuchProcess:
                        memory_mb = 0.0

                    # Get environment variables with error handling
                    environ = {}
                    try:
                        environ = proc.environ()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    process_info = ProcessInfo(
                        pid=info["pid"],
                        name=info["name"],
                        exe=info["exe"] or "",
                        cmdline=info["cmdline"] or [],
                        uid=info["uid"] or 0,
                        ppid=info["ppid"] or 0,
                        cpu_percent=cpu_percent,
                        memory_mb=memory_mb,
                        status=info["status"] or "unknown",
                        create_time=info["create_time"] or 0.0,
                        environ=environ,
                    )
                    processes.append(process_info)
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue
        except Exception as e:
            logger.error(f"Error listing processes: {e}")

        return processes

    def list_network_connections(self) -> List[NetworkConnection]:
        """List all network connections on macOS using psutil."""
        connections = []
        try:
            for conn in psutil.net_connections():
                try:
                    # Get process name from PID
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "unknown"

                    # Map status to string
                    status = conn.status if conn.status else "UNKNOWN"

                    # Map protocol number to string
                    protocol = "unknown"
                    if conn.type == 1:  # SOCK_STREAM
                        protocol = "tcp"
                    elif conn.type == 2:  # SOCK_DGRAM
                        protocol = "udp"

                    net_conn = NetworkConnection(
                        pid=conn.pid or 0,
                        process_name=proc_name,
                        local_addr=conn.laddr.ip if conn.laddr else "0.0.0.0",
                        local_port=conn.laddr.port if conn.laddr else 0,
                        remote_addr=conn.raddr.ip if conn.raddr else "0.0.0.0",
                        remote_port=conn.raddr.port if conn.raddr else 0,
                        protocol=protocol,
                        status=status,
                    )
                    connections.append(net_conn)
                except Exception as e:
                    logger.debug(f"Error processing connection: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error listing network connections: {e}")

        return connections

    def get_file_info(self, path: str) -> Optional[FileInfo]:
        """Get file information using os.stat."""
        import os

        try:
            stat_info = os.stat(path)

            # Try to get extended attributes (xattrs)
            xattrs = {}
            try:
                xattrs = dict(os.listxattr(path) or {})
            except (OSError, AttributeError):
                pass

            file_info = FileInfo(
                path=path,
                size=stat_info.st_size,
                mode=stat_info.st_mode,
                uid=stat_info.st_uid,
                gid=stat_info.st_gid,
                mtime=stat_info.st_mtime,
                sha256=None,  # Could compute if needed
                xattrs=xattrs if xattrs else None,
            )
            return file_info
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Error getting file info for {path}: {e}")
            return None

    def list_usb_devices(self) -> List[USBDevice]:
        """List USB devices using system_profiler on macOS."""
        devices = []
        try:
            # Use system_profiler to get USB devices
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                logger.warning(f"system_profiler failed: {result.stderr}")
                return devices

            try:
                data = json.loads(result.stdout)
                # Navigate the JSON structure
                usb_data = data.get("SPUSBDataType", [])

                for controller in usb_data:
                    items = controller.get("_items", [])
                    for item in items:
                        device = USBDevice(
                            vendor_id=item.get("idVendor", "unknown"),
                            product_id=item.get("idProduct", "unknown"),
                            name=item.get("_name", "unknown"),
                            serial=item.get("serial_num"),
                            bus=item.get("bus_power"),
                        )
                        devices.append(device)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse system_profiler output: {e}")

        except subprocess.TimeoutExpired:
            logger.warning("system_profiler timed out")
        except Exception as e:
            logger.error(f"Error listing USB devices: {e}")

        return devices

    def query_security_logs(
        self, subsystems: List[str], last_seconds: int = 10
    ) -> List[Dict]:
        """Query macOS security logs using 'log show' command.

        Args:
            subsystems: List of subsystems to query (e.g., ['auth', 'security']).
            last_seconds: How many seconds back to query.

        Returns:
            List of log entries as dictionaries.
        """
        logs = []

        if not subsystems:
            return logs

        try:
            # Build predicate for log show command
            # Example: log show --style syslog --info --predicate 'eventMessage contains[cd] "error"' --last 10s
            predicate_parts = []
            for subsystem in subsystems:
                predicate_parts.append(f'subsystem == "{subsystem}"')

            predicate = (
                " OR ".join(predicate_parts) if predicate_parts else "level >= debug"
            )

            cmd = [
                "log",
                "show",
                "--style",
                "syslog",
                "--predicate",
                predicate,
                f"--last",
                f"{last_seconds}s",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                logger.warning(f"log show failed: {result.stderr}")
                return logs

            # Parse syslog output
            for line in result.stdout.split("\n"):
                if line.strip():
                    logs.append({"line": line, "raw": True})

        except subprocess.TimeoutExpired:
            logger.warning("log show timed out")
        except Exception as e:
            logger.error(f"Error querying security logs: {e}")

        return logs


class LinuxLayer(OSLayer):
    """Linux implementation using psutil + /proc filesystem.

    Provides basic Linux support using psutil. Can be extended with
    /proc filesystem parsing, auditd, systemd journal, etc.
    """

    def __init__(self):
        if not HAS_PSUTIL:
            raise RuntimeError("psutil is required for LinuxLayer")

    def get_platform_name(self) -> str:
        """Return 'Linux'."""
        return "Linux"

    def list_processes(self) -> List[ProcessInfo]:
        """List all running processes on Linux using psutil."""
        processes = []
        try:
            for proc in psutil.process_iter(
                [
                    "pid",
                    "name",
                    "exe",
                    "cmdline",
                    "uid",
                    "ppid",
                    "status",
                    "create_time",
                ]
            ):
                try:
                    info = proc.as_dict(
                        attrs=[
                            "pid",
                            "name",
                            "exe",
                            "cmdline",
                            "uid",
                            "ppid",
                            "status",
                            "create_time",
                        ]
                    )

                    # P0-18: Get CPU and memory — AccessDenied → -1.0 sentinel
                    try:
                        cpu_percent = proc.cpu_percent(interval=0.01)
                    except psutil.AccessDenied:
                        cpu_percent = -1.0
                    except psutil.NoSuchProcess:
                        cpu_percent = 0.0

                    try:
                        memory_info = proc.memory_info()
                        memory_mb = memory_info.rss / (1024 * 1024)
                    except psutil.AccessDenied:
                        memory_mb = -1.0
                    except psutil.NoSuchProcess:
                        memory_mb = 0.0

                    # Get environment variables with error handling
                    environ = {}
                    try:
                        environ = proc.environ()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    process_info = ProcessInfo(
                        pid=info["pid"],
                        name=info["name"],
                        exe=info["exe"] or "",
                        cmdline=info["cmdline"] or [],
                        uid=info["uid"] or 0,
                        ppid=info["ppid"] or 0,
                        cpu_percent=cpu_percent,
                        memory_mb=memory_mb,
                        status=info["status"] or "unknown",
                        create_time=info["create_time"] or 0.0,
                        environ=environ,
                    )
                    processes.append(process_info)
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue
        except Exception as e:
            logger.error(f"Error listing processes: {e}")

        return processes

    def list_network_connections(self) -> List[NetworkConnection]:
        """List all network connections on Linux using psutil."""
        connections = []
        try:
            for conn in psutil.net_connections():
                try:
                    # Get process name from PID
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "unknown"

                    # Map status to string
                    status = conn.status if conn.status else "UNKNOWN"

                    # Map protocol number to string
                    protocol = "unknown"
                    if conn.type == 1:  # SOCK_STREAM
                        protocol = "tcp"
                    elif conn.type == 2:  # SOCK_DGRAM
                        protocol = "udp"

                    net_conn = NetworkConnection(
                        pid=conn.pid or 0,
                        process_name=proc_name,
                        local_addr=conn.laddr.ip if conn.laddr else "0.0.0.0",
                        local_port=conn.laddr.port if conn.laddr else 0,
                        remote_addr=conn.raddr.ip if conn.raddr else "0.0.0.0",
                        remote_port=conn.raddr.port if conn.raddr else 0,
                        protocol=protocol,
                        status=status,
                    )
                    connections.append(net_conn)
                except Exception as e:
                    logger.debug(f"Error processing connection: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error listing network connections: {e}")

        return connections

    def get_file_info(self, path: str) -> Optional[FileInfo]:
        """Get file information using os.stat."""
        import os

        try:
            stat_info = os.stat(path)

            # Try to get extended attributes (xattrs) on Linux
            xattrs = {}
            try:
                if hasattr(os, "listxattr"):
                    xattrs = dict(
                        zip(
                            os.listxattr(path) or [],
                            [
                                os.getxattr(path, attr)
                                for attr in (os.listxattr(path) or [])
                            ],
                        )
                    )
            except (OSError, AttributeError):
                pass

            file_info = FileInfo(
                path=path,
                size=stat_info.st_size,
                mode=stat_info.st_mode,
                uid=stat_info.st_uid,
                gid=stat_info.st_gid,
                mtime=stat_info.st_mtime,
                sha256=None,  # Could compute if needed
                xattrs=xattrs if xattrs else None,
            )
            return file_info
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Error getting file info for {path}: {e}")
            return None

    def list_usb_devices(self) -> List[USBDevice]:
        """List USB devices on Linux using lsusb command."""
        devices = []
        try:
            result = subprocess.run(
                ["lsusb", "-v", "-s"], capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                # Fallback to simple lsusb
                result = subprocess.run(
                    ["lsusb"], capture_output=True, text=True, timeout=10
                )

                if result.returncode != 0:
                    logger.warning(f"lsusb failed: {result.stderr}")
                    return devices

                # Parse simple lsusb output: "Bus 001 Device 002: ID 1234:5678 Device Name"
                for line in result.stdout.split("\n"):
                    if "ID" in line:
                        parts = line.split("ID ")
                        if len(parts) > 1:
                            ids = parts[1].split()[0]
                            if ":" in ids:
                                vendor_id, product_id = ids.split(":")
                                name = (
                                    parts[1].split(None, 1)[1]
                                    if len(parts[1].split(None, 1)) > 1
                                    else "Unknown"
                                )
                                device = USBDevice(
                                    vendor_id=vendor_id,
                                    product_id=product_id,
                                    name=name,
                                )
                                devices.append(device)

        except subprocess.TimeoutExpired:
            logger.warning("lsusb timed out")
        except FileNotFoundError:
            logger.debug("lsusb command not found")
        except Exception as e:
            logger.error(f"Error listing USB devices: {e}")

        return devices

    def query_security_logs(
        self, subsystems: List[str], last_seconds: int = 10
    ) -> List[Dict]:
        """Query Linux security logs using journalctl or /var/log.

        Args:
            subsystems: List of subsystems to query (e.g., ['auth', 'security']).
            last_seconds: How many seconds back to query.

        Returns:
            List of log entries as dictionaries.
        """
        logs = []

        if not subsystems:
            return logs

        try:
            # Try journalctl first (systemd)
            since_time = f"{last_seconds}s ago"

            cmd = ["journalctl", "--since", since_time, "-o", "json"]

            # Add unit filters for each subsystem
            for subsystem in subsystems:
                cmd.extend(["-u", subsystem])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Parse JSON output
                for line in result.stdout.split("\n"):
                    if line.strip():
                        try:
                            logs.append(json.loads(line))
                        except json.JSONDecodeError:
                            logs.append({"raw": line})
            else:
                # Fallback to /var/log files
                for subsystem in subsystems:
                    log_file = f"/var/log/{subsystem}.log"
                    try:
                        with open(log_file, "r") as f:
                            for line in f.readlines()[-100:]:  # Last 100 lines
                                if line.strip():
                                    logs.append(
                                        {"line": line.strip(), "file": log_file}
                                    )
                    except FileNotFoundError:
                        pass

        except subprocess.TimeoutExpired:
            logger.warning("journalctl timed out")
        except Exception as e:
            logger.error(f"Error querying security logs: {e}")

        return logs


class StubOSLayer(OSLayer):
    """Testing stub with injectable data.

    Used for testing without requiring actual OS-specific dependencies.
    Allows injecting test data for each method.
    """

    def __init__(self):
        self.processes_data: List[ProcessInfo] = []
        self.connections_data: List[NetworkConnection] = []
        self.files_data: Dict[str, FileInfo] = {}
        self.usb_devices_data: List[USBDevice] = []
        self.logs_data: List[Dict] = []
        self.platform_name_value: str = "Stub"

    def set_processes(self, processes: List[ProcessInfo]) -> None:
        """Set the processes to return from list_processes()."""
        self.processes_data = processes

    def set_connections(self, connections: List[NetworkConnection]) -> None:
        """Set the connections to return from list_network_connections()."""
        self.connections_data = connections

    def set_file_info(self, path: str, info: FileInfo) -> None:
        """Set file info for a specific path."""
        self.files_data[path] = info

    def set_usb_devices(self, devices: List[USBDevice]) -> None:
        """Set the USB devices to return from list_usb_devices()."""
        self.usb_devices_data = devices

    def set_logs(self, logs: List[Dict]) -> None:
        """Set the logs to return from query_security_logs()."""
        self.logs_data = logs

    def set_platform_name(self, name: str) -> None:
        """Set the platform name to return from get_platform_name()."""
        self.platform_name_value = name

    def get_platform_name(self) -> str:
        """Return the injected platform name."""
        return self.platform_name_value

    def list_processes(self) -> List[ProcessInfo]:
        """Return the injected processes."""
        return self.processes_data.copy()

    def list_network_connections(self) -> List[NetworkConnection]:
        """Return the injected connections."""
        return self.connections_data.copy()

    def get_file_info(self, path: str) -> Optional[FileInfo]:
        """Return the injected file info for the path."""
        return self.files_data.get(path)

    def list_usb_devices(self) -> List[USBDevice]:
        """Return the injected USB devices."""
        return self.usb_devices_data.copy()

    def query_security_logs(
        self, subsystems: List[str], last_seconds: int = 10
    ) -> List[Dict]:
        """Return the injected logs."""
        return self.logs_data.copy()


def create_os_layer() -> OSLayer:
    """Factory function to create the appropriate OS layer for the current platform.

    Returns:
        An OSLayer instance appropriate for the current platform:
        - MacOSLayer for macOS (Darwin)
        - LinuxLayer for Linux
        - StubOSLayer as fallback (e.g., for testing or unsupported platforms)
    """
    system = platform.system()

    if system == "Darwin":
        try:
            return MacOSLayer()
        except RuntimeError as e:
            logger.warning(f"Failed to create MacOSLayer: {e}, using StubOSLayer")
            return StubOSLayer()
    elif system == "Linux":
        try:
            return LinuxLayer()
        except RuntimeError as e:
            logger.warning(f"Failed to create LinuxLayer: {e}, using StubOSLayer")
            return StubOSLayer()
    else:
        logger.info(f"Unsupported platform: {system}, using StubOSLayer")
        return StubOSLayer()
