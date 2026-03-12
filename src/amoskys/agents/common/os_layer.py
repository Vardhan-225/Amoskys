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
from typing import Any, Dict, List, Optional, Tuple

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


# ─── Data Models (v2) ────────────────────────────────────────────────


@dataclass
class PersistenceEntry:
    """A persistence mechanism entry.

    Covers: LaunchAgents/Daemons (macOS), systemd/cron/init.d (Linux),
    registry run keys/scheduled tasks (Windows).
    """

    path: str  # File path of the persistence config
    mechanism: str  # "launch_agent", "launch_daemon", "cron", etc.
    label: str  # Identifier (plist label, service name)
    program: str  # Path to executable
    enabled: bool = True
    run_at_load: bool = False  # Starts at boot/login
    user: str = ""  # Owner user
    plist_data: Dict[str, Any] = field(default_factory=dict)
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class CodeSigningInfo:
    """Code signing verification result for a binary.

    macOS: codesign / Gatekeeper
    Linux: ELF signing, dpkg --verify, rpm -V
    Windows: Authenticode, catalog signing
    """

    path: str
    signed: bool
    valid: bool  # Signature is valid and untampered
    authority: str = ""  # Signing authority chain
    team_id: str = ""  # macOS Team ID / Linux key ID
    identifier: str = ""  # Bundle ID or package name
    flags: List[str] = field(default_factory=list)
    error: str = ""  # Verification error message
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class SIPStatus:
    """System integrity protection state.

    macOS: SIP (csrutil status)
    Linux: SELinux mode / AppArmor status
    Windows: Secure Boot / Device Guard
    """

    enabled: bool
    status_text: str  # Raw status string
    custom_config: bool = False  # Non-default configuration
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class BluetoothDevice:
    """A Bluetooth device."""

    name: str
    address: str  # MAC address
    connected: bool = False
    device_type: str = ""  # "keyboard", "mouse", "audio", etc.
    paired: bool = False
    rssi: Optional[int] = None  # Signal strength (dBm)
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class DNSEntry:
    """A DNS cache/resolution entry."""

    domain: str
    record_type: str  # A, AAAA, CNAME, TXT, MX, etc.
    value: str  # IP address or record value
    ttl: int = 0
    source: str = ""  # "cache", "resolver", "mdns"
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class NetworkInterface:
    """A network interface."""

    name: str  # e.g., "en0", "eth0", "wlan0"
    hw_addr: str = ""  # MAC address
    ipv4_addrs: List[str] = field(default_factory=list)
    ipv6_addrs: List[str] = field(default_factory=list)
    is_up: bool = False
    is_loopback: bool = False
    mtu: int = 0
    speed_mbps: int = 0
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class ARPEntry:
    """An ARP table entry (IP-to-MAC mapping)."""

    ip_addr: str
    hw_addr: str  # MAC address
    interface: str = ""
    is_permanent: bool = False
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class FirewallStatus:
    """Firewall state.

    macOS: Application Layer Firewall (socketfilterfw)
    Linux: iptables / nftables / ufw
    Windows: Windows Defender Firewall
    """

    enabled: bool
    stealth_mode: bool = False  # macOS stealth mode
    block_all_incoming: bool = False
    allowed_apps: List[str] = field(default_factory=list)
    status_text: str = ""  # Raw status output
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class LoginItem:
    """A login/startup item.

    macOS: Login Items (System Settings)
    Linux: XDG autostart, .profile scripts
    Windows: Startup folder, registry Run keys
    """

    name: str
    path: str
    kind: str = ""  # "app", "agent", "helper", "script"
    enabled: bool = True
    hidden: bool = False
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


@dataclass
class ListeningService:
    """A service listening on a network port.

    Used by HTTP Inspector and DB Activity agents to discover
    local web servers and databases.
    """

    pid: int
    process_name: str
    port: int
    protocol: str  # "tcp", "udp"
    bind_addr: str = "0.0.0.0"
    service_name: str = ""  # Known service if resolvable
    _schema_version: str = field(default=SCHEMA_VERSION, init=False, repr=False)


# ─── OS Layer ABC ────────────────────────────────────────────────────


class OSLayer(ABC):
    """Abstract OS layer interface.

    Defines the contract for platform-specific operations.
    Implementations should override these methods for their target OS.

    v2: Added 10 new methods for persistence, code signing, system
    integrity, bluetooth, DNS, network interfaces, ARP, firewall,
    login items, and listening services.
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

    # ── v2 Methods ──

    @abstractmethod
    def list_persistence_entries(self) -> List[PersistenceEntry]:
        """List all persistence mechanisms (LaunchAgents, cron, systemd, etc.).

        Returns:
            List of PersistenceEntry for all discovered persistence mechanisms.
        """
        ...

    @abstractmethod
    def get_code_signing_info(self, path: str) -> Optional[CodeSigningInfo]:
        """Verify code signing for a binary.

        Args:
            path: Path to the binary to verify.

        Returns:
            CodeSigningInfo if the file exists, None otherwise.
        """
        ...

    @abstractmethod
    def get_sip_status(self) -> SIPStatus:
        """Get system integrity protection state (SIP/SELinux/SecureBoot).

        Returns:
            SIPStatus with current protection state.
        """
        ...

    @abstractmethod
    def list_bluetooth_devices(self) -> List[BluetoothDevice]:
        """List all Bluetooth devices (paired and connected).

        Returns:
            List of BluetoothDevice objects.
        """
        ...

    @abstractmethod
    def query_dns_cache(self) -> List[DNSEntry]:
        """Query DNS resolver configuration and recent resolutions.

        Returns:
            List of DNSEntry objects from cache/resolver.
        """
        ...

    @abstractmethod
    def list_network_interfaces(self) -> List[NetworkInterface]:
        """List all network interfaces with addresses and status.

        Returns:
            List of NetworkInterface objects.
        """
        ...

    @abstractmethod
    def get_arp_table(self) -> List[ARPEntry]:
        """Get the ARP neighbor cache (IP-to-MAC mappings).

        Returns:
            List of ARPEntry objects.
        """
        ...

    @abstractmethod
    def get_firewall_status(self) -> FirewallStatus:
        """Get firewall state (ALF/iptables/Windows Firewall).

        Returns:
            FirewallStatus with current state.
        """
        ...

    @abstractmethod
    def list_login_items(self) -> List[LoginItem]:
        """List login/startup items.

        Returns:
            List of LoginItem objects.
        """
        ...

    @abstractmethod
    def list_listening_services(self) -> List[ListeningService]:
        """List services listening on network ports.

        Returns:
            List of ListeningService objects.
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

    # ── v2 Methods (macOS implementations) ──

    def list_persistence_entries(self) -> List[PersistenceEntry]:
        """List persistence mechanisms on macOS.

        Scans LaunchAgents (user + system), LaunchDaemons, and crontab.
        """
        import os
        import plistlib

        entries: List[PersistenceEntry] = []

        persistence_dirs = {
            os.path.expanduser("~/Library/LaunchAgents"): "launch_agent",
            "/Library/LaunchAgents": "launch_agent",
            "/Library/LaunchDaemons": "launch_daemon",
            "/System/Library/LaunchAgents": "launch_agent",
            "/System/Library/LaunchDaemons": "launch_daemon",
        }

        for dir_path, mechanism in persistence_dirs.items():
            if not os.path.isdir(dir_path):
                continue
            try:
                for filename in os.listdir(dir_path):
                    if not filename.endswith(".plist"):
                        continue
                    plist_path = os.path.join(dir_path, filename)
                    try:
                        with open(plist_path, "rb") as f:
                            plist = plistlib.load(f)

                        program = plist.get("Program", "")
                        if not program:
                            args = plist.get("ProgramArguments", [])
                            program = args[0] if args else ""

                        entries.append(
                            PersistenceEntry(
                                path=plist_path,
                                mechanism=mechanism,
                                label=plist.get("Label", filename),
                                program=program,
                                enabled=not plist.get("Disabled", False),
                                run_at_load=plist.get("RunAtLoad", False),
                                user=plist.get("UserName", ""),
                                plist_data=dict(plist),
                            )
                        )
                    except Exception as exc:
                        logger.debug(
                            "PERSISTENCE_PLIST_ERROR: path=%s error=%s",
                            plist_path,
                            exc,
                        )
            except PermissionError:
                logger.debug("PERSISTENCE_DIR_DENIED: path=%s", dir_path)

        # Crontab
        stdout, outcome = self._run_subprocess(
            ["crontab", "-l"],
            timeout=5,
            operation="crontab",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            for i, line in enumerate(stdout.strip().split("\n")):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 5)
                program = parts[5] if len(parts) > 5 else line
                entries.append(
                    PersistenceEntry(
                        path="crontab",
                        mechanism="cron",
                        label=f"cron_{i}",
                        program=program,
                        enabled=True,
                    )
                )

        return entries

    def get_code_signing_info(self, path: str) -> Optional[CodeSigningInfo]:
        """Verify code signing for a binary on macOS using codesign."""
        import os

        if not os.path.exists(path):
            return None

        try:
            # codesign -dvv outputs signing details to stderr
            result = subprocess.run(
                ["codesign", "-dvv", path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            info_text = result.stderr or ""

            authority = ""
            team_id = ""
            identifier = ""
            flags: List[str] = []
            signed = False

            for line in info_text.split("\n"):
                line = line.strip()
                if line.startswith("Authority=") and not authority:
                    authority = line.split("=", 1)[1]
                elif line.startswith("TeamIdentifier="):
                    team_id = line.split("=", 1)[1]
                elif line.startswith("Identifier="):
                    identifier = line.split("=", 1)[1]
                    signed = True
                elif line.startswith("CodeDirectory") and "flags=" in line:
                    flag_part = line.split("flags=")[1].split(")")[0]
                    flags = [f.strip() for f in flag_part.split(",") if f.strip()]

            # Verify signature validity
            verify = subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            valid = verify.returncode == 0
            error = verify.stderr.strip() if verify.returncode != 0 else ""

            return CodeSigningInfo(
                path=path,
                signed=signed,
                valid=valid,
                authority=authority,
                team_id=team_id,
                identifier=identifier,
                flags=flags,
                error=error,
            )
        except subprocess.TimeoutExpired:
            logger.warning("CODESIGN_TIMEOUT: path=%s", path)
            return CodeSigningInfo(
                path=path,
                signed=False,
                valid=False,
                error="timeout",
            )
        except FileNotFoundError:
            return CodeSigningInfo(
                path=path,
                signed=False,
                valid=False,
                error="codesign not found",
            )
        except Exception as exc:
            logger.error("CODESIGN_ERROR: path=%s error=%s", path, exc)
            return None

    def get_sip_status(self) -> SIPStatus:
        """Get System Integrity Protection status on macOS."""
        stdout, outcome = self._run_subprocess(
            ["csrutil", "status"],
            timeout=5,
            operation="sip_status",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            enabled = "enabled" in stdout.lower() and "disabled" not in stdout.lower()
            custom = "custom configuration" in stdout.lower()
            return SIPStatus(
                enabled=enabled,
                status_text=stdout.strip(),
                custom_config=custom,
            )
        return SIPStatus(enabled=True, status_text="unknown (csrutil unavailable)")

    def list_bluetooth_devices(self) -> List[BluetoothDevice]:
        """List Bluetooth devices on macOS using system_profiler."""
        devices: List[BluetoothDevice] = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return devices

            data = json.loads(result.stdout)
            bt_data = data.get("SPBluetoothDataType", [])

            for controller in bt_data:
                # Handle both connected and not-connected device groups
                for group_key, is_connected in [
                    ("device_connected", True),
                    ("device_not_connected", False),
                ]:
                    device_group = controller.get(group_key, [])
                    items = (
                        device_group
                        if isinstance(device_group, list)
                        else [device_group]
                    )
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        for name, details in item.items():
                            if not isinstance(details, dict):
                                continue
                            devices.append(
                                BluetoothDevice(
                                    name=name,
                                    address=details.get("device_address", ""),
                                    connected=is_connected,
                                    device_type=details.get("device_minorType", ""),
                                    paired=details.get("device_isPaired", "attrib_No")
                                    == "attrib_Yes",
                                )
                            )
        except json.JSONDecodeError as exc:
            logger.debug("BT_JSON_ERROR: %s", exc)
        except subprocess.TimeoutExpired:
            logger.warning("BT_TIMEOUT")
        except Exception as exc:
            logger.error("BT_ERROR: %s", exc)

        return devices

    def query_dns_cache(self) -> List[DNSEntry]:
        """Query DNS resolver configuration on macOS via scutil --dns."""
        import re

        entries: List[DNSEntry] = []

        stdout, outcome = self._run_subprocess(
            ["scutil", "--dns"],
            timeout=5,
            operation="dns_config",
        )
        if not stdout or outcome != SubprocessOutcome.SUCCESS:
            return entries

        # Parse nameserver entries from scutil --dns output
        current_domain = ""
        for line in stdout.split("\n"):
            line = line.strip()
            domain_match = re.match(r"domain\s*:\s*(.+)", line)
            if domain_match:
                current_domain = domain_match.group(1)
            ns_match = re.match(r"nameserver\[(\d+)\]\s*:\s*(.+)", line)
            if ns_match:
                entries.append(
                    DNSEntry(
                        domain=current_domain or ".",
                        record_type="NS",
                        value=ns_match.group(2).strip(),
                        source="resolver",
                    )
                )
            search_match = re.match(r"search domain\[(\d+)\]\s*:\s*(.+)", line)
            if search_match:
                entries.append(
                    DNSEntry(
                        domain=search_match.group(2).strip(),
                        record_type="SEARCH",
                        value=search_match.group(2).strip(),
                        source="resolver",
                    )
                )

        return entries

    def list_network_interfaces(self) -> List[NetworkInterface]:
        """List network interfaces on macOS using psutil."""
        interfaces: List[NetworkInterface] = []

        if not HAS_PSUTIL:
            return interfaces

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for name, addr_list in addrs.items():
                iface = NetworkInterface(name=name)

                for addr in addr_list:
                    if addr.family.name == "AF_INET":
                        iface.ipv4_addrs.append(addr.address)
                    elif addr.family.name == "AF_INET6":
                        iface.ipv6_addrs.append(addr.address)
                    elif addr.family.name == "AF_LINK":
                        iface.hw_addr = addr.address

                if name in stats:
                    st = stats[name]
                    iface.is_up = st.isup
                    iface.mtu = st.mtu
                    iface.speed_mbps = st.speed
                    iface.is_loopback = name == "lo0"

                interfaces.append(iface)
        except Exception as exc:
            logger.error("NETIF_ERROR: %s", exc)

        return interfaces

    def get_arp_table(self) -> List[ARPEntry]:
        """Get ARP table on macOS using arp -a."""
        import re

        entries: List[ARPEntry] = []

        stdout, outcome = self._run_subprocess(
            ["arp", "-a"],
            timeout=5,
            operation="arp_table",
        )
        if not stdout or outcome != SubprocessOutcome.SUCCESS:
            return entries

        # Parse: hostname (ip) at mac on iface [ethernet]
        for line in stdout.strip().split("\n"):
            match = re.match(
                r"\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)",
                line,
            )
            if match:
                hw = match.group(2)
                if hw == "(incomplete)":
                    continue
                entries.append(
                    ARPEntry(
                        ip_addr=match.group(1),
                        hw_addr=hw,
                        interface=match.group(3),
                        is_permanent="permanent" in line.lower(),
                    )
                )

        return entries

    def get_firewall_status(self) -> FirewallStatus:
        """Get Application Layer Firewall status on macOS."""
        fw_path = "/usr/libexec/ApplicationFirewall/socketfilterfw"

        # Global state
        stdout, outcome = self._run_subprocess(
            [fw_path, "--getglobalstate"],
            timeout=5,
            operation="fw_state",
        )
        enabled = False
        status_text = ""
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            enabled = "enabled" in stdout.lower()
            status_text = stdout.strip()

        # Stealth mode
        stealth = False
        stdout, outcome = self._run_subprocess(
            [fw_path, "--getstealthmode"],
            timeout=5,
            operation="fw_stealth",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            stealth = "enabled" in stdout.lower()

        # Block all incoming
        block_all = False
        stdout, outcome = self._run_subprocess(
            [fw_path, "--getblockall"],
            timeout=5,
            operation="fw_blockall",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            block_all = "enabled" in stdout.lower()

        return FirewallStatus(
            enabled=enabled,
            stealth_mode=stealth,
            block_all_incoming=block_all,
            status_text=status_text,
        )

    def list_login_items(self) -> List[LoginItem]:
        """List login items on macOS.

        Scans ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/
        and uses sfltool if available.
        """
        import os

        items: List[LoginItem] = []

        # Check known login item plist locations
        btm_dir = os.path.expanduser(
            "~/Library/Application Support/" "com.apple.backgroundtaskmanagementagent"
        )
        if os.path.isdir(btm_dir):
            for filename in os.listdir(btm_dir):
                if filename.endswith(".plist"):
                    items.append(
                        LoginItem(
                            name=filename.replace(".plist", ""),
                            path=os.path.join(btm_dir, filename),
                            kind="agent",
                        )
                    )

        # Also check LaunchAgents with RunAtLoad=true (already discovered items)
        for entry in self.list_persistence_entries():
            if entry.run_at_load and entry.mechanism in ("launch_agent",):
                items.append(
                    LoginItem(
                        name=entry.label,
                        path=entry.path,
                        kind="agent",
                        enabled=entry.enabled,
                    )
                )

        return items

    def list_listening_services(self) -> List[ListeningService]:
        """List services listening on ports on macOS using psutil."""
        services: List[ListeningService] = []

        if not HAS_PSUTIL:
            return services

        try:
            for conn in psutil.net_connections():
                if conn.status != "LISTEN":
                    continue

                proc_name = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "unknown"

                protocol = "tcp" if conn.type == 1 else "udp"

                services.append(
                    ListeningService(
                        pid=conn.pid or 0,
                        process_name=proc_name,
                        port=conn.laddr.port if conn.laddr else 0,
                        protocol=protocol,
                        bind_addr=conn.laddr.ip if conn.laddr else "0.0.0.0",
                    )
                )
        except Exception as exc:
            logger.error("LISTEN_ERROR: %s", exc)

        return services


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

    # ── v2 Methods (Linux implementations) ──

    def list_persistence_entries(self) -> List[PersistenceEntry]:
        """List persistence mechanisms on Linux: systemd, cron, init.d."""
        import os

        entries: List[PersistenceEntry] = []

        # Systemd user services
        systemd_dirs = [
            os.path.expanduser("~/.config/systemd/user"),
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
        ]
        for dir_path in systemd_dirs:
            if not os.path.isdir(dir_path):
                continue
            try:
                for filename in os.listdir(dir_path):
                    if not filename.endswith(".service"):
                        continue
                    svc_path = os.path.join(dir_path, filename)
                    exec_start = ""
                    try:
                        with open(svc_path, "r") as f:
                            for line in f:
                                if line.strip().startswith("ExecStart="):
                                    exec_start = line.strip().split("=", 1)[1]
                                    break
                    except Exception:
                        pass
                    entries.append(
                        PersistenceEntry(
                            path=svc_path,
                            mechanism="systemd_service",
                            label=filename,
                            program=exec_start,
                            enabled=True,
                        )
                    )
            except PermissionError:
                logger.debug("PERSISTENCE_DIR_DENIED: path=%s", dir_path)

        # Crontab
        stdout, outcome = self._run_subprocess(
            ["crontab", "-l"],
            timeout=5,
            operation="crontab",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            for i, line in enumerate(stdout.strip().split("\n")):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 5)
                program = parts[5] if len(parts) > 5 else line
                entries.append(
                    PersistenceEntry(
                        path="crontab",
                        mechanism="cron",
                        label=f"cron_{i}",
                        program=program,
                        enabled=True,
                    )
                )

        return entries

    def get_code_signing_info(self, path: str) -> Optional[CodeSigningInfo]:
        """Verify package signing on Linux using dpkg or rpm."""
        import os

        if not os.path.exists(path):
            return None

        # Try dpkg --verify
        stdout, outcome = self._run_subprocess(
            ["dpkg", "-S", path],
            timeout=5,
            operation="dpkg_check",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            return CodeSigningInfo(
                path=path,
                signed=True,
                valid=True,
                authority="dpkg",
                identifier=stdout.strip().split(":")[0],
            )

        return CodeSigningInfo(path=path, signed=False, valid=False)

    def get_sip_status(self) -> SIPStatus:
        """Get SELinux / AppArmor status on Linux."""
        # Try SELinux
        stdout, outcome = self._run_subprocess(
            ["getenforce"],
            timeout=5,
            operation="selinux_status",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            mode = stdout.strip().lower()
            return SIPStatus(
                enabled=mode == "enforcing",
                status_text=f"SELinux: {stdout.strip()}",
                custom_config=mode == "permissive",
            )

        # Try AppArmor
        stdout, outcome = self._run_subprocess(
            ["aa-status", "--enabled"],
            timeout=5,
            operation="apparmor_status",
        )
        if outcome == SubprocessOutcome.SUCCESS:
            return SIPStatus(
                enabled=True,
                status_text="AppArmor: enabled",
            )

        return SIPStatus(enabled=False, status_text="No MAC framework detected")

    def list_bluetooth_devices(self) -> List[BluetoothDevice]:
        """List Bluetooth devices on Linux using bluetoothctl."""
        devices: List[BluetoothDevice] = []
        import re

        stdout, outcome = self._run_subprocess(
            ["bluetoothctl", "devices"],
            timeout=5,
            operation="bt_devices",
        )
        if not stdout or outcome != SubprocessOutcome.SUCCESS:
            return devices

        # Parse: Device AA:BB:CC:DD:EE:FF DeviceName
        for line in stdout.strip().split("\n"):
            match = re.match(r"Device\s+([0-9A-Fa-f:]+)\s+(.*)", line.strip())
            if match:
                devices.append(
                    BluetoothDevice(
                        name=match.group(2),
                        address=match.group(1),
                    )
                )

        return devices

    def query_dns_cache(self) -> List[DNSEntry]:
        """Query DNS resolver configuration on Linux."""
        entries: List[DNSEntry] = []

        # Parse /etc/resolv.conf
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            entries.append(
                                DNSEntry(
                                    domain=".",
                                    record_type="NS",
                                    value=parts[1],
                                    source="resolv.conf",
                                )
                            )
                    elif line.startswith("search"):
                        for domain in line.split()[1:]:
                            entries.append(
                                DNSEntry(
                                    domain=domain,
                                    record_type="SEARCH",
                                    value=domain,
                                    source="resolv.conf",
                                )
                            )
        except FileNotFoundError:
            pass

        return entries

    def list_network_interfaces(self) -> List[NetworkInterface]:
        """List network interfaces on Linux using psutil."""
        interfaces: List[NetworkInterface] = []

        if not HAS_PSUTIL:
            return interfaces

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for name, addr_list in addrs.items():
                iface = NetworkInterface(name=name)

                for addr in addr_list:
                    if addr.family.name == "AF_INET":
                        iface.ipv4_addrs.append(addr.address)
                    elif addr.family.name == "AF_INET6":
                        iface.ipv6_addrs.append(addr.address)
                    elif addr.family.name == "AF_PACKET":
                        iface.hw_addr = addr.address

                if name in stats:
                    st = stats[name]
                    iface.is_up = st.isup
                    iface.mtu = st.mtu
                    iface.speed_mbps = st.speed
                    iface.is_loopback = name == "lo"

                interfaces.append(iface)
        except Exception as exc:
            logger.error("NETIF_ERROR: %s", exc)

        return interfaces

    def get_arp_table(self) -> List[ARPEntry]:
        """Get ARP table on Linux using ip neigh or arp -a."""
        import re

        entries: List[ARPEntry] = []

        # Try ip neigh first (modern)
        stdout, outcome = self._run_subprocess(
            ["ip", "neigh"],
            timeout=5,
            operation="arp_table",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            # Parse: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            for line in stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    idx = parts.index("lladdr")
                    entries.append(
                        ARPEntry(
                            ip_addr=parts[0],
                            hw_addr=parts[idx + 1] if idx + 1 < len(parts) else "",
                            interface=parts[2] if len(parts) > 2 else "",
                            is_permanent="PERMANENT" in line,
                        )
                    )
            return entries

        # Fallback to arp -a
        stdout, outcome = self._run_subprocess(
            ["arp", "-a"],
            timeout=5,
            operation="arp_table_legacy",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            for line in stdout.strip().split("\n"):
                match = re.match(
                    r"\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+.*on\s+(\S+)",
                    line,
                )
                if match and match.group(2) != "(incomplete)":
                    entries.append(
                        ARPEntry(
                            ip_addr=match.group(1),
                            hw_addr=match.group(2),
                            interface=match.group(3),
                        )
                    )

        return entries

    def get_firewall_status(self) -> FirewallStatus:
        """Get firewall status on Linux (iptables/ufw)."""
        # Try ufw first
        stdout, outcome = self._run_subprocess(
            ["ufw", "status"],
            timeout=5,
            operation="ufw_status",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            enabled = "active" in stdout.lower() and "inactive" not in stdout.lower()
            return FirewallStatus(
                enabled=enabled,
                status_text=stdout.strip(),
            )

        # Fallback: check if iptables has rules
        stdout, outcome = self._run_subprocess(
            ["iptables", "-L", "-n", "--line-numbers"],
            timeout=5,
            operation="iptables_status",
        )
        if stdout and outcome == SubprocessOutcome.SUCCESS:
            # If there are rules beyond default, firewall is active
            rule_lines = [
                line
                for line in stdout.strip().split("\n")
                if line.strip()
                and not line.startswith("Chain")
                and not line.startswith("num")
            ]
            return FirewallStatus(
                enabled=len(rule_lines) > 0,
                status_text=f"iptables: {len(rule_lines)} rules",
            )

        return FirewallStatus(enabled=False, status_text="unknown")

    def list_login_items(self) -> List[LoginItem]:
        """List login/autostart items on Linux (XDG autostart)."""
        import os

        items: List[LoginItem] = []

        autostart_dirs = [
            os.path.expanduser("~/.config/autostart"),
            "/etc/xdg/autostart",
        ]
        for dir_path in autostart_dirs:
            if not os.path.isdir(dir_path):
                continue
            try:
                for filename in os.listdir(dir_path):
                    if not filename.endswith(".desktop"):
                        continue
                    desktop_path = os.path.join(dir_path, filename)
                    name = filename.replace(".desktop", "")
                    exec_cmd = ""
                    hidden = False
                    try:
                        with open(desktop_path, "r") as f:
                            for line in f:
                                if line.startswith("Name="):
                                    name = line.strip().split("=", 1)[1]
                                elif line.startswith("Exec="):
                                    exec_cmd = line.strip().split("=", 1)[1]
                                elif line.startswith("Hidden="):
                                    hidden = (
                                        line.strip().split("=", 1)[1].lower() == "true"
                                    )
                    except Exception:
                        pass
                    items.append(
                        LoginItem(
                            name=name,
                            path=exec_cmd or desktop_path,
                            kind="autostart",
                            hidden=hidden,
                        )
                    )
            except PermissionError:
                pass

        return items

    def list_listening_services(self) -> List[ListeningService]:
        """List services listening on ports on Linux using psutil."""
        services: List[ListeningService] = []

        if not HAS_PSUTIL:
            return services

        try:
            for conn in psutil.net_connections():
                if conn.status != "LISTEN":
                    continue

                proc_name = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "unknown"

                protocol = "tcp" if conn.type == 1 else "udp"

                services.append(
                    ListeningService(
                        pid=conn.pid or 0,
                        process_name=proc_name,
                        port=conn.laddr.port if conn.laddr else 0,
                        protocol=protocol,
                        bind_addr=conn.laddr.ip if conn.laddr else "0.0.0.0",
                    )
                )
        except Exception as exc:
            logger.error("LISTEN_ERROR: %s", exc)

        return services


class StubOSLayer(OSLayer):
    """Testing stub with injectable data.

    Used for testing without requiring actual OS-specific dependencies.
    Allows injecting test data for each method.
    """

    def __init__(self):
        # v1 injectable data
        self.processes_data: List[ProcessInfo] = []
        self.connections_data: List[NetworkConnection] = []
        self.files_data: Dict[str, FileInfo] = {}
        self.usb_devices_data: List[USBDevice] = []
        self.logs_data: List[Dict] = []
        self.platform_name_value: str = "Stub"
        # v2 injectable data
        self.persistence_data: List[PersistenceEntry] = []
        self.code_signing_data: Dict[str, CodeSigningInfo] = {}
        self.sip_status_data: SIPStatus = SIPStatus(enabled=True, status_text="Stub")
        self.bluetooth_data: List[BluetoothDevice] = []
        self.dns_data: List[DNSEntry] = []
        self.network_interfaces_data: List[NetworkInterface] = []
        self.arp_data: List[ARPEntry] = []
        self.firewall_data: FirewallStatus = FirewallStatus(
            enabled=False, status_text="Stub"
        )
        self.login_items_data: List[LoginItem] = []
        self.listening_services_data: List[ListeningService] = []

    # ── v1 Setters ──

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

    # ── v2 Setters ──

    def set_persistence_entries(self, entries: List[PersistenceEntry]) -> None:
        self.persistence_data = entries

    def set_code_signing_info(self, path: str, info: CodeSigningInfo) -> None:
        self.code_signing_data[path] = info

    def set_sip_status(self, status: SIPStatus) -> None:
        self.sip_status_data = status

    def set_bluetooth_devices(self, devices: List[BluetoothDevice]) -> None:
        self.bluetooth_data = devices

    def set_dns_entries(self, entries: List[DNSEntry]) -> None:
        self.dns_data = entries

    def set_network_interfaces(self, interfaces: List[NetworkInterface]) -> None:
        self.network_interfaces_data = interfaces

    def set_arp_table(self, entries: List[ARPEntry]) -> None:
        self.arp_data = entries

    def set_firewall_status(self, status: FirewallStatus) -> None:
        self.firewall_data = status

    def set_login_items(self, items: List[LoginItem]) -> None:
        self.login_items_data = items

    def set_listening_services(self, services: List[ListeningService]) -> None:
        self.listening_services_data = services

    # ── v1 Methods ──

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

    # ── v2 Methods ──

    def list_persistence_entries(self) -> List[PersistenceEntry]:
        return self.persistence_data.copy()

    def get_code_signing_info(self, path: str) -> Optional[CodeSigningInfo]:
        return self.code_signing_data.get(path)

    def get_sip_status(self) -> SIPStatus:
        return self.sip_status_data

    def list_bluetooth_devices(self) -> List[BluetoothDevice]:
        return self.bluetooth_data.copy()

    def query_dns_cache(self) -> List[DNSEntry]:
        return self.dns_data.copy()

    def list_network_interfaces(self) -> List[NetworkInterface]:
        return self.network_interfaces_data.copy()

    def get_arp_table(self) -> List[ARPEntry]:
        return self.arp_data.copy()

    def get_firewall_status(self) -> FirewallStatus:
        return self.firewall_data

    def list_login_items(self) -> List[LoginItem]:
        return self.login_items_data.copy()

    def list_listening_services(self) -> List[ListeningService]:
        return self.listening_services_data.copy()


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
