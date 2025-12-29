#!/usr/bin/env python3
"""
AMOSKYS File Integrity Monitoring Agent (FIMAgent)

Monitors critical system files and directories for unauthorized changes:
- System binaries (/usr/bin, /bin, /sbin, /usr/sbin)
- Configuration files (/etc, /Library/Preferences)
- User SSH keys (~/.ssh)
- Web server roots (if detected)
- Application bundles (/Applications)

Detects:
- Rootkit installation
- Webshell deployment
- Configuration tampering
- Binary replacement attacks
- Unauthorized permission changes
- SUID/SGID bit manipulation

Uses cryptographic hashing (SHA-256) with baseline comparison.
"""

import hashlib
import json
import logging
import os
import socket
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import grpc

from amoskys.agents.common import LocalQueue
from amoskys.agents.common.hardened_base import (
    HardenedAgentBase,
)
from amoskys.config import get_config
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import universal_telemetry_pb2_grpc as universal_pbrpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FIMAgent")

config = get_config()
EVENTBUS_ADDRESS = config.agent.bus_address
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = getattr(config.agent, "fim_queue_path", "data/queue/fim_agent.db")
BASELINE_PATH = getattr(config.agent, "fim_baseline_path", "data/fim_baseline.json")


@dataclass
class FileState:
    """Represents the monitored state of a file"""

    path: str
    sha256: str
    size: int
    mode: int  # Unix permissions
    uid: int
    gid: int
    mtime: float
    is_suid: bool = False
    is_sgid: bool = False
    is_world_writable: bool = False
    extended_attrs: Dict[str, str] = field(default_factory=dict)


@dataclass
class FileChange:
    """Represents a detected file change"""

    path: str
    change_type: str  # CREATED, MODIFIED, DELETED, PERMISSION_CHANGED, OWNER_CHANGED
    old_state: Optional[FileState]
    new_state: Optional[FileState]
    severity: str  # INFO, WARN, HIGH, CRITICAL
    description: str
    mitre_techniques: List[str] = field(default_factory=list)


class FIMAgent(HardenedAgentBase):
    """File Integrity Monitoring Agent with hardened anti-evasion"""

    # Critical system paths to monitor
    CRITICAL_PATHS_MACOS = [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
        "/etc",
        "/private/etc",
    ]

    CRITICAL_PATHS_LINUX = [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/etc",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/boot",
    ]

    # High-value files that attackers commonly target
    HIGH_VALUE_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/pam.d",
        "/etc/crontab",
        "/etc/hosts",
        "/etc/resolv.conf",
        # macOS specific
        "/etc/authorization",
        "/Library/Preferences/com.apple.loginwindow.plist",
    ]

    # Webshell indicators - file extensions often used
    WEBSHELL_EXTENSIONS = {
        ".php",
        ".jsp",
        ".jspx",
        ".asp",
        ".aspx",
        ".cfm",
        ".py",
        ".pl",
        ".cgi",
        ".sh",
    }

    # Common web roots to monitor for webshells
    WEB_ROOTS = [
        "/var/www",
        "/var/www/html",
        "/usr/share/nginx/html",
        "/Library/WebServer/Documents",
        "/Applications/MAMP/htdocs",
    ]

    def __init__(
        self,
        queue_path: Optional[str] = None,
        baseline_path: Optional[str] = None,
        scan_interval: int = 300,  # 5 minutes default
        enable_realtime: bool = True,
    ):
        """Initialize FIM Agent

        Args:
            queue_path: Path to offline queue database
            baseline_path: Path to baseline state file
            scan_interval: Seconds between full scans
            enable_realtime: Enable filesystem event monitoring (FSEvents/inotify)
        """
        super().__init__(agent_name="FIMAgent")

        self.queue_path = queue_path or QUEUE_PATH
        self.baseline_path = baseline_path or BASELINE_PATH
        self.scan_interval = scan_interval
        self.enable_realtime = enable_realtime

        # Ensure directories exist
        Path(self.queue_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.baseline_path).parent.mkdir(parents=True, exist_ok=True)

        self.queue = LocalQueue(
            path=self.queue_path, max_bytes=100 * 1024 * 1024, max_retries=10  # 100MB
        )

        # Load or create baseline
        self.baseline: Dict[str, FileState] = self._load_baseline()

        # Determine platform and set paths
        self.platform = self._detect_platform()
        self.monitored_paths = self._get_monitored_paths()

        # Track changes for reporting
        self.pending_changes: List[FileChange] = []

        logger.info(
            f"FIMAgent initialized: platform={self.platform}, "
            f"paths={len(self.monitored_paths)}, baseline={len(self.baseline)} files"
        )

    def _detect_platform(self) -> str:
        """Detect operating system"""
        import platform

        system = platform.system().lower()
        if system == "darwin":
            return "macos"
        elif system == "linux":
            return "linux"
        elif system == "windows":
            return "windows"
        return "unknown"

    def _get_monitored_paths(self) -> List[str]:
        """Get paths to monitor based on platform"""
        if self.platform == "macos":
            paths = self.CRITICAL_PATHS_MACOS.copy()
        elif self.platform == "linux":
            paths = self.CRITICAL_PATHS_LINUX.copy()
        else:
            paths = []

        # Add user home directories
        try:
            home = Path.home()
            paths.extend(
                [
                    str(home / ".ssh"),
                    str(home / ".bashrc"),
                    str(home / ".bash_profile"),
                    str(home / ".zshrc"),
                    str(home / ".profile"),
                ]
            )
            if self.platform == "macos":
                paths.append(str(home / "Library/LaunchAgents"))
        except Exception:
            pass

        # Add existing web roots
        for web_root in self.WEB_ROOTS:
            if Path(web_root).exists():
                paths.append(web_root)

        # Filter to existing paths
        return [p for p in paths if Path(p).exists()]

    def _load_baseline(self) -> Dict[str, FileState]:
        """Load baseline from disk"""
        if not Path(self.baseline_path).exists():
            return {}

        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)
                baseline = {}
                for path, state_dict in data.items():
                    baseline[path] = FileState(
                        path=state_dict["path"],
                        sha256=state_dict["sha256"],
                        size=state_dict["size"],
                        mode=state_dict["mode"],
                        uid=state_dict["uid"],
                        gid=state_dict["gid"],
                        mtime=state_dict["mtime"],
                        is_suid=state_dict.get("is_suid", False),
                        is_sgid=state_dict.get("is_sgid", False),
                        is_world_writable=state_dict.get("is_world_writable", False),
                        extended_attrs=state_dict.get("extended_attrs", {}),
                    )
                return baseline
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return {}

    def _save_baseline(self) -> None:
        """Save baseline to disk"""
        try:
            data = {}
            for path, state in self.baseline.items():
                data[path] = {
                    "path": state.path,
                    "sha256": state.sha256,
                    "size": state.size,
                    "mode": state.mode,
                    "uid": state.uid,
                    "gid": state.gid,
                    "mtime": state.mtime,
                    "is_suid": state.is_suid,
                    "is_sgid": state.is_sgid,
                    "is_world_writable": state.is_world_writable,
                    "extended_attrs": state.extended_attrs,
                }
            with open(self.baseline_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved baseline: {len(data)} files")
        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")

    def _hash_file(self, path: str) -> Optional[str]:
        """Calculate SHA-256 hash of a file"""
        try:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as e:
            logger.debug(f"Cannot hash {path}: {e}")
            return None

    def _get_file_state(self, path: str) -> Optional[FileState]:
        """Get current state of a file"""
        try:
            stat_info = os.stat(path)
            file_hash = self._hash_file(path)

            if file_hash is None:
                return None

            mode = stat_info.st_mode
            is_suid = bool(mode & stat.S_ISUID)
            is_sgid = bool(mode & stat.S_ISGID)
            is_world_writable = bool(mode & stat.S_IWOTH)

            # Get extended attributes (macOS)
            extended_attrs = {}
            if self.platform == "macos":
                try:
                    import xattr

                    attrs = xattr.listxattr(path)
                    for attr in attrs[:5]:  # Limit to first 5
                        try:
                            val = xattr.getxattr(path, attr)
                            extended_attrs[attr] = val.hex()[:32]  # Truncate
                        except Exception:
                            pass
                except ImportError:
                    pass

            return FileState(
                path=path,
                sha256=file_hash,
                size=stat_info.st_size,
                mode=mode,
                uid=stat_info.st_uid,
                gid=stat_info.st_gid,
                mtime=stat_info.st_mtime,
                is_suid=is_suid,
                is_sgid=is_sgid,
                is_world_writable=is_world_writable,
                extended_attrs=extended_attrs,
            )
        except Exception as e:
            logger.debug(f"Cannot get state for {path}: {e}")
            return None

    def _classify_change(self, change: FileChange) -> None:
        """Classify the severity and MITRE techniques for a change"""
        path = change.path
        path_lower = path.lower()

        # Default severity
        severity = "INFO"
        techniques = []

        # Check for critical file modifications
        if change.change_type in ("MODIFIED", "DELETED"):
            if any(critical in path for critical in ["/bin/", "/sbin/", "/usr/bin/"]):
                severity = "CRITICAL"
                techniques.append("T1574")  # Hijack Execution Flow
                techniques.append("T1036")  # Masquerading

            if "/etc/shadow" in path or "/etc/passwd" in path:
                severity = "CRITICAL"
                techniques.append("T1003")  # OS Credential Dumping

            if "/etc/sudoers" in path:
                severity = "CRITICAL"
                techniques.append("T1548")  # Abuse Elevation Control

            if "LaunchAgent" in path or "LaunchDaemon" in path:
                severity = "HIGH"
                techniques.append("T1543.001")  # Launch Agent

            if "/etc/ssh" in path:
                severity = "HIGH"
                techniques.append("T1098.004")  # SSH Authorized Keys

            if "/.ssh/" in path:
                severity = "HIGH"
                techniques.append("T1098.004")  # SSH Authorized Keys

        # Check for new SUID/SGID binaries (privilege escalation)
        if change.new_state:
            if change.new_state.is_suid and (
                not change.old_state or not change.old_state.is_suid
            ):
                severity = "CRITICAL"
                techniques.append("T1548.001")  # Setuid and Setgid
                change.description += " [NEW SUID BIT]"

            if change.new_state.is_sgid and (
                not change.old_state or not change.old_state.is_sgid
            ):
                severity = "HIGH"
                techniques.append("T1548.001")  # Setuid and Setgid
                change.description += " [NEW SGID BIT]"

        # Check for webshell indicators
        if change.change_type == "CREATED":
            ext = Path(path).suffix.lower()
            if ext in self.WEBSHELL_EXTENSIONS:
                for web_root in self.WEB_ROOTS:
                    if path.startswith(web_root):
                        severity = "CRITICAL"
                        techniques.append("T1505.003")  # Web Shell
                        change.description += " [POTENTIAL WEBSHELL]"
                        break

        # World-writable files in sensitive locations
        if change.new_state and change.new_state.is_world_writable:
            if any(x in path for x in ["/etc/", "/bin/", "/sbin/"]):
                severity = max(severity, "HIGH")
                techniques.append("T1222")  # File and Directory Permissions
                change.description += " [WORLD WRITABLE]"

        change.severity = severity
        change.mitre_techniques = techniques

    def scan_directory(self, path: str, recursive: bool = True) -> Dict[str, FileState]:
        """Scan a directory and return file states"""
        states = {}
        path_obj = Path(path)

        if not path_obj.exists():
            return states

        try:
            if path_obj.is_file():
                state = self._get_file_state(str(path_obj))
                if state:
                    states[str(path_obj)] = state
            elif path_obj.is_dir():
                iterator = path_obj.rglob("*") if recursive else path_obj.iterdir()
                for item in iterator:
                    if item.is_file():
                        try:
                            state = self._get_file_state(str(item))
                            if state:
                                states[str(item)] = state
                        except Exception:
                            continue
        except PermissionError:
            logger.debug(f"Permission denied: {path}")
        except Exception as e:
            logger.debug(f"Error scanning {path}: {e}")

        return states

    def full_scan(self) -> List[FileChange]:
        """Perform a full scan and compare against baseline"""
        # Check for evasion before scanning
        self.detect_evasion_attempts()

        changes = []
        current_states: Dict[str, FileState] = {}

        logger.info(f"Starting full FIM scan: {len(self.monitored_paths)} paths")
        start_time = time.time()

        # Scan all monitored paths
        for path in self.monitored_paths:
            try:
                # Limit recursion depth for large directories
                recursive = not any(x in path for x in ["/usr/lib", "/lib", "/boot"])
                states = self.scan_directory(path, recursive=recursive)
                current_states.update(states)
            except Exception as e:
                logger.error(f"Error scanning {path}: {e}")

        # Also scan high-value individual files
        for path in self.HIGH_VALUE_FILES:
            if Path(path).exists():
                state = self._get_file_state(path)
                if state:
                    current_states[path] = state

        scan_time = time.time() - start_time
        logger.info(
            f"FIM scan complete: {len(current_states)} files in {scan_time:.2f}s"
        )

        # Compare with baseline
        all_paths = set(self.baseline.keys()) | set(current_states.keys())

        for path in all_paths:
            old_state = self.baseline.get(path)
            new_state = current_states.get(path)

            change = self._compare_states(path, old_state, new_state)
            if change:
                self._classify_change(change)
                changes.append(change)

        # Update baseline with current state
        self.baseline = current_states
        self._save_baseline()

        # Check for suspicious patterns in changes
        if len(changes) > 50:
            # Many changes at once could indicate mass tampering
            logger.warning(
                f"Suspicious: {len(changes)} file changes detected in single scan"
            )
            self.assess_threat_level()

        return changes

    def _compare_states(
        self,
        path: str,
        old_state: Optional[FileState],
        new_state: Optional[FileState],
    ) -> Optional[FileChange]:
        """Compare old and new file states"""
        if old_state is None and new_state is not None:
            # New file created
            return FileChange(
                path=path,
                change_type="CREATED",
                old_state=None,
                new_state=new_state,
                severity="INFO",
                description=f"New file created: {path}",
            )

        if old_state is not None and new_state is None:
            # File deleted
            return FileChange(
                path=path,
                change_type="DELETED",
                old_state=old_state,
                new_state=None,
                severity="WARN",
                description=f"File deleted: {path}",
            )

        if old_state is not None and new_state is not None:
            changes = []

            # Content changed
            if old_state.sha256 != new_state.sha256:
                changes.append("content")

            # Permissions changed
            if old_state.mode != new_state.mode:
                changes.append("permissions")

            # Owner changed
            if old_state.uid != new_state.uid or old_state.gid != new_state.gid:
                changes.append("owner")

            # Size changed (redundant with content but useful info)
            if old_state.size != new_state.size:
                changes.append("size")

            if changes:
                change_type = "MODIFIED"
                if "permissions" in changes and "content" not in changes:
                    change_type = "PERMISSION_CHANGED"
                elif "owner" in changes and "content" not in changes:
                    change_type = "OWNER_CHANGED"

                return FileChange(
                    path=path,
                    change_type=change_type,
                    old_state=old_state,
                    new_state=new_state,
                    severity="INFO",
                    description=f"File {change_type.lower()}: {path} ({', '.join(changes)})",
                )

        return None

    def _get_grpc_channel(self):
        """Create gRPC channel to EventBus with mTLS"""
        try:
            with open(f"{CERT_DIR}/ca.crt", "rb") as f:
                ca_cert = f.read()
            with open(f"{CERT_DIR}/agent.crt", "rb") as f:
                client_cert = f.read()
            with open(f"{CERT_DIR}/agent.key", "rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            channel = grpc.secure_channel(EVENTBUS_ADDRESS, credentials)
            logger.debug("Created secure gRPC channel with mTLS")
            return channel
        except FileNotFoundError as e:
            logger.error("Certificate not found: %s", e)
            return None
        except Exception as e:
            logger.error("Failed to create gRPC channel: %s", str(e))
            return None

    def _create_telemetry(
        self, changes: List[FileChange]
    ) -> telemetry_pb2.DeviceTelemetry:
        """Create DeviceTelemetry protobuf from file changes"""
        timestamp_ns = int(time.time() * 1e9)
        hostname = socket.gethostname()

        events = []
        for change in changes:
            # Map severity to proto severity
            severity_map = {
                "INFO": "INFO",
                "WARN": "WARN",
                "HIGH": "ERROR",
                "CRITICAL": "CRITICAL",
            }

            event = telemetry_pb2.TelemetryEvent(
                event_id=f"fim_{hash(change.path)}_{timestamp_ns}",
                event_type="SECURITY",
                severity=severity_map.get(change.severity, "INFO"),
                event_timestamp_ns=timestamp_ns,
                security_event=telemetry_pb2.SecurityEvent(
                    event_action="FILE_INTEGRITY",
                    event_outcome=change.change_type,
                    process_name="fim_agent",
                    process_path=change.path,
                    user_name=str(change.new_state.uid if change.new_state else ""),
                    source_ip="127.0.0.1",
                    details=json.dumps(
                        {
                            "description": change.description,
                            "mitre_techniques": change.mitre_techniques,
                            "old_hash": (
                                change.old_state.sha256 if change.old_state else None
                            ),
                            "new_hash": (
                                change.new_state.sha256 if change.new_state else None
                            ),
                            "old_mode": (
                                oct(change.old_state.mode) if change.old_state else None
                            ),
                            "new_mode": (
                                oct(change.new_state.mode) if change.new_state else None
                            ),
                        }
                    ),
                ),
            )
            events.append(event)

        return telemetry_pb2.DeviceTelemetry(
            device_id=f"endpoint_{hostname}",
            device_type="ENDPOINT",
            collection_timestamp_ns=timestamp_ns,
            events=events,
        )

    def publish_changes(self, changes: List[FileChange]) -> bool:
        """Publish file changes to EventBus"""
        if not changes:
            return True

        # Filter to only significant changes
        significant_changes = [
            c for c in changes if c.severity in ("WARN", "HIGH", "CRITICAL")
        ]

        if not significant_changes:
            logger.debug(f"No significant changes to publish ({len(changes)} total)")
            return True

        telemetry = self._create_telemetry(significant_changes)

        channel = self._get_grpc_channel()
        if not channel:
            # Queue for later
            self.queue.push(telemetry.SerializeToString())
            logger.warning(f"Queued {len(significant_changes)} FIM events (no channel)")
            return False

        try:
            stub = universal_pbrpc.UniversalTelemetryServiceStub(channel)

            envelope = telemetry_pb2.UniversalEnvelope(
                version="v1",
                ts_ns=int(time.time() * 1e9),
                idempotency_key=f"fim_{socket.gethostname()}_{int(time.time())}",
                device_telemetry=telemetry,
            )

            response = stub.Publish(envelope, timeout=10)

            if response.ack == telemetry_pb2.UniversalAck.Ack.OK:
                logger.info(f"Published {len(significant_changes)} FIM events")
                return True
            else:
                self.queue.push(telemetry.SerializeToString())
                logger.warning(f"EventBus returned {response.ack}, queued events")
                return False

        except grpc.RpcError as e:
            self.queue.push(telemetry.SerializeToString())
            logger.error(f"gRPC error: {e}, queued events")
            return False
        finally:
            channel.close()

    def collect(self) -> bool:
        """Perform one collection cycle (implements abstract method)

        Returns:
            True if collection succeeded, False otherwise
        """
        try:
            changes = self.run_once()
            return True
        except Exception as e:
            logger.error(f"Collection failed: {e}")
            return False

    def run_once(self) -> List[FileChange]:
        """Run a single scan cycle"""
        # Verify agent integrity before running
        if not self.verify_integrity():
            logger.error("Agent integrity check failed!")
            self.assess_threat_level()

        changes = self.full_scan()

        if changes:
            logger.info(
                f"Detected {len(changes)} changes: "
                f"CRITICAL={sum(1 for c in changes if c.severity == 'CRITICAL')}, "
                f"HIGH={sum(1 for c in changes if c.severity == 'HIGH')}, "
                f"WARN={sum(1 for c in changes if c.severity == 'WARN')}"
            )
            self.publish_changes(changes)

        return changes

    def run(self) -> None:
        """Run continuous monitoring loop"""
        logger.info(f"Starting FIM Agent: interval={self.scan_interval}s")

        # Initial baseline scan
        if not self.baseline:
            logger.info("Creating initial baseline...")
            self.full_scan()
            logger.info(f"Baseline created: {len(self.baseline)} files")

        while True:
            try:
                changes = self.run_once()

                # Flush queue if we have connectivity
                self._flush_queue()

                time.sleep(self.scan_interval)

            except KeyboardInterrupt:
                logger.info("Shutting down FIM Agent...")
                break
            except Exception as e:
                logger.error(f"Error in FIM loop: {e}")
                time.sleep(60)  # Wait before retry

    def _flush_queue(self) -> None:
        """Attempt to flush queued events"""
        while True:
            item = self.queue.pop()
            if item is None:
                break

            channel = self._get_grpc_channel()
            if not channel:
                self.queue.push(item)  # Re-queue
                break

            try:
                telemetry = telemetry_pb2.DeviceTelemetry()
                telemetry.ParseFromString(item)

                stub = universal_pbrpc.UniversalTelemetryServiceStub(channel)
                envelope = telemetry_pb2.UniversalEnvelope(
                    version="v1",
                    ts_ns=int(time.time() * 1e9),
                    idempotency_key=f"fim_queue_{int(time.time())}",
                    device_telemetry=telemetry,
                )
                stub.Publish(envelope, timeout=10)
                logger.debug("Flushed queued FIM event")
            except Exception as e:
                self.queue.push(item)  # Re-queue on failure
                logger.debug(f"Failed to flush queue: {e}")
                break
            finally:
                channel.close()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS File Integrity Monitor")
    parser.add_argument(
        "--interval", type=int, default=300, help="Scan interval in seconds"
    )
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="Create baseline and exit",
    )
    parser.add_argument(
        "--scan-once", action="store_true", help="Run single scan and exit"
    )
    args = parser.parse_args()

    agent = FIMAgent(scan_interval=args.interval)

    if args.baseline_only:
        agent.full_scan()
        print(f"Baseline created: {len(agent.baseline)} files")
    elif args.scan_once:
        changes = agent.run_once()
        print(f"Detected {len(changes)} changes")
        for change in changes:
            print(f"  [{change.severity}] {change.change_type}: {change.path}")
    else:
        agent.run()


if __name__ == "__main__":
    main()
