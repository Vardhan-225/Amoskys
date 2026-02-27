#!/usr/bin/env python3
"""PersistenceGuardV2 - Persistence Mechanism Monitoring with Micro-Probe Architecture.

Monitors autostart mechanisms and persistence techniques for threat detection:
    - macOS LaunchAgents/LaunchDaemons
    - Linux systemd services
    - Cron jobs and anacron @reboot
    - SSH authorized_keys backdoors
    - Shell profile hijacking
    - Browser extension persistence
    - GUI startup items
    - Hidden executable loaders

Architecture:
    - PersistenceCollector: Platform-specific persistence enumeration
    - PersistenceBaselineEngine: Snapshot & diff management
    - 8 Micro-Probes: Specialized threat detectors
    - HardenedAgentBase: Circuit breaker + offline resilience

CLI Usage:
    ```bash
    # Create baseline
    python persistence_agent_v2.py --mode create

    # Monitor for changes
    python persistence_agent_v2.py --mode monitor --interval 300
    ```

MITRE ATT&CK Coverage:
    - T1037: Logon Scripts / Autostart
    - T1053.003: Cron
    - T1098.004: SSH Authorized Keys
    - T1176: Browser Extensions
    - T1543: Create or Modify System Process
    - T1546.004: Shell Profiles
    - T1547: Boot or Logon Autostart Execution
    - T1564: Hide Artifacts
"""

from __future__ import annotations

import argparse
import logging
import socket
import time
from typing import Any, Dict, Optional, Sequence

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import (
    MicroProbeAgentMixin,
    ProbeContext,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.persistence.probes import (
    PersistenceBaselineEngine,
    PersistenceEntry,
    create_persistence_probes,
)
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

logger = logging.getLogger(__name__)


# =============================================================================
# Persistence Collector (Platform-Specific)
# =============================================================================


class PersistenceCollector:
    """Platform-specific persistence mechanism collector.

    Collects snapshot of all persistence mechanisms on macOS:
        - launchd: enumerate LaunchAgents/LaunchDaemons plists
        - cron: parse crontab -l output
        - shell profiles: hash ~/.bashrc, ~/.zshrc, ~/.bash_profile, etc.
        - SSH keys: hash & count authorized_keys
    """

    def __init__(self):
        """Initialize persistence collector."""
        self.entries_collected = 0

    def collect_snapshot(self) -> Dict[str, PersistenceEntry]:
        """Enumerate all persistence mechanisms on this host.

        Returns:
            Dictionary mapping entry_id to PersistenceEntry
        """
        import hashlib
        import os
        import platform
        import plistlib
        import re
        import subprocess
        import time

        logger.debug("Collecting persistence snapshot")
        snapshot: Dict[str, PersistenceEntry] = {}
        now_ns = int(time.time() * 1e9)

        if platform.system() != "Darwin":
            logger.info("Non-macOS platform — persistence collector deferred")
            self.entries_collected = len(snapshot)
            return snapshot

        # ── 1. LaunchAgents / LaunchDaemons ───────────────────────────
        home = os.path.expanduser("~")
        launch_dirs = [
            (f"{home}/Library/LaunchAgents", "USER_LAUNCH_AGENT"),
            ("/Library/LaunchAgents", "SYSTEM_LAUNCH_AGENT"),
            ("/Library/LaunchDaemons", "SYSTEM_LAUNCH_DAEMON"),
        ]

        for dir_path, mech_type in launch_dirs:
            if not os.path.isdir(dir_path):
                continue
            try:
                for fname in os.listdir(dir_path):
                    if not fname.endswith(".plist"):
                        continue
                    fpath = os.path.join(dir_path, fname)
                    try:
                        file_hash = self._sha256_file(fpath)
                        cmd, args_str, label, enabled = "", "", fname, True
                        try:
                            with open(fpath, "rb") as pf:
                                plist = plistlib.load(pf)
                        except Exception:
                            # Fallback: use plutil to convert binary plist
                            try:
                                plutil_result = subprocess.run(
                                    ["plutil", "-convert", "xml1", "-o", "-", fpath],
                                    capture_output=True,
                                    timeout=5,
                                )
                                if plutil_result.returncode == 0:
                                    plist = plistlib.loads(plutil_result.stdout)
                                else:
                                    plist = {}
                                    logger.debug("plist parse failed for %s", fpath)
                            except Exception as pe:
                                plist = {}
                                logger.debug(
                                    "plutil fallback failed for %s: %s", fpath, pe
                                )

                        if plist:
                            prog_args = plist.get("ProgramArguments", [])
                            cmd = plist.get(
                                "Program", prog_args[0] if prog_args else ""
                            )
                            args_str = (
                                " ".join(prog_args[1:]) if len(prog_args) > 1 else ""
                            )
                            label = plist.get("Label", fname)
                            enabled = not plist.get("Disabled", False)

                        stat = os.stat(fpath)
                        entry_id = f"launchd:{fpath}"
                        snapshot[entry_id] = PersistenceEntry(
                            id=entry_id,
                            mechanism_type=mech_type,
                            user=self._file_owner(fpath),
                            path=fpath,
                            command=cmd,
                            args=args_str,
                            enabled=enabled,
                            hash=file_hash,
                            metadata={
                                "label": label,
                                "dir": dir_path,
                                "mtime": str(int(stat.st_mtime)),
                                "size": str(stat.st_size),
                            },
                            last_seen_ns=now_ns,
                        )
                    except OSError as e:
                        logger.debug(f"Skipping {fpath}: {e}")
            except PermissionError:
                logger.debug(f"Cannot list {dir_path}")

        # ── 2. Cron jobs ──────────────────────────────────────────────
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                cron_content = result.stdout.strip()
                cron_hash = hashlib.sha256(cron_content.encode()).hexdigest()
                entry_id = f"cron:user:{os.environ.get('USER', 'unknown')}"
                snapshot[entry_id] = PersistenceEntry(
                    id=entry_id,
                    mechanism_type="CRON_USER",
                    user=os.environ.get("USER", "unknown"),
                    path=None,
                    command=cron_content[:200],
                    args=None,
                    enabled=True,
                    hash=cron_hash,
                    metadata={"line_count": str(len(cron_content.splitlines()))},
                    last_seen_ns=now_ns,
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # ── 3. Shell profiles ─────────────────────────────────────────
        shell_files = [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".zlogin",
            ".zshenv",
        ]
        for fname in shell_files:
            fpath = os.path.join(home, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                file_hash = self._sha256_file(fpath)
                stat = os.stat(fpath)
                # Read content for ShellProfileHijackProbe pattern matching
                content = None
                try:
                    with open(fpath, "r", errors="replace") as sf:
                        content = sf.read(4096)  # bounded read
                except OSError:
                    pass
                entry_id = f"shell_profile:{fpath}"
                snapshot[entry_id] = PersistenceEntry(
                    id=entry_id,
                    mechanism_type="SHELL_PROFILE",
                    user=self._file_owner(fpath),
                    path=fpath,
                    command=content,
                    args=None,
                    enabled=True,
                    hash=file_hash,
                    metadata={
                        "mtime": str(int(stat.st_mtime)),
                        "size": str(stat.st_size),
                    },
                    last_seen_ns=now_ns,
                )
            except OSError:
                pass

        # ── 4. SSH authorized_keys ────────────────────────────────────
        ak_path = os.path.join(home, ".ssh", "authorized_keys")
        if os.path.isfile(ak_path):
            try:
                file_hash = self._sha256_file(ak_path)
                with open(ak_path) as f:
                    lines = [
                        l.strip() for l in f if l.strip() and not l.startswith("#")
                    ]
                # Extract forced commands from key lines
                forced_commands = []
                for key_line in lines:
                    if key_line.startswith("command="):
                        cmd_match = re.match(r'command="([^"]*)"', key_line)
                        if cmd_match:
                            forced_commands.append(cmd_match.group(1))
                entry_id = f"ssh_keys:{ak_path}"
                snapshot[entry_id] = PersistenceEntry(
                    id=entry_id,
                    mechanism_type="SSH_AUTHORIZED_KEYS",
                    user=self._file_owner(ak_path),
                    path=ak_path,
                    command=None,
                    args=None,
                    enabled=True,
                    hash=file_hash,
                    metadata={
                        "key_count": str(len(lines)),
                        "mtime": str(int(os.stat(ak_path).st_mtime)),
                        "has_forced_command": str(bool(forced_commands)),
                        "forced_commands": (
                            ",".join(forced_commands) if forced_commands else ""
                        ),
                    },
                    last_seen_ns=now_ns,
                )
            except OSError:
                pass

        # ── 5. Browser extensions ─────────────────────────────────────
        self._collect_browser_extensions(snapshot, home, now_ns)

        # ── 6. Login items ───────────────────────────────────────────
        self._collect_login_items(snapshot, now_ns)

        # ── 7. Hidden executable files ───────────────────────────────
        self._collect_hidden_executables(snapshot, home, now_ns)

        self.entries_collected += len(snapshot)
        logger.info(f"Persistence snapshot: {len(snapshot)} entries collected")
        return snapshot

    def _collect_browser_extensions(
        self,
        snapshot: Dict[str, "PersistenceEntry"],
        home: str,
        now_ns: int,
    ) -> None:
        """Scan Chrome and Firefox extension directories."""
        import json
        import os

        chrome_ext_dir = os.path.join(
            home,
            "Library",
            "Application Support",
            "Google",
            "Chrome",
            "Default",
            "Extensions",
        )
        firefox_profile_dir = os.path.join(
            home,
            "Library",
            "Application Support",
            "Firefox",
            "Profiles",
        )

        # Chrome extensions
        if os.path.isdir(chrome_ext_dir):
            try:
                for ext_id in os.listdir(chrome_ext_dir):
                    ext_path = os.path.join(chrome_ext_dir, ext_id)
                    if not os.path.isdir(ext_path):
                        continue
                    manifest = self._read_chrome_manifest(ext_path)
                    if not manifest:
                        continue
                    entry_id = f"browser_ext:chrome:{ext_id}"
                    snapshot[entry_id] = PersistenceEntry(
                        id=entry_id,
                        mechanism_type="BROWSER_EXTENSION",
                        user=os.environ.get("USER", "unknown"),
                        path=ext_path,
                        command=manifest.get("name", ext_id),
                        args=None,
                        enabled=True,
                        hash=None,
                        metadata={
                            "browser": "chrome",
                            "version": manifest.get("version", "unknown"),
                            "permissions": ",".join(manifest.get("permissions", [])),
                        },
                        last_seen_ns=now_ns,
                    )
            except OSError:
                pass

        # Firefox extensions
        if os.path.isdir(firefox_profile_dir):
            try:
                for profile in os.listdir(firefox_profile_dir):
                    ext_dir = os.path.join(firefox_profile_dir, profile, "extensions")
                    if not os.path.isdir(ext_dir):
                        continue
                    for ext_name in os.listdir(ext_dir):
                        ext_path = os.path.join(ext_dir, ext_name)
                        entry_id = f"browser_ext:firefox:{ext_name}"
                        snapshot[entry_id] = PersistenceEntry(
                            id=entry_id,
                            mechanism_type="BROWSER_EXTENSION",
                            user=os.environ.get("USER", "unknown"),
                            path=ext_path,
                            command=ext_name,
                            args=None,
                            enabled=True,
                            hash=None,
                            metadata={"browser": "firefox"},
                            last_seen_ns=now_ns,
                        )
            except OSError:
                pass

    @staticmethod
    def _read_chrome_manifest(ext_path: str) -> Optional[dict]:
        """Read manifest.json from the latest version subdirectory."""
        import json
        import os

        try:
            versions = sorted(os.listdir(ext_path))
            if not versions:
                return None
            manifest_path = os.path.join(ext_path, versions[-1], "manifest.json")
            if os.path.isfile(manifest_path):
                with open(manifest_path) as f:
                    return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def _collect_login_items(
        self,
        snapshot: Dict[str, "PersistenceEntry"],
        now_ns: int,
    ) -> None:
        """Collect macOS login items via osascript."""
        import os
        import subprocess

        try:
            result = subprocess.run(
                [
                    "osascript",
                    "-e",
                    'tell application "System Events" to get {name, path, hidden} of every login item',
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return

            # Output format: {name1, name2, ...}, {path1, path2, ...}, {hidden1, hidden2, ...}
            output = result.stdout.strip()
            # Parse the three lists
            parts = output.split("}, {")
            if len(parts) < 3:
                return
            names = parts[0].lstrip("{").split(", ")
            paths = parts[1].split(", ")
            hiddens = parts[2].rstrip("}").split(", ")

            for i, name in enumerate(names):
                path = paths[i] if i < len(paths) else ""
                hidden = hiddens[i].lower() == "true" if i < len(hiddens) else False
                entry_id = f"login_item:{name}"
                snapshot[entry_id] = PersistenceEntry(
                    id=entry_id,
                    mechanism_type="STARTUP_ITEM",
                    user=os.environ.get("USER", "unknown"),
                    path=path,
                    command=name,
                    args=None,
                    enabled=True,
                    hash=None,
                    metadata={"hidden": str(hidden)},
                    last_seen_ns=now_ns,
                )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _collect_hidden_executables(
        self,
        snapshot: Dict[str, "PersistenceEntry"],
        home: str,
        now_ns: int,
    ) -> None:
        """Scan monitored directories for hidden executable files."""
        import os

        monitored_dirs = [
            os.path.join(home, "Library", "LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/usr/local/bin",
            os.path.join(home, "bin"),
            os.path.join(home, ".local", "bin"),
        ]

        for dir_path in monitored_dirs:
            if not os.path.isdir(dir_path):
                continue
            try:
                for fname in os.listdir(dir_path):
                    if not fname.startswith("."):
                        continue
                    fpath = os.path.join(dir_path, fname)
                    if not os.path.isfile(fpath) or not os.access(fpath, os.X_OK):
                        continue
                    entry_id = f"hidden_file:{fpath}"
                    snapshot[entry_id] = PersistenceEntry(
                        id=entry_id,
                        mechanism_type="HIDDEN_FILE",
                        user=self._file_owner(fpath),
                        path=fpath,
                        command=fname,
                        args=None,
                        enabled=True,
                        hash=self._sha256_file(fpath),
                        metadata={
                            "is_executable": "True",
                            "mtime": str(int(os.stat(fpath).st_mtime)),
                        },
                        last_seen_ns=now_ns,
                    )
            except OSError:
                pass

    @staticmethod
    def _sha256_file(path: str) -> str:
        """Compute SHA-256 hash of a file."""
        import hashlib

        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ""

    @staticmethod
    def _file_owner(path: str) -> str:
        """Get file owner username."""
        import os as _os
        import pwd

        try:
            return pwd.getpwuid(_os.stat(path).st_uid).pw_name
        except (OSError, KeyError):
            return "unknown"


# =============================================================================
# PersistenceGuardV2 - Main Agent
# =============================================================================


class PersistenceGuard(MicroProbeAgentMixin, HardenedAgentBase):
    """Persistence monitoring agent with micro-probe architecture.

    Monitors persistence mechanisms using 8 specialized threat detectors:
        1. LaunchAgentDaemonProbe - macOS launchd persistence
        2. SystemdServicePersistenceProbe - Linux systemd services
        3. CronJobPersistenceProbe - cron/anacron @reboot
        4. SSHKeyBackdoorProbe - authorized_keys tampering
        5. ShellProfileHijackProbe - bashrc/zshrc hijacking
        6. BrowserExtensionPersistenceProbe - malicious extensions
        7. StartupFolderLoginItemProbe - GUI autostart items
        8. HiddenFilePersistenceProbe - hidden executable loaders
    """

    AGENT_NAME = "persistence"
    COLLECTION_INTERVAL_SECONDS = 300.0  # 5 minutes default

    def __init__(
        self,
        device_id: Optional[str] = None,
        queue_path: str = "data/queue/persistence.db",
        baseline_mode: str = "monitor",  # "create" or "monitor"
        baseline_path: str = "data/persistence_baseline.json",
        collection_interval: float = COLLECTION_INTERVAL_SECONDS,
    ):
        """Initialize PersistenceGuardV2."""
        if device_id is None:
            device_id = socket.gethostname()

        from pathlib import Path

        Path(queue_path).parent.mkdir(parents=True, exist_ok=True)

        queue_adapter = LocalQueueAdapter(
            queue_path=queue_path,
            agent_name=self.AGENT_NAME,
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path="certs/agent.ed25519",
        )

        super().__init__(
            agent_name=self.AGENT_NAME,
            device_id=device_id,
            collection_interval=collection_interval,
            local_queue=queue_adapter,
        )

        # Register probes
        self.register_probes(create_persistence_probes())

        # Initialize collector and baseline engine
        self.collector = PersistenceCollector()
        self.baseline_engine = PersistenceBaselineEngine(baseline_path)
        self.baseline_mode = baseline_mode

        # Load baseline if in monitor mode
        if self.baseline_mode == "monitor":
            if not self.baseline_engine.load():
                logger.warning(
                    "No baseline found — first cycle will create one automatically"
                )
                self.baseline_mode = "auto_create"

        logger.info(
            f"PersistenceGuardV2 initialized: device={device_id}, "
            f"mode={baseline_mode}, baseline={baseline_path}, "
            f"interval={collection_interval}s, probes={len(self._probes)}"
        )

    def setup(self) -> bool:
        """Setup hook - called once at agent startup.

        Returns:
            True if setup successful, False otherwise
        """
        logger.info(f"{self.AGENT_NAME} setup starting...")

        # TODO: Validate collector capabilities
        # - Check permissions for reading persistence mechanisms
        # - Verify baseline path is writable
        # - Test collector enumeration

        logger.info(f"{self.AGENT_NAME} setup complete")
        return True

    def collect_data(self) -> Sequence[Any]:
        """Collect persistence snapshot and run threat detection probes.

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        now_ns = int(time.time() * 1e9)

        # Collect current persistence state
        snapshot = self.collector.collect_snapshot()

        logger.debug(f"Collected {len(snapshot)} persistence entries in this cycle")

        # Auto-create baseline on first cycle if none exists
        if self.baseline_mode in ("create", "auto_create"):
            self.baseline_engine.create_from_snapshot(snapshot)
            self.baseline_engine.save()
            logger.info(f"Baseline created with {len(snapshot)} persistence entries")
            if self.baseline_mode == "auto_create":
                self.baseline_mode = "monitor"
            else:
                return []

        # Monitor mode - compare against baseline
        changes = self.baseline_engine.compare(snapshot)

        # Build a snapshot-summary event every cycle (so EOA can verify signal)
        proto_events = []

        # Always emit a snapshot summary event
        summary_event = telemetry_pb2.TelemetryEvent(
            event_id=f"persistence_snapshot_{now_ns}",
            event_type="METRIC",
            severity="INFO",
            event_timestamp_ns=now_ns,
            source_component="persistence_collector",
            metric_data=telemetry_pb2.MetricData(
                metric_name="persistence_entries",
                metric_type="GAUGE",
                numeric_value=float(len(snapshot)),
                unit="entries",
            ),
        )
        proto_events.append(summary_event)

        if changes:
            logger.info(f"Detected {len(changes)} persistence changes")
            # Run all probes via mixin
            probe_events = self.scan_all_probes()

            # Also emit raw change events even if probes don't fire
            for change in changes:
                security_event = telemetry_pb2.SecurityEvent(
                    event_category=f"persistence_{change.mechanism_type.lower()}",
                    risk_score=0.6,
                    analyst_notes=f"Change type: {change.change_type.name}, "
                    f"entry: {change.entry_id}",
                )
                # Add MITRE techniques based on mechanism type
                mitre_map = {
                    "USER_LAUNCH_AGENT": ["T1543", "T1547"],
                    "SYSTEM_LAUNCH_AGENT": ["T1543", "T1547"],
                    "SYSTEM_LAUNCH_DAEMON": ["T1543", "T1547"],
                    "CRON_USER": ["T1053.003"],
                    "SHELL_PROFILE": ["T1546.004"],
                    "SSH_AUTHORIZED_KEYS": ["T1098.004"],
                }
                techniques = mitre_map.get(change.mechanism_type, ["T1547"])
                security_event.mitre_techniques.extend(techniques)

                change_event = telemetry_pb2.TelemetryEvent(
                    event_id=f"persistence_change_{change.entry_id}_{now_ns}",
                    event_type="SECURITY",
                    severity=(
                        "HIGH" if change.change_type.name == "CREATED" else "MEDIUM"
                    ),
                    event_timestamp_ns=now_ns,
                    source_component=f"persistence_{change.mechanism_type.lower()}",
                    security_event=security_event,
                    confidence_score=0.6,
                )

                # Populate attributes with evidence
                change_event.attributes["change_type"] = change.change_type.name
                change_event.attributes["mechanism_type"] = change.mechanism_type
                change_event.attributes["entry_id"] = change.entry_id
                if change.new_entry:
                    if change.new_entry.path:
                        change_event.attributes["file_path"] = change.new_entry.path
                    if change.new_entry.command:
                        change_event.attributes["command"] = str(
                            change.new_entry.command
                        )
                    if change.new_entry.hash:
                        change_event.attributes["file_hash"] = change.new_entry.hash
                    if change.new_entry.user:
                        change_event.attributes["user"] = change.new_entry.user
                if change.old_entry and change.old_entry.hash:
                    change_event.attributes["old_hash"] = change.old_entry.hash

                proto_events.append(change_event)

            # Update baseline with current snapshot
            self.baseline_engine.create_from_snapshot(snapshot)
        else:
            logger.debug("No persistence changes detected in this cycle")

        # Create DeviceTelemetry
        device_telemetry = telemetry_pb2.DeviceTelemetry(
            device_id=self.device_id,
            device_type="HOST",
            protocol="PERSISTENCE",
            events=proto_events,
            timestamp_ns=now_ns,
            collection_agent=self.AGENT_NAME,
            agent_version="2.0.0",
        )

        return [device_telemetry]

    def validate_event(self, event: Any) -> ValidationResult:
        """Validate telemetry before publishing."""
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        if not hasattr(event, "timestamp_ns") or event.timestamp_ns == 0:
            errors.append("Missing timestamp_ns")
        now = time.time() * 1e9
        if hasattr(event, "timestamp_ns") and event.timestamp_ns > 0:
            if abs(event.timestamp_ns - now) > 3600 * 1e9:
                errors.append("timestamp_ns too far from current time")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        """Cleanup hook - called at agent shutdown."""
        logger.info(f"{self.AGENT_NAME} shutting down...")
        logger.info(f"{self.AGENT_NAME} shutdown complete")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main():
    """CLI entry point for PersistenceGuardV2."""
    parser = argparse.ArgumentParser(
        description="PersistenceGuardV2 - Persistence Mechanism Monitoring with Micro-Probe Architecture"
    )
    parser.add_argument(
        "--device-id",
        type=str,
        default=None,
        help="Device identifier (default: hostname)",
    )
    parser.add_argument(
        "--queue-path",
        type=str,
        default="data/queue/persistence.db",
        help="Local queue database path",
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="monitor",
        choices=["create", "monitor"],
        help="Mode: create baseline or monitor for changes (default: monitor)",
    )
    parser.add_argument(
        "--baseline-path",
        type=str,
        default="data/persistence_baseline.json",
        help="Baseline JSON file path (default: data/persistence_baseline.json)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=PersistenceGuardV2.COLLECTION_INTERVAL_SECONDS,
        help="Collection interval in seconds (default: 300)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create and run agent
    agent = PersistenceGuardV2(
        device_id=args.device_id,
        queue_path=args.queue_path,
        baseline_mode=args.mode,
        baseline_path=args.baseline_path,
        collection_interval=args.interval,
    )

    try:
        if args.mode == "create":
            logger.info("Creating persistence baseline...")
            agent.setup()
            agent.collect_data()
            logger.info(f"Baseline created and saved to {args.baseline_path}")
        else:
            logger.info("Starting PersistenceGuardV2 in monitor mode...")
            agent.run_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
        agent.shutdown()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        agent.shutdown()
        raise


if __name__ == "__main__":
    main()


# B5.1: Deprecated alias — will be removed in v1.0
PersistenceGuardV2 = PersistenceGuard
