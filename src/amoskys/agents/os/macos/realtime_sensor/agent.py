"""macOS Real-Time Sensor Agent — Event-driven detection.

Converts AMOSKYS from polling-based to event-driven detection by combining
three macOS kernel event sources: FSEvents, kqueue, and Unified Log stream.

Addresses peer review criticisms:
  #3: "Python is wrong" — proves event-driven Python agent works
  #8: "No evasion discussion" — eliminates 60s polling window
"""

from __future__ import annotations

import logging
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, List

from amoskys.agents.common.base import HardenedAgentBase
from amoskys.agents.common.probes import (
    MicroProbe,
    MicroProbeAgentMixin,
    ProbeContext,
    Severity,
    TelemetryEvent,
)
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.config import get_config

from .collector import RealTimeEvent, RealtimeSensorCollector

logger = logging.getLogger(__name__)

config = get_config()
CERT_DIR = config.agent.cert_dir
QUEUE_PATH = "data/queue/realtime_sensor.db"


def _te(
    event_type: str,
    severity: Severity,
    probe_name: str,
    data: Dict[str, Any],
    mitre: List[str],
    confidence: float,
    device_id: str,
    ts_ns: int,
) -> TelemetryEvent:
    """Helper to construct a TelemetryEvent with correct fields."""
    return TelemetryEvent(
        event_type=event_type,
        severity=severity,
        probe_name=probe_name,
        data=data,
        mitre_techniques=mitre,
        confidence=confidence,
        device_id=device_id,
        timestamp_ns=ts_ns,
    )


# ── Probes ───────────────────────────────────────────────────────────────────


class PersistenceDropProbe(MicroProbe):
    """Detects files created in persistence locations (LaunchAgents, etc.)."""

    name = "rt_persistence_drop"
    description = "Real-time detection of persistence mechanism creation"
    mitre_techniques = ["T1543.001", "T1543.004"]
    severity = Severity.HIGH
    requires_fields = {}
    requires_event_types = frozenset()

    PERSISTENCE_PATHS = {
        "LaunchAgents": "T1543.001",
        "LaunchDaemons": "T1543.004",
        ".ssh/authorized_keys": "T1098.004",
        "crontab": "T1053.003",
    }

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "fsevents":
                continue
            if rt.event_type not in ("file_created", "file_modified"):
                continue

            for pattern, technique in self.PERSISTENCE_PATHS.items():
                if pattern in rt.path:
                    events.append(
                        _te(
                            event_type=f"rt_persistence_{rt.event_type}",
                            severity=Severity.HIGH,
                            probe_name=self.name,
                            data={
                                "path": rt.path,
                                "change_type": rt.event_type,
                                "watch_dir": rt.details.get("watch_dir", ""),
                                "file_size": rt.details.get("size", -1),
                                "detection_source": "fsevents_realtime",
                                "event_category": "persistence_creation",
                                "risk_score": 0.85,
                            },
                            mitre=[technique],
                            confidence=0.9,
                            device_id=device_id,
                            ts_ns=rt.timestamp_ns,
                        )
                    )
                    break

        return events


class TempExecutionProbe(MicroProbe):
    """Detects executable files created in /tmp or /var/tmp."""

    name = "rt_temp_execution"
    description = "Real-time detection of executables dropped in temp directories"
    mitre_techniques = ["T1059.004", "T1204"]
    severity = Severity.HIGH
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "fsevents" or rt.event_type not in (
                "file_created",
                "file_modified",
            ):
                continue
            if not (rt.path.startswith("/tmp/") or rt.path.startswith("/var/tmp/")):
                continue

            try:
                mode = os.stat(rt.path).st_mode
                is_exec = bool(mode & 0o111)
            except OSError:
                is_exec = False

            suspicious_exts = {".sh", ".py", ".command", ".app", ".dylib", ".so"}
            ext = os.path.splitext(rt.path)[1].lower()

            if is_exec or ext in suspicious_exts:
                events.append(
                    _te(
                        event_type="rt_temp_executable",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": rt.path,
                            "extension": ext,
                            "is_executable": is_exec,
                            "file_size": rt.details.get("size", -1),
                            "detection_source": "fsevents_realtime",
                            "event_category": "execution_from_temp",
                            "risk_score": 0.80,
                        },
                        mitre=["T1059.004"],
                        confidence=0.85,
                        device_id=device_id,
                        ts_ns=rt.timestamp_ns,
                    )
                )

        return events


class QuarantineBypassProbe(MicroProbe):
    """Detects .command/.app files in Downloads without quarantine xattr."""

    name = "rt_quarantine_bypass"
    description = "Real-time detection of Gatekeeper quarantine bypass"
    mitre_techniques = ["T1553.001"]
    severity = Severity.HIGH
    requires_fields = {}
    requires_event_types = frozenset()

    RISKY_EXTENSIONS = {".command", ".app", ".pkg", ".dmg", ".sh", ".terminal"}

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "fsevents" or rt.event_type != "file_created":
                continue

            downloads = str(os.path.expanduser("~/Downloads"))
            if not rt.path.startswith(downloads):
                continue

            ext = os.path.splitext(rt.path)[1].lower()
            if ext not in self.RISKY_EXTENSIONS:
                continue

            has_quarantine = False
            try:
                import xattr

                attrs = xattr.listxattr(rt.path)
                has_quarantine = "com.apple.quarantine" in attrs
            except (ImportError, OSError):
                pass

            if not has_quarantine:
                events.append(
                    _te(
                        event_type="rt_quarantine_bypass",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "path": rt.path,
                            "extension": ext,
                            "has_quarantine": has_quarantine,
                            "file_size": rt.details.get("size", -1),
                            "detection_source": "fsevents_realtime",
                            "event_category": "quarantine_bypass",
                            "risk_score": 0.85,
                        },
                        mitre=["T1553.001"],
                        confidence=0.9,
                        device_id=device_id,
                        ts_ns=rt.timestamp_ns,
                    )
                )

        return events


class ShortLivedProcessProbe(MicroProbe):
    """Detects processes that exit — visibility into process lifecycle."""

    name = "rt_short_lived_process"
    description = "Real-time process exit detection via kqueue"
    mitre_techniques = ["T1059", "T1204"]
    severity = Severity.LOW
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "kqueue" or rt.event_type != "process_exit":
                continue
            if not rt.process_name:
                continue

            events.append(
                _te(
                    event_type="rt_process_exit",
                    severity=Severity.LOW,
                    probe_name=self.name,
                    data={
                        "pid": rt.pid,
                        "process_name": rt.process_name,
                        "exit_status": rt.details.get("exit_status", -1),
                        "detection_source": "kqueue_realtime",
                        "event_category": "process_exit",
                    },
                    mitre=[],
                    confidence=0.7,
                    device_id=device_id,
                    ts_ns=rt.timestamp_ns,
                )
            )

        return events


class TCCPermissionProbe(MicroProbe):
    """Real-time TCC permission monitoring via log stream."""

    name = "rt_tcc_permission"
    description = "Real-time TCC permission grant/deny detection"
    mitre_techniques = ["T1548"]
    severity = Severity.MEDIUM
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream":
                continue
            # Only alert on actual grants and denials — skip generic tcc_event noise
            if rt.event_type == "tcc_permission_granted":
                severity = Severity.HIGH
            elif rt.event_type == "tcc_permission_denied":
                severity = Severity.MEDIUM
            else:
                continue  # Skip tcc_event, tcc_permission_request (too noisy)

            events.append(
                _te(
                    event_type=f"rt_{rt.event_type}",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "subsystem": rt.details.get("subsystem", ""),
                        "category": rt.details.get("category", ""),
                        "process_name": rt.process_name,
                        "pid": rt.pid,
                        "message": rt.details.get("message", "")[:200],
                        "detection_source": "logstream_realtime",
                        "event_category": rt.event_type,
                    },
                    mitre=["T1548"],
                    confidence=0.8,
                    device_id=device_id,
                    ts_ns=rt.timestamp_ns,
                )
            )

        return events


class XProtectMalwareProbe(MicroProbe):
    """Real-time XProtect/MRT malware detection events."""

    name = "rt_xprotect_malware"
    description = "Apple XProtect malware block detection"
    mitre_techniques = ["T1204.002"]
    severity = Severity.CRITICAL
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream":
                continue
            if rt.event_type == "xprotect_malware_blocked":
                events.append(
                    _te(
                        event_type="rt_xprotect_malware_blocked",
                        severity=Severity.CRITICAL,
                        probe_name=self.name,
                        data={
                            "process_name": rt.process_name,
                            "pid": rt.pid,
                            "message": rt.details.get("message", "")[:300],
                            "detection_source": "logstream_realtime",
                            "event_category": "malware_blocked",
                            "risk_score": 0.95,
                        },
                        mitre=["T1204.002"],
                        confidence=0.95,
                        device_id=device_id,
                        ts_ns=rt.timestamp_ns,
                    )
                )
            elif rt.event_type == "xprotect_scan":
                events.append(
                    _te(
                        event_type="rt_xprotect_scan",
                        severity=Severity.INFO,
                        probe_name=self.name,
                        data={
                            "message": rt.details.get("message", "")[:200],
                            "detection_source": "logstream_realtime",
                            "event_category": "xprotect_scan",
                        },
                        mitre=[],
                        confidence=0.5,
                        device_id=device_id,
                        ts_ns=rt.timestamp_ns,
                    )
                )
        return events


class AMFICodeSigningProbe(MicroProbe):
    """Real-time AMFI code signing enforcement detection."""

    name = "rt_amfi_code_signing"
    description = "AMFI unsigned/invalid binary execution detection"
    mitre_techniques = ["T1553.002"]
    severity = Severity.HIGH
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream" or rt.event_type != "amfi_code_signing_denied":
                continue
            events.append(
                _te(
                    event_type="rt_amfi_code_signing_denied",
                    severity=Severity.HIGH,
                    probe_name=self.name,
                    data={
                        "process_name": rt.process_name,
                        "pid": rt.pid,
                        "message": rt.details.get("message", "")[:300],
                        "detection_source": "logstream_realtime",
                        "event_category": "code_signing_violation",
                        "risk_score": 0.85,
                    },
                    mitre=["T1553.002"],
                    confidence=0.9,
                    device_id=device_id,
                    ts_ns=rt.timestamp_ns,
                )
            )
        return events


class FirewallProbe(MicroProbe):
    """Real-time macOS ALF firewall block detection."""

    name = "rt_firewall"
    description = "Application Layer Firewall block detection"
    mitre_techniques = ["T1071"]
    severity = Severity.MEDIUM
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream" or rt.event_type != "firewall_blocked":
                continue
            events.append(
                _te(
                    event_type="rt_firewall_blocked",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    data={
                        "process_name": rt.process_name,
                        "pid": rt.pid,
                        "message": rt.details.get("message", "")[:200],
                        "detection_source": "logstream_realtime",
                        "event_category": "firewall_block",
                        "risk_score": 0.6,
                    },
                    mitre=["T1071"],
                    confidence=0.7,
                    device_id=device_id,
                    ts_ns=rt.timestamp_ns,
                )
            )
        return events


class SSHRealtimeProbe(MicroProbe):
    """Real-time SSH login success/failure detection."""

    name = "rt_ssh_auth"
    description = "Real-time SSH authentication monitoring"
    mitre_techniques = ["T1021.004", "T1110"]
    severity = Severity.HIGH
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream":
                continue
            if rt.event_type == "ssh_login_failure":
                events.append(
                    _te(
                        event_type="rt_ssh_login_failure",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "process_name": rt.process_name,
                            "pid": rt.pid,
                            "message": rt.details.get("message", "")[:200],
                            "detection_source": "logstream_realtime",
                            "event_category": "ssh_auth_failure",
                            "risk_score": 0.7,
                        },
                        mitre=["T1110"],
                        confidence=0.85,
                        device_id=device_id,
                        ts_ns=rt.timestamp_ns,
                    )
                )
            elif rt.event_type == "ssh_login_success":
                events.append(
                    _te(
                        event_type="rt_ssh_login_success",
                        severity=Severity.MEDIUM,
                        probe_name=self.name,
                        data={
                            "process_name": rt.process_name,
                            "pid": rt.pid,
                            "message": rt.details.get("message", "")[:200],
                            "detection_source": "logstream_realtime",
                            "event_category": "ssh_auth_success",
                            "risk_score": 0.3,
                        },
                        mitre=["T1021.004"],
                        confidence=0.9,
                        device_id=device_id,
                        ts_ns=rt.timestamp_ns,
                    )
                )
        return events


class DiskMountProbe(MicroProbe):
    """Real-time disk/volume mount detection."""

    name = "rt_disk_mount"
    description = "Real-time disk mount/unmount detection"
    mitre_techniques = ["T1200", "T1052.001"]
    severity = Severity.MEDIUM
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream" or rt.event_type not in (
                "disk_mounted",
                "disk_unmounted",
                "disk_ejected",
                "usb_event",
            ):
                continue
            events.append(
                _te(
                    event_type=f"rt_{rt.event_type}",
                    severity=Severity.MEDIUM,
                    probe_name=self.name,
                    data={
                        "process_name": rt.process_name,
                        "pid": rt.pid,
                        "message": rt.details.get("message", "")[:200],
                        "detection_source": "logstream_realtime",
                        "event_category": "peripheral_event",
                        "risk_score": 0.4,
                    },
                    mitre=["T1200"],
                    confidence=0.7,
                    device_id=device_id,
                    ts_ns=rt.timestamp_ns,
                )
            )
        return events


class GatekeeperRealtimeProbe(MicroProbe):
    """Real-time Gatekeeper assessment detection."""

    name = "rt_gatekeeper"
    description = "Real-time Gatekeeper allow/block detection"
    mitre_techniques = ["T1553.001"]
    severity = Severity.HIGH
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream":
                continue
            if rt.event_type == "gatekeeper_blocked":
                events.append(
                    _te(
                        event_type="rt_gatekeeper_blocked",
                        severity=Severity.HIGH,
                        probe_name=self.name,
                        data={
                            "process_name": rt.process_name,
                            "pid": rt.pid,
                            "message": rt.details.get("message", "")[:200],
                            "detection_source": "logstream_realtime",
                            "event_category": "gatekeeper_block",
                            "risk_score": 0.8,
                        },
                        mitre=["T1553.001"],
                        confidence=0.9,
                        device_id=device_id,
                        ts_ns=rt.timestamp_ns,
                    )
                )
        return events


class CriticalFileProbe(MicroProbe):
    """Zero-latency critical file modification detection via kqueue VNODE."""

    name = "rt_critical_file"
    description = "Immediate detection of critical system file modification"
    mitre_techniques = ["T1565", "T1098.004"]
    severity = Severity.CRITICAL
    requires_fields = {}
    requires_event_types = frozenset()

    # Files that should NEVER change during normal operation
    _CRITICAL_MAP = {
        "/etc/sudoers": ("T1548.003", Severity.CRITICAL, 0.95),
        "/etc/hosts": ("T1565.001", Severity.HIGH, 0.85),
        "/etc/pam.d/sudo": ("T1556", Severity.CRITICAL, 0.95),
        "/etc/ssh/sshd_config": ("T1098.004", Severity.HIGH, 0.85),
        "authorized_keys": ("T1098.004", Severity.CRITICAL, 0.90),
        ".zshrc": ("T1546.004", Severity.HIGH, 0.80),
        ".bash_profile": ("T1546.004", Severity.HIGH, 0.80),
        ".zprofile": ("T1546.004", Severity.HIGH, 0.80),
        "/etc/resolv.conf": ("T1565.001", Severity.MEDIUM, 0.70),
    }

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "kqueue_vnode" or rt.event_type != "critical_file_modified":
                continue

            # Match against critical file map
            technique = "T1565"
            severity = Severity.HIGH
            confidence = 0.85
            for pattern, (tech, sev, conf) in self._CRITICAL_MAP.items():
                if pattern in rt.path:
                    technique = tech
                    severity = sev
                    confidence = conf
                    break

            changes = rt.details.get("changes", [])
            events.append(
                _te(
                    event_type="rt_critical_file_modified",
                    severity=severity,
                    probe_name=self.name,
                    data={
                        "path": rt.path,
                        "changes": changes,
                        "detection_source": "kqueue_vnode_realtime",
                        "event_category": "critical_file_modification",
                        "risk_score": confidence,
                    },
                    mitre=[technique],
                    confidence=confidence,
                    device_id=device_id,
                    ts_ns=rt.timestamp_ns,
                )
            )
        return events


class LogDestructionProbe(MicroProbe):
    """Detect unified log erasure and evidence destruction."""

    name = "rt_log_destruction"
    description = "Real-time detection of log evidence destruction"
    mitre_techniques = ["T1070.002"]
    severity = Severity.CRITICAL
    requires_fields = {}
    requires_event_types = frozenset()

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            # Process-based detection: "log" command with "erase"
            if rt.source == "logstream" and rt.process_name == "log":
                msg = rt.details.get("message", "").lower()
                if "erase" in msg:
                    events.append(
                        _te(
                            event_type="rt_log_erasure",
                            severity=Severity.CRITICAL,
                            probe_name=self.name,
                            data={
                                "process_name": rt.process_name,
                                "pid": rt.pid,
                                "message": rt.details.get("message", "")[:300],
                                "detection_source": "logstream_realtime",
                                "event_category": "evidence_destruction",
                                "risk_score": 0.95,
                            },
                            mitre=["T1070.002"],
                            confidence=0.95,
                            device_id=device_id,
                            ts_ns=rt.timestamp_ns,
                        )
                    )

            # FSEvents-based detection: deletion in /var/db/diagnostics/
            if rt.source == "fsevents" and rt.event_type == "file_deleted":
                if "/var/db/diagnostics" in rt.path or "/var/audit" in rt.path:
                    events.append(
                        _te(
                            event_type="rt_log_file_deleted",
                            severity=Severity.CRITICAL,
                            probe_name=self.name,
                            data={
                                "path": rt.path,
                                "detection_source": "fsevents_realtime",
                                "event_category": "evidence_destruction",
                                "risk_score": 0.90,
                            },
                            mitre=["T1070.002"],
                            confidence=0.9,
                            device_id=device_id,
                            ts_ns=rt.timestamp_ns,
                        )
                    )

        return events


class AppLifecycleProbe(MicroProbe):
    """Real-time app launch/termination tracking for behavioral analysis."""

    name = "rt_app_lifecycle"
    description = "Real-time macOS application lifecycle monitoring"
    mitre_techniques = ["T1204"]
    severity = Severity.INFO
    requires_fields = {}
    requires_event_types = frozenset()

    # App launches we always want to record for the timeline
    _INTERESTING_KEYWORDS = frozenset(
        {
            "terminal",
            "iterm",
            "warp",
            "ssh",
            "python",
            "node",
            "ruby",
            "curl",
            "wget",
            "nc",
            "ncat",
            "osascript",
            "security",
            "installer",
            "brew",
            "pip",
            "npm",
            "cargo",
        }
    )

    def scan(self, shared_data: Dict[str, Any]) -> List[TelemetryEvent]:
        events = []
        rt_events: List[RealTimeEvent] = shared_data.get("realtime_events", [])
        device_id = shared_data.get("device_id", "")

        for rt in rt_events:
            if rt.source != "logstream" or rt.event_type != "app_launched":
                continue

            proc_lower = rt.process_name.lower()
            msg_lower = rt.details.get("message", "").lower()

            # Filter: only record launches of security-interesting apps
            is_interesting = any(
                kw in proc_lower or kw in msg_lower for kw in self._INTERESTING_KEYWORDS
            )
            if not is_interesting:
                continue

            events.append(
                _te(
                    event_type="rt_app_launched",
                    severity=Severity.INFO,
                    probe_name=self.name,
                    data={
                        "process_name": rt.process_name,
                        "pid": rt.pid,
                        "message": rt.details.get("message", "")[:200],
                        "detection_source": "logstream_realtime",
                        "event_category": "app_launch",
                    },
                    mitre=[],
                    confidence=0.5,
                    device_id=device_id,
                    ts_ns=rt.timestamp_ns,
                )
            )
        return events


# ── Agent ────────────────────────────────────────────────────────────────────


class MacOSRealtimeSensorAgent(HardenedAgentBase, MicroProbeAgentMixin):
    """Event-driven macOS security sensor.

    Detection latency: <1 second (vs 30-60s for polling agents)
    Evasion window: effectively zero for monitored paths/events
    """

    AGENT_NAME = "realtime_sensor"
    AGENT_VERSION = "1.0.0"
    DEFAULT_INTERVAL = 2.0

    def __init__(self, **kwargs):
        device_id = kwargs.pop("device_id", socket.gethostname())

        # Wire queue_adapter so events flow to WAL → analysis pipeline
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name=self.AGENT_NAME,
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{CERT_DIR}/agent.ed25519",
        )

        super().__init__(
            agent_name=self.AGENT_NAME,
            device_id=device_id,
            collection_interval=self.DEFAULT_INTERVAL,
            queue_adapter=queue_adapter,
            **kwargs,
        )

        self._collector = RealtimeSensorCollector()
        self._probes = [
            # ── FSEvents probes ──
            PersistenceDropProbe(),
            TempExecutionProbe(),
            QuarantineBypassProbe(),
            # ── kqueue probes ──
            ShortLivedProcessProbe(),
            # ── kqueue VNODE probes ──
            CriticalFileProbe(),
            # ── Log stream probes ──
            LogDestructionProbe(),
            TCCPermissionProbe(),
            XProtectMalwareProbe(),
            AMFICodeSigningProbe(),
            FirewallProbe(),
            SSHRealtimeProbe(),
            DiskMountProbe(),
            GatekeeperRealtimeProbe(),
            AppLifecycleProbe(),
        ]
        MicroProbeAgentMixin.__init__(self, probes=self._probes)
        logger.info(
            "%s initialized: %d probes, device=%s",
            self.AGENT_NAME,
            len(self._probes),
            device_id,
        )

    def setup(self) -> bool:
        self._collector.start()
        return True

    def collect_data(self):
        if not self._collector._started:
            self._collector.start()
            time.sleep(0.5)

        rt_events = self._collector.collect()
        device_id = (
            self._device_id if hasattr(self, "_device_id") else socket.gethostname()
        )

        shared_data = {"realtime_events": rt_events, "device_id": device_id}

        probe_events = []
        for probe in self._probes:
            if not probe.enabled:
                continue
            try:
                probe_events.extend(probe.scan(shared_data))
            except Exception:
                logger.debug("Probe %s failed", probe.name, exc_info=True)

        logger.info(
            "Realtime sensor: %d raw events -> %d detections (fs=%d, kq=%d, log=%d)",
            len(rt_events),
            len(probe_events),
            sum(1 for e in rt_events if e.source == "fsevents"),
            sum(1 for e in rt_events if e.source == "kqueue"),
            sum(1 for e in rt_events if e.source == "logstream"),
        )

        # Convert to DeviceTelemetry for pipeline compatibility
        from amoskys.proto import universal_telemetry_pb2 as pb2

        dt = pb2.DeviceTelemetry()
        dt.device_id = device_id
        dt.timestamp_ns = int(time.time() * 1e9)
        dt.device_type = "HOST"
        dt.collection_agent = "macos_realtime_sensor"
        dt.agent_version = self.AGENT_VERSION

        for pe in probe_events:
            te = dt.events.add()
            te.event_id = f"{pe.probe_name}_{pe.event_type}_{dt.timestamp_ns}"
            te.event_type = "SECURITY"
            te.severity = (
                pe.severity.value if hasattr(pe.severity, "value") else "MEDIUM"
            )
            te.source_component = self.AGENT_NAME
            te.event_timestamp_ns = dt.timestamp_ns
            ts = pe.timestamp_ns or dt.timestamp_ns
            te.attributes["event_timestamp_ns"] = str(ts)

            se = te.security_event
            se.event_category = pe.data.get("event_category", pe.event_type)
            se.risk_score = pe.data.get("risk_score", 0.5)
            te.attributes["confidence"] = str(pe.confidence)
            te.attributes["description"] = (
                f"[{self.AGENT_NAME}] {pe.event_type}: "
                f"{pe.data.get('path', pe.data.get('process_name', ''))}"
            )

            for tech in pe.mitre_techniques or []:
                se.mitre_techniques.append(tech)

            for k, v in pe.data.items():
                te.attributes[k] = str(v)

        # Always emit a heartbeat OBSERVATION so the agent appears in observation_events
        # even on cycles where no suspicious events fired.
        heartbeat = dt.events.add()
        heartbeat.event_id = f"rt_heartbeat_{dt.timestamp_ns}"
        heartbeat.event_type = "OBSERVATION"
        heartbeat.severity = "INFO"
        heartbeat.event_timestamp_ns = dt.timestamp_ns
        heartbeat.source_component = self.AGENT_NAME
        heartbeat.attributes["_domain"] = "realtime_sensor"
        heartbeat.attributes["fs_events"] = str(
            sum(1 for e in rt_events if e.source == "fsevents")
        )
        heartbeat.attributes["kqueue_events"] = str(
            sum(1 for e in rt_events if e.source == "kqueue")
        )
        heartbeat.attributes["log_events"] = str(
            sum(1 for e in rt_events if e.source == "logstream")
        )
        heartbeat.attributes["probe_detections"] = str(len(probe_events))

        return [dt]

    def shutdown(self) -> bool:
        self._collector.stop()
        return True
