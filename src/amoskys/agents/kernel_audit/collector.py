"""Kernel Audit Collector - Collect and normalize audit events.

This module provides collectors for kernel audit events from various sources:
    - AuditdLogCollector: Parse /var/log/audit/audit.log (Linux)
    - MacOSAuditCollector: Parse OpenBSM trails via praudit (macOS)
    - StubCollector: For testing with injected events

Design:
    - Collectors return normalized KernelAuditEvent objects
    - Bookmark/offset tracking for incremental collection
    - Pluggable architecture for different audit sources
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.agents.kernel_audit.types import KernelAuditEvent

logger = logging.getLogger(__name__)


# =============================================================================
# Base Collector
# =============================================================================


class BaseKernelAuditCollector:
    """Base class for kernel audit collectors."""

    def __init__(self) -> None:
        """Initialize collector."""
        self.hostname = socket.gethostname()
        self._event_counter = 0

    def collect_batch(self) -> List[KernelAuditEvent]:
        """Collect a batch of normalized kernel audit events.

        Returns:
            List of KernelAuditEvent objects since last call
        """
        raise NotImplementedError

    def _generate_event_id(self, raw_data: str) -> str:
        """Generate stable event ID from raw data."""
        self._event_counter += 1
        hash_input = f"{self._event_counter}:{raw_data}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]


# =============================================================================
# Linux Auditd Log Collector
# =============================================================================


class AuditdLogCollector(BaseKernelAuditCollector):
    """Collector for Linux audit events from /var/log/audit/audit.log.

    Parses audit log entries in the standard auditd format:
        type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 ...

    Attributes:
        source: Path to audit log file
        _offset: Current file offset for incremental reading
        _inode: Inode for detecting log rotation
    """

    # Regex patterns for parsing audit logs
    AUDIT_LINE_RE = re.compile(
        r"type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)"
    )
    KEY_VALUE_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

    # Syscall number to name mapping (x86_64 Linux)
    SYSCALL_MAP: Dict[int, str] = {
        0: "read",
        1: "write",
        2: "open",
        3: "close",
        9: "mmap",
        10: "mprotect",
        21: "access",
        56: "clone",
        57: "fork",
        58: "vfork",
        59: "execve",
        60: "exit",
        61: "wait4",
        62: "kill",
        90: "chmod",
        91: "fchmod",
        92: "chown",
        93: "fchown",
        94: "lchown",
        101: "ptrace",
        105: "setuid",
        106: "setgid",
        113: "setreuid",
        114: "setregid",
        117: "setresuid",
        119: "setresgid",
        122: "setfsuid",
        123: "setfsgid",
        125: "capset",
        128: "init_module",
        129: "delete_module",
        175: "init_module",  # alternate
        176: "delete_module",  # alternate
        313: "finit_module",
        322: "execveat",
        435: "clone3",
    }

    def __init__(
        self,
        source: str = "/var/log/audit/audit.log",
        start_at_end: bool = True,
    ) -> None:
        """Initialize auditd log collector.

        Args:
            source: Path to audit log file
            start_at_end: If True, start reading from end of file
        """
        super().__init__()
        self.source = Path(source)
        self._offset: int = 0
        self._inode: Optional[int] = None
        self._pending_events: Dict[str, Dict[str, Any]] = {}

        # Initialize offset
        if self.source.exists():
            stat = self.source.stat()
            self._inode = stat.st_ino
            if start_at_end:
                self._offset = stat.st_size
        else:
            logger.warning("Audit log not found: %s", self.source)

    def collect_batch(self) -> List[KernelAuditEvent]:
        """Collect batch of events from audit log.

        Returns:
            List of normalized KernelAuditEvent objects
        """
        if not self.source.exists():
            return []

        # Check for log rotation
        stat = self.source.stat()
        if self._inode != stat.st_ino:
            logger.info("Audit log rotated, resetting offset")
            self._offset = 0
            self._inode = stat.st_ino

        # Check if file grew
        if stat.st_size < self._offset:
            logger.info("Audit log truncated, resetting offset")
            self._offset = 0

        if stat.st_size == self._offset:
            return []

        events: List[KernelAuditEvent] = []

        try:
            with open(self.source, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                lines = f.readlines()
                self._offset = f.tell()

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                parsed = self._parse_audit_line(line)
                if parsed:
                    event = self._build_event(parsed)
                    if event:
                        events.append(event)

        except Exception as e:
            logger.error("Error reading audit log: %s", e)

        return events

    def _parse_audit_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single audit log line.

        Args:
            line: Raw audit log line

        Returns:
            Parsed dict or None if not parseable
        """
        match = self.AUDIT_LINE_RE.match(line)
        if not match:
            return None

        record_type = match.group(1)
        timestamp = match.group(2)
        serial = match.group(3)
        fields_str = match.group(4)

        # Parse key=value pairs
        fields: Dict[str, str] = {}
        for kv_match in self.KEY_VALUE_RE.finditer(fields_str):
            key = kv_match.group(1)
            value = kv_match.group(2)
            # Remove quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            fields[key] = value

        return {
            "type": record_type,
            "timestamp": timestamp,
            "serial": serial,
            "fields": fields,
            "raw": line,
        }

    def _build_event(self, parsed: Dict[str, Any]) -> Optional[KernelAuditEvent]:
        """Build KernelAuditEvent from parsed audit record.

        Args:
            parsed: Parsed audit record dict

        Returns:
            KernelAuditEvent or None
        """
        fields = parsed["fields"]
        record_type = parsed["type"]

        # Only process SYSCALL records for now
        if record_type != "SYSCALL":
            return None

        # Get syscall name
        syscall_num = fields.get("syscall", "")
        try:
            syscall_int = int(syscall_num)
            syscall_name = self.SYSCALL_MAP.get(syscall_int, f"syscall_{syscall_num}")
        except ValueError:
            syscall_name = syscall_num

        # Parse timestamp
        try:
            ts_float = float(parsed["timestamp"])
            timestamp_ns = int(ts_float * 1e9)
        except ValueError:
            timestamp_ns = int(time.time() * 1e9)

        # Parse numeric fields safely
        def safe_int(val: Optional[str]) -> Optional[int]:
            if val is None:
                return None
            try:
                return int(val)
            except ValueError:
                return None

        # Determine action type
        action = self._classify_action(syscall_name)

        # Determine result
        result = "success" if fields.get("success") == "yes" else "failed"

        return KernelAuditEvent(
            event_id=self._generate_event_id(parsed["raw"]),
            timestamp_ns=timestamp_ns,
            host=self.hostname,
            syscall=syscall_name,
            exe=fields.get("exe"),
            pid=safe_int(fields.get("pid")),
            ppid=safe_int(fields.get("ppid")),
            uid=safe_int(fields.get("uid")),
            euid=safe_int(fields.get("euid")),
            gid=safe_int(fields.get("gid")),
            egid=safe_int(fields.get("egid")),
            tty=fields.get("tty"),
            cwd=fields.get("cwd"),
            path=fields.get("name") or fields.get("path"),
            audit_user=fields.get("auid"),
            session=fields.get("ses"),
            action=action,
            result=result,
            comm=fields.get("comm"),
            raw=fields,
        )

    def _classify_action(self, syscall: str) -> str:
        """Classify syscall into high-level action type."""
        if syscall in ("execve", "execveat"):
            return "EXEC"
        elif syscall in ("init_module", "finit_module"):
            return "MODULE_LOAD"
        elif syscall == "delete_module":
            return "MODULE_UNLOAD"
        elif syscall == "ptrace":
            return "PTRACE"
        elif syscall in ("chmod", "fchmod", "fchmodat"):
            return "CHMOD"
        elif syscall in ("chown", "fchown", "lchown", "fchownat"):
            return "CHOWN"
        elif syscall in ("setuid", "seteuid", "setreuid", "setresuid"):
            return "SETUID"
        elif syscall in ("setgid", "setegid", "setregid", "setresgid"):
            return "SETGID"
        elif syscall == "capset":
            return "CAPSET"
        elif syscall in ("fork", "vfork", "clone", "clone3"):
            return "FORK"
        elif syscall == "kill":
            return "KILL"
        elif syscall in ("mmap", "mprotect"):
            return "MEMORY"
        else:
            return "OTHER"


# =============================================================================
# macOS OpenBSM Collector
# =============================================================================


class MacOSAuditCollector(BaseKernelAuditCollector):
    """Collector for macOS audit events via OpenBSM.

    Uses ``praudit -x`` to convert binary BSM audit trails into XML,
    then parses ``<record>`` elements into KernelAuditEvent objects.

    Trail lifecycle:
        macOS writes to ``/var/audit/<datestamp>`` and keeps a symlink at
        ``/var/audit/current`` pointing to the active trail. When the trail
        rotates, a new file is created and the symlink is updated.

    Attributes:
        _trail_path: Resolved path to the current BSM trail file
        _record_offset: Number of records already consumed (for incremental reads)
    """

    # BSM event-name → normalised syscall name
    BSM_EVENT_MAP: Dict[str, str] = {
        "AUE_EXECVE": "execve",
        "AUE_EXEC": "execve",
        "AUE_POSIX_SPAWN": "execve",
        "AUE_FORK": "fork",
        "AUE_VFORK": "vfork",
        "AUE_PTRACE": "ptrace",
        "AUE_KILL": "kill",
        "AUE_SETUID": "setuid",
        "AUE_SETEUID": "seteuid",
        "AUE_SETREUID": "setreuid",
        "AUE_SETGID": "setgid",
        "AUE_SETEGID": "setegid",
        "AUE_SETREGID": "setregid",
        "AUE_CHMOD": "chmod",
        "AUE_FCHMOD": "fchmod",
        "AUE_CHOWN": "chown",
        "AUE_FCHOWN": "fchown",
        "AUE_LCHOWN": "lchown",
        "AUE_OPEN_RC": "open",
        "AUE_OPEN_RTC": "open",
        "AUE_OPEN_WC": "open",
        "AUE_OPEN_WTC": "open",
        "AUE_OPEN_R": "open",
        "AUE_OPEN_W": "open",
        "AUE_OPEN_RW": "open",
        "AUE_UNLINK": "unlink",
        "AUE_TRUNCATE": "truncate",
        "AUE_CONNECT": "connect",
        "AUE_BIND": "bind",
        "AUE_LISTEN": "listen",
        "AUE_ACCEPT": "accept",
        "AUE_MMAP": "mmap",
        "AUE_MPROTECT": "mprotect",
        "AUE_MAC_EXECVE": "execve",
    }

    DEFAULT_TRAIL = "/var/audit/current"

    def __init__(
        self,
        trail_path: str = DEFAULT_TRAIL,
        start_at_end: bool = True,
    ) -> None:
        """Initialize macOS OpenBSM collector.

        Args:
            trail_path: Path to active BSM trail (usually /var/audit/current)
            start_at_end: If True, skip existing records on first call
        """
        super().__init__()
        self._trail_symlink = Path(trail_path)
        self._trail_path: Optional[Path] = None
        self._record_offset: int = 0
        self._start_at_end = start_at_end

        self._resolve_trail()

    def _resolve_trail(self) -> None:
        """Resolve the current trail file and detect rotation."""
        if not self._trail_symlink.exists():
            logger.warning("BSM trail not found: %s", self._trail_symlink)
            self._trail_path = None
            return

        resolved = self._trail_symlink.resolve()
        if self._trail_path != resolved:
            if self._trail_path is not None:
                logger.info(
                    "BSM trail rotated: %s -> %s", self._trail_path, resolved
                )
            self._trail_path = resolved
            self._record_offset = 0

    def collect_batch(self) -> List[KernelAuditEvent]:
        """Collect batch of events from OpenBSM trail.

        Runs ``praudit -x`` on the active trail, skips already-seen records,
        and parses new ones into KernelAuditEvent objects.

        Returns:
            List of normalised KernelAuditEvent objects
        """
        self._resolve_trail()
        if self._trail_path is None or not self._trail_path.exists():
            return []

        xml_output = self._run_praudit()
        if not xml_output:
            return []

        records = self._parse_xml(xml_output)
        if not records:
            return []

        # Incremental: skip already-consumed records
        if self._start_at_end and self._record_offset == 0:
            self._record_offset = len(records)
            return []

        new_records = records[self._record_offset:]
        self._record_offset = len(records)

        events: List[KernelAuditEvent] = []
        for rec in new_records:
            event = self._build_event(rec)
            if event:
                events.append(event)

        return events

    def _run_praudit(self) -> Optional[str]:
        """Run praudit -x on the current trail file.

        Returns:
            XML string output or None on error
        """
        try:
            result = subprocess.run(
                ["praudit", "-x", str(self._trail_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.error("praudit failed: %s", result.stderr)
                return None
            return result.stdout
        except FileNotFoundError:
            logger.error("praudit not found — is OpenBSM installed?")
            return None
        except subprocess.TimeoutExpired:
            logger.error("praudit timed out after 30s")
            return None
        except Exception as e:
            logger.error("Error running praudit: %s", e)
            return None

    def _parse_xml(self, xml_text: str) -> List[Dict[str, Any]]:
        """Parse praudit -x XML output into record dicts.

        The XML schema looks like::

            <audit>
              <record ...>
                <subject .../>
                <return .../>
                <path .../>
                <exec_args .../>
                ...
              </record>
              ...
            </audit>

        Args:
            xml_text: Raw XML from praudit -x

        Returns:
            List of parsed record dicts
        """
        # praudit output may not have a root element — wrap it
        wrapped = f"<audit>{xml_text}</audit>"

        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError as e:
            logger.error("XML parse error: %s", e)
            return []

        records: List[Dict[str, Any]] = []
        for record_el in root.findall("record"):
            rec = self._parse_record_element(record_el)
            if rec:
                records.append(rec)

        return records

    def _parse_record_element(self, el: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse a single <record> XML element.

        Args:
            el: An ElementTree <record> element

        Returns:
            Parsed record dict or None
        """
        rec: Dict[str, Any] = {
            "event": el.get("event", ""),
            "time": el.get("time", ""),
            "msec": el.get("msec", "0"),
            "modifier": el.get("modifier", ""),
        }

        # Subject token: uid, gid, pid, etc.
        subject = el.find("subject")
        if subject is not None:
            rec["audit_uid"] = subject.get("audit-uid", "")
            rec["uid"] = subject.get("uid", "")
            rec["euid"] = subject.get("euid", "")
            rec["gid"] = subject.get("gid", "")
            rec["egid"] = subject.get("egid", "")
            rec["pid"] = subject.get("pid", "")
            rec["sid"] = subject.get("sid", "")
            rec["tid"] = subject.get("tid", "")

        # Return token: errval, retval
        return_el = el.find("return")
        if return_el is not None:
            rec["errval"] = return_el.get("errval", "")
            rec["retval"] = return_el.get("retval", "")

        # Path token(s)
        paths = el.findall("path")
        if paths:
            rec["path"] = paths[0].text or ""
            if len(paths) > 1:
                rec["path2"] = paths[1].text or ""

        # exec_args token
        exec_args = el.find("exec_args")
        if exec_args is not None:
            args = [arg.text or "" for arg in exec_args.findall("arg")]
            rec["exec_args"] = args
            if args:
                rec["exe"] = args[0]

        # Attribute token (file attributes)
        attr = el.find("attribute")
        if attr is not None:
            rec["attr_mode"] = attr.get("mode", "")
            rec["attr_uid"] = attr.get("uid", "")
            rec["attr_gid"] = attr.get("gid", "")

        # Text token
        text_el = el.find("text")
        if text_el is not None and text_el.text:
            rec["text"] = text_el.text

        return rec

    def _build_event(self, rec: Dict[str, Any]) -> Optional[KernelAuditEvent]:
        """Build KernelAuditEvent from a parsed BSM record.

        Args:
            rec: Parsed record dict from _parse_record_element

        Returns:
            KernelAuditEvent or None if not mappable
        """
        bsm_event = rec.get("event", "")
        syscall = self.BSM_EVENT_MAP.get(bsm_event)
        if syscall is None:
            # Skip events we don't map
            return None

        # Parse timestamp
        try:
            time_str = rec.get("time", "")
            msec = int(rec.get("msec", "0"))
            # praudit time format: "Wed Feb 12 14:30:05 2025"
            import calendar
            from datetime import datetime as _dt

            dt = _dt.strptime(time_str, "%a %b %d %H:%M:%S %Y")
            ts_epoch = calendar.timegm(dt.timetuple())
            timestamp_ns = int(ts_epoch * 1e9) + msec * 1_000_000
        except (ValueError, OverflowError):
            timestamp_ns = int(time.time() * 1e9)

        # Numeric helpers
        def safe_int(val: Any) -> Optional[int]:
            if val is None or val == "":
                return None
            try:
                return int(val)
            except (ValueError, TypeError):
                return None

        # Determine result
        errval = rec.get("errval", "")
        result = "success" if errval in ("success", "0", "") else "failed"

        # Classify action (reuse Linux classifier logic)
        action = self._classify_action(syscall)

        # Build cmdline from exec_args
        exec_args = rec.get("exec_args", [])
        cmdline = " ".join(exec_args) if exec_args else None

        # Build raw dict for deep inspection
        raw_dict = {k: str(v) for k, v in rec.items()}

        return KernelAuditEvent(
            event_id=self._generate_event_id(str(rec)),
            timestamp_ns=timestamp_ns,
            host=self.hostname,
            syscall=syscall,
            exe=rec.get("exe"),
            pid=safe_int(rec.get("pid")),
            ppid=None,  # BSM does not provide ppid
            uid=safe_int(rec.get("uid")),
            euid=safe_int(rec.get("euid")),
            gid=safe_int(rec.get("gid")),
            egid=safe_int(rec.get("egid")),
            tty=None,
            cwd=None,
            path=rec.get("path"),
            audit_user=rec.get("audit_uid"),
            session=rec.get("sid"),
            action=action,
            result=result,
            cmdline=cmdline,
            comm=rec.get("exe", "").rsplit("/", 1)[-1] if rec.get("exe") else None,
            raw=raw_dict,
        )

    def _classify_action(self, syscall: str) -> str:
        """Classify syscall into high-level action type."""
        if syscall in ("execve", "execveat"):
            return "EXEC"
        elif syscall == "ptrace":
            return "PTRACE"
        elif syscall in ("chmod", "fchmod"):
            return "CHMOD"
        elif syscall in ("chown", "fchown", "lchown"):
            return "CHOWN"
        elif syscall in ("setuid", "seteuid", "setreuid"):
            return "SETUID"
        elif syscall in ("setgid", "setegid", "setregid"):
            return "SETGID"
        elif syscall in ("fork", "vfork"):
            return "FORK"
        elif syscall == "kill":
            return "KILL"
        elif syscall in ("mmap", "mprotect"):
            return "MEMORY"
        elif syscall in ("connect", "bind", "listen", "accept"):
            return "NETWORK"
        elif syscall in ("open", "unlink", "truncate"):
            return "FILE"
        else:
            return "OTHER"


# =============================================================================
# Stub Collector for Testing
# =============================================================================


class StubKernelAuditCollector(BaseKernelAuditCollector):
    """Stub collector for testing with injected events.

    Usage:
        collector = StubKernelAuditCollector()
        collector.inject([event1, event2])
        events = collector.collect_batch()  # Returns injected events
    """

    def __init__(self) -> None:
        """Initialize stub collector."""
        super().__init__()
        self._injected: List[KernelAuditEvent] = []

    def inject(self, events: List[KernelAuditEvent]) -> None:
        """Inject events to be returned by next collect_batch call."""
        self._injected.extend(events)

    def collect_batch(self) -> List[KernelAuditEvent]:
        """Return and clear injected events."""
        events = self._injected.copy()
        self._injected.clear()
        return events


# =============================================================================
# Factory
# =============================================================================


def create_kernel_audit_collector(
    source: Optional[str] = None,
    use_stub: bool = False,
) -> BaseKernelAuditCollector:
    """Create appropriate kernel audit collector for the current platform.

    Auto-detects the platform and returns the matching collector:
        - Linux: AuditdLogCollector (reads /var/log/audit/audit.log)
        - macOS/Darwin: MacOSAuditCollector (reads OpenBSM trails via praudit)

    Args:
        source: Override path to audit log/trail. Defaults per-platform.
        use_stub: If True, return StubKernelAuditCollector for testing

    Returns:
        Collector instance
    """
    if use_stub:
        return StubKernelAuditCollector()

    system = platform.system()

    if system == "Darwin":
        trail = source or MacOSAuditCollector.DEFAULT_TRAIL
        return MacOSAuditCollector(trail_path=trail)

    # Default to Linux auditd
    log_path = source or "/var/log/audit/audit.log"
    return AuditdLogCollector(source=log_path)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "BaseKernelAuditCollector",
    "AuditdLogCollector",
    "MacOSAuditCollector",
    "StubKernelAuditCollector",
    "create_kernel_audit_collector",
]
