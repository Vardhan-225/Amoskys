"""Kernel Audit Collector - Collect and normalize audit events.

This module provides collectors for kernel audit events from various sources:
    - AuditdLogCollector: Parse /var/log/audit/audit.log (Linux)
    - MacOSUnifiedLogCollector: Query unified logging (macOS 10.15+) - PRIMARY
    - MacOSAuditCollector: Parse OpenBSM trails via praudit (macOS) - LEGACY FALLBACK
    - StubCollector: For testing with injected events

Design:
    - Collectors return normalized KernelAuditEvent objects
    - Bookmark/offset tracking for incremental collection
    - Pluggable architecture for different audit sources

Note on macOS:
    OpenBSM is broken on macOS 10.15+ due to SIP disabling BSM audit trails.
    MacOSUnifiedLogCollector uses the modern 'log show' command instead.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from amoskys.agents.kernel_audit.agent_types import KernelAuditEvent

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
    AUDIT_LINE_RE = re.compile(r"type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)")
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
                logger.info("BSM trail rotated: %s -> %s", self._trail_path, resolved)
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

        new_records = records[self._record_offset :]
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
# macOS Unified Log Collector
# =============================================================================


class MacOSUnifiedLogCollector(BaseKernelAuditCollector):
    """Collector for macOS kernel/security audit events via Unified Logging.

    Uses ``log show`` with NDJSON output to query security-relevant events.
    This is the modern replacement for OpenBSM on macOS 10.15+ where SIP
    disables BSM audit trails.

    Monitored subsystems:
        - com.apple.securityd
        - com.apple.authd
        - com.apple.sandbox
        - com.apple.kernel

    Attributes:
        _last_timestamp: Last seen event timestamp for incremental collection
        _subsystems: List of security-relevant subsystems to monitor
    """

    # Security-relevant subsystems for macOS unified logging
    SECURITY_SUBSYSTEMS = [
        "com.apple.securityd",
        "com.apple.authd",
        "com.apple.sandbox",
        "com.apple.kernel",
    ]

    # Unified log event → normalized syscall/action name
    EVENT_ACTION_MAP: Dict[str, str] = {
        "execve": "execve",
        "exec": "execve",
        "ptrace": "ptrace",
        "setuid": "setuid",
        "setgid": "setgid",
        "chmod": "chmod",
        "chown": "chown",
        "kill": "kill",
        "fork": "fork",
        "vfork": "vfork",
        "clone": "clone",
        "mmap": "mmap",
        "mprotect": "mprotect",
    }

    # Query window for unified log (10 seconds - keeps recent events)
    QUERY_WINDOW = "10s"

    def __init__(self) -> None:
        """Initialize macOS Unified Log collector."""
        super().__init__()
        self._last_timestamp: Optional[float] = None
        self._seen_timestamps: Dict[float, int] = {}  # timestamp -> count for dedup

    def collect_batch(self) -> List[KernelAuditEvent]:
        """Collect batch of events from macOS Unified Logging.

        Runs ``log show`` with an NDJSON predicate for security subsystems,
        parses JSON output, and converts to KernelAuditEvent objects.

        Returns:
            List of normalised KernelAuditEvent objects
        """
        entries = self._query_unified_log()
        if not entries:
            return []

        events: List[KernelAuditEvent] = []
        for entry in entries:
            event = self._build_event(entry)
            if event:
                events.append(event)

        return events

    def _query_unified_log(self) -> List[Dict[str, Any]]:
        """Query unified log for security events.

        Returns:
            List of parsed JSON log entries or empty list on error
        """
        try:
            # Build predicate for security subsystems
            subsystem_predicates = " OR ".join(
                f'subsystem == "{subsys}"' for subsys in self.SECURITY_SUBSYSTEMS
            )
            predicate = f"({subsystem_predicates})"

            cmd = [
                "log",
                "show",
                "--predicate",
                predicate,
                "--last",
                self.QUERY_WINDOW,
                "--style",
                "ndjson",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.debug(
                    f"log show returned {result.returncode}: {result.stderr[:200]}"
                )
                return []

            if not result.stdout or result.stdout.strip() == "":
                return []

            # Parse NDJSON (one JSON object per line)
            entries: List[Dict[str, Any]] = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    entries.append(obj)
                except json.JSONDecodeError:
                    logger.debug(f"Failed to parse NDJSON line: {line[:100]}")
                    continue

            logger.debug(f"Unified log query returned {len(entries)} entries")
            return entries

        except subprocess.TimeoutExpired:
            logger.error("log show timed out after 30s")
            return []
        except FileNotFoundError:
            logger.error("log command not found — is macOS present?")
            return []
        except Exception as e:
            logger.error(f"Error querying unified log: {e}")
            return []

    def _build_event(self, entry: Dict[str, Any]) -> Optional[KernelAuditEvent]:
        """Build KernelAuditEvent from a unified log JSON entry.

        Args:
            entry: Parsed JSON log entry with keys like:
                - timestamp: ISO 8601 timestamp
                - processImagePath: Path to executable
                - processID: Process ID
                - senderImagePath: Sender/caller path
                - eventMessage: Event description
                - category: Event category
                - subsystem: Subsystem identifier

        Returns:
            KernelAuditEvent or None if not mappable to a security event
        """
        try:
            message = entry.get("eventMessage", "").lower()
            process_path = entry.get("processImagePath", "")
            sender_path = entry.get("senderImagePath", "")
            category = entry.get("category", "").lower()
            subsystem = entry.get("subsystem", "").lower()
            timestamp_str = entry.get("timestamp", "")
            process_id = entry.get("processID", 0)

            # Extract process name from path
            process_name = (
                process_path.rsplit("/", 1)[-1] if process_path else ""
            ).lower()

            # Skip entries without meaningful event messages
            if not message or not process_name:
                return None

            # Parse timestamp
            try:
                if timestamp_str:
                    # macOS format: "2026-02-17 17:17:13.534573-0600"
                    dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    timestamp_ns = int(dt.timestamp() * 1e9)
                else:
                    timestamp_ns = int(time.time() * 1e9)
            except (ValueError, TypeError):
                timestamp_ns = int(time.time() * 1e9)

            # Determine action type based on message content
            action = self._classify_action(message, process_name, category)
            if action is None:
                return None

            # Infer syscall from action
            syscall = self._action_to_syscall(action)

            # Determine result (success/failed) from message
            result = self._infer_result(message)

            # Extract relevant fields from message
            exe = process_path or None
            comm = process_name or None

            # Try to extract UID from message if present
            uid: Optional[int] = None
            uid_match = re.search(r"uid[=:\s]+(\d+)", message)
            if uid_match:
                try:
                    uid = int(uid_match.group(1))
                except ValueError:
                    pass

            # Build raw dict from entry
            raw_dict = {k: str(v) for k, v in entry.items()}

            return KernelAuditEvent(
                event_id=self._generate_event_id(
                    f"{timestamp_ns}:{process_id}:{message[:50]}"
                ),
                timestamp_ns=timestamp_ns,
                host=self.hostname,
                syscall=syscall,
                exe=exe,
                pid=process_id if process_id > 0 else None,
                ppid=None,  # Unified log does not provide ppid
                uid=uid,
                euid=None,
                gid=None,
                egid=None,
                tty=None,
                cwd=None,
                path=None,
                audit_user=None,
                session=None,
                action=action,
                result=result,
                comm=comm,
                raw=raw_dict,
            )

        except Exception as e:
            logger.debug(f"Failed to build event from unified log entry: {e}")
            return None

    def _classify_action(
        self, message: str, process_name: str, category: str
    ) -> Optional[str]:
        """Classify unified log event into high-level action type.

        Args:
            message: Event message (lowercase)
            process_name: Process name (lowercase)
            category: Event category (lowercase)

        Returns:
            Action string ("EXEC", "PTRACE", etc.) or None if not security-relevant
        """
        # Check for privilege escalation patterns
        if any(
            kw in message for kw in ["setuid", "setgid", "seteuid", "setegid", "capset"]
        ):
            if "setuid" in message or "seteuid" in message:
                return "SETUID"
            elif "setgid" in message or "setegid" in message:
                return "SETGID"
            elif "capset" in message:
                return "CAPSET"

        # Check for process execution patterns
        if any(kw in message for kw in ["execve", "exec", "execute"]):
            return "EXEC"

        # Check for ptrace patterns
        if "ptrace" in message or "trace" in message or "debugger" in message:
            return "PTRACE"

        # Check for privilege patterns in securityd/authd
        if process_name in ("securityd", "authd", "sandbox"):
            if any(
                kw in message
                for kw in ["deny", "denied", "allow", "allowed", "privilege"]
            ):
                if "deny" in message or "denied" in message:
                    return "PRIVILEGE_DENY"
                else:
                    return "PRIVILEGE_ALLOW"

        # Check for module/driver loading
        if any(
            kw in message for kw in ["module", "driver", "kernel extension", "kext"]
        ):
            if "load" in message or "unload" in message:
                return "MODULE_LOAD"

        # Check for sandbox violations
        if "sandbox" in process_name or "sandbox" in message:
            return "SANDBOX_VIOLATION"

        # Check for fork/clone patterns
        if any(kw in message for kw in ["fork", "vfork", "clone"]):
            return "FORK"

        # Check for kill patterns
        if "kill" in message or "signal" in message:
            return "KILL"

        # Generic security event
        if any(
            kw in message
            for kw in [
                "security",
                "auth",
                "permission",
                "access",
                "violation",
            ]
        ):
            return "OTHER"

        return None

    def _action_to_syscall(self, action: str) -> Optional[str]:
        """Map action type to syscall name.

        Args:
            action: Action type string

        Returns:
            Syscall name or None
        """
        action_syscall_map = {
            "EXEC": "execve",
            "PTRACE": "ptrace",
            "SETUID": "setuid",
            "SETGID": "setgid",
            "CAPSET": "capset",
            "PRIVILEGE_DENY": "access",
            "PRIVILEGE_ALLOW": "access",
            "MODULE_LOAD": "init_module",
            "SANDBOX_VIOLATION": "mprotect",
            "FORK": "fork",
            "KILL": "kill",
        }
        return action_syscall_map.get(action)

    def _infer_result(self, message: str) -> str:
        """Infer syscall result from event message.

        Args:
            message: Event message (lowercase)

        Returns:
            "success" or "failed"
        """
        if any(kw in message for kw in ["deny", "denied", "failed", "error"]):
            return "failed"
        return "success"


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
    use_bsm_fallback: bool = False,
) -> BaseKernelAuditCollector:
    """Create appropriate kernel audit collector for the current platform.

    Auto-detects the platform and returns the matching collector:
        - Linux: AuditdLogCollector (reads /var/log/audit/audit.log)
        - macOS/Darwin: MacOSUnifiedLogCollector (via unified logging)
            - Falls back to MacOSAuditCollector (OpenBSM) if use_bsm_fallback=True

    Args:
        source: Override path to audit log/trail. Only used for fallback modes.
        use_stub: If True, return StubKernelAuditCollector for testing
        use_bsm_fallback: If True on macOS, use OpenBSM collector instead of unified log

    Returns:
        Collector instance
    """
    if use_stub:
        return StubKernelAuditCollector()

    system = platform.system()

    if system == "Darwin":
        if use_bsm_fallback:
            # Legacy: Use OpenBSM collector if explicitly requested
            trail = source or MacOSAuditCollector.DEFAULT_TRAIL
            logger.info("Using OpenBSM collector (legacy fallback)")
            return MacOSAuditCollector(trail_path=trail)
        else:
            # Default: Use modern Unified Logging collector
            logger.info("Using macOS Unified Logging collector")
            return MacOSUnifiedLogCollector()

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
    "MacOSUnifiedLogCollector",
    "StubKernelAuditCollector",
    "create_kernel_audit_collector",
]
