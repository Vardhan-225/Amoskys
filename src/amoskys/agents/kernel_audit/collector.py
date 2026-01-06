"""Kernel Audit Collector - Collect and normalize audit events.

This module provides collectors for Linux audit events from various sources:
    - AuditdLogCollector: Parse /var/log/audit/audit.log
    - NetlinkCollector: Real-time netlink subscription (future)
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
import re
import socket
import time
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
    source: str = "/var/log/audit/audit.log",
    use_stub: bool = False,
) -> BaseKernelAuditCollector:
    """Create appropriate kernel audit collector.

    Args:
        source: Path to audit log (for AuditdLogCollector)
        use_stub: If True, return StubKernelAuditCollector for testing

    Returns:
        Collector instance
    """
    if use_stub:
        return StubKernelAuditCollector()

    return AuditdLogCollector(source=source)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "BaseKernelAuditCollector",
    "AuditdLogCollector",
    "StubKernelAuditCollector",
    "create_kernel_audit_collector",
]
