"""macOS Unified Log Collector — predicate-based log extraction.

Collects security-relevant log entries from the macOS Unified Logging system
using `log show` with targeted predicates. Each predicate group focuses on a
specific subsystem or process family:

    - Security:   subsystem == "com.apple.securityd"
    - Gatekeeper: process == "syspolicyd" OR process == "GatekeeperXPC"
    - Installer:  process == "installer" OR process == "Installer"
    - TCC:        subsystem == "com.apple.TCC"
    - Sharing:    process == "sharingd" OR process == "AirDrop"
    - XPC:        subsystem == "com.apple.xpc"

Data source:
    log show --predicate '<predicate>' --last <N>s --style json

No root required for most predicates. TCC subsystem returns degraded
results without Full Disk Access (FDA) — only current-session events
are visible.

The collector returns a structured dict that probes consume via shared_data.
It never makes detection decisions — that is the probes' job.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# Log Entry Dataclass
# =============================================================================


@dataclass
class LogEntry:
    """A single parsed Unified Log entry."""

    timestamp: str  # ISO-8601 from log show
    subsystem: str  # e.g. "com.apple.securityd"
    process: str  # e.g. "syspolicyd"
    category: str  # e.g. "trust"
    message: str  # Free-form log message
    event_type: str  # Predicate group that matched: security, gatekeeper, etc.
    process_id: int = 0  # PID if available
    sender: str = ""  # Sender image name
    activity_id: int = 0  # Activity identifier for correlation
    trace_id: int = 0  # Trace identifier


# =============================================================================
# Predicate Groups
# =============================================================================


# Each group: (name, predicate_string)
_PREDICATE_GROUPS: List[tuple] = [
    (
        "security",
        'subsystem == "com.apple.securityd"',
    ),
    (
        "gatekeeper",
        'process == "syspolicyd" OR process == "GatekeeperXPC"',
    ),
    (
        "installer",
        'process == "installer" OR process == "Installer"',
    ),
    (
        "tcc",
        'subsystem == "com.apple.TCC"',
    ),
    (
        "sharing",
        'process == "sharingd" OR process == "AirDrop"',
    ),
    (
        "xpc",
        'subsystem == "com.apple.xpc"',
    ),
]


# =============================================================================
# Collector
# =============================================================================


class MacOSUnifiedLogCollector:
    """Collects Unified Log entries from macOS using targeted predicates.

    Runs `log show --predicate '...' --last <N>s --style json` for each
    predicate group, parses JSON output, and returns a shared_data dict.

    Returns shared_data dict with keys:
        log_entries: List[LogEntry] — all collected log entries
        entry_count: int — total number of entries
        subsystems: List[str] — unique subsystems seen
        collection_time_ms: float — how long collection took
    """

    def __init__(
        self,
        lookback_seconds: int = 60,
        timeout_per_query: int = 10,
        predicate_groups: Optional[List[tuple]] = None,
    ) -> None:
        self._lookback_seconds = lookback_seconds
        self._timeout = timeout_per_query
        self._predicate_groups = predicate_groups or _PREDICATE_GROUPS

    def collect(self) -> Dict[str, Any]:
        """Collect log entries from all predicate groups.

        Returns dict for ProbeContext.shared_data.
        """
        start = time.monotonic()
        all_entries: List[LogEntry] = []
        subsystems_seen: set = set()

        for group_name, predicate in self._predicate_groups:
            entries = self._query_log(group_name, predicate)
            for entry in entries:
                if entry.subsystem:
                    subsystems_seen.add(entry.subsystem)
            all_entries.extend(entries)

        elapsed_ms = (time.monotonic() - start) * 1000

        logger.debug(
            "Unified log collection: %d entries from %d subsystems in %.1fms",
            len(all_entries),
            len(subsystems_seen),
            elapsed_ms,
        )

        return {
            "log_entries": all_entries,
            "entry_count": len(all_entries),
            "subsystems": sorted(subsystems_seen),
            "collection_time_ms": round(elapsed_ms, 2),
        }

    def _query_log(self, group_name: str, predicate: str) -> List[LogEntry]:
        """Run a single `log show` query and parse the JSON output."""
        entries: List[LogEntry] = []

        cmd = [
            "log",
            "show",
            "--predicate",
            predicate,
            "--last",
            f"{self._lookback_seconds}s",
            "--style",
            "json",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

            if result.returncode != 0:
                # log show returns 1 when no results match — not an error
                stderr = result.stderr.strip()
                if stderr and "no matches" not in stderr.lower():
                    logger.warning(
                        "log show returned %d for group %s: %s",
                        result.returncode,
                        group_name,
                        stderr[:200],
                    )
                return entries

            entries = self._parse_json_output(result.stdout, group_name)

        except subprocess.TimeoutExpired:
            logger.warning(
                "log show timed out for group %s (timeout=%ds)",
                group_name,
                self._timeout,
            )
        except FileNotFoundError:
            logger.error("'log' command not found — not macOS?")
        except Exception as e:
            logger.error("log show failed for group %s: %s", group_name, e)

        return entries

    def _parse_json_output(
        self,
        stdout: str,
        group_name: str,
    ) -> List[LogEntry]:
        """Parse `log show --style json` output into LogEntry objects.

        The output is a JSON array of log event objects. Each object has
        keys like: timestamp, subsystem, processImagePath, category,
        eventMessage, processID, senderImagePath, activityIdentifier, traceID.
        """
        entries: List[LogEntry] = []

        if not stdout or not stdout.strip():
            return entries

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            # Sometimes log show emits partial JSON or preamble text.
            # Try to find the JSON array start.
            bracket = stdout.find("[")
            if bracket < 0:
                logger.debug(
                    "No JSON array found in log show output for %s", group_name
                )
                return entries
            try:
                raw = json.loads(stdout[bracket:])
            except json.JSONDecodeError as e:
                logger.warning(
                    "Failed to parse log show JSON for %s: %s",
                    group_name,
                    e,
                )
                return entries

        if not isinstance(raw, list):
            raw = [raw]

        for item in raw:
            if not isinstance(item, dict):
                continue

            try:
                # Extract process name from processImagePath
                process_path = item.get("processImagePath", "")
                process_name = process_path.rsplit("/", 1)[-1] if process_path else ""

                entry = LogEntry(
                    timestamp=item.get("timestamp", ""),
                    subsystem=item.get("subsystem", ""),
                    process=process_name or item.get("process", ""),
                    category=item.get("category", ""),
                    message=item.get("eventMessage", ""),
                    event_type=group_name,
                    process_id=int(item.get("processID", 0)),
                    sender=(
                        item.get("senderImagePath", "").rsplit("/", 1)[-1]
                        if item.get("senderImagePath")
                        else ""
                    ),
                    activity_id=int(item.get("activityIdentifier", 0)),
                    trace_id=int(item.get("traceID", 0)),
                )
                entries.append(entry)

            except (ValueError, TypeError, KeyError) as e:
                logger.debug("Skipping malformed log entry: %s", e)
                continue

        return entries
