"""nettop Byte Count Collector for macOS.

Supplements the lsof-based flow collector with per-process byte counts
from macOS's built-in ``nettop`` utility.  Without byte counts,
DataExfilVolumeSpikeProbe (≥50 MB threshold), C2BeaconFlowProbe (avg bytes
check), and SuspiciousTunnelProbe (avg packet size) can never fire
meaningfully.

Design:
    - Runs ``nettop -P -L 1 -J bytes_in,bytes_out -x`` (one snapshot, exits)
    - Parses CSV output: ``ProcessName.PID,bytes_in,bytes_out,``
    - Returns Dict[int, NettopRecord] keyed by PID
    - Merged into FlowEvent objects by PID after lsof parsing
    - Graceful fallback: returns empty dict if nettop unavailable
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NettopRecord:
    """Per-process byte counts from nettop."""

    pid: int
    process_name: str
    bytes_in: int
    bytes_out: int

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out


class MacOSNettopCollector:
    """Collects per-process byte counts via macOS ``nettop``.

    Usage::

        collector = MacOSNettopCollector()
        records = collector.collect()
        # records[1234] → NettopRecord(pid=1234, ...)
    """

    CMD = ["nettop", "-P", "-L", "1", "-J", "bytes_in,bytes_out", "-x"]

    def __init__(self, timeout: int = 10) -> None:
        self._timeout = timeout
        self._collection_errors = 0

    def collect(self) -> Dict[int, NettopRecord]:
        """Run nettop and return per-process byte counts keyed by PID."""
        try:
            result = subprocess.run(
                self.CMD,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

            if result.returncode != 0 and not result.stdout:
                logger.warning(
                    "nettop returned code %d: %s",
                    result.returncode,
                    result.stderr[:200] if result.stderr else "(no stderr)",
                )
                self._collection_errors += 1
                return {}

            return self._parse_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.warning("nettop timed out after %d s", self._timeout)
            self._collection_errors += 1
        except FileNotFoundError:
            logger.warning("nettop not found on PATH (non-macOS?)")
            self._collection_errors += 1
        except Exception as e:
            logger.error("nettop collection error: %s", e, exc_info=True)
            self._collection_errors += 1

        return {}

    @staticmethod
    def _parse_output(raw: str) -> Dict[int, NettopRecord]:
        """Parse nettop CSV output into NettopRecord dict keyed by PID.

        Format::

            ,bytes_in,bytes_out,
            launchd.1,0,0,
            mDNSResponder.514,43284870,26438227,
            Google Chrome H.1019,47787,92643,

        The first line is a header.  Each data line is
        ``ProcessName.PID,bytes_in,bytes_out,`` with a trailing comma.
        Process names can contain spaces and dots; the PID is always the
        last ``.``-separated segment before the first comma.
        """
        records: Dict[int, NettopRecord] = {}

        lines = raw.strip().splitlines()
        if len(lines) < 2:
            return records

        for line in lines[1:]:  # skip header
            line = line.strip()
            if not line:
                continue

            record = MacOSNettopCollector._parse_line(line)
            if record is not None:
                # If multiple entries for same PID, sum bytes
                if record.pid in records:
                    existing = records[record.pid]
                    records[record.pid] = NettopRecord(
                        pid=record.pid,
                        process_name=existing.process_name,
                        bytes_in=existing.bytes_in + record.bytes_in,
                        bytes_out=existing.bytes_out + record.bytes_out,
                    )
                else:
                    records[record.pid] = record

        return records

    @staticmethod
    def _parse_line(line: str) -> Optional[NettopRecord]:
        """Parse a single nettop output line.

        Line format: ``ProcessName.PID,bytes_in,bytes_out,``
        The trailing comma is present.  Process names may contain spaces
        and dots (e.g. ``Google Chrome H.1019``).
        """
        # Strip trailing comma if present
        if line.endswith(","):
            line = line[:-1]

        # Split by comma — expect exactly 3 fields
        parts = line.split(",")
        if len(parts) != 3:
            return None

        name_pid, bytes_in_str, bytes_out_str = parts

        # Extract PID: last dot-separated segment
        dot_idx = name_pid.rfind(".")
        if dot_idx == -1 or dot_idx == len(name_pid) - 1:
            return None

        process_name = name_pid[:dot_idx].strip()
        pid_str = name_pid[dot_idx + 1 :]

        try:
            pid = int(pid_str)
            bytes_in = int(bytes_in_str.strip())
            bytes_out = int(bytes_out_str.strip())
        except ValueError:
            return None

        if not process_name:
            return None

        return NettopRecord(
            pid=pid,
            process_name=process_name,
            bytes_in=bytes_in,
            bytes_out=bytes_out,
        )


__all__ = ["MacOSNettopCollector", "NettopRecord"]
