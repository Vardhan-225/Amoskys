"""Ingest the ESF Sentinel's NDJSON exec stream into the telemetry store.

The Sentinel is the only sensor on this machine that sees a process BEFORE it
runs, and the only one that reads cdhash and code-signing state as the KERNEL
saw them at exec time. Until this collector existed it wrote to a file nothing
read: a nerve wired to the kernel with no axon to the brain.

DESIGN NOTES, all of them learned from failures in this codebase:

  * The stream is TAILED, not polled. Exec events are not resamplable — a
    process that starts and exits between two polls simply never happened as
    far as a polling sensor is concerned. That gap is the entire reason ESF is
    worth wiring.

  * Drops are RECORDED, never inferred. The Sentinel drops rather than stalling
    the kernel and reports its own drop count on a 30s heartbeat. Those land in
    esf_stream_health so a hole in the timeline is visible AS a hole. This
    module's guiding rule is that "nothing happened" and "we stopped looking"
    must never render identically.

  * Malformed lines are counted and surfaced, not swallowed. A parser that
    silently skips what it cannot read reports perfect health on a broken
    stream.

  * Storage is BOUNDED from the first commit. Unbounded telemetry from this
    agent filled the SSD to 99% and panicked the kernel six times in 2026-08.
    Retention is not a later feature here.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)

AGENT = "macos_esf"
AGENT_VERSION = "1.0.0"
EVENT_SOURCE = "esf_auth_exec"

# Batch size trades ingest latency against write amplification. Exec bursts are
# spiky (a build fires hundreds in a second), so batching matters; but a batch
# so large it delays visibility defeats the point of a pre-execution sensor.
BATCH_MAX = 256
BATCH_MAX_AGE_S = 2.0

# Sanity bounds for an epoch-nanosecond timestamp: 2020-01-01 .. 2100-01-01.
# The Sentinel's first working build emitted raw mach_absolute_time(), which
# counts from BOOT — about 2.4e14 on a machine up for three days, versus 1.8e18
# for a real epoch value. Stored unchecked that is quietly catastrophic: window
# queries match nothing, correlation with other telemetry is impossible, and
# retention compares it against an epoch cutoff, finds every row older than the
# window, and deletes the entire evidence table on its first pass.
#
# Checked here as well as fixed at the source, because the cost of being wrong
# is silent destruction of evidence and the cost of the check is two integer
# comparisons.
_TS_MIN_NS = 1_577_836_800_000_000_000   # 2020-01-01
_TS_MAX_NS = 4_102_444_800_000_000_000   # 2100-01-01


class ESFStreamCollector:
    """Parse Sentinel NDJSON and write forensic rows."""

    def __init__(self, store, device_id: str, retention_days: int = 14):
        self.store = store
        self.device_id = device_id
        self.retention_days = retention_days
        self.parsed = 0
        self.malformed = 0
        self.bad_timestamps = 0
        self.heartbeats = 0
        self.dropped_reported = 0
        self._batch: list = []
        self._batch_started = time.time()

    # ── parsing ───────────────────────────────────────────────────────────
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Return a normalised record, or None when the line is not one.

        Returns None for BLANK and non-JSON lines (the Sentinel writes its
        human-readable status banner and WOULD-DENY lines to stderr, which may
        be interleaved when the caller merges the two streams). A line that
        looks like JSON but does not parse is counted as malformed, because
        that is a real signal about stream integrity rather than noise.
        """
        line = line.strip()
        if not line:
            return None
        if not line.startswith("{"):
            # Sentinel status text, not an event. Not malformed.
            return None
        try:
            rec = json.loads(line)
        except ValueError:
            self.malformed += 1
            if self.malformed <= 5 or self.malformed % 1000 == 0:
                logger.warning(
                    "ESF stream: malformed JSON line (%d so far): %.120s",
                    self.malformed,
                    line,
                )
            return None
        if not isinstance(rec, dict):
            self.malformed += 1
            return None
        return rec

    def is_heartbeat(self, rec: Dict[str, Any]) -> bool:
        return rec.get("type") == "heartbeat"

    # ── normalisation ─────────────────────────────────────────────────────
    def _timestamp_ns(self, rec: Dict[str, Any], now_ns: int) -> int:
        """Validate the event timestamp, falling back to ingest time.

        Substitutes ingest time rather than dropping the event: a record with a
        questionable clock still carries a real exec — the binary, its hash,
        its parent — and discarding all of that over one bad field would lose
        more evidence than it protects. The substitution is COUNTED and logged
        so the timeline is known to be approximate rather than silently wrong.
        """
        raw = rec.get("t")
        try:
            ts = int(raw)
        except (TypeError, ValueError):
            ts = 0
        if _TS_MIN_NS <= ts <= _TS_MAX_NS:
            return ts
        self.bad_timestamps += 1
        if self.bad_timestamps <= 3 or self.bad_timestamps % 1000 == 0:
            logger.warning(
                "ESF timestamp %r is not plausible epoch-ns (%d so far). Using "
                "ingest time instead. A boot-relative value here means the "
                "Sentinel is emitting raw mach_absolute_time; the timeline for "
                "these rows is approximate.",
                raw, self.bad_timestamps,
            )
        return now_ns

    def to_row(self, rec: Dict[str, Any], now_ns: int) -> Dict[str, Any]:
        """Map a Sentinel record onto the esf_exec_events schema."""
        argv = rec.get("argv")
        return {
            "timestamp_ns": self._timestamp_ns(rec, now_ns),
            "device_id": self.device_id,
            "exe": rec.get("exe") or "",
            "argv": json.dumps(argv) if isinstance(argv, list) else None,
            # Empty string is normalised to None so "no cdhash" is a real NULL
            # and never groups with a legitimate hash in the ledger.
            "cdhash": (rec.get("cdhash") or None) or None,
            "signing_id": (rec.get("signing_id") or None) or None,
            "team_id": (rec.get("team_id") or None) or None,
            "cs_flags": rec.get("cs_flags"),
            "is_signed": bool(rec.get("signed")),
            "is_valid": bool(rec.get("valid")),
            "is_adhoc": bool(rec.get("adhoc")),
            "is_platform": bool(rec.get("platform")),
            "pid": rec.get("pid"),
            "ppid": rec.get("ppid"),
            "euid": rec.get("uid"),
            "username": None,
            "decision": rec.get("decision") or "allow",
            "decision_reason": rec.get("reason") or None,
            "process_guid": None,
            "parent_guid": None,
            "ingested_at_ns": now_ns,
        }

    # ── ingest ────────────────────────────────────────────────────────────
    def ingest_line(self, line: str) -> None:
        rec = self.parse_line(line)
        if rec is None:
            return
        now_ns = time.time_ns()
        if self.is_heartbeat(rec):
            self.heartbeats += 1
            dropped = int(rec.get("dropped") or 0)
            self.dropped_reported += dropped
            self._write_health(rec, dropped, now_ns)
            if dropped:
                # Loud on purpose. This is the only moment anyone can learn
                # that the forensic timeline has a hole in it.
                logger.warning(
                    "ESF stream DROPPED %d exec events — forensic timeline has "
                    "a gap at %d. The Sentinel drops rather than stalling the "
                    "kernel; this is the record of that trade.",
                    dropped,
                    rec.get("t"),
                )
            return
        self.parsed += 1
        self._batch.append(self.to_row(rec, now_ns))
        if len(self._batch) >= BATCH_MAX or (
            time.time() - self._batch_started > BATCH_MAX_AGE_S
        ):
            self.flush()

    def ingest(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.ingest_line(line)
        self.flush()

    # ── persistence ───────────────────────────────────────────────────────
    def flush(self) -> None:
        if not self._batch:
            self._batch_started = time.time()
            return
        rows, self._batch = self._batch, []
        self._batch_started = time.time()
        cols = list(rows[0].keys())
        sql = "INSERT INTO esf_exec_events (%s) VALUES (%s)" % (
            ", ".join(cols),
            ", ".join("?" for _ in cols),
        )
        try:
            self.store.executemany(sql, [tuple(r[c] for c in cols) for r in rows])
            self._update_ledger(rows)
        except Exception:
            logger.exception("ESF ingest failed for %d rows", len(rows))

    def _update_ledger(self, rows) -> None:
        """Maintain first-seen novelty per cdhash.

        UPSERT rather than read-then-write: the collector and any backfill can
        run concurrently, and a read-modify-write would lose the earlier
        first_seen under interleaving. first_seen_ns uses MIN so replaying an
        older log can only ever move it BACKWARD, never forward — a binary must
        not appear newer because we re-read history.
        """
        for r in rows:
            if not r["cdhash"]:
                continue
            try:
                self.store.execute(
                    """
                    INSERT INTO esf_binary_ledger
                        (cdhash, first_seen_ns, last_seen_ns, exec_count,
                         first_exe, distinct_paths, signing_id, team_id,
                         is_platform, is_adhoc)
                    VALUES (?, ?, ?, 1, ?, 1, ?, ?, ?, ?)
                    ON CONFLICT(cdhash) DO UPDATE SET
                        first_seen_ns = MIN(first_seen_ns, excluded.first_seen_ns),
                        last_seen_ns  = MAX(last_seen_ns,  excluded.last_seen_ns),
                        exec_count    = exec_count + 1
                    """,
                    (
                        r["cdhash"], r["timestamp_ns"], r["timestamp_ns"],
                        r["exe"], r["signing_id"], r["team_id"],
                        r["is_platform"], r["is_adhoc"],
                    ),
                )
            except Exception:
                logger.debug("ledger upsert failed for %s", r["cdhash"], exc_info=True)

    def _write_health(self, rec, dropped: int, now_ns: int) -> None:
        try:
            self.store.execute(
                "INSERT INTO esf_stream_health "
                "(timestamp_ns, device_id, dropped, enforce_mode, collector_lag_ns) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    self._timestamp_ns(rec, now_ns), self.device_id, dropped,
                    bool(rec.get("enforce")),
                    now_ns - self._timestamp_ns(rec, now_ns),
                ),
            )
        except Exception:
            logger.debug("stream-health write failed", exc_info=True)

    # ── retention ─────────────────────────────────────────────────────────
    def prune(self) -> int:
        """Age out evidence. Bounded from day one, not as a later feature.

        The ledger is deliberately NOT pruned with the events. It is small
        (one row per distinct binary) and it is the only place novelty lives —
        deleting it would make every binary look new again after the retention
        window, turning the strongest signal here into noise on a timer.
        """
        cutoff = time.time_ns() - self.retention_days * 86400 * 1_000_000_000
        removed = 0
        for table in ("esf_exec_events", "esf_stream_health"):
            try:
                # The lower bound is not redundant. Without it, any row whose
                # timestamp is below the epoch floor — a boot-relative mach
                # value, a zero, a corrupted field — is "older" than every
                # cutoff and gets deleted on the first prune. Retention must
                # never be the thing that destroys the evidence it is meant to
                # bound. Rows it cannot date are KEPT and stay visible.
                cur = self.store.execute(
                    f"DELETE FROM {table} WHERE timestamp_ns < ? AND timestamp_ns >= ?",
                    (cutoff, _TS_MIN_NS),
                )
                removed += getattr(cur, "rowcount", 0) or 0
            except Exception:
                logger.debug("prune failed for %s", table, exc_info=True)
        return removed

    def stats(self) -> Dict[str, int]:
        return {
            "parsed": self.parsed,
            "malformed": self.malformed,
            "heartbeats": self.heartbeats,
            "bad_timestamps": self.bad_timestamps,
            "dropped_reported": self.dropped_reported,
            "pending": len(self._batch),
        }
