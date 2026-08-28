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
        self.control_records = 0
        self.kernel_events = 0
        self.kernel_dropped = 0
        self._batch_kernel: list = []
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

    # Kernel TRANSITION events. These carry a "type" like control records do,
    # so without this set they would all be swallowed by is_control() and
    # silently discarded -- a whole new sensing capability wired at the kernel
    # and thrown away at the parser, with the collector reporting healthy
    # throughout.
    KERNEL_EVENT_KINDS = frozenset({
        "setuid", "setgid", "kextload", "cs_invalidated", "mount", "unmount",
        # Lifecycle. A forked child is a real process with its own pid that
        # never execs — visible to any sampler, invisible to an exec-only
        # stream. Without these, "every process has a witnessed origin" is only
        # true of processes that exec, which quietly excludes the forked child.
        "fork", "exit",
    })

    def is_kernel_event(self, rec: Dict[str, Any]) -> bool:
        kind = rec.get("type")
        return bool(kind) and (
            kind in self.KERNEL_EVENT_KINDS or str(kind).startswith("notify_")
        )

    def is_control(self, rec: Dict[str, Any]) -> bool:
        """Any record carrying a "type" is control traffic, not an exec.

        Checked as a CLASS rather than by matching "heartbeat" specifically.
        The narrower check let sentinel_start — added later, to prove liveness
        at startup — fall through and be stored as an exec event: a row with no
        binary, no pid and no cdhash, sitting in the evidence table as though
        something had run. Every future control record would have done the
        same. Exec records are exactly those with no "type" field.
        """
        return "type" in rec

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
        if rec.get("type") == "kernel_drop":
            # The kernel discarded events before we saw them. Loudest possible
            # signal: nothing downstream can recover them, and the gap in the
            # timeline is permanent.
            self.kernel_dropped += int(rec.get("dropped") or 0)
            self._write_kernel_drop(rec, now_ns)
            logger.warning(
                "KERNEL DROPPED %s event(s) of type %s before the Sentinel saw "
                "them (seq=%s). This is loss inside the kernel, not our buffer "
                "— a lighter subscription or tighter muting is the fix, not a "
                "bigger queue.",
                rec.get("dropped"), rec.get("event_type"), rec.get("seq"),
            )
            return

        if self.is_kernel_event(rec):
            self.kernel_events += 1
            self._batch_kernel.append(self._kernel_row(rec, now_ns))
            if len(self._batch_kernel) >= BATCH_MAX:
                self.flush()
            return

        if self.is_control(rec):
            if not self.is_heartbeat(rec):
                self.control_records += 1
                logger.info("ESF control record: %s", rec.get("type"))
                if rec.get("type") == "sentinel_start":
                    # RECORDED, not just logged. A witnessing SESSION boundary
                    # is load-bearing: coverage analysis needs to know when the
                    # current stream began, and inferring it from
                    # MIN(timestamp_ns) silently spans restarts. It did exactly
                    # that here — reporting 34.4h of "continuous witnessing"
                    # across a restart AND a clock correction, so rows from
                    # before the epoch fix (stamped 17.5h in the past) were
                    # treated as part of the live session and produced 13,249
                    # phantom conservation violations.
                    self._write_session_start(rec, now_ns)
                return
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
    def _flush_kernel(self) -> None:
        if not self._batch_kernel:
            return
        rows, self._batch_kernel = self._batch_kernel, []
        cols = list(rows[0].keys())
        sql = "INSERT INTO esf_kernel_events (%s) VALUES (%s)" % (
            ", ".join(cols), ", ".join("?" for _ in cols))
        try:
            self.store._executemany(sql, [tuple(r[c] for c in cols) for r in rows])
            self.store._commit()
        except Exception:
            logger.exception("kernel-event ingest failed for %d rows", len(rows))

    def _kernel_row(self, rec: Dict[str, Any], now_ns: int) -> Dict[str, Any]:
        """Normalise a transition event.

        Kind-specific fields go to `detail` as JSON rather than to columns.
        These events share almost nothing: a mount has filesystem names, a
        setuid has a uid, a cs_invalidated has only the process. Forty sparse
        columns would be mostly NULL, and every Phase-4 event type would need a
        migration to add fields nothing else uses.
        """
        known = {"v", "t", "type", "pid", "uid", "exe", "cdhash", "platform"}
        detail = {k: v for k, v in rec.items() if k not in known}
        return {
            "timestamp_ns": self._timestamp_ns(rec, now_ns),
            "device_id": self.device_id,
            "kind": rec.get("type"),
            "pid": rec.get("pid"),
            "euid": rec.get("uid"),
            "exe": rec.get("exe"),
            "cdhash": (rec.get("cdhash") or None) or None,
            "is_platform": bool(rec.get("platform")),
            "detail": json.dumps(detail) if detail else None,
            "ingested_at_ns": now_ns,
        }

    def _write_session_start(self, rec: Dict[str, Any], now_ns: int) -> None:
        """Mark a witnessing-session boundary in esf_stream_health.

        Reuses that table with dropped=0 and an explicit note rather than
        adding another one: it is already the record of stream continuity, and
        a session start is the most important continuity event there is.
        """
        try:
            self.store._execute(
                "INSERT INTO esf_stream_health "
                "(timestamp_ns, device_id, dropped, enforce_mode, note) "
                "VALUES (?, ?, 0, ?, ?)",
                (
                    self._timestamp_ns(rec, now_ns), self.device_id,
                    bool(rec.get("enforce")),
                    "session_start subscriptions=%s buffer=%s" % (
                        rec.get("subscriptions"), rec.get("buffer")),
                ),
            )
            self.store._commit()
        except Exception:
            logger.debug("session-start write failed", exc_info=True)

    def _write_kernel_drop(self, rec: Dict[str, Any], now_ns: int) -> None:
        try:
            self.store._execute(
                "INSERT INTO esf_kernel_drops "
                "(timestamp_ns, device_id, event_type, dropped, seq_num, ingested_at_ns) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    self._timestamp_ns(rec, now_ns), self.device_id,
                    rec.get("event_type"), int(rec.get("dropped") or 0),
                    rec.get("seq"), now_ns,
                ),
            )
            self.store._commit()
        except Exception:
            logger.debug("kernel-drop write failed", exc_info=True)

    def flush(self) -> None:
        self._flush_kernel()
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
            # _executemany / _execute, not raw db access: they carry the
            # lock backoff that everything else in this store goes through.
            # Reaching past them drops the whole batch on the first
            # "database is locked".
            self.store._executemany(sql, [tuple(r[c] for c in cols) for r in rows])
            self._update_ledger(rows)
            self.store._commit()
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
                self.store._execute(
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
            self.store._execute(
                "INSERT INTO esf_stream_health "
                "(timestamp_ns, device_id, dropped, enforce_mode, collector_lag_ns) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    self._timestamp_ns(rec, now_ns), self.device_id, dropped,
                    bool(rec.get("enforce")),
                    now_ns - self._timestamp_ns(rec, now_ns),
                ),
            )
            self.store._commit()
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
                cur = self.store._execute(
                    f"DELETE FROM {table} WHERE timestamp_ns < ? AND timestamp_ns >= ?",
                    (cutoff, _TS_MIN_NS),
                )
                self.store._commit()
                removed += getattr(cur, "rowcount", 0) or 0
            except Exception:
                logger.debug("prune failed for %s", table, exc_info=True)
        return removed

    def stats(self) -> Dict[str, int]:
        return {
            "parsed": self.parsed,
            "malformed": self.malformed,
            "heartbeats": self.heartbeats,
            "control_records": self.control_records,
            "kernel_events": self.kernel_events,
            "kernel_dropped": self.kernel_dropped,
            "bad_timestamps": self.bad_timestamps,
            "dropped_reported": self.dropped_reported,
            "pending": len(self._batch),
        }
