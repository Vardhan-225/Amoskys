"""Carry the kernel's verdict to the scoring layer.

The scoring layer could not see the Sentinel. A five-stage kill chain was
capped at 0.40 "for lack of corroboration" while, on the same machine at the
same moment, the kernel had already evaluated that exec and returned
would_deny. The strongest independent signal available was sitting in a table
nobody joined.

This is the join. It is deliberately small and cached, because it runs per
scored event on the analyzer's hot path.

WHAT IT DOES NOT DO. It does not re-derive a verdict, re-check a signature, or
score anything. It reports what the kernel already decided, so the scorer can
count it as an independent witness. A second opinion that re-runs the first
opinion's reasoning is not corroboration.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# An exec witnessed within this window of the event is taken to be the same
# process. Matched against create_time where available, otherwise the event
# timestamp. Wide enough to absorb analyzer lag, far too narrow to span a pid
# recycle on a normally-loaded machine.
_MATCH_WINDOW_NS = 30 * 1_000_000_000
_CACHE_MAX = 4096
_CACHE_TTL_S = 300.0


class ESFCorroborator:
    """Look up kernel-witnessed evidence for a scored event."""

    def __init__(self, store):
        self.store = store
        self._cache: Dict[int, tuple] = {}
        self._hits = 0
        self._misses = 0
        self._unavailable = False

    def _lookup(self, pid: int, ts_ns: int) -> Optional[Dict[str, Any]]:
        try:
            with self.store._read_pool.connection() as db:
                row = db.execute(
                    "SELECT decision, is_signed, is_valid, is_adhoc, is_platform, "
                    "       cdhash, timestamp_ns, quarantine "
                    "FROM esf_exec_events "
                    # Causal direction only: the exec must precede the event.
                    # A process cannot act before it execs, so an exec AFTER the
                    # event is a different process that inherited a recycled pid.
                    #
                    # Measured on 7d of real data this changes nothing -- 1112 of
                    # 1112 matches were already exec-before-event, and 0 were
                    # acausal. It is kept because 52.6% of matched events have
                    # MORE THAN ONE candidate exec on the same pid in-window, so
                    # the ordering is doing real work; the day pid reuse puts a
                    # candidate on the future side, ABS() would silently attach a
                    # kernel witness from an unrelated process -- and a witness
                    # lifts the cap to 0.70, so a wrong one manufactures a
                    # malicious verdict rather than merely missing one.
                    #
                    # Among past candidates DESC picks the most recent exec,
                    # which is the image actually running (exec replaces it).
                    "WHERE pid = ? AND timestamp_ns <= ? AND ? - timestamp_ns <= ? "
                    "ORDER BY timestamp_ns DESC LIMIT 1",
                    (pid, ts_ns, ts_ns, _MATCH_WINDOW_NS),
                ).fetchone()
                if not row:
                    return None
                decision, signed, valid, adhoc, platform, cdhash, ets, quarantine = row
                novel = False
                if cdhash:
                    # Novel means the ledger's FIRST sighting is this execution,
                    # not merely that the hash is present — every hash is
                    # present once it has run.
                    first = db.execute(
                        "SELECT first_seen_ns FROM esf_binary_ledger WHERE cdhash = ?",
                        (cdhash,),
                    ).fetchone()
                    if first and first[0]:
                        novel = abs(first[0] - ets) <= _MATCH_WINDOW_NS
                untrusted = bool(
                    not platform and (not signed or adhoc or not valid)
                )
                return {
                    # Private, popped by enrich() before the event is updated:
                    # the cache needs to know WHICH execution answered, not just
                    # that one did. Never reaches the scorer.
                    "_exec_ts_ns": ets,
                    "esf_decision": decision,
                    "esf_untrusted": untrusted,
                    "esf_novel_binary": novel,
                    "esf_cdhash": cdhash,
                    # Raw xattr; field 3 names the source agent. Provenance is
                    # the only thing that separates a downloaded dropper from a
                    # local build, both of which are ad-hoc signed.
                    "esf_quarantine": quarantine,
                }
        except Exception:
            # An older schema, or the ESF tier not deployed. Recorded once and
            # then silent: absence of the kernel witness is a NORMAL state, not
            # an error, and logging it per event would drown the analyzer.
            if not self._unavailable:
                self._unavailable = True
                logger.info(
                    "ESF corroboration unavailable (no exec stream on this "
                    "device). Scoring proceeds without kernel witnesses."
                )
            return None

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Attach kernel evidence to an event, in place. Absent is not negative.

        An event with no matching exec is UNATTRIBUTED, not exonerated — the
        fields are simply omitted, so a downstream reader cannot mistake
        "we did not see it" for "the kernel approved it".
        """
        # COERCE, DO NOT TYPE-CHECK. The analyzer's protobuf conversion does
        # `proto_event.attributes[k] = str(v)`, so every attribute reaching the
        # scorer is a STRING — pid arrives as '81786', not 81786.
        #
        # The first version required isinstance(pid, int) and returned early on
        # everything. Measured: 30 of 30 execute_to_exfil events carry a pid,
        # all of them strings, and the corroborator attached witnesses to zero
        # of them. The gate would have stayed capped at 0.40 no matter what the
        # kernel saw — a second null result indistinguishable from "the gate
        # does not work", which is precisely the wrong conclusion to draw.
        #
        # Both forms are accepted because the same dict is built from a DB
        # column (int) in one path and from proto attributes (str) in another,
        # and a corroborator that works on only one of them is worse than none:
        # it succeeds often enough to look correct.
        raw_pid = event.get("pid")
        try:
            pid = int(raw_pid)
        except (TypeError, ValueError):
            return event
        if pid <= 0:
            return event
        try:
            ts = int(event.get("timestamp_ns"))
        except (TypeError, ValueError):
            ts = time.time_ns()

        now = time.time()
        cached = self._cache.get(pid)
        if cached and (now - cached[1]) < _CACHE_TTL_S:
            payload, _cached_at, exec_ts = cached
            # A cached witness is only valid for events that fall inside the
            # SAME execution's window. pid is not an identity: macOS recycles
            # them, and one live dropper investigation saw pid 85170 reused 13
            # times. Serving a cached witness on pid alone would attach exec A's
            # kernel record to exec B's event — and a witness LIFTS the cap to
            # malicious, so a wrong one manufactures a verdict rather than
            # merely missing one. That is the more expensive direction to err.
            if abs(ts - exec_ts) <= _MATCH_WINDOW_NS:
                self._hits += 1
                event.update(payload)
                return event
            # Same pid, different execution — fall through and look it up again.

        self._misses += 1
        found = self._lookup(pid, ts)
        if found:
            exec_ts = found.pop("_exec_ts_ns")
            if len(self._cache) >= _CACHE_MAX:
                self._cache.clear()
            self._cache[pid] = (found, now, exec_ts)
            event.update(found)
        # NEGATIVES ARE NEVER CACHED.
        #
        # A miss is not a stable fact — it usually means the exec row has not
        # been flushed by the ESF collector yet. Caching it froze that race for
        # the full 300s TTL: a live dropper's first event (process_spawned)
        # missed by milliseconds, cached None, and its execute_to_exfil 1.6s
        # later — with the would_deny + Safari-quarantine exec row now sitting
        # in the table, 1.6s inside a 30s window — read the stale None and
        # scored 0.40 instead of 0.70. The corroborator never looked again.
        #
        # A miss costs one indexed query on the next event for that pid. A
        # wrongly-cached miss costs the detection outright, and looks exactly
        # like a working gate declining to fire.
        return event

    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "lookups": total,
            "cache_hits": self._hits,
            "hit_rate": (self._hits / total) if total else 0.0,
            "esf_available": not self._unavailable,
        }
