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
                    "WHERE pid = ? AND ABS(timestamp_ns - ?) <= ? "
                    "ORDER BY ABS(timestamp_ns - ?) LIMIT 1",
                    (pid, ts_ns, _MATCH_WINDOW_NS, ts_ns),
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
        pid = event.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return event
        ts = event.get("timestamp_ns")
        if not isinstance(ts, int):
            ts = time.time_ns()

        now = time.time()
        cached = self._cache.get(pid)
        if cached and (now - cached[1]) < _CACHE_TTL_S:
            self._hits += 1
            if cached[0]:
                event.update(cached[0])
            return event

        self._misses += 1
        found = self._lookup(pid, ts)
        if len(self._cache) >= _CACHE_MAX:
            self._cache.clear()
        self._cache[pid] = (found, now)
        if found:
            event.update(found)
        return event

    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "lookups": total,
            "cache_hits": self._hits,
            "hit_rate": (self._hits / total) if total else 0.0,
            "esf_available": not self._unavailable,
        }
