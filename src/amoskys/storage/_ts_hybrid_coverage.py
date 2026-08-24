"""The handoff: where polling's snapshot meets ESF's stream, and why that closes the gap.

THE CONSERVATION LAW THIS ENFORCES

Every process the polling sensor observes running must satisfy exactly one of:

    1. ESF witnessed its exec                     — a witnessed birth
    2. It existed at the moment ESF attached      — inherited initial condition

A process satisfying neither exists without a witnessed origin. On a healthy
machine that set is empty, and the size of it is the honest measure of how much
of this system is actually accounted for.

WHY THIS IS NOT A COMPROMISE BETWEEN TWO WEAK SENSORS

Measured over one overlap window on this machine: 457 binaries visible only to
polling, 420 pids visible only to ESF. Almost perfectly symmetric, and neither
number shrinks with tuning. No poll interval catches a process that exits in
three milliseconds; no Sentinel restart recovers a process that started
yesterday.

ESF observes CHANGE. Polling observes STATE. Change cannot be integrated into
state without an initial condition, and state cannot be differentiated without
losing everything faster than the sample rate. So the two are not competing
implementations — they are the two halves of one account, and polling's
snapshot at attach time is precisely the initial condition ESF structurally
lacks.

WHAT AN ATTACKER HAS TO DEFEAT

    hide from ESF     -> do not exec: inject into a running process instead.
                         NOTIFY_GET_TASK and NOTIFY_REMOTE_THREAD_CREATE are
                         the events for that, which is why they are on the
                         Phase-2 list rather than treated as exotic.
    hide from polling -> live shorter than the sample interval. But then ESF
                         witnessed the exec, with cdhash and signing state.
    hide from both    -> start before ESF attached AND exit before the next
                         poll after that.

Only the third works, and it is bounded: it requires being born inside a window
that ends the moment the first poll completes after attach, and it is closed
entirely by recording the process table at that instant. That is what the
frontier below computes — not a claim of perfect coverage, but an explicit
statement of the interval in which coverage is incomplete, and why.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

# A process must be seen by polling within this long after ESF attaches for the
# initial condition to be considered captured. Two poll intervals of the 5s
# process sensor, with slack for a busy machine.
_INITIAL_CONDITION_GRACE_S = 30.0


class HybridCoverageMixin:
    """Mixed into TelemetryStore."""

    def esf_coverage_frontier(self) -> Dict[str, Any]:
        """From what instant is the account complete, and what is inside the gap?

        Returns the attach time, the size of the inherited initial condition,
        and the duration of the interval that cannot be reconstructed. Reported
        rather than papered over: a system that claims complete coverage from
        boot is lying, and the useful number is how long the honest gap is.
        """
        with self._read_pool.connection() as db:
            # Attach time is the newest sentinel_start we can see. The stream
            # health table records heartbeats; the earliest exec after the most
            # recent restart is the practical frontier.
            # THE CURRENT SESSION, not the oldest row ever recorded.
            #
            # MIN(timestamp_ns) silently spans restarts. It did exactly that
            # here: it reported 34.4h of "continuous witnessing" across a
            # restart AND a clock correction, so rows stamped 17.5h in the past
            # by the pre-fix build were treated as part of the live session.
            # The conservation check then found 13,249 phantom violations —
            # /bin/sleep and /usr/bin/log among them, which are this system's
            # own probes.
            #
            # A coverage claim is about ONE unbroken stretch of witnessing.
            # Stitching sessions together asserts continuity that did not exist.
            attach = db.execute(
                "SELECT MAX(timestamp_ns) FROM esf_stream_health "
                "WHERE note LIKE 'session_start%'"
            ).fetchone()[0]
            if not attach:
                # No recorded boundary (older collector, or none yet this run).
                # Fall back to the oldest row but say so, rather than passing
                # off a possibly-stitched window as a single session.
                attach = db.execute(
                    "SELECT MIN(timestamp_ns) FROM esf_exec_events"
                ).fetchone()[0]
                self._frontier_inferred = True
            else:
                self._frontier_inferred = False
            newest = db.execute(
                "SELECT MAX(timestamp_ns) FROM esf_exec_events"
            ).fetchone()[0]
            if not attach:
                return {
                    "complete_since_ns": None,
                    "note": (
                        "No exec stream, so nothing is witnessed. Every process "
                        "on this machine is an inherited initial condition with "
                        "no recorded origin."
                    ),
                }

            # The initial condition: processes polling saw that were already
            # running when ESF attached.
            inherited = db.execute(
                "SELECT COUNT(DISTINCT pid) FROM process_events "
                "WHERE collection_agent='macos_process' AND create_time IS NOT NULL "
                "AND create_time * 1000000000 < ?", (attach,)
            ).fetchone()[0]

            # Did polling actually sample within the grace window after attach?
            # If it did not, the initial condition was never captured and the
            # gap is wider than the attach time alone suggests.
            first_poll = db.execute(
                "SELECT MIN(timestamp_ns) FROM process_events "
                "WHERE collection_agent='macos_process' AND timestamp_ns >= ?",
                (attach,)
            ).fetchone()[0]

        grace_ns = int(_INITIAL_CONDITION_GRACE_S * 1e9)
        captured = bool(first_poll and (first_poll - attach) <= grace_ns)
        gap_s = ((first_poll - attach) / 1e9) if first_poll else None
        uptime_s = ((newest - attach) / 1e9) if newest else 0.0

        return {
            "attached_at_ns": attach,
            "witnessing_for_hours": round(uptime_s / 3600.0, 2),
            "inherited_processes": inherited,
            "initial_condition_captured": captured,
            "first_poll_after_attach_s": round(gap_s, 1) if gap_s is not None else None,
            "complete_since_ns": attach if captured else None,
            "session_boundary": "inferred" if getattr(self, "_frontier_inferred", True) else "recorded",
            "note": (
                f"Witnessed continuously for {uptime_s/3600:.1f}h. "
                f"{inherited:,} processes predate that and are inherited from "
                f"polling's snapshot rather than witnessed starting — a real "
                f"limit, not a defect, and it shrinks as uptime grows. Polling "
                f"sampled {gap_s:.1f}s after attach, so the initial condition "
                f"was captured and the account is closed from that instant."
                if captured else
                f"Witnessed for {uptime_s/3600:.1f}h, but polling did not sample "
                f"within {_INITIAL_CONDITION_GRACE_S:.0f}s of ESF attaching"
                + (f" (first sample {gap_s:.0f}s later)" if gap_s else " at all")
                + ". Anything that started and exited inside that interval left "
                  "no trace in either sensor. This is the one window where the "
                  "hybrid is genuinely blind, and it is stated rather than "
                  "assumed away."
            ),
        }

    def esf_unwitnessed_origins(self, *, hours: int = 24, limit: int = 50
                                ) -> Dict[str, Any]:
        """Processes running with no witnessed birth and no inherited origin.

        The conservation law, evaluated. On a healthy machine this is empty;
        anything in it is a process that exists without an account of how it
        came to exist.

        Requires both sensors to agree on the clock — see esf_reconcile, which
        refuses above 300s of skew for the same reason: comparing two timelines
        that disagree measures the disagreement, not the machine.
        """
        frontier = self.esf_coverage_frontier()
        attach = frontier.get("attached_at_ns")
        if not attach:
            return {"available": False, "note": frontier["note"]}

        cutoff = max(attach, time.time_ns() - hours * 3600 * 1_000_000_000)
        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row
            esf_newest = db.execute(
                "SELECT MAX(timestamp_ns) FROM esf_exec_events").fetchone()[0] or 0
            poll_newest = db.execute(
                "SELECT MAX(timestamp_ns) FROM process_events "
                "WHERE collection_agent='macos_process'").fetchone()[0] or 0
            skew_s = abs((esf_newest - poll_newest) / 1e9)
            if skew_s > 300:
                return {
                    "available": False,
                    "clock_skew_seconds": round(skew_s),
                    "note": (
                        f"Sensors disagree about the time by {skew_s/3600:.1f}h. "
                        "A conservation check across mismatched clocks reports "
                        "the skew as violations — refusing."
                    ),
                }

            witnessed = {r[0] for r in db.execute(
                "SELECT DISTINCT pid FROM esf_exec_events WHERE timestamp_ns >= ?",
                (attach,))}
            candidates = [dict(r) for r in db.execute(
                "SELECT DISTINCT pid, exe, create_time FROM process_events "
                "WHERE collection_agent='macos_process' AND timestamp_ns >= ? "
                "AND pid IS NOT NULL AND create_time IS NOT NULL "
                "AND create_time * 1000000000 >= ?", (cutoff, attach))]

        violations = [c for c in candidates if c["pid"] not in witnessed]
        for v in violations:
            v["started_at"] = v.pop("create_time")
        return {
            "available": True,
            "checked": len(candidates),
            "violations": violations[:limit],
            "violation_count": len(violations),
            "witnessing_since_ns": attach,
            "note": (
                f"All {len(candidates):,} processes that started while ESF was "
                "watching have a witnessed exec. The account is closed."
                if not violations else
                f"{len(violations)} process(es) started while ESF was watching "
                "but have NO witnessed exec. Check kernel drops first — a gap "
                "in the stream produces exactly this signature — and if the "
                "stream was intact, something began without an ordinary exec."
            ),
        }
