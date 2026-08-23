"""Head-to-head: does the kernel sensor actually beat the polling sensor?

AMOSKYS now has two ways to know a process ran, and they are NOT
interchangeable:

    ESF      witnessed at exec, pre-execution, carries the cdhash and the
             code-signing state the KERNEL used to authorise it. Cannot miss a
             short-lived process. Blind to anything that ran before it started.

    polling  samples /proc-equivalent state on an interval. Structurally
             cannot see a process that begins and ends between samples, and
             reads a binary's CURRENT signature rather than the authorised one.
             But it observes long-lived processes reliably and survives its own
             restarts, because state persists where events do not.

THE RULE THIS MODULE EXISTS TO ENFORCE: measure them SEPARATELY, and retire a
polling sensor only when the kernel sensor has demonstrably beaten it on the
same question, over the same window, on this machine.

The temptation is to blend them — take ESF where available, fall back to
polling, report the combined coverage and feel good. That number is true and
useless: it hides which source did the work, it makes a permanent hybrid look
like a completed migration, and it means the day ESF regresses, the fallback
quietly absorbs the loss and nothing looks wrong. An earlier version of the
ancestry resolver did exactly this and reported 85.3% coverage while ESF alone
supplied 2.0% of it.

Comparison is restricted to the OVERLAP WINDOW — the period during which both
sensors were actually running. Comparing a 1.7-hour kernel stream against a
24-hour polling history is not a fair fight in either direction, and the
resulting ratio says more about uptime than capability.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional


class SensorParity:
    """Compare the ESF exec stream against the polling process sensor."""

    def __init__(self, store):
        self.store = store

    # ── window ────────────────────────────────────────────────────────────
    def overlap_window(self) -> Optional[Dict[str, int]]:
        """The period during which BOTH sensors were producing.

        Returns None when they never overlapped, rather than silently
        comparing disjoint periods and reporting the difference as capability.
        """
        with self.store._read_pool.connection() as db:
            esf = db.execute(
                "SELECT MIN(timestamp_ns), MAX(timestamp_ns) FROM esf_exec_events"
            ).fetchone()
            poll = db.execute(
                "SELECT MIN(timestamp_ns), MAX(timestamp_ns) FROM process_events "
                "WHERE collection_agent = 'macos_process'"
            ).fetchone()
        if not esf or not esf[0] or not poll or not poll[0]:
            return None
        start, end = max(esf[0], poll[0]), min(esf[1], poll[1])
        if end <= start:
            return None
        return {"start_ns": start, "end_ns": end,
                "duration_s": (end - start) / 1e9}

    # ── the comparison ────────────────────────────────────────────────────
    def compare(self) -> Dict[str, Any]:
        win = self.overlap_window()
        if not win:
            return {
                "verdict": "no_overlap",
                "note": (
                    "The two sensors have no common window, so no comparison "
                    "is possible. This is the honest answer — comparing "
                    "disjoint periods measures uptime, not capability."
                ),
            }
        s, e = win["start_ns"], win["end_ns"]
        with self.store._read_pool.connection() as db:
            esf_n = db.execute(
                "SELECT COUNT(*) FROM esf_exec_events WHERE timestamp_ns BETWEEN ? AND ?",
                (s, e)).fetchone()[0]
            esf_bins = {r[0] for r in db.execute(
                "SELECT DISTINCT exe FROM esf_exec_events "
                "WHERE timestamp_ns BETWEEN ? AND ? AND exe IS NOT NULL", (s, e))}
            poll_n = db.execute(
                "SELECT COUNT(*) FROM process_events WHERE timestamp_ns BETWEEN ? AND ? "
                "AND collection_agent = 'macos_process'", (s, e)).fetchone()[0]
            # FAIRNESS CORRECTION. A process that STARTED before the Sentinel
            # did can never appear in an exec stream — ESF witnesses the exec
            # itself, so anything already running when it attached is
            # permanently invisible to it. Counting those against ESF measures
            # its uptime, not its capability, and would understate it forever.
            #
            # process_events.create_time is a UNIX float. Only processes that
            # started INSIDE the overlap window are comparable; long-lived apps
            # are reported separately as `polling_only_prestart`, because they
            # are a real coverage difference that a replacement decision must
            # account for — just not a capability one.
            poll_bins = {r[0] for r in db.execute(
                "SELECT DISTINCT exe FROM process_events "
                "WHERE timestamp_ns BETWEEN ? AND ? AND collection_agent='macos_process' "
                "AND exe IS NOT NULL "
                "AND create_time IS NOT NULL AND create_time * 1000000000 >= ?",
                (s, e, s))}
            poll_prestart = {r[0] for r in db.execute(
                "SELECT DISTINCT exe FROM process_events "
                "WHERE timestamp_ns BETWEEN ? AND ? AND collection_agent='macos_process' "
                "AND exe IS NOT NULL "
                "AND (create_time IS NULL OR create_time * 1000000000 < ?)",
                (s, e, s))}
            esf_cdhash = db.execute(
                "SELECT COUNT(*) FROM esf_exec_events "
                "WHERE timestamp_ns BETWEEN ? AND ? AND cdhash IS NOT NULL", (s, e)
            ).fetchone()[0]
            # Re-reporting: polling re-emits a long-lived process every sample.
            poll_pids = db.execute(
                "SELECT COUNT(*), COUNT(DISTINCT pid) FROM process_events "
                "WHERE timestamp_ns BETWEEN ? AND ? AND collection_agent='macos_process'",
                (s, e)).fetchone()
            dropped = db.execute(
                "SELECT IFNULL(SUM(dropped),0) FROM esf_stream_health "
                "WHERE timestamp_ns BETWEEN ? AND ?", (s, e)).fetchone()[0]

        only_esf = sorted(esf_bins - poll_bins)
        only_poll = sorted(poll_bins - esf_bins)
        both = esf_bins & poll_bins

        return {
            "window": win,
            "esf": {
                "events": esf_n,
                "distinct_binaries": len(esf_bins),
                "with_cdhash": esf_cdhash,
                "cdhash_coverage": (esf_cdhash / esf_n) if esf_n else 0.0,
                "dropped": dropped,
                "complete": dropped == 0,
            },
            "polling": {
                "events": poll_n,
                "distinct_binaries": len(poll_bins),
                "with_cdhash": 0,
                "cdhash_coverage": 0.0,
                "distinct_pids": poll_pids[1],
                "re_report_ratio": (
                    (poll_pids[0] / poll_pids[1]) if poll_pids[1] else 0.0),
            },
            "only_esf_saw": only_esf[:40],
            "only_esf_count": len(only_esf),
            "only_polling_saw": only_poll[:40],
            "only_polling_count": len(only_poll),
            "both_saw": len(both),
            "polling_only_prestart": len(poll_prestart - esf_bins),
            "fairness_note": (
                "Binaries whose process started BEFORE the overlap window are "
                "excluded from the head-to-head: ESF witnesses execs, so it "
                "cannot see something already running when it attached. They "
                "are counted separately as polling_only_prestart — a real "
                "coverage difference, but one about uptime rather than "
                "capability, and one a restart of the Sentinel does not fix."
            ),
            "verdict": self._verdict(esf_n, poll_n, len(only_esf), len(only_poll),
                                     dropped, win["duration_s"]),
        }

    def _verdict(self, esf_n, poll_n, only_esf, only_poll, dropped, duration_s):
        """State plainly whether ESF has earned a replacement — and refuse to
        say yes on a short window.

        A sensor that looks better for two hours has proven nothing about a
        Tuesday afternoon build, a reboot, or a week of ordinary drift. The
        minimum is deliberately conservative: this decision retires a working
        sensor, and the cost of being wrong is a blind spot nobody is looking
        for.
        """
        MIN_HOURS = 168.0  # one full week
        hours = duration_s / 3600.0
        if hours < MIN_HOURS:
            return {
                "decision": "insufficient_evidence",
                "reason": (
                    f"Overlap is {hours:.1f}h; {MIN_HOURS:.0f}h (one week) is "
                    "the minimum. Retiring a working sensor on a short window "
                    "trades a known cost for an unknown blind spot."
                ),
                "hours_observed": round(hours, 2),
                "hours_required": MIN_HOURS,
            }
        if dropped > 0:
            return {
                "decision": "esf_not_ready",
                "reason": (
                    f"ESF dropped {dropped} events in the window. A sensor that "
                    "loses evidence under load cannot replace one that does not."
                ),
            }
        if only_poll > only_esf:
            return {
                "decision": "keep_polling",
                "reason": (
                    f"Polling saw {only_poll} binaries ESF did not, against "
                    f"{only_esf} the other way. ESF has not covered it yet."
                ),
            }
        return {
            "decision": "esf_supersedes",
            "reason": (
                f"Over {hours:.0f}h with zero drops, ESF saw {only_esf} binaries "
                f"polling missed against {only_poll} the other way, and supplies "
                "cdhash and authorised signing state that polling structurally "
                "cannot. The polling exec sensor can be retired."
            ),
        }


def render(report: Dict[str, Any]) -> str:
    if report.get("verdict") == "no_overlap":
        return "  " + report["note"]
    w, e, p = report["window"], report["esf"], report["polling"]
    v = report["verdict"]
    out = []
    out.append(f"  overlap window : {w['duration_s']/3600:.2f} h\n")
    out.append(f"  {'':<22}{'ESF (witnessed)':>18}{'polling (sampled)':>20}")
    out.append(f"  {'events':<22}{e['events']:>18,}{p['events']:>20,}")
    out.append(f"  {'distinct binaries':<22}{e['distinct_binaries']:>18,}{p['distinct_binaries']:>20,}")
    out.append(f"  {'cdhash coverage':<22}{e['cdhash_coverage']:>17.1%}{p['cdhash_coverage']:>20.1%}")
    out.append(f"  {'events dropped':<22}{e['dropped']:>18,}{'n/a':>20}")
    out.append(f"  {'re-reports per pid':<22}{'1.0':>18}{p['re_report_ratio']:>20.1f}")
    out.append(f"\n  seen ONLY by ESF     : {report['only_esf_count']}")
    for b in report["only_esf_saw"][:8]:
        out.append(f"      {b}")
    out.append(f"  seen ONLY by polling : {report['only_polling_count']}")
    for b in report["only_polling_saw"][:8]:
        out.append(f"      {b}")
    out.append(f"  seen by both         : {report['both_saw']}")
    out.append(f"  polling-only, PRE-START (excluded from the comparison): "
               f"{report['polling_only_prestart']}")
    out.append(f"    {report['fairness_note'][:150]}")
    out.append(f"\n  DECISION: {v['decision'].upper()}")
    out.append(f"    {v['reason']}")
    return "\n".join(out)
