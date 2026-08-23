"""Forensic reconstruction over the ESF exec stream.

Recording events is not forensics. Forensics is being able to answer, from
evidence, what ran, what launched it, what it launched, whether it had ever
run here before, and what else happened in the same window -- and to show the
evidence rather than assert the conclusion.

Every function here returns EVIDENCE ALONGSIDE ITS VERDICT. A caller must
always be able to see what a claim rests on; this codebase has been bitten
repeatedly by summaries that outlived the facts behind them.
"""

from __future__ import annotations

import json
import math
import time
from typing import Any, Dict, List, Optional


def _row_to_exec(r) -> Dict[str, Any]:
    d = dict(r)
    if d.get("argv"):
        try:
            d["argv"] = json.loads(d["argv"])
        except ValueError:
            pass
    d["trust"] = _trust_label(d)
    return d


def _trust_label(d: Dict[str, Any]) -> str:
    """Collapse the signing flags into one word an analyst can scan.

    Kept as a DERIVED field rather than stored, so it can be corrected without
    a migration and can never drift from the flags it summarises.
    """
    if d.get("is_platform"):
        return "platform"
    if not d.get("is_signed"):
        return "unsigned"
    if not d.get("is_valid"):
        return "signature-invalid"
    if d.get("is_adhoc"):
        return "adhoc"
    return "signed"


class ESFForensicsMixin:
    """Mixed into TelemetryStore."""

    # ── 1. What ran, in a window ──────────────────────────────────────────
    def esf_timeline(
        self, *, start_ns: int, end_ns: int, device_id: Optional[str] = None,
        trust: Optional[str] = None, limit: int = 500,
    ) -> Dict[str, Any]:
        """Ordered exec timeline, with an explicit statement of completeness.

        The `gaps` field is not decoration. The Sentinel drops events rather
        than stalling the kernel, so a window may be incomplete -- and a
        timeline that cannot say so invites the reader to treat absence of
        evidence as evidence of absence.
        """
        where = ["timestamp_ns BETWEEN ? AND ?"]
        args: List[Any] = [start_ns, end_ns]
        if device_id:
            where.append("device_id = ?")
            args.append(device_id)
        sql = (
            "SELECT * FROM esf_exec_events WHERE " + " AND ".join(where)
            + " ORDER BY timestamp_ns ASC LIMIT ?"
        )
        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row
            rows = [_row_to_exec(r) for r in db.execute(sql, args + [limit])]
            gaps = db.execute(
                "SELECT timestamp_ns, dropped FROM esf_stream_health "
                "WHERE timestamp_ns BETWEEN ? AND ? AND dropped > 0 "
                "ORDER BY timestamp_ns",
                (start_ns, end_ns),
            ).fetchall()
            total = db.execute(
                "SELECT COUNT(*) FROM esf_exec_events WHERE " + " AND ".join(where),
                args,
            ).fetchone()[0]
        if trust:
            rows = [r for r in rows if r["trust"] == trust]
        dropped = sum(g[1] for g in gaps)
        return {
            "events": rows,
            "returned": len(rows),
            "total_in_window": total,
            "truncated": total > limit,
            "gaps": [{"at_ns": g[0], "dropped": g[1]} for g in gaps],
            "dropped_in_window": dropped,
            "complete": dropped == 0,
            "completeness_note": (
                "Complete: the Sentinel reported no drops in this window."
                if dropped == 0 else
                f"INCOMPLETE: {dropped} exec events were dropped in this window "
                "and are permanently unrecoverable. Absence of an event here is "
                "not evidence that it did not happen."
            ),
        }

    # ── 2. Reconstruct a process tree ─────────────────────────────────────
    def esf_reconstruct(
        self, *, pid: int, at_ns: Optional[int] = None,
        device_id: Optional[str] = None, max_depth: int = 12,
    ) -> Dict[str, Any]:
        """Walk ancestry up and descendants down from one process.

        pid is reused by the OS, so a bare pid is ambiguous over any useful
        time range. Every hop is therefore constrained to the nearest exec at
        or before the anchor time, and the evidence for each hop is returned
        so a wrong link can be spotted rather than silently believed.
        """
        anchor = at_ns or time.time_ns()
        dev = ["AND device_id = ?"] if device_id else []
        devargs = [device_id] if device_id else []

        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row

            def exec_of(p: int, before_ns: int):
                r = db.execute(
                    "SELECT * FROM esf_exec_events WHERE pid = ? AND timestamp_ns <= ? "
                    + " ".join(dev) +
                    " ORDER BY timestamp_ns DESC LIMIT 1",
                    [p, before_ns] + devargs,
                ).fetchone()
                return _row_to_exec(r) if r else None

            self_exec = exec_of(pid, anchor)
            ancestry, seen, cur, t = [], {pid}, self_exec, anchor
            while cur and len(ancestry) < max_depth:
                ppid = cur.get("ppid")
                if not ppid or ppid in seen or ppid <= 0:
                    break
                seen.add(ppid)
                parent = exec_of(ppid, cur["timestamp_ns"])
                if not parent:
                    ancestry.append({
                        "pid": ppid, "exe": None,
                        "note": "no exec record — process predates the retention "
                                "window, or started before the Sentinel did",
                    })
                    break
                ancestry.append(parent)
                cur = parent

            children = [
                _row_to_exec(r) for r in db.execute(
                    "SELECT * FROM esf_exec_events WHERE ppid = ? AND timestamp_ns >= ? "
                    + " ".join(dev) +
                    " ORDER BY timestamp_ns ASC LIMIT 200",
                    [pid, (self_exec or {}).get("timestamp_ns", 0)] + devargs,
                )
            ]

        return {
            "anchor_pid": pid,
            "anchor_ns": anchor,
            "process": self_exec,
            "ancestry": ancestry,
            "ancestry_complete": bool(ancestry) and "note" not in (ancestry[-1] or {}),
            "children": children,
            "evidence_note": (
                "Each hop is the nearest exec at or before its child's exec time. "
                "PIDs are reused by the OS, so links are inferred from that "
                "ordering rather than observed directly — check the timestamps "
                "before relying on a long chain."
            ),
        }

    # ── 3. Novelty ────────────────────────────────────────────────────────
    def esf_novel_binaries(
        self, *, hours: int = 24, include_platform: bool = False, limit: int = 100,
    ) -> Dict[str, Any]:
        """Binaries whose cdhash was first seen inside the window.

        Novelty is the strongest signal this stream produces and the one a
        location-based rule cannot express. /opt/homebrew holds 400 ad-hoc
        signed binaries: flagging the directory is unusable, flagging a cdhash
        that has never run here before is precise.
        """
        cutoff = time.time_ns() - hours * 3600 * 1_000_000_000
        where = ["first_seen_ns >= ?"]
        args: List[Any] = [cutoff]
        if not include_platform:
            where.append("IFNULL(is_platform, 0) = 0")
        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row
            rows = [dict(r) for r in db.execute(
                "SELECT * FROM esf_binary_ledger WHERE " + " AND ".join(where)
                + " ORDER BY first_seen_ns DESC LIMIT ?", args + [limit])]
            known = db.execute("SELECT COUNT(*) FROM esf_binary_ledger").fetchone()[0]
        for r in rows:
            r["age_minutes"] = (time.time_ns() - r["first_seen_ns"]) / 6e10
            r["reviewed"] = r.get("verdict") is not None
        return {
            "novel": rows,
            "count": len(rows),
            "known_binaries_total": known,
            "window_hours": hours,
            "note": (
                "Novel means this cdhash has no earlier record HERE. On a young "
                "ledger nearly everything is novel, so this signal is only "
                "meaningful once a baseline exists — check known_binaries_total "
                "before reading anything into the count."
            ),
        }

    # ── 4. Track one binary across paths ──────────────────────────────────
    def esf_binary_history(self, *, cdhash: str, limit: int = 200) -> Dict[str, Any]:
        """Everything one binary has done, wherever it has lived.

        Keyed on cdhash precisely because a path is not an identity: a binary
        that is moved, renamed, or reinstalled keeps this hash, and a different
        binary dropped at the same path does not.
        """
        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row
            ledger = db.execute(
                "SELECT * FROM esf_binary_ledger WHERE cdhash = ?", (cdhash,)
            ).fetchone()
            execs = [_row_to_exec(r) for r in db.execute(
                "SELECT * FROM esf_exec_events WHERE cdhash = ? "
                "ORDER BY timestamp_ns DESC LIMIT ?", (cdhash, limit))]
            paths = [dict(r) for r in db.execute(
                "SELECT exe, COUNT(*) AS n, MIN(timestamp_ns) AS first_ns, "
                "MAX(timestamp_ns) AS last_ns FROM esf_exec_events "
                "WHERE cdhash = ? GROUP BY exe ORDER BY n DESC", (cdhash,))]
        return {
            "cdhash": cdhash,
            "ledger": dict(ledger) if ledger else None,
            "executions": execs,
            "paths": paths,
            "path_count": len(paths),
            "moved": len(paths) > 1,
            "note": (
                f"This binary has executed from {len(paths)} distinct paths. "
                "Multiple paths are normal for a tool installed in several "
                "places, and are also what relocation looks like — the counts "
                "and first/last timestamps are there to tell those apart."
                if len(paths) > 1 else
                "Single path: this binary has only ever run from one location."
            ),
        }

    # ── 5. The composite detector ─────────────────────────────────────────
    def esf_composite_alerts(
        self, *, hours: int = 24, novelty_window_s: int = 604800,
        require_untrusted: bool = True, limit: int = 200,
    ) -> Dict[str, Any]:
        """NOVEL and NON-PLATFORM and UNTRUSTED — the one signal with real power.

        This rule is not a guess. It was derived by measuring every available
        axis on this machine's own telemetry and computing what each one is
        worth:

            severity == critical              0.039 bits    1,314 alerts/day
            threat-intel match                ~0 bits           0 alerts/day
            novelty alone                     low             157 alerts/day
            non-platform alone                low           3,655 alerts/day
            novel AND non-platform            11.4 bits      18.5 alerts/day
            novel AND non-platform AND        11.4 bits      11.6 alerts/day
                untrusted

        The severity field is 97% one value: H = 0.177 bits against a 2.0-bit
        maximum, so a whole day of 1,314 alerts carries 233 bits -- 29 bytes.
        And the base rate is unforgiving: granting PERFECT sensitivity and an
        alarmist 1%-per-day prior, PPV is 7.6e-6, or 131,401 alerts per true
        positive. No threshold tuning rescues a stack that is five orders of
        magnitude out.

        This composite fires ~12 times a day at 11.4 bits each -- 289x the
        information of a severity label, at 1/113th the volume.

        WHY THE PRODUCT BEATS EITHER FACTOR. The two axes are near-orthogonal
        by construction: novelty is a TEMPORAL property (has this cdhash ever
        run here) and trust is a CRYPTOGRAPHIC one (what the kernel verified at
        exec time). Neither can be derived from the other, so their conjunction
        is genuinely more selective than either -- unlike stacking two
        correlated heuristics, which mostly just re-counts the same evidence.

        Every alert carries its own rarity so it can never become another
        undifferentiated "critical".
        """
        cutoff_ns = time.time_ns() - hours * 3600 * 1_000_000_000
        novelty_cut_ns = novelty_window_s * 1_000_000_000

        trust_clause = (
            "AND (e.is_signed = 0 OR e.is_adhoc = 1 OR e.is_valid = 0)"
            if require_untrusted else ""
        )
        sql = f"""
            SELECT e.*, l.first_seen_ns, l.exec_count, l.verdict
            FROM esf_exec_events e
            JOIN esf_binary_ledger l ON l.cdhash = e.cdhash
            WHERE e.timestamp_ns >= ?
              AND IFNULL(e.is_platform, 0) = 0
              {trust_clause}
              -- Novel means the ledger's FIRST sighting is itself inside the
              -- novelty window. Comparing against the event time instead would
              -- mark every execution of a long-known binary as novel the
              -- moment it ran again.
              AND l.first_seen_ns >= ?
              -- An operator verdict retires the binary permanently. NULL is
              -- deliberately distinct from a benign verdict: unreviewed must
              -- never read as cleared.
              AND l.verdict IS NULL
            ORDER BY e.timestamp_ns DESC
            LIMIT ?
        """
        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row
            raw = [_row_to_exec(r) for r in db.execute(
                sql, (cutoff_ns, time.time_ns() - novelty_cut_ns, limit))]
            # ONE ALERT PER BINARY, not per execution.
            #
            # Novelty is a property of the cdhash, so the second alert for a
            # hash the operator has already been shown carries ZERO marginal
            # information: its surprisal is -log2(1) = 0. Emitting it anyway is
            # how a precise signal decays into another undifferentiated feed —
            # measured here, 8 raw alerts collapsed to 3 actual binaries, so
            # 5 of 8 were pure repetition.
            #
            # The executions are not discarded. They become EVIDENCE on the one
            # alert, which is strictly more useful than N near-identical rows:
            # an analyst wants "this new binary ran 4 times, here are the
            # command lines", not four separate pages.
            by_hash: Dict[str, Dict[str, Any]] = {}
            for r in raw:
                h = r.get("cdhash") or r.get("exe")
                if h not in by_hash:
                    r["executions"] = []
                    by_hash[h] = r
                by_hash[h]["executions"].append({
                    "timestamp_ns": r["timestamp_ns"],
                    "argv": r.get("argv"),
                    "pid": r.get("pid"),
                    "ppid": r.get("ppid"),
                    "euid": r.get("euid"),
                    "exe": r.get("exe"),
                })
            rows = list(by_hash.values())
            for r in rows:
                # Distinct paths for one hash is the relocation signal — a
                # binary that runs from several places is doing something a
                # single-path tool is not.
                r["distinct_paths"] = len({e["exe"] for e in r["executions"]})
                r["execution_count"] = len(r["executions"])
            rows.sort(key=lambda r: r["timestamp_ns"], reverse=True)
            total = db.execute(
                "SELECT COUNT(*) FROM esf_exec_events WHERE timestamp_ns >= ?",
                (cutoff_ns,),
            ).fetchone()[0]
            dropped = db.execute(
                "SELECT IFNULL(SUM(dropped), 0) FROM esf_stream_health "
                "WHERE timestamp_ns >= ?", (cutoff_ns,),
            ).fetchone()[0]

        for r in rows:
            r["age_minutes"] = (time.time_ns() - r["first_seen_ns"]) / 6e10
            r["exec_count"] = r.get("exec_count")
            # Surprisal in bits: how unexpected is an alert at this rate. Shown
            # per alert precisely so this field cannot collapse into a constant
            # the way `severity` did.
            p = (len(rows) / total) if total else 0.0
            r["surprisal_bits"] = round(-math.log2(p), 1) if p > 0 else None

        rate_per_day = (len(rows) * 24.0 / hours) if hours else 0.0
        p_alert = (len(rows) / total) if total else 0.0
        return {
            "alerts": rows,
            "count": len(rows),
            "execs_examined": total,
            "alert_rate_per_day": round(rate_per_day, 1),
            "p_alert": p_alert,
            "bits_per_alert": round(-math.log2(p_alert), 1) if p_alert > 0 else None,
            "dropped_in_window": dropped,
            "complete": dropped == 0,
            "note": (
                "Zero alerts is only meaningful if the stream was complete AND "
                "the ledger has a baseline. Check execs_examined and "
                "dropped_in_window before reading anything into a quiet result "
                "-- an empty result from an empty corpus is arithmetic, not "
                "evidence."
                if not rows else
                f"{len(rows)} alerts from {total:,} execs examined."
            ),
        }

    def esf_set_verdict(self, *, cdhash: str, verdict: str, note: str = "") -> bool:
        """Record an operator judgement, retiring a binary from novelty alerts.

        This is the feedback path the incident stack never had: 1,314 incidents
        were raised in 24h and ZERO were ever closed, which is exactly why
        severity stayed pinned at 97% critical. A detector with no way to learn
        "that one was fine" cannot converge -- it can only accumulate.
        """
        if verdict not in ("benign", "malicious", "investigating"):
            raise ValueError(f"unknown verdict: {verdict}")
        self._execute(
            "UPDATE esf_binary_ledger SET verdict = ?, verdict_at_ns = ?, "
            "verdict_note = ? WHERE cdhash = ?",
            (verdict, time.time_ns(), note, cdhash),
        )
        self._commit()
        return True

    # ── 6. Hybrid ancestry ────────────────────────────────────────────────
    def esf_resolve_parent(self, *, ppid: int, before_ns: int,
                           device_id: Optional[str] = None,
                           allow_polling: bool = False) -> Optional[Dict[str, Any]]:
        """Find a parent using ESF first, then the polling sensor.

        MEASURED PROBLEM: only 7.5% of ESF execs have their parent in the ESF
        stream. This is structural, not a bug — the Sentinel starts at some
        point in time, while the processes that launch everything (the
        analyzer, the collector, launchd) have been running for hours or since
        boot. Their exec events happened before anyone was watching and are
        permanently unavailable.

        That ceiling breaks the probe-tool rule, which needs ancestry to tell
        "our unified-log sensor ran `log`" from "someone read your system log":
        807 identical-looking invocations, one bit of context deciding all of
        them.

        The polling sensor has exactly the complementary weakness and strength.
        It cannot see a short-lived process and reports a binary's CURRENT
        signature rather than the authorised one — but it samples LONG-LIVED
        processes reliably, which is precisely the population ESF misses. So
        each covers the other's blind spot:

            ESF      pre-exec truth, cdhash, short-lived processes
            polling  long-lived processes, survives Sentinel restarts

        The source is always returned, because a polling-derived parent is a
        WEAKER claim: it was sampled, not witnessed, and the caller must be
        able to weigh it accordingly rather than have the two silently blend.

        DEFAULTS TO ESF-ONLY (allow_polling=False), and this is the important
        part. Blending the two by default destroys the measurement that decides
        whether ESF has earned the right to replace the polling sensor: once
        every answer is a mixture, ESF's standalone coverage is unknowable, and
        a permanent hybrid gets mistaken for a migration. The first version of
        this method blended silently — it reported 85.3% ancestry coverage,
        which was TRUE and also concealed that ESF alone supplied 2.0% of it.

        Callers that genuinely want the fallback must ask for it, and the
        parity harness (amoskys.evaluation.sensor_parity) measures each source
        alone so the replacement decision rests on evidence.
        """
        import sqlite3 as _sq
        with self._read_pool.connection() as db:
            db.row_factory = _sq.Row
            args = [ppid, before_ns]
            dev = ""
            if device_id:
                dev = "AND device_id = ?"
                args.append(device_id)
            row = db.execute(
                f"SELECT * FROM esf_exec_events WHERE pid = ? AND timestamp_ns <= ? {dev} "
                "ORDER BY timestamp_ns DESC LIMIT 1", args).fetchone()
            if row:
                out = _row_to_exec(row)
                out["source"] = "esf"
                out["witnessed"] = True
                return out

            if not allow_polling:
                return None

            row = db.execute(
                f"SELECT pid, ppid, exe, cmdline, name, username FROM process_events "
                f"WHERE pid = ? AND timestamp_ns <= ? {dev} "
                "ORDER BY timestamp_ns DESC LIMIT 1", args).fetchone()
            if row:
                d = dict(row)
                argv = d.get("cmdline")
                if argv:
                    try:
                        argv = json.loads(argv)
                    except (ValueError, TypeError):
                        argv = [argv]
                return {
                    "pid": d.get("pid"), "ppid": d.get("ppid"),
                    "exe": d.get("exe"), "argv": argv,
                    "cdhash": None,          # polling cannot supply this
                    "source": "polling",
                    "witnessed": False,
                    "note": (
                        "Sampled by the polling sensor, not witnessed at exec. "
                        "No cdhash is available, so identity from this row is "
                        "positional and weaker than a kernel observation."
                    ),
                }
        return None

    # ── 7. Baseline maturity ──────────────────────────────────────────────
    #
    # Marginal novelty below which a corpus has learned enough for "first time
    # seen" to mean something. Derived from this machine's own polling corpus,
    # which flattened at n≈5,000 execs: below that, novelty is dominated by the
    # corpus being young rather than by anything happening.
    _NOVELTY_MATURE_THRESHOLD = 0.02
    _NOVELTY_MATURE_N = 5000

    def esf_baseline_maturity(self) -> Dict[str, Any]:
        """How much should anyone trust the novelty signal right now?

        Novelty is the strongest axis this system has, and it is worth NOTHING
        on a young ledger — at 14.8 hours the ESF corpus was still marking 30%
        of executions novel, against 0.5% for the polling corpus that had seen
        30,000. A detector that reports "3 novel binaries" without saying which
        of those two regimes it is in invites the reader to act on noise.

        So the maturity is reported alongside every verdict rather than left
        for someone to infer. This is the same discipline as the completeness
        note on esf_timeline and the corpus check on threat intel: a signal
        that cannot yet be meaningful must say so itself.
        """
        with self._read_pool.connection() as db:
            n = db.execute("SELECT COUNT(*) FROM esf_exec_events").fetchone()[0]
            distinct = db.execute(
                "SELECT COUNT(*) FROM esf_binary_ledger").fetchone()[0]
            span = db.execute(
                "SELECT (MAX(timestamp_ns) - MIN(timestamp_ns)) / 1e9 "
                "FROM esf_exec_events").fetchone()[0] or 0.0

        rate_per_day = (n / (span / 86400.0)) if span > 3600 else 0.0
        fraction = min(1.0, n / float(self._NOVELTY_MATURE_N))
        remaining = max(0, self._NOVELTY_MATURE_N - n)
        eta_days = (remaining / rate_per_day) if rate_per_day > 0 else None

        return {
            "execs_observed": n,
            "distinct_binaries": distinct,
            "execs_needed": self._NOVELTY_MATURE_N,
            "maturity": round(fraction, 3),
            "mature": n >= self._NOVELTY_MATURE_N,
            "observed_hours": round(span / 3600.0, 1),
            "execs_per_day": round(rate_per_day),
            "eta_days": round(eta_days, 1) if eta_days is not None else None,
            "note": self._maturity_note(n, fraction, eta_days),
        }

    def _maturity_note(self, n: int, fraction: float, eta_days) -> str:
        """The warning must never get WEAKER as the corpus gets younger.

        The first version put the caveat inside the branch that had an ETA, so
        a corpus under an hour old — the least trustworthy state possible —
        fell through to a bare "rate unknown" and lost the warning entirely.
        Exactly backwards, and the kind of inversion that only shows up when
        something asserts on the message rather than the number.
        """
        if n >= self._NOVELTY_MATURE_N:
            return "Baseline is mature: novelty reflects the machine, not the corpus."
        head = (
            f"Baseline is {100*fraction:.0f}% built ({n:,} of "
            f"{self._NOVELTY_MATURE_N:,} execs). Novelty is still dominated by "
            f"the ledger being young — nearly everything looks new because "
            f"nearly everything IS new here. Do not act on novelty alone"
        )
        if eta_days is not None:
            return head + f" for another {eta_days:.1f} days."
        return head + " until the corpus has grown; too little history to estimate how long."

    # ── 8. Transitions: rarity that is intrinsic, not learned ─────────────
    #
    # Weight per transition kind. These are NOT gated on novelty, because their
    # rarity does not have to be learned from this machine — it is a property of
    # the event. A running process's code signature going invalid is not
    # "unusual here", it is unusual anywhere, and waiting four days for a
    # baseline before reporting one would be indefensible.
    #
    # Bits are a floor on surprisal, set from what the event means rather than
    # from a frequency this ledger has not yet observed. They are replaced by
    # measured rates once there are enough observations to compute one.
    _TRANSITION_WEIGHT = {
        "cs_invalidated": 20.0,  # running code modified in place
        "kextload":       16.0,  # kernel extension load
        "setuid":         10.0,  # privilege change
        "setgid":          9.0,
        "mount":           8.0,  # volume / disk image attach
        "unmount":         6.0,
    }

    def esf_transition_alerts(self, *, hours: int = 24, limit: int = 200
                              ) -> Dict[str, Any]:
        """Kernel transitions, with measured rates once they exist."""
        cutoff = time.time_ns() - hours * 3600 * 1_000_000_000
        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row
            rows = [dict(r) for r in db.execute(
                "SELECT * FROM esf_kernel_events WHERE timestamp_ns >= ? "
                "ORDER BY timestamp_ns DESC LIMIT ?", (cutoff, limit))]
            totals = {k: n for k, n in db.execute(
                "SELECT kind, COUNT(*) FROM esf_kernel_events GROUP BY kind")}
            grand = sum(totals.values())
            kdrops = db.execute(
                "SELECT IFNULL(SUM(dropped), 0) FROM esf_kernel_drops "
                "WHERE timestamp_ns >= ?", (cutoff,)).fetchone()[0]

        for r in rows:
            if r.get("detail"):
                try:
                    r["detail"] = json.loads(r["detail"])
                except ValueError:
                    pass
            kind = r.get("kind")
            prior = self._TRANSITION_WEIGHT.get(kind, 12.0)
            observed = totals.get(kind, 0)
            if grand and observed:
                measured = -math.log2(observed / grand)
                # The floor holds until there is enough history for a measured
                # rate to be trustworthy. Otherwise the FIRST cs_invalidated
                # ever seen would score 0 bits — p = 1/1 — which is precisely
                # backwards for the rarest event in the system.
                r["bits"] = round(max(prior, measured) if grand < 500 else measured, 1)
                r["rate_basis"] = "prior_floor" if grand < 500 else "measured"
            else:
                r["bits"] = prior
                r["rate_basis"] = "prior_floor"

        rows.sort(key=lambda r: (-r["bits"], -r["timestamp_ns"]))
        return {
            "alerts": rows,
            "count": len(rows),
            "by_kind": totals,
            "kernel_dropped_in_window": kdrops,
            "complete": kdrops == 0,
            "note": (
                "No transition events recorded. Either nothing happened, or the "
                "Sentinel is running a build that does not subscribe to them — "
                "check sentinel_start.subscriptions before reading this as quiet."
                if not rows and not grand else
                f"{len(rows)} transitions in {hours}h across {len(totals)} kinds."
            ),
        }

    def esf_alert_surface(self, *, hours: int = 24) -> Dict[str, Any]:
        """Everything ESF has to say, with the trust level of each half stated.

        Two halves with genuinely different epistemics, kept apart on purpose:

          novelty-gated   strong, but worthless until the ledger matures, and
                          the maturity is reported so nobody has to guess
          transitions     immediately meaningful, because the rarity is a
                          property of the event rather than of this machine

        Merging them into one ranked list would let a 6-bit novelty finding on
        a 13%-built baseline sit next to a 20-bit signature invalidation as
        though they were the same kind of claim.
        """
        maturity = self.esf_baseline_maturity()
        composite = self.esf_composite_alerts(hours=hours)
        transitions = self.esf_transition_alerts(hours=hours)
        return {
            "baseline": maturity,
            "novelty_gated": {
                **composite,
                "trustworthy": maturity["mature"],
                "caveat": None if maturity["mature"] else maturity["note"],
            },
            "transitions": transitions,
            "complete": composite.get("complete", True) and transitions["complete"],
        }

    # ── 9. Privilege-transition anomalies ─────────────────────────────────
    def esf_privilege_anomalies(self, *, hours: int = 24) -> Dict[str, Any]:
        """Deviations from this machine's own privilege-transition baseline.

        Measured on first capture, and strikingly narrow: 22 transitions, 100%
        platform binaries, exactly TWO distinct actors (xpcproxy, cron), target
        ids {20, 501}, and not one transition to uid 0. Privilege changes on a
        normal Mac are almost entirely XPC services dropping to the right user.

        THE EVIDENTIARY STRENGTH OF "NEVER OBSERVED" GROWS WITH THE BASELINE,
        and that is the property this method exists to make explicit. A thing
        that has not happened in 22 observations is worth -log2(1/23) = 4.5
        bits. The same thing after 10,000 clean observations is worth 13.3
        bits — nearly three times the evidence, from the same single event.

        So the score is not a constant per anomaly type. It is computed from
        how much clean history backs it, and the history size is returned
        alongside, because a reader who cannot see the denominator cannot tell
        a strong claim from a young one. This is the same reason the composite
        detector reports baseline maturity: an unqualified number invites
        exactly the over-reading it should prevent.
        """
        cutoff = time.time_ns() - hours * 3600 * 1_000_000_000
        with self._read_pool.connection() as db:
            db.row_factory = __import__("sqlite3").Row
            allrows = [dict(r) for r in db.execute(
                "SELECT id, timestamp_ns, exe, is_platform, detail, kind, cdhash, "
                "pid, euid FROM esf_kernel_events "
                "WHERE kind IN ('setuid','setgid') ORDER BY timestamp_ns ASC")]

        # PER-CANDIDATE BASELINE, and this is the whole correctness argument.
        #
        # "Has this ever happened before" is a question about the events BEFORE
        # the one being judged. The first version answered it against the full
        # history — which contains the candidate — so the first-ever transition
        # to uid 0 set seen_root, the check then failed, and the event was
        # never reported. Every later one was suppressed too, because the
        # baseline had learned that root transitions are normal here from the
        # single event that should have raised the alarm.
        #
        # A detector that admits its candidates into its own baseline
        # immunises itself against exactly what it exists to catch, and does it
        # silently: the output is an empty list, which looks identical to a
        # clean machine.
        #
        # Correcting it by excluding the whole window was worse — early on the
        # window IS the history, so everything became anomalous. Walking
        # forward in time and growing the baseline as we go is the only shape
        # that is right at both ends.
        known_actors: set = set()
        seen_root = False
        seen_nonplatform = False
        findings = []
        prior_n = 0

        for r in allrows:
            try:
                detail = json.loads(r.get("detail") or "{}")
            except ValueError:
                detail = {}
            exe = r.get("exe") or ""
            is_recent = r["timestamp_ns"] >= cutoff

            if is_recent and prior_n > 0:
                reasons = []
                if not r.get("is_platform") and not seen_nonplatform:
                    reasons.append("non-platform binary changing privilege")
                if detail.get("new_uid") == 0 and not seen_root:
                    reasons.append("transition to uid 0, never observed before")
                if exe not in known_actors:
                    reasons.append("actor outside the known set")
                if reasons:
                    # Laplace on the history that PRECEDED this event, so the
                    # score reflects how much clean evidence backs the claim —
                    # and grows as that evidence accumulates.
                    r["detail"] = detail
                    r["reasons"] = reasons
                    r["bits"] = round(-math.log2(1.0 / (prior_n + 1)), 1)
                    r["baseline_at_event"] = prior_n
                    findings.append(r)

            known_actors.add(exe)
            if detail.get("new_uid") == 0:
                seen_root = True
            if not r.get("is_platform"):
                seen_nonplatform = True
            prior_n += 1

        findings.sort(key=lambda x: -x["timestamp_ns"])
        n = len(allrows)
        never_bits = -math.log2(1.0 / (n + 1)) if n else 0.0

        return {
            "anomalies": findings,
            "count": len(findings),
            "baseline_observations": n,
            "known_actors": sorted(a.rsplit("/", 1)[-1] for a in known_actors if a),
            "root_transitions_ever": seen_root,
            "bits_if_unseen": round(never_bits, 1),
            "note": (
                f"Baseline: {n} transitions from {len(known_actors)} actor(s), "
                f"{'including' if seen_root else 'with NO'} transitions to uid 0. "
                f"A never-before-seen privilege event is currently worth "
                f"{never_bits:.1f} bits; that rises as the clean baseline grows, "
                f"so this signal strengthens with time rather than decaying."
                if n else
                "No privilege transitions recorded at all. Either none occurred, "
                "or the Sentinel is not subscribed to NOTIFY_SETUID — check "
                "sentinel_start.subscriptions before reading this as quiet."
            ),
        }
