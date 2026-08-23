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
