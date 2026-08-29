"""The kernel's own record, surfaced — and the difference between witnessed and sampled.

AMOSKYS's claim is that you cannot hide from it. That claim is only honest if
the interface can answer three questions, and until now it could answer none of
them:

  **Was it watching?**  The Sentinel drops events rather than stalling the
  kernel, and records every drop on a 30-second heartbeat. A gap in the exec
  timeline is therefore knowable, and a product that does not show it is asking
  the reader to treat absence of evidence as evidence of absence.

  **Did it witness this, or merely sample it?**  ``process_events`` comes from a
  polling sensor: it cannot see a process that starts and exits between samples,
  and it reads the binary's signature as it is NOW. ``esf_exec_events`` is the
  kernel's report of the exec itself, carrying the signing state the kernel used
  to authorise it. Those are different grades of evidence and the UI must say
  which one it is showing.

  **Is this thing new here?**  ``esf_binary_ledger`` keys on cdhash, so a binary
  that is moved, renamed or reinstalled stays one binary. A cdhash that has
  never run on this machine before is the strongest signal the stream produces,
  and it is the one a path-based rule cannot express.

The ledger's ``verdict`` column was built with NULL meaning "nobody has judged
this yet", deliberately distinct from "judged benign". That is exactly the
distinction the ledger's *That's me / Not me* buttons exist to close, so this
module also writes it.

Tier note: these tables live in the agent's telemetry store. On a presentation
server that store is a synced fleet cache which may not carry them at all —
reported as ``missing``, never as quiet.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger(__name__)

NS = 1_000_000_000

# The Sentinel heartbeats every 30s; two missed beats is a stopped stream.
HEARTBEAT_STALE_SECONDS = 90

# Least trustworthy first — this decides what a person is asked about first.
# "unknown" sits above "unsigned" deliberately: we are not entitled to alarm
# someone about a signature we simply failed to read.
TRUST_ORDER = {
    "signature-invalid": 0,
    "unsigned": 1,
    "adhoc": 2,
    "unknown": 3,
    "signed": 4,
    "platform": 5,
}


def _candidate_paths() -> list[str]:
    root = Path(__file__).resolve().parents[3]
    return [
        p
        for p in (
            os.getenv("AMOSKYS_TELEMETRY_DB", ""),
            str(root / "data" / "telemetry.db"),
            "/opt/amoskys/data/telemetry.db",
            os.getenv("AMOSKYS_FLEET_CACHE", ""),
            str(root / "data" / "fleet_cache.db"),
        )
        if p
    ]


def _open() -> sqlite3.Connection | None:
    """First reachable store that actually carries the exec stream."""
    for path in _candidate_paths():
        if not Path(path).exists():
            continue
        try:
            db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
            db.row_factory = sqlite3.Row
            has = db.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                "AND name='esf_exec_events'"
            ).fetchone()[0]
            if has:
                return db
            db.close()
        except sqlite3.Error:
            continue
    return None


def _writable() -> sqlite3.Connection | None:
    """Read-write handle, for the one thing we write: an operator verdict."""
    for path in _candidate_paths():
        if not Path(path).exists():
            continue
        try:
            db = sqlite3.connect(path, timeout=5.0)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=5000")
            has = db.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                "AND name='esf_binary_ledger'"
            ).fetchone()[0]
            if has:
                return db
            db.close()
        except sqlite3.Error:
            continue
    return None


def _trust(row: dict) -> str:
    """Collapse the kernel's signing flags into one word.

    IMPORTANT: this must be fed the flags from an EXEC EVENT, not from the
    binary ledger. The ledger summarises a binary and carries only
    is_platform/is_adhoc — reading it as if it carried is_signed labels every
    signed application "unsigned". Measured live, that mislabelled Claude,
    Chrome's helper and Homebrew's Python, which is precisely the confidently
    wrong claim this product exists to stop making.

    Where the flags are genuinely absent the answer is "unknown", never
    "unsigned": not knowing and knowing-it-is-bad are different statements.
    """
    if row.get("is_platform"):
        return "platform"
    if row.get("is_signed") is None:
        return "unknown"
    if not row.get("is_signed"):
        return "unsigned"
    if row.get("is_valid") is not None and not row.get("is_valid"):
        return "signature-invalid"
    if row.get("is_adhoc"):
        return "adhoc"
    return "signed"


def stream_health(window_hours: int = 24) -> dict:
    """Is the kernel actually watching, and did the record survive intact?"""
    absent = {
        "present": False,
        "watching": False,
        "status": "missing",
        "headline": "The kernel witness is not reaching this view",
        "detail": (
            "This tier has no exec stream from the Sentinel. Everything here "
            "comes from the polling sensor, which cannot see a process that "
            "starts and exits between samples."
        ),
        "events_24h": 0,
        "dropped": 0,
        "kernel_dropped": 0,
        "enforce_mode": None,
        "last_beat_age_seconds": None,
    }
    db = _open()
    if db is None:
        return absent
    try:
        now_ns = time.time_ns()
        cutoff = now_ns - window_hours * 3600 * NS
        events = db.execute(
            "SELECT COUNT(*) FROM esf_exec_events WHERE timestamp_ns >= ?", (cutoff,)
        ).fetchone()[0]
        beat = db.execute(
            "SELECT timestamp_ns, dropped, enforce_mode FROM esf_stream_health "
            "ORDER BY timestamp_ns DESC LIMIT 1"
        ).fetchone()
        dropped = (
            db.execute(
                "SELECT IFNULL(SUM(dropped), 0) FROM esf_stream_health "
                "WHERE timestamp_ns >= ?",
                (cutoff,),
            ).fetchone()[0]
            or 0
        )
        # KERNEL-SIDE LOSS, read here because `db` is closed in the finally
        # below. The first version of this ran after the close, raised
        # ProgrammingError — a subclass of sqlite3.Error — and was silently
        # swallowed by its own defensive except, reporting zero kernel drops
        # forever. A broad exception handler written to survive an old schema
        # ended up hiding a placement bug instead, which is the more common way
        # that kind of handler earns its keep in reverse.
        # Probe for the table before trusting a zero from it. A store at
        # migration 015 without 016 has esf_exec_events but no esf_kernel_drops,
        # so the query fails and any fallback value is a guess. Returning 0
        # there made "this tier cannot answer" byte-identical to "the kernel
        # dropped nothing" — and the second reading is the one that prints
        # "this timeline is complete". None is the third state that keeps them
        # apart, exactly as coverage.py::_blindness() does for its own ledger.
        #
        # OperationalError is also NOT only "no such table": a locked database
        # or a corrupt page raises it too, and those must not be absorbed into
        # a reassuring number either. The probe distinguishes them — absent
        # table means unmeasured, anything else means the read genuinely broke.
        kernel_dropped = None
        has_drop_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='esf_kernel_drops'"
        ).fetchone()
        if has_drop_table:
            try:
                kernel_dropped = int(
                    db.execute(
                        "SELECT IFNULL(SUM(dropped), 0) FROM esf_kernel_drops "
                        "WHERE timestamp_ns >= ?",
                        (cutoff,),
                    ).fetchone()[0]
                    or 0
                )
            except sqlite3.OperationalError:
                logger.warning("kernel drop read failed", exc_info=True)
                kernel_dropped = None
    except sqlite3.Error:
        return absent
    finally:
        db.close()

    beat_age = None
    enforce = None
    if beat and beat["timestamp_ns"]:
        beat_age = max(0, int((now_ns - beat["timestamp_ns"]) / NS))
        enforce = bool(beat["enforce_mode"])

    if beat_age is None and events == 0:
        return {
            **absent,
            "present": True,
            "status": "idle",
            "headline": "The kernel witness is installed but has not reported",
            "detail": (
                "The exec stream exists on this tier and is empty. The Sentinel "
                "needs root and is started separately — until it runs, nothing "
                "here is kernel-witnessed."
            ),
        }

    watching = beat_age is not None and beat_age <= HEARTBEAT_STALE_SECONDS
    if watching and dropped == 0:
        status = "witnessing"
        headline = "The kernel is witnessing every execution"
        detail = (
            f"{events:,} executions recorded in the last {window_hours}h with no "
            "dropped events — this timeline is complete."
        )
    elif watching and dropped:
        # Note: this branch reports the USERSPACE drop. The kernel-side check
        # below deliberately runs afterwards and can only ever add to the
        # picture — an earlier version let a non-zero userspace count take this
        # branch and then skipped the kernel check entirely, so whenever both
        # were failing the operator was told about the recoverable half only.
        status = "gapped"
        headline = "Watching, but the record has holes"
        detail = (
            f"{dropped:,} events were dropped rather than stall the kernel. "
            "Anything that ran during those moments is missing from the timeline, "
            "and absence here does not mean nothing happened."
        )
    else:
        status = "stopped"
        headline = "The kernel witness has stopped reporting"
        detail = (
            "The last heartbeat was "
            + (f"{beat_age}s ago. " if beat_age is not None else "never seen. ")
            + "Executions since then were not witnessed — only whatever the "
            "polling sensor happened to sample."
        )

    # KERNEL-SIDE LOSS, counted separately from ours.
    #
    # `dropped` above comes from esf_stream_health, which records what the
    # Sentinel's OWN buffer discarded. It says nothing about events the KERNEL
    # dropped before the Sentinel ever saw them — detected from gaps in the
    # per-event-type seq_num the kernel stamps on every message.
    #
    # Without this, a kernel-side drop would render as "Watching, and the
    # record is intact": the most reassuring status this function can produce,
    # emitted at the exact moment the timeline had holes in it.
    #
    # The two are not summed. They have opposite remedies — a larger userspace
    # buffer versus a lighter subscription — and merging them hides which half
    # is failing.
    # Matched against the actual status vocabulary of this module, not an
    # assumed one. The first version compared to "watching"; this module says
    # "witnessing", so the branch never fired and kernel-side loss stayed
    # invisible in the verdict even once it was being counted correctly.
    if kernel_dropped and status == "gapped" and dropped:
        # Both halves failing. Say so, and keep them separate: they have
        # opposite remedies (a bigger buffer vs a lighter subscription).
        headline = "Watching, but events were lost on both sides"
        detail = (
            f"{dropped:,} events were dropped by the Sentinel's own buffer AND "
            f"{kernel_dropped:,} were discarded inside the kernel before it saw "
            "them. These need different fixes — a larger userspace queue for the "
            "first, a lighter subscription for the second — and neither is "
            "recoverable."
        )
    elif kernel_dropped is None and status in ("witnessing", "watching"):
        # Watching, but we cannot say the record is whole. Not an alarm — an
        # explicit gap in what this tier is able to report about itself.
        status = "unverified"
        headline = "Watching, but kernel-side loss cannot be checked here"
        detail = (
            "The Sentinel's own buffer reports no drops, but this store has no "
            "kernel drop-accounting table, so events the kernel discarded before "
            "the Sentinel saw them cannot be counted. Treat this timeline as "
            "probably complete rather than known complete."
        )
    elif kernel_dropped and status in ("witnessing", "watching"):
        status = "gapped"
        headline = "Watching, but the kernel itself dropped events"
        detail = (
            f"{kernel_dropped:,} events were discarded inside the kernel before "
            "the Sentinel could see them, detected from gaps in the sequence "
            "numbers the kernel stamps on every message. These are "
            "unrecoverable, and a lighter subscription or tighter muting is the "
            "fix — not a bigger queue."
        )

    return {
        "present": True,
        "watching": watching,
        "status": status,
        "headline": headline,
        "detail": detail,
        "events_24h": events,
        "dropped": int(dropped),
        "kernel_dropped_measurable": kernel_dropped is not None,
        "kernel_dropped": kernel_dropped,
        "enforce_mode": enforce,
        "last_beat_age_seconds": beat_age,
    }


def transitions(hours: int = 24, limit: int = 40) -> dict:
    """State CHANGES the kernel witnessed — not processes starting, but things changing.

    A privilege change, a signature going invalid, a volume attaching. No
    polling sensor produces any of these at any interval, because there is
    nothing to sample: an instant either had a witness or it did not happen as
    far as the record is concerned.

    Ranked by how rare the kind is rather than by recency, because a signature
    invalidation from an hour ago matters more than a mount from a minute ago,
    and a feed sorted newest-first would bury it.
    """
    unreadable = {
        "present": False,
        "count": 0,
        "by_kind": {},
        "events": [],
        "headline": "Kernel state changes could not be read",
        # A failed query is not a quiet machine, and it needs a different
        # sentence: the one below sends the reader to check a subscription,
        # which is the wrong thing to go and do when the table would not read.
        "detail": (
            "The transition table could not be queried on this tier, so state "
            "changes cannot be ruled out. This is a gap in the record, not a "
            "quiet period."
        ),
    }
    absent = {
        "present": False,
        "count": 0,
        "by_kind": {},
        "events": [],
        "headline": "No kernel state-change record",
        "detail": (
            "The Sentinel is not subscribed to transition events, or none have "
            "occurred. Check the subscription count in its start record before "
            "reading this as quiet — an empty list looks the same either way."
        ),
    }
    db = _open()
    if db is None:
        return absent
    try:
        cutoff = time.time_ns() - hours * 3600 * NS
        # RANK IN SQL, not after the fetch.
        #
        # Fetching the most RECENT n and then sorting them by severity only
        # reorders within the recency window — a rare event outside it never
        # enters the candidate set at all. Measured here: the 40 most recent
        # transitions were all setuid/setgid, so the two kextload events in the
        # same window were invisible. The docstring above claimed this function
        # avoids burying rare events in a newest-first feed, and the
        # implementation did exactly that, one level up.
        #
        # The weights live in SQL so the LIMIT applies after ranking.
        rows = [
            dict(r)
            for r in db.execute(
                "SELECT timestamp_ns, kind, pid, euid, exe, cdhash, is_platform, detail, "
                "  CASE kind "
                "    WHEN 'cs_invalidated' THEN 100 "
                "    WHEN 'kextload'       THEN 90 "
                "    WHEN 'setuid'         THEN 60 "
                "    WHEN 'setgid'         THEN 55 "
                "    WHEN 'mount'          THEN 50 "
                "    WHEN 'unmount'        THEN 30 "
                "    ELSE 70 END AS severity "
                "FROM esf_kernel_events WHERE timestamp_ns >= ? "
                "ORDER BY severity DESC, timestamp_ns DESC LIMIT ?",
                (cutoff, limit),
            )
        ]
        by_kind = {
            k: n
            for k, n in db.execute(
                "SELECT kind, COUNT(*) FROM esf_kernel_events WHERE timestamp_ns >= ? "
                "GROUP BY kind",
                (cutoff,),
            )
        }
    except sqlite3.OperationalError:
        # "no such table" — this tier predates the transitions migration.
        return absent
    except sqlite3.Error:
        logger.warning("kernel transitions read failed", exc_info=True)
        return unreadable
    finally:
        # Every other reader in this module closes in a finally; this one closed
        # on no path at all, so each call leaked a SQLite handle. Under the
        # ledger's 60s refresh that is slow descriptor exhaustion in a
        # long-lived gunicorn worker.
        db.close()
    if not rows and not by_kind:
        return absent

    # Severity floor per kind. Deliberately NOT frequency-derived: the first
    # signature invalidation ever seen would otherwise score as the most common
    # thing in its own table, which is exactly backwards for the rarest event
    # the Sentinel can report.
    for r in rows:
        # _trust() is this module's single vocabulary and it has an "unknown"
        # for flags that could not be read. A local platform/third-party split
        # invented a second vocabulary with no such state, so a transition whose
        # signing flags were absent came out labelled "third-party" — an
        # assertion about provenance made from missing data.
        r["trust"] = _trust(r)
        if r.get("detail"):
            try:
                r["detail"] = json.loads(r["detail"])
            except (ValueError, TypeError):
                pass

    total = sum(by_kind.values())
    return {
        "present": True,
        "count": total,
        "by_kind": by_kind,
        "events": rows,
        "headline": f"{total:,} state changes witnessed at the kernel",
        "detail": (
            "Privilege changes, volume attachments and signature invalidations, "
            "recorded at the instant they happened. Nothing that samples on an "
            "interval can produce these."
        ),
    }


def novel_binaries(hours: int = 24, limit: int = 25) -> dict:
    """Binaries whose cdhash has never run on this machine before.

    Carries the ledger's own caveat forward: on a young ledger nearly everything
    is novel, so the count means nothing until a baseline exists. A UI that
    shows the number without the caveat manufactures alarm out of a fresh
    install.
    """
    empty = {
        "novel": [],
        "count": 0,
        "known_binaries_total": 0,
        "baseline_ready": False,
        "note": None,
        "available": False,
    }
    db = _open()
    if db is None:
        return empty
    try:
        cutoff = time.time_ns() - hours * 3600 * NS
        # Trust comes from the kernel's own observation of the exec, joined in
        # from the most recent event for this cdhash. The ledger row alone
        # cannot answer "was it signed" — see _trust().
        rows = [
            dict(r)
            for r in db.execute(
                """
                SELECT l.*,
                       e.is_signed  AS is_signed,
                       e.is_valid   AS is_valid,
                       e.is_adhoc   AS exec_is_adhoc,
                       e.signing_id AS exec_signing_id
                  FROM esf_binary_ledger l
                  LEFT JOIN esf_exec_events e
                    ON e.id = (SELECT id FROM esf_exec_events
                                WHERE cdhash = l.cdhash
                                ORDER BY timestamp_ns DESC LIMIT 1)
                 WHERE l.first_seen_ns >= ?
                   AND IFNULL(l.is_platform, 0) = 0
                   AND l.verdict IS NULL
                 ORDER BY l.first_seen_ns DESC LIMIT ?
                """,
                (cutoff, limit),
            )
        ]
        known = db.execute("SELECT COUNT(*) FROM esf_binary_ledger").fetchone()[0]
    except sqlite3.Error:
        # Degrading to "nothing is new" on a failed query is the wrong direction
        # for this product: it looks exactly like a calm machine. Say it failed.
        logger.warning("novel-binary query failed", exc_info=True)
        return {
            **empty,
            "available": False,
            "note": "The binary ledger could not be read — this is not a statement "
            "that nothing new ran.",
        }
    finally:
        db.close()

    now_ns = time.time_ns()
    for r in rows:
        if r.get("exec_is_adhoc") is not None:
            r["is_adhoc"] = r["exec_is_adhoc"]
        if r.get("exec_signing_id") and not r.get("signing_id"):
            r["signing_id"] = r["exec_signing_id"]
        r["trust"] = _trust(r)
        r["age_minutes"] = int((now_ns - (r.get("first_seen_ns") or now_ns)) / 6e10)
        r["reviewed"] = r.get("verdict") is not None
    rows.sort(
        key=lambda r: (TRUST_ORDER.get(r["trust"], 9), -(r["first_seen_ns"] or 0))
    )

    # A ledger this small cannot distinguish "new" from "not seen yet".
    baseline_ready = known >= 200
    return {
        "novel": rows,
        "count": len(rows),
        "known_binaries_total": known,
        "baseline_ready": baseline_ready,
        "available": True,
        "note": (
            None
            if baseline_ready
            else (
                f"Only {known} binaries have ever been recorded here, so almost "
                "everything still looks new. Novelty becomes meaningful once the "
                "ledger has seen this machine's normal software."
            )
        ),
    }


def record_binary_verdict(cdhash: str, verdict: str, note: str = "") -> dict:
    """Write an operator's judgement onto the binary ledger.

    ``esf_binary_ledger.verdict`` was built with NULL meaning "nobody has judged
    this", explicitly not "judged benign". This is the write that closes that
    gap, and it is the same press as the ledger's That's me / Not me — one
    decision, recorded everywhere it means something.
    """
    if verdict not in ("benign", "suspicious"):
        return {"written": False, "detail": f"unknown verdict {verdict!r}"}
    db = _writable()
    if db is None:
        return {
            "written": False,
            "detail": "The binary ledger is not writable from this tier.",
        }
    try:
        cur = db.execute(
            "UPDATE esf_binary_ledger SET verdict = ?, verdict_at_ns = ?, "
            "verdict_note = ? WHERE cdhash = ?",
            (verdict, time.time_ns(), note[:500], cdhash),
        )
        db.commit()
        if cur.rowcount == 0:
            return {"written": False, "detail": "No such binary in the ledger."}
        return {"written": True, "detail": f"Binary marked {verdict}."}
    except sqlite3.Error as exc:
        logger.warning("binary verdict write failed", exc_info=True)
        return {"written": False, "detail": str(exc)[:200]}
    finally:
        db.close()


def witnessed_window(start_ns: int, end_ns: int) -> dict:
    """Was the kernel watching across a specific window?

    Used to stamp evidence with the grade it deserves: an event inside a window
    the Sentinel covered is corroborated by the kernel; one outside it rests on
    a poll sample alone.
    """
    db = _open()
    if db is None:
        return {"witnessed": False, "reason": "no exec stream on this tier"}
    try:
        beats = db.execute(
            "SELECT IFNULL(SUM(dropped), 0) AS dropped, COUNT(*) AS beats "
            "FROM esf_stream_health WHERE timestamp_ns BETWEEN ? AND ?",
            (start_ns, end_ns),
        ).fetchone()
        execs = db.execute(
            "SELECT COUNT(*) FROM esf_exec_events WHERE timestamp_ns BETWEEN ? AND ?",
            (start_ns, end_ns),
        ).fetchone()[0]
    except sqlite3.Error:
        return {"witnessed": False, "reason": "exec stream unreadable"}
    finally:
        db.close()
    return {
        "witnessed": bool(beats["beats"]) or bool(execs),
        "execs": execs,
        "dropped": int(beats["dropped"] or 0),
        "reason": None if beats["beats"] else "no heartbeat covers this window",
    }


def enforcement_decisions(hours: int = 24, limit: int = 25) -> dict:
    """What the Sentinel decided to block — the signal with almost no noise.

    The kernel's allow/deny is a far cleaner signal than any probe score for a
    genuinely untrusted binary — a staged infostealer capped at 0.53 "suspicious"
    across nine probes while the Sentinel decided against it outright. But the
    deny POLICY is coarse (untrusted-signature AND a risky path prefix), and
    ad-hoc is how every local `cc`/`cargo`/`go` build is signed — measured on
    this same machine, 2 of 3 would_deny events were the owner's own rustc and
    rustup. So this function reports the decisions; `_enforcement_items` in
    ledger.py, NOT here, decides which signature classes are alarming enough to
    lead the queue (unsigned / invalid / blocklisted) versus merely worth a look
    (ad-hoc, the local-build population).

    That decision is made on every single exec and, until now, shown nowhere.
    This surfaces it. In MONITOR mode a ``would_deny`` is "I would have stopped
    this and did not" — which is exactly the shape of a dropper and worth the
    owner's attention, but it is not containment, so the wording never claims
    the thing was blocked when it was only flagged.
    """
    empty = {
        "available": False,
        "mode": None,
        "decisions": [],
        "count": 0,
        "allowed": 0,
    }
    db = _open()
    if db is None:
        return empty
    try:
        cutoff = time.time_ns() - hours * 3600 * NS
        allowed = db.execute(
            "SELECT COUNT(*) FROM esf_exec_events "
            "WHERE timestamp_ns >= ? AND decision = 'allow'",
            (cutoff,),
        ).fetchone()[0]
        decided_total = db.execute(
            "SELECT COUNT(*) FROM esf_exec_events "
            "WHERE timestamp_ns >= ? AND decision IS NOT NULL AND decision <> 'allow'",
            (cutoff,),
        ).fetchone()[0]
        rows = [
            dict(r)
            for r in db.execute(
                """
                SELECT cdhash, exe, decision, decision_reason,
                       COUNT(*) AS hits, MAX(timestamp_ns) AS last_ns,
                       MAX(is_signed) AS is_signed, MAX(is_valid) AS is_valid,
                       MAX(is_adhoc) AS is_adhoc, MAX(is_platform) AS is_platform,
                       MAX(euid) AS euid, MAX(pid) AS pid
                  FROM esf_exec_events
                 WHERE timestamp_ns >= ?
                   AND decision IS NOT NULL AND decision <> 'allow'
                 GROUP BY cdhash
                 ORDER BY last_ns DESC
                 LIMIT ?
                """,
                (cutoff, limit),
            )
        ]
        beat = db.execute(
            "SELECT enforce_mode FROM esf_stream_health "
            "ORDER BY timestamp_ns DESC LIMIT 1"
        ).fetchone()
    except sqlite3.Error:
        logger.warning("enforcement read failed", exc_info=True)
        return empty
    finally:
        db.close()

    enforcing = bool(beat["enforce_mode"]) if beat else False
    now_ns = time.time_ns()
    decisions = []
    for r in rows:
        # "denied" only when enforcement is actually on; otherwise it is a
        # would-block, and the row says so rather than implying containment.
        actually_blocked = enforcing and r["decision"] == "denied"
        decisions.append(
            {
                "cdhash": r["cdhash"],
                "name": (r["exe"] or "an unnamed binary").rsplit("/", 1)[-1],
                "exe": r["exe"],
                "trust": _trust(r),
                "reason": r["decision_reason"] or "",
                "hits": r["hits"],
                "as_root": bool(r["euid"] == 0),
                "blocked": actually_blocked,
                "age_minutes": int((now_ns - (r["last_ns"] or now_ns)) / 6e10),
            }
        )
    decisions.sort(key=lambda d: (TRUST_ORDER.get(d["trust"], 9), -d["hits"]))
    return {
        "available": True,
        "mode": "enforce" if enforcing else "monitor",
        "decisions": decisions,
        # count is the number SHOWN (deduped by cdhash, capped at `limit`);
        # decided_total is every non-allow event, uncapped. The "why" text uses
        # decided_total so it can never understate how many the kernel flagged.
        "count": len(decisions),
        "decided_total": decided_total,
        "allowed": allowed,
    }


def summary_for_ledger(hours: int = 24) -> dict:
    """One compact payload for the ledger page."""
    health = stream_health(hours)
    novel = novel_binaries(hours)
    enforcement = enforcement_decisions(hours)
    return {
        "health": health,
        "novel": novel,
        "enforcement": enforcement,
        "headline": health["headline"],
        "watching": health["watching"],
    }


def _json(value) -> str:
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return "{}"
