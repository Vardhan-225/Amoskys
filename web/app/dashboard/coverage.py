"""What AMOSKYS could not see — published, not hidden.

Every security product tells you what it found. Almost none tell you where it
was not looking, which is the number that decides how much a quiet dashboard is
worth. A page that says "All Clear" while its file monitor has been dark for
three days is not reporting a clean machine; it is reporting a clean *sample*,
and the difference is the whole product.

This module answers one question — "how much should I trust the quiet?" — from
two sources that already exist:

  * **Per-sensor freshness**, computed from the domain tables themselves. A
    sensor that has never written a row is ``absent``; one whose table is not
    in this tier's schema at all is ``missing`` (the fleet sync is known to drop
    tables and columns silently); one that stopped is ``dark``, with the time it
    stopped.
  * **The blindness ledger** (``observability/blindness.py``), which the
    pipeline and the action-budget governor already write to and which nothing
    in the UI has ever displayed.

The rule this enforces: a coverage report never rounds up. A sensor we cannot
prove is working is reported as not working.
"""

from __future__ import annotations

import logging
import sqlite3
import time

logger = logging.getLogger(__name__)

try:
    from . import insight_service
except Exception:  # pragma: no cover - defensive import
    insight_service = None  # type: ignore[assignment]

FRESH_SECONDS = 15 * 60
STALE_SECONDS = 24 * 60 * 60

# The domains a person would expect to be watched, in the words they'd use.
SENSORS = (
    ("process_events", "Processes", "what runs on the machine"),
    ("flow_events", "Network", "what it connects to"),
    ("dns_events", "DNS", "what it looks up"),
    ("fim_events", "Files", "what changes on disk"),
    ("persistence_events", "Persistence", "what installs itself to survive a reboot"),
    ("peripheral_events", "Peripherals", "what gets plugged in"),
    ("security_events", "Detections", "what the probes flagged"),
)

STATUS_ORDER = {"missing": 0, "absent": 1, "dark": 2, "stale": 3, "fresh": 4}


def _age_human(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds}s ago"
    if seconds < 5400:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _span_hours(
    db: sqlite3.Connection, table: str, scope: str, params: tuple
) -> tuple[float | None, int]:
    """How much time the cached rows actually cover, and how many there are.

    This is the difference between a window a page ASKS for and a window it can
    ANSWER. Measured on a real cache: flow_events held 23,450 rows spanning 2.5
    hours while every network figure on the dashboard was labelled "last 24
    hours" — an 89% shortfall, stated nowhere. On the production tier the same
    gap reads 29,721 cached rows against 137,095 on the fleet backend for the
    same window.

    A count is not coverage. Twenty thousand rows sounds like plenty until you
    know they are all from one afternoon.
    """
    try:
        row = db.execute(
            f"SELECT COUNT(*), MIN(timestamp_ns), MAX(timestamp_ns) FROM {table}"
            + scope,
            params,
        ).fetchone()
    except sqlite3.Error:
        return None, 0
    if not row or not row[0] or row[1] is None or row[2] is None:
        return None, (row[0] if row else 0) or 0
    try:
        return max(0.0, (float(row[2]) - float(row[1])) / 1e9 / 3600.0), int(row[0])
    except (TypeError, ValueError):
        return None, int(row[0] or 0)


def _latest_epoch(db: sqlite3.Connection, table: str, scope: str, params: tuple):
    """Newest row in a table, as an epoch, whichever time column it carries."""
    try:
        columns = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return None, "missing"
    if not columns:
        return None, "missing"

    if "timestamp_ns" in columns:
        expression = "MAX(timestamp_ns) / 1000000000.0"
    elif "timestamp_dt" in columns:
        expression = "MAX(strftime('%s', timestamp_dt))"
    elif "timestamp" in columns:
        expression = "MAX(timestamp)"
    else:
        return None, "missing"

    try:
        row = db.execute(f"SELECT {expression} FROM {table}" + scope, params).fetchone()
    except sqlite3.Error:
        return None, "missing"
    if not row or row[0] is None:
        return None, "absent"
    try:
        return float(row[0]), None
    except (TypeError, ValueError):
        return None, "absent"


_LEDGER_UNKNOWN = {
    "status": "unknown",
    "active_count": 0,
    "events": [],
    "by_sensor": {},
    "message": "The blindness ledger could not be read on this tier — "
    "absence of recorded gaps is not evidence there were none.",
}


def _sync_window_hours(db: sqlite3.Connection) -> int | None:
    """The horizon this tier deliberately keeps, if it recorded one.

    A cache holding six hours because that is its configured window is a very
    different thing from one holding six hours because the sync is failing, and
    a coverage report that cannot tell them apart sends someone to debug a
    pipeline that is working as designed.
    """
    try:
        row = db.execute(
            "SELECT value FROM _sync_meta WHERE key='sync_window_hours'"
        ).fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return None


def _blindness(db: sqlite3.Connection, device_id: str | None) -> dict:
    """Active blindness events, or an honest "cannot tell".

    ``list_blindness_events`` returns [] both when the ledger is EMPTY and when
    the table does not exist, and ``summarize_blindness_events([])`` calls that
    "healthy — No active blindness events". On a synced fleet cache the table is
    simply absent, so the panel whose entire job is to report unseen gaps was
    itself reporting a missing ledger as a clean one. Check for the table before
    trusting the summary.
    """
    try:
        from amoskys.observability.blindness import (
            BLINDNESS_TABLE,
            list_blindness_events,
            summarize_blindness_events,
        )
    except Exception:
        return dict(_LEDGER_UNKNOWN)
    try:
        present = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (BLINDNESS_TABLE,),
        ).fetchone()
        if not present:
            return dict(_LEDGER_UNKNOWN)
        events = list_blindness_events(db, device_id=device_id, limit=50)
    except Exception:
        logger.debug("blindness ledger unreadable", exc_info=True)
        return dict(_LEDGER_UNKNOWN)
    return summarize_blindness_events(events)


def report(
    allowed_device_ids: list[str] | None = None, device_id: str | None = None
) -> dict:
    """The coverage report. Never raises; an unreadable store is itself a gap."""
    unreachable = {
        "available": False,
        "headline": "AMOSKYS cannot read its own telemetry store",
        "detail": "Nothing below can be trusted, and this is not an all-clear.",
        "sensors": [],
        "reporting": 0,
        "expected": len(SENSORS),
        "blindness": {"status": "unknown", "active_count": 0, "events": []},
    }
    if insight_service is None:
        return unreachable
    db_path = insight_service.resolve_db_path()
    if not db_path:
        return unreachable
    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
        db.row_factory = sqlite3.Row
    except sqlite3.Error:
        return unreachable

    scope_ids = [device_id] if device_id else allowed_device_ids
    now = time.time()
    sensors = []
    try:
        for table, label, blurb in SENSORS:
            scope, params = insight_service._scope_sql(scope_ids, " WHERE ")
            latest, failure = _latest_epoch(db, table, scope, params)
            if failure == "missing":
                status, age, age_human = "missing", None, "not in this tier's schema"
            elif failure == "absent" or latest is None:
                status, age, age_human = "absent", None, "never"
            else:
                age = max(0.0, now - latest)
                age_human = _age_human(age)
                if age <= FRESH_SECONDS:
                    status = "fresh"
                elif age <= STALE_SECONDS:
                    status = "stale"
                else:
                    status = "dark"
            span, rows = _span_hours(db, table, scope, params)
            sensors.append(
                {
                    "table": table,
                    "label": label,
                    "blurb": blurb,
                    "status": status,
                    "age_seconds": age,
                    "age_human": age_human,
                    "rows": rows,
                    "span_hours": None if span is None else round(span, 1),
                    # The honest answer to "can this sensor answer a 24h
                    # question?" — asked here so no page has to guess.
                    "covers_24h": bool(span is not None and span >= 23.0),
                }
            )
        blindness = _blindness(db, device_id)
        sync_window = _sync_window_hours(db)
    finally:
        db.close()

    # The kernel witness is not one sensor among seven — it is the difference
    # between witnessing an execution and sampling for it afterwards. It gets
    # its own row, and its dropped-event count is reported as a hole in the
    # record rather than folded into a freshness colour.
    try:
        from . import kernel

        health = kernel.stream_health()
        if not health["present"]:
            k_status, k_age = "missing", "no exec stream on this tier"
        elif health["status"] == "idle":
            k_status, k_age = "absent", "installed, never reported"
        elif health["status"] == "stopped":
            beat = health.get("last_beat_age_seconds")
            k_status = "dark"
            k_age = _age_human(beat) if beat is not None else "never"
        elif health["status"] == "gapped":
            k_status = "stale"
            k_age = f"{health['dropped']:,} events dropped"
        else:
            k_status, k_age = "fresh", _age_human(health.get("last_beat_age_seconds"))
        sensors.append(
            {
                "table": "esf_exec_events",
                "label": "Kernel witness",
                "blurb": "every execution, seen by the kernel as it happens",
                "status": k_status,
                "age_seconds": health.get("last_beat_age_seconds"),
                "age_human": k_age,
                "detail": health.get("detail"),
            }
        )
    except Exception:  # pragma: no cover - the report must never fail closed
        logger.debug("kernel witness unavailable", exc_info=True)

    sensors.sort(key=lambda s: (STATUS_ORDER.get(s["status"], 9), s["label"]))
    reporting = sum(1 for s in sensors if s["status"] == "fresh")
    not_fresh = [s for s in sensors if s["status"] != "fresh"]

    if reporting == len(sensors):
        headline = "Every sensor is reporting"
        detail = "Coverage is complete for the domains AMOSKYS watches."
    elif reporting == 0:
        headline = "No sensor is currently reporting"
        detail = (
            "Anything this dashboard says about the last few minutes is a "
            "statement about missing data, not about a quiet machine."
        )
    else:
        worst = ", ".join(f"{s['label']} ({s['age_human']})" for s in not_fresh[:3])
        headline = f"{reporting} of {len(sensors)} sensors reporting"
        detail = f"Not current: {worst}."

    # A windowed page asks for 24h. Say which sensors can actually answer that.
    # Any sensor that HAS data can be asked a windowed question, whether or not
    # its newest row is recent. Freshness and span are separate failures: a
    # sensor can be up to the minute and still hold only two hours of history,
    # and a page that reports the first without the second still overstates
    # what its "last 24 hours" figure was computed from.
    windowed = [s for s in sensors if s.get("span_hours") is not None]
    short = [s for s in windowed if not s["covers_24h"]]
    window_note = None
    if short:
        worst = min(short, key=lambda s: s["span_hours"])
        if sync_window and sync_window < 24:
            # By design, and say so. "Less than a day of data" without this
            # sends someone looking for a broken pipeline that is working.
            window_note = (
                f"This server keeps a {sync_window}-hour window by design, so "
                'figures labelled "last 24 hours" are answered from at most '
                f"{sync_window}h of data — the fleet backend holds more. "
                f"Shortest right now: {worst['label']} at {worst['span_hours']}h."
            )
        else:
            window_note = (
                f"{len(short)} of {len(windowed)} reporting sensors hold less than a "
                f"day of data — {worst['label']} covers only {worst['span_hours']}h. "
                'Figures on this dashboard labelled "last 24 hours" are answered '
                "from what reached this server, which is less than the fleet holds."
            )

    return {
        "available": True,
        "headline": headline,
        "detail": detail,
        "reporting": reporting,
        "expected": len(sensors),
        "sensors": sensors,
        "blindness": blindness,
        "window_note": window_note,
        "window_short_count": len(short),
        "sync_window_hours": sync_window,
    }
