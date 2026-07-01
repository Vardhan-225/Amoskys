#!/usr/bin/env python3
"""
Standalone, idempotent retention/GC for the fleet command-center database.

Problem this fixes
------------------
``fleet.db`` grows without bound:

  * ``fleet_incidents`` accumulates forever — resolved incidents are never
    purged (a snapshot had 22,140 resolved rows never cleaned up);
  * ``dns_events`` / ``process_events`` / ``security_events`` / ``audit_events``
    are uncapped, unlike ``flow_events`` / ``observation_events`` which the
    command-center maintenance loop already row-caps.

This script applies the same maintenance the command-center performs inline
(see ``server/command_center.py`` ``run_maintenance`` and the ``_TABLE_CAPS``
map), but as a re-runnable CLI you can point at any DB copy, plus the missing
``fleet_incidents`` purge. It is safe to run repeatedly.

What it does
------------
  1. DELETE resolved incidents: ``fleet_incidents`` rows with
     ``status='resolved'`` whose resolution timestamp
     (``COALESCE(resolved_at, updated_at)``) is older than ``--incident-days``
     (default 7).
  2. Rolling row-cap: for ``dns_events`` / ``process_events`` /
     ``security_events`` / ``audit_events``, keep only the newest N rows
     (by autoincrement ``id``, matching the command-center idiom
     ``DELETE ... WHERE id IN (SELECT id ... ORDER BY id ASC LIMIT excess)``).
     Per-table caps default to the command-center values and are overridable.
  3. Reclaim space: ``PRAGMA incremental_vacuum`` when the DB is in
     incremental auto-vacuum mode, otherwise a full ``VACUUM`` — only when
     meaningful deletions occurred, and guarded so a locked/other error never
     aborts the run.

Design notes
------------
  * ``--dry-run`` computes and prints every count WITHOUT modifying the DB
    (it opens the DB read-only so it physically cannot write).
  * Idempotent: a second run deletes ~0 additional rows.
  * Ordering key is ``id`` (autoincrement, monotonic) rather than
    ``timestamp_ns`` — the latter is NULL in some event tables
    (e.g. ``observation_events.event_timestamp_ns``), whereas ``id`` is always
    present and reflects insertion order. This mirrors the command-center cap.

Usage
-----
    # Preview only, no writes:
    python scripts/fleet_retention.py --db /path/to/fleet.db --dry-run

    # Apply:
    python scripts/fleet_retention.py --db /path/to/fleet.db

    # Custom windows / caps:
    python scripts/fleet_retention.py --db fleet.db \
        --incident-days 14 --max-rows 250000 \
        --cap dns_events=300000 --cap audit_events=50000
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from typing import Dict, List, Tuple

# Tables that get a rolling newest-N row cap. Defaults mirror the command
# center's ``_TABLE_CAPS`` (server/command_center.py). Overridable via
# --max-rows (applies to all) and --cap TABLE=N (per-table).
DEFAULT_CAPS: Dict[str, int] = {
    "dns_events": 500_000,
    "process_events": 200_000,
    "security_events": 100_000,
    "audit_events": 100_000,
}

# All capped tables order by autoincrement ``id`` (always present, monotonic).
_CAP_ORDER_COL = "id"


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def plan_incident_purge(
    conn: sqlite3.Connection, incident_days: int, now: float
) -> Tuple[int, int]:
    """Return (total_resolved, purgeable) for resolved incidents older than N days."""
    if not _table_exists(conn, "fleet_incidents"):
        return (0, 0)
    cutoff = now - incident_days * 86400
    total_resolved = int(
        conn.execute(
            "SELECT COUNT(*) FROM fleet_incidents WHERE status = 'resolved'"
        ).fetchone()[0]
    )
    purgeable = int(
        conn.execute(
            "SELECT COUNT(*) FROM fleet_incidents "
            "WHERE status = 'resolved' "
            "AND COALESCE(resolved_at, updated_at) < ?",
            (cutoff,),
        ).fetchone()[0]
    )
    return (total_resolved, purgeable)


def plan_caps(
    conn: sqlite3.Connection, caps: Dict[str, int]
) -> List[Tuple[str, int, int, int]]:
    """Return per-table (table, current, cap, excess) for capped tables."""
    plan: List[Tuple[str, int, int, int]] = []
    for table, cap in caps.items():
        if not _table_exists(conn, table):
            plan.append((table, -1, cap, 0))  # missing table
            continue
        current = _count(conn, table)
        excess = max(0, current - cap)
        plan.append((table, current, cap, excess))
    return plan


def apply_incident_purge(
    conn: sqlite3.Connection, incident_days: int, now: float
) -> int:
    """DELETE old resolved incidents. Returns rows deleted."""
    if not _table_exists(conn, "fleet_incidents"):
        return 0
    cutoff = now - incident_days * 86400
    cur = conn.execute(
        "DELETE FROM fleet_incidents "
        "WHERE status = 'resolved' "
        "AND COALESCE(resolved_at, updated_at) < ?",
        (cutoff,),
    )
    return cur.rowcount


def apply_caps(conn: sqlite3.Connection, caps: Dict[str, int]) -> Dict[str, int]:
    """Trim each capped table to its newest-N rows. Returns rows deleted per table."""
    deleted: Dict[str, int] = {}
    for table, cap in caps.items():
        if not _table_exists(conn, table):
            continue
        current = _count(conn, table)
        excess = current - cap
        if excess <= 0:
            deleted[table] = 0
            continue
        cur = conn.execute(
            f"DELETE FROM {table} WHERE {_CAP_ORDER_COL} IN "
            f"(SELECT {_CAP_ORDER_COL} FROM {table} "
            f"ORDER BY {_CAP_ORDER_COL} ASC LIMIT ?)",
            (excess,),
        )
        deleted[table] = cur.rowcount
    return deleted


def reclaim_space(conn: sqlite3.Connection) -> str:
    """Reclaim freed pages. Returns a short human description of what ran."""
    try:
        mode = int(conn.execute("PRAGMA auto_vacuum").fetchone()[0])
    except sqlite3.Error:
        mode = 0
    try:
        if mode == 2:  # INCREMENTAL
            conn.execute("PRAGMA incremental_vacuum")
            conn.commit()
            return "incremental_vacuum"
        conn.execute("VACUUM")
        return "VACUUM"
    except sqlite3.Error as exc:
        return f"skipped ({exc})"


def _parse_cap_overrides(pairs: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for pair in pairs:
        if "=" not in pair:
            raise argparse.ArgumentTypeError(f"--cap expects TABLE=N, got {pair!r}")
        table, _, raw = pair.partition("=")
        table = table.strip()
        try:
            out[table] = int(raw)
        except ValueError:
            raise argparse.ArgumentTypeError(f"--cap value not an int: {pair!r}")
    return out


def build_caps(max_rows: int | None, overrides: Dict[str, int]) -> Dict[str, int]:
    """Merge the default caps with a global --max-rows and per-table overrides."""
    caps = dict(DEFAULT_CAPS)
    if max_rows is not None:
        caps = {table: max_rows for table in caps}
    caps.update(overrides)
    return caps


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Idempotent retention/GC for the fleet command-center DB."
    )
    parser.add_argument("--db", required=True, help="Path to fleet.db.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report counts without modifying the DB (opens it read-only).",
    )
    parser.add_argument(
        "--incident-days",
        type=int,
        default=7,
        help="Purge resolved incidents older than this many days (default: 7).",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Uniform row cap applied to ALL capped event tables "
        "(overrides per-table defaults; --cap still takes precedence).",
    )
    parser.add_argument(
        "--cap",
        action="append",
        default=[],
        metavar="TABLE=N",
        help="Per-table row cap override, e.g. --cap dns_events=300000. " "Repeatable.",
    )
    parser.add_argument(
        "--no-vacuum",
        action="store_true",
        help="Skip the vacuum/reclaim step even when rows were deleted.",
    )
    args = parser.parse_args()

    caps = build_caps(args.max_rows, _parse_cap_overrides(args.cap))
    now = time.time()

    if args.dry_run:
        # Read-only connection: cannot write even if code tried to.
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(args.db, timeout=30.0)

    try:
        total_resolved, purgeable = plan_incident_purge(conn, args.incident_days, now)
        cap_plan = plan_caps(conn, caps)

        mode = "DRY-RUN (no changes)" if args.dry_run else "APPLY"
        print(f"=== fleet_retention {mode} — {args.db} ===")
        print(f"now={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}\n")

        print("fleet_incidents (resolved purge):")
        print(f"  status='resolved' total      : {total_resolved}")
        print(
            f"  older-than-{args.incident_days}d (purgeable) : {purgeable}"
            "  [COALESCE(resolved_at, updated_at)]"
        )

        print("\nrolling row-caps (keep newest N by id):")
        planned_cap_deletes = 0
        for table, current, cap, excess in cap_plan:
            if current < 0:
                print(f"  {table:<18} MISSING (skipped)")
                continue
            planned_cap_deletes += excess
            after = current - excess
            print(
                f"  {table:<18} current={current:>8}  cap={cap:>8}  "
                f"excess={excess:>8}  -> after={after:>8}"
            )

        total_planned = purgeable + planned_cap_deletes
        print(f"\nTOTAL rows to delete: {total_planned}")

        if args.dry_run:
            print("\n(dry-run: no rows deleted, no vacuum performed)")
            return 0

        # ── APPLY ──
        inc_deleted = apply_incident_purge(conn, args.incident_days, now)
        cap_deleted = apply_caps(conn, caps)
        conn.commit()

        total_deleted = inc_deleted + sum(cap_deleted.values())

        print("\n--- applied ---")
        print(f"  fleet_incidents purged : {inc_deleted}")
        for table, n in cap_deleted.items():
            print(f"  {table:<18} trimmed : {n}")
        print(f"  TOTAL deleted          : {total_deleted}")

        if total_deleted > 0 and not args.no_vacuum:
            what = reclaim_space(conn)
            print(f"  reclaim                : {what}")
        else:
            print("  reclaim                : skipped (no deletions)")

        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
