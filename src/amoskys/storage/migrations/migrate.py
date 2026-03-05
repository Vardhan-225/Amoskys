"""
AMOSKYS Schema Migration Runner (A3.3)

Reads numbered SQL migration files, tracks applied versions in a
``schema_migrations`` table, and applies pending migrations in order.

Usage:
    python -m amoskys.storage.migrations.migrate          # apply pending
    python -m amoskys.storage.migrations.migrate --dry-run # preview only
    python -m amoskys.storage.migrations.migrate --rollback 1  # undo migration 1

Migration files live in ``sql/`` next to this module and follow the naming
convention ``NNN_description.sql``.  Each file contains two sections
separated by ``-- DOWN``:

    -- UP
    ALTER TABLE process_events ADD COLUMN schema_version INTEGER DEFAULT 1;

    -- DOWN
    -- SQLite cannot DROP COLUMN; this is a no-op placeholder.

The runner guarantees:
    - Migrations are applied in numeric order.
    - Each migration runs inside a transaction (atomic).
    - Re-running is safe (idempotent via schema_migrations table).
"""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

SQL_DIR = Path(__file__).parent / "sql"

# Regex: leading digits before first underscore
_VERSION_RE = re.compile(r"^(\d+)")

BOOTSTRAP_SQL = """\
CREATE TABLE IF NOT EXISTS schema_migrations (
    version  INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL,
    checksum TEXT
);
"""


def _parse_migration(path: Path) -> Tuple[str, str]:
    """Split a migration file into (up_sql, down_sql).

    Convention: everything before ``-- DOWN`` is the UP section,
    everything after is the DOWN section.
    """
    text = path.read_text()
    parts = re.split(r"(?m)^--\s*DOWN\b.*$", text, maxsplit=1)
    up_sql = parts[0].strip()
    # Remove the optional ``-- UP`` header
    up_sql = re.sub(r"(?m)^--\s*UP\b.*$", "", up_sql).strip()
    down_sql = parts[1].strip() if len(parts) > 1 else ""
    return up_sql, down_sql


def discover_migrations() -> List[Tuple[int, str, Path]]:
    """Return sorted list of (version, description, path) from sql/ dir."""
    if not SQL_DIR.is_dir():
        return []
    migrations = []
    for p in sorted(SQL_DIR.glob("*.sql")):
        m = _VERSION_RE.match(p.stem)
        if not m:
            continue
        version = int(m.group(1))
        description = p.stem[len(m.group(1)) :].lstrip("_").replace("_", " ")
        migrations.append((version, description, p))
    return migrations


def applied_versions(conn: sqlite3.Connection) -> set[int]:
    """Return set of already-applied migration versions."""
    try:
        rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
        return {r[0] for r in rows}
    except sqlite3.OperationalError:
        return set()


def apply_migration(
    conn: sqlite3.Connection,
    version: int,
    description: str,
    sql: str,
    *,
    dry_run: bool = False,
) -> bool:
    """Apply a single migration inside a transaction.

    Returns True if applied (or would be applied in dry-run mode).
    """
    if dry_run:
        logger.info("[DRY-RUN] Would apply migration %03d: %s", version, description)
        return True

    try:
        # Execute each statement separately (executescript commits implicitly)
        for stmt in _split_statements(sql):
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError as col_err:
                # Tolerate "duplicate column" from idempotent re-runs
                if "duplicate column name" in str(col_err):
                    logger.debug("Column already exists, skipping: %s", col_err)
                    continue
                raise
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at, description) "
            "VALUES (?, ?, ?)",
            (version, datetime.now(timezone.utc).isoformat(), description),
        )
        conn.commit()
        logger.info("Applied migration %03d: %s", version, description)
        return True
    except Exception:
        conn.rollback()
        logger.exception("Migration %03d FAILED — rolled back", version)
        return False


def rollback_migration(
    conn: sqlite3.Connection,
    version: int,
    description: str,
    down_sql: str,
    *,
    dry_run: bool = False,
) -> bool:
    """Rollback a single migration."""
    if not down_sql:
        logger.warning("Migration %03d has no DOWN section — cannot rollback", version)
        return False

    if dry_run:
        logger.info("[DRY-RUN] Would rollback migration %03d: %s", version, description)
        return True

    try:
        for stmt in _split_statements(down_sql):
            conn.execute(stmt)
        conn.execute("DELETE FROM schema_migrations WHERE version = ?", (version,))
        conn.commit()
        logger.info("Rolled back migration %03d: %s", version, description)
        return True
    except Exception:
        conn.rollback()
        logger.exception("Rollback of migration %03d FAILED", version)
        return False


def _split_statements(sql: str) -> List[str]:
    """Split SQL text into individual statements, filtering blanks/comments."""
    stmts = []
    for raw in sql.split(";"):
        # Strip comment-only lines, keep lines with actual SQL
        lines = [
            line
            for line in raw.strip().splitlines()
            if line.strip() and not line.strip().startswith("--")
        ]
        stmt = "\n".join(lines).strip()
        if stmt:
            stmts.append(stmt)
    return stmts


def run_migrations(
    db_path: str,
    *,
    dry_run: bool = False,
    target_rollback: Optional[int] = None,
) -> int:
    """Main entry point: apply all pending migrations or rollback one.

    Args:
        db_path: Path to SQLite database.
        dry_run: If True, only log what would happen.
        target_rollback: If set, rollback this specific migration version.

    Returns:
        Number of migrations applied (or rolled back).
    """
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # Bootstrap migration tracking table
    conn.executescript(BOOTSTRAP_SQL)

    already = applied_versions(conn)
    all_migrations = discover_migrations()

    if target_rollback is not None:
        # Find the migration to rollback
        for version, desc, path in all_migrations:
            if version == target_rollback:
                if version not in already:
                    logger.warning(
                        "Migration %03d not applied — nothing to rollback", version
                    )
                    conn.close()
                    return 0
                _, down_sql = _parse_migration(path)
                result = rollback_migration(
                    conn, version, desc, down_sql, dry_run=dry_run
                )
                conn.close()
                return 1 if result else 0
        logger.error("Migration %03d not found in sql/ directory", target_rollback)
        conn.close()
        return 0

    # Apply pending migrations in order
    count = 0
    for version, desc, path in all_migrations:
        if version in already:
            continue
        up_sql, _ = _parse_migration(path)
        if apply_migration(conn, version, desc, up_sql, dry_run=dry_run):
            count += 1
        else:
            logger.error("Stopping — migration %03d failed", version)
            break

    conn.close()

    if count == 0:
        logger.info("Database is up to date — no pending migrations.")
    else:
        action = "previewed" if dry_run else "applied"
        logger.info("Successfully %s %d migration(s).", action, count)

    return count


def auto_migrate(db_path: str) -> int:
    """Called at app startup to auto-apply pending migrations.

    This is the integration hook for TelemetryStore.__init__ and similar.
    Never does dry-run; logs at INFO level.
    """
    return run_migrations(db_path, dry_run=False)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="AMOSKYS Schema Migration Runner")
    parser.add_argument(
        "--db",
        default="data/telemetry.db",
        help="Path to SQLite database (default: data/telemetry.db)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview migrations without applying",
    )
    parser.add_argument(
        "--rollback",
        type=int,
        metavar="VERSION",
        help="Rollback a specific migration version",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    count = run_migrations(
        args.db,
        dry_run=args.dry_run,
        target_rollback=args.rollback,
    )
    sys.exit(0 if count >= 0 else 1)


if __name__ == "__main__":
    main()
