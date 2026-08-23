"""Lifecycle, dedup, batch, receipt, genealogy, and cleanup mixin for TelemetryStore."""

from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("TelemetryStore")

# Upper bound on the process-genealogy first_seen_ns cache (see
# upsert_genealogy). One entry per live process incarnation; a machine running
# ~900 processes sits far below this, and the bound exists only so PID churn
# over a long uptime cannot grow the dict without limit.
_GENEALOGY_CACHE_MAX = 8192


class LifecycleMixin:
    """Batch mode, snapshot dedup, baselines, cleanup, receipts, genealogy, close."""

    # ── Batch API (used by WALProcessor for single-commit batches) ──

    def begin_batch(self) -> None:
        """Enter batch mode — per-insert commits are suppressed."""
        self._batch_mode = True
        self._batch_count = 0

    def end_batch(self) -> None:
        """Commit all buffered inserts and leave batch mode.

        Retries up to 3 times on transient SQLite lock errors, then
        explicitly rolls back to leave the connection in a clean state
        so subsequent batches aren't poisoned.
        """
        last_err = None
        for attempt in range(3):
            try:
                self.db.commit()
                self._batch_mode = False
                self._batch_count = 0
                self._cache.invalidate()
                return
            except sqlite3.OperationalError as e:
                last_err = e
                err_msg = str(e).lower()
                if "locked" in err_msg or "busy" in err_msg:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                # Non-lock error — break and rollback
                break

        # Commit failed after retries — rollback to reset connection state
        try:
            self.db.rollback()
        except Exception:
            pass  # Already clean or no active transaction
        self._batch_mode = False
        self._batch_count = 0
        self._cache.invalidate()
        raise sqlite3.OperationalError(f"Batch commit failed after retries: {last_err}")

    def _execute(self, sql: str, params: tuple = ()):
        """Execute with the same lock backoff _commit() uses.

        The retry was originally added to _commit() only. But db.execute() runs
        *before* the commit and takes the write lock first, so it is the half
        that actually loses under contention: 698,015 "database is locked"
        errors were measured in one analyzer log, every one a discarded event,
        because the caller catches sqlite3.Error, returns None, and the drain
        deletes the queue row regardless.

        Fixing one half of a pair and not the other is the recurring failure in
        this codebase, so this is the shared helper both halves now go through.
        """
        for attempt in range(3):
            try:
                return self.db.execute(sql, params)
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                if ("locked" not in msg and "busy" not in msg) or attempt == 2:
                    raise
                time.sleep(0.2 * (attempt + 1))

    def _executemany(self, sql: str, seq):
        """Batch twin of _execute, sharing its lock backoff.

        _execute existed alone, so any caller with many rows either looped it
        (paying per-row overhead on a hot path) or reached past it to
        self.db.executemany and lost the retry entirely — silently discarding
        the whole batch on the first "database is locked". That is exactly the
        half-a-pair failure _execute's own docstring warns about, so the pair
        is completed here rather than left for the next caller to rediscover.
        """
        for attempt in range(3):
            try:
                return self.db.executemany(sql, seq)
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                if ("locked" not in msg and "busy" not in msg) or attempt == 2:
                    raise
                time.sleep(0.2 * (attempt + 1))

    def _commit(self) -> None:
        """Commit unless in batch mode.

        Retries on transient lock contention like end_batch() does. Without
        this, a single busy writer drops the event and the caller logs a
        "database is locked" error — the failure mode that discarded most
        of the pipeline and filled the disk with 21M identical log lines.
        """
        if self._batch_mode:
            self._batch_count += 1
            return
        for attempt in range(3):
            try:
                self.db.commit()
                self._cache.invalidate()
                return
            except sqlite3.OperationalError as e:
                err_msg = str(e).lower()
                if "locked" not in err_msg and "busy" not in err_msg:
                    raise
                if attempt == 2:
                    raise
                time.sleep(0.2 * (attempt + 1))

    # ------------------------------------------------------------------
    # Layer 1: Unified snapshot dedup
    # ------------------------------------------------------------------

    def _check_snapshot_dedup(
        self, table_name: str, dedup_key: str, content_hash: str, timestamp_ns: int
    ) -> bool:
        """Check if a snapshot event is a duplicate and should be suppressed."""
        try:
            row = self.db.execute(
                "SELECT content_hash FROM _snapshot_baseline "
                "WHERE table_name=? AND dedup_key=?",
                (table_name, dedup_key),
            ).fetchone()

            if row and row[0] == content_hash:
                self.db.execute(
                    "UPDATE _snapshot_baseline SET updated_ns=? "
                    "WHERE table_name=? AND dedup_key=?",
                    (timestamp_ns, table_name, dedup_key),
                )
                return True

            self.db.execute(
                "INSERT INTO _snapshot_baseline "
                "(table_name, dedup_key, content_hash, updated_ns) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT(table_name, dedup_key) DO UPDATE SET "
                "content_hash=excluded.content_hash, "
                "updated_ns=excluded.updated_ns",
                (table_name, dedup_key, content_hash, timestamp_ns),
            )
            return False
        except sqlite3.Error:
            return False

    @staticmethod
    def _dedup_key(*parts: object) -> str:
        """Build a pipe-delimited dedup key from component parts."""
        return "|".join(str(p) if p is not None else "" for p in parts)

    @staticmethod
    def _content_fingerprint(*fields: object) -> str:
        """Compute a fast content hash from the mutable fields of a snapshot."""
        import hashlib

        payload = "|".join(str(f) if f is not None else "" for f in fields)
        return hashlib.md5(payload.encode("utf-8", errors="replace")).hexdigest()

    # ------------------------------------------------------------------
    # Layer 1: Bulk baseline population + historical dedup
    # ------------------------------------------------------------------

    def populate_baselines(self) -> dict:
        """Seed _snapshot_baseline from existing snapshot events (all tables)."""
        stats: dict = {}
        _queries = [
            (
                "fim_events",
                """
                INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
                SELECT 'fim_events', device_id || '|' || path, new_hash, MAX(timestamp_ns)
                FROM fim_events
                WHERE device_id IS NOT NULL AND path != ''
                GROUP BY device_id, path
            """,
            ),
            (
                "persistence_events",
                """
                INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
                SELECT 'persistence_events',
                       device_id || '|' || mechanism || '|' || entry_id,
                       content_hash, MAX(timestamp_ns)
                FROM persistence_events
                WHERE device_id IS NOT NULL
                  AND mechanism IS NOT NULL AND mechanism != ''
                  AND entry_id IS NOT NULL AND entry_id != ''
                GROUP BY device_id, mechanism, entry_id
            """,
            ),
            (
                "process_events",
                """
                INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
                SELECT 'process_events',
                       device_id || '|' || pid || '|' || COALESCE(exe, ''),
                       COALESCE(cmdline, ''), MAX(timestamp_ns)
                FROM process_events
                WHERE device_id IS NOT NULL AND pid IS NOT NULL
                GROUP BY device_id, pid, exe
            """,
            ),
            (
                "peripheral_events",
                """
                INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
                SELECT 'peripheral_events',
                       device_id || '|' || peripheral_device_id,
                       COALESCE(connection_status, '') || '|' || COALESCE(device_name, ''),
                       MAX(timestamp_ns)
                FROM peripheral_events
                WHERE device_id IS NOT NULL
                GROUP BY device_id, peripheral_device_id
            """,
            ),
            (
                "observation_events_discovery",
                """
                INSERT OR REPLACE INTO _snapshot_baseline (table_name, dedup_key, content_hash, updated_ns)
                SELECT 'observation_events',
                       device_id || '|discovery|' || COALESCE(attributes, ''),
                       COALESCE(attributes, ''), MAX(timestamp_ns)
                FROM observation_events
                WHERE domain = 'discovery' AND device_id IS NOT NULL
                GROUP BY device_id, attributes
            """,
            ),
        ]
        for label, sql in _queries:
            try:
                cur = self.db.execute(sql)
                self.db.commit()
                stats[label] = cur.rowcount
                logger.info("Baseline seeded for %s: %d entries", label, cur.rowcount)
            except sqlite3.Error as e:
                logger.error("Baseline seed failed for %s: %s", label, e)
                stats[label] = 0
        return stats

    def deduplicate_snapshots(self) -> dict:
        """Remove duplicate snapshot rows from ALL snapshot-heavy tables."""
        stats: dict = {}
        _dedup_ops = [
            ("fim_events", "device_id, path, new_hash", "change_type = 'snapshot'"),
            (
                "persistence_events",
                "device_id, mechanism, entry_id, content_hash",
                "change_type = 'snapshot'",
            ),
            (
                "process_events",
                "device_id, pid, exe, cmdline",
                "1=1",
            ),
            (
                "peripheral_events",
                "device_id, peripheral_device_id, connection_status, device_name",
                "1=1",
            ),
            (
                "observation_events",
                "device_id, domain, attributes",
                "domain = 'discovery'",
            ),
        ]
        for table, group_cols, where_clause in _dedup_ops:
            try:
                cur = self.db.execute(
                    f"""
                    DELETE FROM {table}
                    WHERE {where_clause}
                      AND id NOT IN (
                          SELECT MAX(id)
                          FROM {table}
                          WHERE {where_clause}
                          GROUP BY {group_cols}
                      )
                """
                )
                stats[table] = cur.rowcount
                self.db.commit()
                logger.info("Deduped %s: %d rows deleted", table, cur.rowcount)
            except sqlite3.Error as e:
                logger.error("Dedup failed for %s: %s", table, e)
                stats[table] = 0
        return stats

    # ── Data Retention ──

    def cleanup_old_data(self, max_age_days: int = 3) -> Dict[str, int]:
        """Delete telemetry data older than max_age_days (default 3 days).

        Aggressive retention by design — disk space is precious on endpoints.
        The ops server keeps the long-term archive via the shipper.
        """
        cutoff_ns = int((time.time() - max_age_days * 86400) * 1e9)
        cutoff_dt = datetime.fromtimestamp(
            time.time() - max_age_days * 86400, tz=timezone.utc
        ).isoformat()

        tables_ns = [
            "process_events",
            "flow_events",
            "security_events",
            "peripheral_events",
            "dns_events",
            "audit_events",
            "persistence_events",
            "fim_events",
        ]
        tables_dt = ["device_telemetry", "metrics_timeseries"]
        deleted: Dict[str, int] = {}

        # These went through db.execute() directly, bypassing the _execute()
        # lock backoff every other write in this class uses. Under the
        # contention that produced 698,015 "database is locked" errors, a
        # retention DELETE is exactly as droppable as an INSERT — and a
        # retention pass that loses the race silently leaks disk instead of
        # losing one event. Same "fixed one half of the pair" bug the
        # _execute() docstring names; both halves now go through it.
        for table in tables_ns:
            try:
                cursor = self._execute(
                    f"DELETE FROM {table} WHERE timestamp_ns < ?", (cutoff_ns,)
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error as e:
                logger.warning("Retention failed for %s: %s", table, e)
                deleted[table] = 0

        for table in tables_dt:
            try:
                cursor = self._execute(
                    f"DELETE FROM {table} WHERE timestamp_dt < ?", (cutoff_dt,)
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error as e:
                logger.warning("Retention failed for %s: %s", table, e)
                deleted[table] = 0

        _short_cutoff_epoch = time.time() - 30 * 86400
        short_cutoff_dt = datetime.fromtimestamp(
            _short_cutoff_epoch, tz=timezone.utc
        ).isoformat()
        short_cutoff_ns = int(_short_cutoff_epoch * 1e9)
        # These two tables hold envelope_bytes BLOBs — the largest per-row
        # payloads in the store — and have no other pruning path. The previous
        # statement deleted on "quarantined_at < ? OR created_at < ?" for both:
        # wal_dead_letter has no created_at, wal_archive has neither, so it
        # raised "no such column" on every run and was swallowed as 0 rows.
        # Same bug class as the four already fixed above; these are five and six.
        try:
            cursor = self._execute(
                "DELETE FROM wal_dead_letter WHERE quarantined_at < ?",
                (short_cutoff_dt,),
            )
            deleted["wal_dead_letter"] = cursor.rowcount
        except sqlite3.Error as e:
            logger.warning("Retention failed for wal_dead_letter: %s", e)
            deleted["wal_dead_letter"] = 0

        # wal_archive.archived_at is INTEGER NOT NULL and nothing in the tree
        # writes it, so its unit cannot be observed — the sibling column is
        # named original_ts_ns, but archived_at is not suffixed. Guessing wrong
        # is not symmetric: comparing it to the ISO cutoff would delete every
        # row (SQLite orders all INTEGER below all TEXT), and assuming ns when
        # it is seconds would do the same. So bound each row on its own scale;
        # ns timestamps are ~1.8e18 and epoch seconds ~1.8e9, and 1e15 separates
        # them for any date this software will see.
        try:
            cursor = self._execute(
                "DELETE FROM wal_archive WHERE "
                "(archived_at > 1000000000000000 AND archived_at < ?) OR "
                "(archived_at <= 1000000000000000 AND archived_at < ?)",
                (short_cutoff_ns, short_cutoff_ns // 1_000_000_000),
            )
            deleted["wal_archive"] = cursor.rowcount
        except sqlite3.Error as e:
            logger.warning("Retention failed for wal_archive: %s", e)
            deleted["wal_archive"] = 0

        # Observation events: shorter retention (7 days default, configurable)
        obs_age_days = min(max_age_days, 7)
        obs_cutoff_ns = int((time.time() - obs_age_days * 86400) * 1e9)
        try:
            cursor = self._execute(
                "DELETE FROM observation_events WHERE timestamp_ns < ?",
                (obs_cutoff_ns,),
            )
            deleted["observation_events"] = cursor.rowcount
        except sqlite3.Error as e:
            logger.warning("Retention failed for observation_events: %s", e)
            deleted["observation_events"] = 0

        # Snapshot baselines and rollups: clean stale entries.
        # These tables each carry their own age column — none of them has
        # timestamp_ns. Deleting on the wrong name raised "no such column",
        # was swallowed below, and reported 0 rows pruned, so all three grew
        # unbounded (observation_rollups reached 10M rows / most of a 21GB
        # database) while retention reported success. All three store
        # nanoseconds, so cutoff_ns applies unchanged.
        age_column = {
            "_snapshot_baseline": "updated_ns",
            "dashboard_rollups": "updated_ns",
            "observation_rollups": "last_seen_ns",
        }
        for table, column in age_column.items():
            try:
                cursor = self._execute(
                    f"DELETE FROM [{table}] WHERE [{column}] < ?",
                    (cutoff_ns,),
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error as e:
                # A retention query that cannot run is a silent disk leak —
                # say so rather than reporting zero rows pruned.
                logger.warning("Retention failed for %s: %s", table, e)
                deleted[table] = 0

        # Telemetry receipts: the per-event delivery ledger. Every event that
        # reaches the store writes one row here, so it grows at the full
        # ingest rate — it reached 4,849,112 rows, the largest table in the
        # 23GB store that filled the disk and panicked the kernel. It had no
        # pruning path at all: the table is only ever INSERTed into and
        # SELECTed from, so unlike the tables above it never even failed
        # loudly, it was simply never considered.
        #
        # emitted_ns is the only always-populated timestamp (queued_ns/wal_ns/
        # persisted_ns are stage markers that stay NULL when an event skips or
        # fails a stage, which would make those rows permanently unprunable —
        # the exact bug the process_genealogy comment above documents). Rows
        # with a NULL/0 emitted_ns cannot be aged and would leak forever, so
        # they are pruned on the same cutoff rather than left behind.
        #
        # WITHOUT ROWID + composite PK, so batches are bounded by the PK, and
        # each batch commits on its own to keep the WAL small — a single
        # multi-million-row DELETE writes GBs of WAL before it can commit,
        # which on a nearly-full disk recreates the outage this prevents.
        RECEIPTS_BATCH = 100_000
        RECEIPTS_MAX_PER_PASS = 2_000_000
        r_pruned = 0
        try:
            while r_pruned < RECEIPTS_MAX_PER_PASS:
                cursor = self._execute(
                    "DELETE FROM telemetry_receipts WHERE (event_id, source_agent) IN ("
                    "  SELECT event_id, source_agent FROM telemetry_receipts"
                    "  WHERE COALESCE(emitted_ns, 0) < ? LIMIT ?)",
                    (cutoff_ns, RECEIPTS_BATCH),
                )
                n = cursor.rowcount
                if n <= 0:
                    break
                r_pruned += n
                self.db.commit()
                try:
                    self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")
                except sqlite3.Error:
                    pass
            deleted["telemetry_receipts"] = r_pruned
            if r_pruned >= RECEIPTS_MAX_PER_PASS:
                logger.info(
                    "telemetry_receipts retention hit the %d-row per-pass cap; "
                    "backlog continues draining next cycle",
                    RECEIPTS_MAX_PER_PASS,
                )
        except sqlite3.Error as e:
            logger.warning("Retention failed for telemetry_receipts: %s", e)
            deleted["telemetry_receipts"] = r_pruned

        # Process genealogy: trim processes not observed within the window.
        #
        # This previously deleted on `exit_ts`, a column that does not exist —
        # it is `exit_time_ns` — so the statement raised "no such column" on
        # every run, was swallowed, and reported 0 rows pruned. The table had
        # therefore never been pruned once and reached 31.3M rows, which was
        # substantially the entire 24GB database.
        #
        # Two further reasons not to simply rename the column here:
        #   - exit_time_ns is nanoseconds, but the old bound was epoch seconds,
        #     so every row would have compared as older than the cutoff.
        #   - exit_time_ns is only set when kqueue delivers NOTE_EXIT. Missed
        #     exits leave it NULL forever, and `exit_ts IS NOT NULL` made those
        #     rows permanently unprunable — unbounded growth even once fixed.
        #
        # last_seen_ns is NOT NULL and refreshed for every live process, so
        # "not seen within the retention window" is both always evaluable and
        # the correct semantic: live processes keep their rows, gone ones age out.
        # Deleted in bounded batches, not one statement. Because this never ran,
        # the first pass after the fix faces a backlog of ~20M rows; a single
        # transaction that large writes multiple GB of WAL before it can commit,
        # which on a nearly-full disk is how the outage this fix exists to
        # prevent happens again. Batches keep the WAL bounded and each commits
        # on its own. The per-pass cap lets a large backlog drain over several
        # cycles rather than stalling the analyzer in one very long delete.
        GENEALOGY_BATCH = 100_000
        GENEALOGY_MAX_PER_PASS = 2_000_000
        pruned = 0
        try:
            while pruned < GENEALOGY_MAX_PER_PASS:
                cursor = self._execute(
                    "DELETE FROM process_genealogy WHERE (device_id, pid, first_seen_ns) IN ("
                    "  SELECT device_id, pid, first_seen_ns FROM process_genealogy"
                    "  WHERE last_seen_ns < ? LIMIT ?)",
                    (cutoff_ns, GENEALOGY_BATCH),
                )
                n = cursor.rowcount
                if n <= 0:
                    break
                pruned += n
                self.db.commit()
                try:
                    self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")
                except sqlite3.Error:
                    pass
            deleted["process_genealogy"] = pruned
            if pruned >= GENEALOGY_MAX_PER_PASS:
                logger.info(
                    "process_genealogy retention hit the %d-row per-pass cap; "
                    "backlog continues draining next cycle",
                    GENEALOGY_MAX_PER_PASS,
                )
        except sqlite3.Error as e:
            logger.warning("Retention failed for process_genealogy: %s", e)
            deleted["process_genealogy"] = pruned

        self.db.commit()

        total = sum(deleted.values())
        if total > 0:
            logger.info(
                "Retention cleanup: deleted %d rows across %d tables (age > %dd, obs > %dd)",
                total,
                sum(1 for v in deleted.values() if v > 0),
                max_age_days,
                obs_age_days,
            )

        # Reclaim the freed pages back to the filesystem.
        #
        # PRAGMA incremental_vacuum is a SILENT NO-OP unless the database was
        # created with auto_vacuum=INCREMENTAL — it does not error, it simply
        # does nothing. auto_vacuum was never set anywhere in this tree, so
        # every retention pass logged "reclaimed space" while reclaiming none.
        # The measured result: the 23GB store carried 4,309,435 free pages —
        # 17.7GB, 73% of the file — that retention had already deleted but
        # SQLite never returned to the OS. The disk filled, macOS could not
        # write its 16.5GB hibernate image, and the kernel panicked.
        #
        # auto_vacuum can only be changed on an empty database or through a
        # full VACUUM, so schema creation now sets it (see _ts_schema.py) and
        # this verifies it actually took. A store that predates the fix keeps
        # leaking silently, so say so loudly and name the one-line remedy
        # rather than logging a success that never happens.
        if total > 10000:
            try:
                mode = self.db.execute("PRAGMA auto_vacuum").fetchone()[0]
                if mode == 2:  # INCREMENTAL
                    before = self.db.execute("PRAGMA freelist_count").fetchone()[0]
                    self.db.execute("PRAGMA incremental_vacuum(1000)")
                    after = self.db.execute("PRAGMA freelist_count").fetchone()[0]
                    page_sz = self.db.execute("PRAGMA page_size").fetchone()[0]
                    logger.info(
                        "Incremental vacuum: returned %.1f MB to the filesystem "
                        "(%d free pages remain) after %d deletes",
                        max(0, before - after) * page_sz / 1e6,
                        after,
                        total,
                    )
                else:
                    free = self.db.execute("PRAGMA freelist_count").fetchone()[0]
                    page_sz = self.db.execute("PRAGMA page_size").fetchone()[0]
                    logger.warning(
                        "auto_vacuum=%d (not INCREMENTAL): %d deleted rows freed "
                        "%.1f MB inside the file but NOTHING was returned to the "
                        "filesystem. This database predates the auto_vacuum fix. "
                        "Reclaim it once with: sqlite3 %s 'VACUUM;'",
                        mode,
                        total,
                        free * page_sz / 1e6,
                        self.db_path,
                    )
            except sqlite3.Error as e:
                logger.warning("Space reclamation check failed: %s", e)

        return deleted

    # ── Directive 4: AMRDR Agent Trust Cross-Validation ─────────────────

    _TRUST_WINDOW_SECONDS = 120

    _CROSS_VALIDATION_PAIRS = [
        (
            "fim",
            "process",
            """SELECT COUNT(*) FROM security_events se
               JOIN process_events pe
                 ON se.device_id = pe.device_id
                AND ABS(se.timestamp_ns - pe.timestamp_ns) < 5000000000
               WHERE se.timestamp_ns > ?
                 AND se.event_category = 'FILE_INTEGRITY'
                 AND pe.timestamp_ns > ?""",
        ),
        (
            "network",
            "dns",
            """SELECT COUNT(*) FROM flow_events fe
               JOIN observation_events oe
                 ON fe.device_id = oe.device_id
                AND fe.dst_ip IS NOT NULL
                AND oe.domain = 'dns'
                AND oe.attributes LIKE '%' || fe.dst_ip || '%'
                AND ABS(fe.timestamp_ns - oe.timestamp_ns) < 30000000000
               WHERE fe.timestamp_ns > ?
                 AND oe.timestamp_ns > ?""",
        ),
        (
            "auth",
            "process",
            """SELECT COUNT(*) FROM security_events se
               JOIN process_events pe
                 ON se.device_id = pe.device_id
                AND pe.timestamp_ns > se.timestamp_ns
                AND pe.timestamp_ns - se.timestamp_ns < 10000000000
               WHERE se.timestamp_ns > ?
                 AND se.event_category = 'AUTHENTICATION'
                 AND pe.timestamp_ns > ?""",
        ),
    ]

    def _update_agent_trust(self) -> None:
        """Cross-validate agents and update reliability trust scores."""
        if self._reliability is None:
            return

        cutoff_ns = int((time.time() - self._TRUST_WINDOW_SECONDS) * 1e9)
        updated = []

        with self._read_pool.connection() as rdb:
            for agent_a, agent_b, query in self._CROSS_VALIDATION_PAIRS:
                try:
                    row = rdb.execute(query, (cutoff_ns, cutoff_ns)).fetchone()
                    match_count = row[0] if row else 0

                    if match_count > 0:
                        self._reliability.update(agent_a, ground_truth_match=True)
                        self._reliability.update(agent_b, ground_truth_match=True)
                        updated.append(
                            f"{agent_a}↔{agent_b}:corroborate({match_count})"
                        )
                    else:
                        a_count = self._agent_event_count(rdb, agent_a, cutoff_ns)
                        b_count = self._agent_event_count(rdb, agent_b, cutoff_ns)

                        if a_count > 0 and b_count > 0:
                            pass
                except Exception:
                    logger.debug(
                        "Trust cross-validation %s↔%s failed",
                        agent_a,
                        agent_b,
                        exc_info=True,
                    )

            for agent_id in ("process", "filesystem", "network", "persistence"):
                try:
                    total = self._agent_event_count(rdb, agent_id, cutoff_ns)
                    sec_count = self._agent_security_count(rdb, agent_id, cutoff_ns)
                    if total > 0 and sec_count == 0:
                        self._reliability.update(agent_id, ground_truth_match=True)
                        updated.append(f"{agent_id}:quiet-corroborate")
                except Exception:
                    logger.debug(
                        "AMRDR corroboration failed for %s", agent_id, exc_info=True
                    )

        for agent_id in self._reliability.list_agents():
            try:
                drift_type, _ = self._reliability.detect_drift(agent_id)
                from amoskys.intel.reliability import DriftType

                if drift_type != DriftType.NONE:
                    tier = self._reliability.recalibrate(agent_id)
                    updated.append(f"{agent_id}:recal→{tier.name}")
            except Exception:
                logger.debug("AMRDR drift check failed for %s", agent_id, exc_info=True)

        if updated:
            logger.info("AMRDR trust update: %s", ", ".join(updated))

    def _agent_event_count(
        self, conn: sqlite3.Connection, agent_id: str, cutoff_ns: int
    ) -> int:
        """Count events from an agent domain in the recent window."""
        _AGENT_TABLE_MAP = {
            "process": ("process_events", "timestamp_ns > ?"),
            "fim": (
                "security_events",
                "timestamp_ns > ? AND event_category = 'FILE_INTEGRITY'",
            ),
            "filesystem": (
                "security_events",
                "timestamp_ns > ? AND event_category = 'FILE_INTEGRITY'",
            ),
            "network": ("flow_events", "timestamp_ns > ?"),
            "dns": ("observation_events", "timestamp_ns > ? AND domain = 'dns'"),
            "auth": (
                "security_events",
                "timestamp_ns > ? AND event_category = 'AUTHENTICATION'",
            ),
            "persistence": (
                "security_events",
                "timestamp_ns > ? AND event_category = 'PERSISTENCE'",
            ),
        }
        entry = _AGENT_TABLE_MAP.get(agent_id)
        if not entry:
            return 0
        table, where = entry
        row = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {where}", (cutoff_ns,)
        ).fetchone()
        return row[0] if row else 0

    def _agent_security_count(
        self, conn: sqlite3.Connection, agent_id: str, cutoff_ns: int
    ) -> int:
        """Count security-flagged events (risk_score > 0.3) for an agent."""
        _AGENT_SEC_MAP = {
            "process": ("process_events", "anomaly_score"),
            "network": ("flow_events", "threat_score"),
            "filesystem": ("security_events", None),
            "persistence": ("security_events", None),
        }
        entry = _AGENT_SEC_MAP.get(agent_id)
        if not entry:
            return 0
        table, score_col = entry
        if score_col:
            row = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ? AND {score_col} > 0.3",
                (cutoff_ns,),
            ).fetchone()
        else:
            row = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ? AND risk_score > 0.3",
                (cutoff_ns,),
            ).fetchone()
        return row[0] if row else 0

    # ══════════════════════════════════════════════════════════════════════
    # Telemetry Receipt Ledger — completeness verification
    # ══════════════════════════════════════════════════════════════════════

    def receipt_emit(
        self, event_id: str, source_agent: str, device_id: str = ""
    ) -> None:
        """Checkpoint 1: agent emitted the event."""
        now_ns = time.time_ns()
        with self._lock:
            self.db.execute(
                """INSERT OR IGNORE INTO telemetry_receipts
                   (event_id, source_agent, device_id, emitted_ns)
                   VALUES (?, ?, ?, ?)""",
                (event_id, source_agent, device_id, now_ns),
            )
            if not self._batch_mode:
                self.db.commit()

    def receipt_queued(self, event_id: str, source_agent: str) -> None:
        """Checkpoint 2: event entered the local queue."""
        now_ns = time.time_ns()
        with self._lock:
            self.db.execute(
                """INSERT INTO telemetry_receipts
                   (event_id, source_agent, queued_ns)
                   VALUES (?, ?, ?)
                   ON CONFLICT(event_id, source_agent) DO UPDATE
                   SET queued_ns = excluded.queued_ns""",
                (event_id, source_agent, now_ns),
            )
            if not self._batch_mode:
                self.db.commit()

    def receipt_wal(self, event_id: str, source_agent: str) -> None:
        """Checkpoint 3: WAL processor accepted the envelope."""
        now_ns = time.time_ns()
        with self._lock:
            self.db.execute(
                """INSERT INTO telemetry_receipts
                   (event_id, source_agent, wal_ns)
                   VALUES (?, ?, ?)
                   ON CONFLICT(event_id, source_agent) DO UPDATE
                   SET wal_ns = excluded.wal_ns""",
                (event_id, source_agent, now_ns),
            )
            if not self._batch_mode:
                self.db.commit()

    def receipt_persisted(
        self,
        event_id: str,
        source_agent: str,
        dest_table: str,
        quality_state: str = "valid",
    ) -> None:
        """Checkpoint 4: TelemetryStore committed to a domain table."""
        now_ns = time.time_ns()
        with self._lock:
            self.db.execute(
                """INSERT INTO telemetry_receipts
                   (event_id, source_agent, persisted_ns, dest_table, quality_state)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(event_id, source_agent) DO UPDATE
                   SET persisted_ns = excluded.persisted_ns,
                       dest_table   = excluded.dest_table,
                       quality_state = excluded.quality_state""",
                (event_id, source_agent, now_ns, dest_table, quality_state),
            )
            if not self._batch_mode:
                self.db.commit()

    def receipt_reconcile(self, source_agent: str = "") -> dict:
        """IGRIS reconciliation: compare counts at each pipeline boundary."""
        agent_filter = ""
        params: tuple = ()
        if source_agent:
            agent_filter = "WHERE source_agent = ?"
            params = (source_agent,)

        with self._lock:
            row = self.db.execute(
                f"""SELECT
                    COUNT(emitted_ns)   AS emitted,
                    COUNT(queued_ns)    AS queued,
                    COUNT(wal_ns)       AS wal_processed,
                    COUNT(persisted_ns) AS persisted
                FROM telemetry_receipts {agent_filter}""",
                params,
            ).fetchone()

            result = {
                "source_agent": source_agent or "all",
                "emitted": row["emitted"],
                "queued": row["queued"],
                "wal_processed": row["wal_processed"],
                "persisted": row["persisted"],
                "gaps": [],
            }

            if source_agent:
                missing_sql = """
                    SELECT event_id, source_agent,
                        emitted_ns, queued_ns, wal_ns, persisted_ns
                    FROM telemetry_receipts
                    WHERE source_agent = ?
                    AND persisted_ns IS NULL
                    AND emitted_ns IS NOT NULL
                    ORDER BY emitted_ns DESC LIMIT 100"""
            else:
                missing_sql = """
                    SELECT event_id, source_agent,
                        emitted_ns, queued_ns, wal_ns, persisted_ns
                    FROM telemetry_receipts
                    WHERE persisted_ns IS NULL
                    AND emitted_ns IS NOT NULL
                    ORDER BY emitted_ns DESC LIMIT 100"""
            missing_rows = self.db.execute(missing_sql, params).fetchall()

            if missing_rows:
                emit_only = []
                queue_only = []
                wal_only = []
                for r in missing_rows:
                    eid = r["event_id"]
                    if r["wal_ns"] and not r["persisted_ns"]:
                        wal_only.append(eid)
                    elif r["queued_ns"] and not r["wal_ns"]:
                        queue_only.append(eid)
                    elif r["emitted_ns"] and not r["queued_ns"]:
                        emit_only.append(eid)

                if emit_only:
                    result["gaps"].append(
                        {
                            "boundary": "emit→queue",
                            "missing": len(emit_only),
                            "event_ids": emit_only[:10],
                        }
                    )
                if queue_only:
                    result["gaps"].append(
                        {
                            "boundary": "queue→wal",
                            "missing": len(queue_only),
                            "event_ids": queue_only[:10],
                        }
                    )
                if wal_only:
                    result["gaps"].append(
                        {
                            "boundary": "wal→persist",
                            "missing": len(wal_only),
                            "event_ids": wal_only[:10],
                        }
                    )

            return result

    # ══════════════════════════════════════════════════════════════════════
    # Process Genealogy — durable spawn chain
    # ══════════════════════════════════════════════════════════════════════

    def upsert_genealogy(self, entry: dict) -> None:
        """Insert or update a process genealogy record.

        The ON CONFLICT target below is the full primary key
        (device_id, pid, first_seen_ns), but first_seen_ns defaulted to
        time.time_ns() on every call — so the conflict could never fire and
        this "upsert" appended a fresh row for every live process on every
        pass. Measured after a clean restart: 42,644 rows for 920 distinct
        PIDs, ~59 rows per process, growing 11,715 rows/min — 97% of all row
        growth in the store, and the dominant cause of the 23GB database that
        filled the disk.

        A process incarnation is (device_id, pid, create_time); create_time is
        what distinguishes a reused PID from the original. So resolve
        first_seen_ns from the row already recorded for that incarnation and
        let the conflict clause do its job. Callers that pass an explicit
        first_seen_ns still win, and a genuinely new process falls back to now.
        """
        now_ns = time.time_ns()
        # The stored row wins over whatever the caller passed. Every caller
        # (_wal_observations.py:146, _wal_security.py:738) supplies
        # "first_seen_ns": ts_ns — the timestamp of the CURRENT observation —
        # because that is the only time it knows. But first_seen_ns means "the
        # first time this incarnation was ever seen", and it is part of the
        # primary key, so taking the caller's value made every observation a
        # new row. Consulting the table first is the only way to get it right:
        # the caller's value is the fallback for a process we have never seen,
        # not an override for one we have.
        #
        # CAST(? AS REAL) is load-bearing, not defensive tidiness. create_time
        # reaches these callers straight out of the agents' JSON attributes,
        # where it is a STRING ("1785739194.770593"). The column has REAL
        # affinity so it is stored as a float, but SQLite applies no affinity
        # when comparing a column against a bound parameter: REAL = TEXT is
        # simply false, forever. Without the cast this lookup missed on every
        # call, which is exactly how the "already fixed" dedup kept producing
        # 61 rows per PID with a single distinct create_time. Verified both
        # ways in isolation: float param -> 1 row, string param -> 30 rows.
        # Bounded in-memory index over the incarnation key, so the steady state
        # is O(1) instead of a SELECT per upsert.
        #
        # The lookup below is correct but ran on EVERY call — and this is the
        # hottest write path in the store (one upsert per live process per
        # collection cycle, ~900 processes). That is ~900 extra queries per
        # cycle to answer a question whose answer never changes for the life of
        # a process: an incarnation's first_seen_ns is immutable once set.
        #
        # Cache it. A miss falls through to the same query, so correctness is
        # unchanged; only the repeat cost disappears. Bounded by _GENEALOGY_CACHE_MAX
        # with cheap FIFO eviction — a full re-scan costs one query per evicted
        # process, never a stall, and PIDs churn so the working set is small.
        ck = (entry["device_id"], entry["pid"], entry.get("create_time"))
        cache = getattr(self, "_genealogy_first_seen", None)
        if cache is None:
            cache = self._genealogy_first_seen = {}
        first_seen = cache.get(ck)
        if first_seen is None:
            row = self.db.execute(
                "SELECT MIN(first_seen_ns) FROM process_genealogy "
                "WHERE device_id = ? AND pid = ? "
                "AND IFNULL(create_time, -1) = IFNULL(CAST(? AS REAL), -1)",
                (entry["device_id"], entry["pid"], entry.get("create_time")),
            ).fetchone()
            first_seen = (
                (row[0] if row else None) or entry.get("first_seen_ns") or now_ns
            )
            if len(cache) >= _GENEALOGY_CACHE_MAX:
                # Drop the oldest inserted key; dicts preserve insertion order.
                cache.pop(next(iter(cache)), None)
            cache[ck] = first_seen
        with self._lock:
            self.db.execute(
                """INSERT INTO process_genealogy
                   (device_id, pid, ppid, name, exe, cmdline, username,
                    parent_name, create_time, exit_time_ns, exit_status,
                    code_signing, is_alive, first_seen_ns, last_seen_ns,
                    process_guid)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(device_id, pid, first_seen_ns) DO UPDATE SET
                    ppid        = COALESCE(excluded.ppid, ppid),
                    name        = COALESCE(excluded.name, name),
                    exe         = COALESCE(excluded.exe, exe),
                    cmdline     = COALESCE(excluded.cmdline, cmdline),
                    username    = COALESCE(excluded.username, username),
                    parent_name = COALESCE(excluded.parent_name, parent_name),
                    exit_time_ns = COALESCE(excluded.exit_time_ns, exit_time_ns),
                    exit_status  = COALESCE(excluded.exit_status, exit_status),
                    code_signing = COALESCE(excluded.code_signing, code_signing),
                    is_alive     = excluded.is_alive,
                    last_seen_ns = excluded.last_seen_ns,
                    process_guid = COALESCE(excluded.process_guid, process_guid)
                """,
                (
                    entry["device_id"],
                    entry["pid"],
                    entry.get("ppid"),
                    entry.get("name"),
                    entry.get("exe"),
                    entry.get("cmdline"),
                    entry.get("username"),
                    entry.get("parent_name"),
                    entry.get("create_time"),
                    entry.get("exit_time_ns"),
                    entry.get("exit_status"),
                    entry.get("code_signing"),
                    entry.get("is_alive", True),
                    first_seen,
                    entry.get("last_seen_ns", now_ns),
                    entry.get("process_guid"),
                ),
            )
            if not self._batch_mode:
                self.db.commit()

    def mark_process_exited(
        self,
        device_id: str,
        pid: int,
        exit_time_ns: int,
        exit_status: int | None = None,
    ) -> None:
        """Mark a process as exited in the genealogy table."""
        with self._lock:
            self.db.execute(
                """UPDATE process_genealogy
                   SET is_alive = 0,
                       exit_time_ns = ?,
                       exit_status = COALESCE(?, exit_status),
                       last_seen_ns = ?
                   WHERE device_id = ? AND pid = ? AND is_alive = 1""",
                (exit_time_ns, exit_status, exit_time_ns, device_id, pid),
            )
            if not self._batch_mode:
                self.db.commit()

    def sweep_stale_processes(
        self,
        device_id: str,
        live_pids: set[int],
        sweep_time_ns: int,
    ) -> int:
        """Mark processes as exited if they weren't seen in the latest collection."""
        with self._lock:
            rows = self.db.execute(
                "SELECT pid FROM process_genealogy "
                "WHERE device_id = ? AND is_alive = 1",
                (device_id,),
            ).fetchall()

            stale_pids = [r["pid"] for r in rows if r["pid"] not in live_pids]
            if not stale_pids:
                return 0

            self.db.executemany(
                """UPDATE process_genealogy
                   SET is_alive = 0,
                       exit_time_ns = ?,
                       last_seen_ns = ?
                   WHERE device_id = ? AND pid = ? AND is_alive = 1""",
                [(sweep_time_ns, sweep_time_ns, device_id, pid) for pid in stale_pids],
            )
            if not self._batch_mode:
                self.db.commit()
            return len(stale_pids)

    def get_spawn_chain(
        self, device_id: str, pid: int, max_depth: int = 10
    ) -> list[dict]:
        """Walk the genealogy tree upward from a PID to its root ancestor."""
        chain = []
        current_pid = pid
        seen = set()
        with self._lock:
            for _ in range(max_depth):
                if current_pid in seen or current_pid <= 0:
                    break
                seen.add(current_pid)
                row = self.db.execute(
                    """SELECT pid, ppid, name, exe, cmdline, username,
                              parent_name, create_time, exit_time_ns,
                              exit_status, code_signing, is_alive,
                              first_seen_ns, process_guid
                       FROM process_genealogy
                       WHERE device_id = ? AND pid = ?
                       ORDER BY first_seen_ns DESC LIMIT 1""",
                    (device_id, current_pid),
                ).fetchone()
                if not row:
                    break
                chain.append(dict(row))
                current_pid = row["ppid"] or 0
        return chain

    def get_children(self, device_id: str, pid: int) -> list[dict]:
        """Get all child processes of a PID from the genealogy table."""
        with self._lock:
            rows = self.db.execute(
                """SELECT pid, name, exe, cmdline, username, create_time,
                          is_alive, exit_time_ns, process_guid
                   FROM process_genealogy
                   WHERE device_id = ? AND ppid = ?
                   ORDER BY first_seen_ns DESC""",
                (device_id, pid),
            ).fetchall()
            return [dict(r) for r in rows]

    def close(self) -> None:
        """Close database connection and evict this store from the instance cache.

        TelemetryStore interns instances per (realpath, readonly) so one process
        keeps exactly one connection per store. Eviction here is what makes that
        safe: without it, a caller that closed the store would leave the dead
        object in the cache and the next construction would hand back a handle
        whose connection is already closed, failing with "Cannot operate on a
        closed database" far from the cause.

        Also clears _initialized so a subsequent construction of the same path
        performs a real __init__ rather than short-circuiting on the flag.
        """
        try:
            self.db.close()
        finally:
            key = getattr(self, "_singleton_key", None)
            if key is not None:
                cls = type(self)
                with cls._instances_lock:
                    if cls._instances.get(key) is self:
                        del cls._instances[key]
            self._initialized = False
