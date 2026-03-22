"""Lifecycle, dedup, batch, receipt, genealogy, and cleanup mixin for TelemetryStore."""

from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("TelemetryStore")


class LifecycleMixin:
    """Batch mode, snapshot dedup, baselines, cleanup, receipts, genealogy, close."""

    # ── Batch API (used by WALProcessor for single-commit batches) ──

    def begin_batch(self) -> None:
        """Enter batch mode — per-insert commits are suppressed."""
        self._batch_mode = True
        self._batch_count = 0

    def end_batch(self) -> None:
        """Commit all buffered inserts and leave batch mode."""
        try:
            self.db.commit()
        finally:
            self._batch_mode = False
            self._batch_count = 0
            self._cache.invalidate()

    def _commit(self) -> None:
        """Commit unless in batch mode."""
        if self._batch_mode:
            self._batch_count += 1
            return
        self.db.commit()
        self._cache.invalidate()

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

    def cleanup_old_data(self, max_age_days: int = 90) -> Dict[str, int]:
        """Delete telemetry data older than max_age_days."""
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

        for table in tables_ns:
            try:
                cursor = self.db.execute(
                    f"DELETE FROM {table} WHERE timestamp_ns < ?", (cutoff_ns,)
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error:
                deleted[table] = 0

        for table in tables_dt:
            try:
                cursor = self.db.execute(
                    f"DELETE FROM {table} WHERE timestamp_dt < ?", (cutoff_dt,)
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error:
                deleted[table] = 0

        short_cutoff_dt = datetime.fromtimestamp(
            time.time() - 30 * 86400, tz=timezone.utc
        ).isoformat()
        for table in ["wal_dead_letter", "wal_archive"]:
            try:
                cursor = self.db.execute(
                    f"DELETE FROM {table} WHERE quarantined_at < ? OR created_at < ?",
                    (short_cutoff_dt, short_cutoff_dt),
                )
                deleted[table] = cursor.rowcount
            except sqlite3.Error:
                deleted[table] = 0

        self.db.commit()

        total = sum(deleted.values())
        if total > 0:
            logger.info(
                "Retention cleanup: deleted %d rows across %d tables (age > %dd)",
                total,
                sum(1 for v in deleted.values() if v > 0),
                max_age_days,
            )
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
        """Insert or update a process genealogy record."""
        now_ns = time.time_ns()
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
                    entry.get("first_seen_ns", now_ns),
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
        """Close database connection."""
        self.db.close()
