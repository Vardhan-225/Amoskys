#!/usr/bin/env python3
"""
WAL Processor - Moves data from WAL queue to permanent storage

This processor runs continuously, draining events from the EventBus WAL
and storing them in the permanent telemetry database for dashboard queries.
"""

import hashlib
import json
import logging
import os
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from amoskys.enrichment import EnrichmentPipeline
from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.models import TelemetryEventView
from amoskys.intel.scoring import ScoringEngine
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.storage._wal_enrichment import EnrichmentMixin
from amoskys.storage._wal_observations import ObservationMixin

# Mixin modules
from amoskys.storage._wal_quality import QualityMixin
from amoskys.storage._wal_routing import RoutingMixin
from amoskys.storage._wal_security import SecurityMixin
from amoskys.storage.dedup import EventDeduplicator
from amoskys.storage.observation_shaper import ObservationShaper
from amoskys.storage.telemetry_store import TelemetryStore

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WALProcessor")


class WALProcessor(
    QualityMixin,
    RoutingMixin,
    ObservationMixin,
    SecurityMixin,
    EnrichmentMixin,
):
    """Processes events from WAL to permanent storage"""

    _ALLOWED_EVENT_TYPES = frozenset(
        {
            "METRIC",
            "LOG",
            "ALARM",
            "STATUS",
            "SECURITY",
            "AUDIT",
            "OBSERVATION",
            "FLOW",
            "PROCESS",
            "DEVICE_TELEMETRY",
            "DEVICE_EVENT",
            "TELEMETRY_BATCH",
        }
    )
    _ALLOWED_SEVERITY = frozenset(
        {"DEBUG", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN", "ERROR"}
    )
    _ALLOWED_DEVICE_TYPES = frozenset(
        {"HOST", "IOT", "MEDICAL", "INDUSTRIAL", "ENDPOINT", "NETWORK", "UNKNOWN"}
    )

    def __init__(
        self,
        wal_path: str = "data/wal/flowagent.db",
        store_path: str = "data/telemetry.db",
    ):
        """Initialize processor

        Args:
            wal_path: Path to WAL database
            store_path: Path to permanent telemetry store
        """
        self.wal_path = wal_path
        self.store = TelemetryStore(store_path)
        self.processed_count = 0
        self.error_count = 0
        self.quarantine_count = 0
        self.chain_break_count = 0

        # A4.4: Enrichment pipeline (GeoIP → ASN → ThreatIntel → MITRE)
        try:
            self._pipeline = EnrichmentPipeline()
            logger.info("Enrichment pipeline initialized: %s", self._pipeline.status())
        except Exception as e:
            logger.warning("Enrichment pipeline unavailable: %s", e)
            self._pipeline = None

        # Scoring engine for signal/noise classification
        try:
            self._scorer = ScoringEngine()
            logger.info(
                "ScoringEngine initialized (signal/noise classification active)"
            )
        except Exception as e:
            logger.warning("ScoringEngine unavailable: %s", e)
            self._scorer = None

        # Event deduplication (BLAKE2b content-hash, configurable TTL)
        dedup_ttl = int(os.environ.get("DEDUP_TTL_SECONDS", "300"))
        self._dedup = EventDeduplicator(ttl_seconds=dedup_ttl, max_cache=50000)
        self._observation_shaper = ObservationShaper()

        # SOMA: FusionEngine for single-device correlation
        # AMRDR: Use BayesianReliabilityTracker for trust-weighted fusion
        try:
            from amoskys.intel.reliability import BayesianReliabilityTracker

            amrdr_tracker = BayesianReliabilityTracker(
                store_path="data/intel/reliability.db"
            )
            logger.info("AMRDR BayesianReliabilityTracker activated")
        except Exception as e:
            from amoskys.intel.reliability import NoOpReliabilityTracker

            amrdr_tracker = NoOpReliabilityTracker()
            logger.warning("AMRDR unavailable, using NoOp: %s", e)
        try:
            self._fusion = FusionEngine(
                db_path="data/intel/fusion.db",
                reliability_tracker=amrdr_tracker,
            )
            logger.info("FusionEngine initialized (correlation active)")
        except Exception as e:
            logger.warning("FusionEngine unavailable: %s", e)
            self._fusion = None
        self._last_fusion_eval = 0.0
        self._fusion_eval_interval = 60  # seconds between correlation evaluations
        self._bridged_incident_ids: set = set()
        self._fusion_thread: threading.Thread | None = None

        # SOMA Brain: autonomous self-training ML engine
        self._brain = None
        try:
            from amoskys.intel.soma_brain import SomaBrain

            self._brain = SomaBrain(
                telemetry_db_path=store_path,
                scoring_engine=self._scorer,
            )
            logger.info("SomaBrain initialized (autonomous training active)")
        except Exception as e:
            logger.warning("SomaBrain unavailable: %s", e)

    def process_batch(self, batch_size: int = 500) -> int:
        """Process a batch of events from WAL with BLAKE2b integrity verification.

        Each event's checksum is verified before processing. Events that fail
        checksum verification are quarantined to the dead letter table with the
        error reason, preserving the original bytes for forensic analysis.

        Uses batch mode for database commits — a single commit per batch
        instead of per-event, reducing I/O by 10-50x.

        Args:
            batch_size: Number of events to process in one batch (max 2000)

        Returns:
            Number of events successfully processed

        Raises:
            sqlite3.OperationalError: If WAL database is locked or corrupt
        """
        batch_size = min(
            batch_size, 2000
        )  # Cap batch size to prevent resource exhaustion
        conn = None
        try:
            # Connect to WAL database
            conn = sqlite3.connect(self.wal_path, timeout=5.0)

            # Check if chain columns exist (legacy WALs may not have them)
            cols = {row[1] for row in conn.execute("PRAGMA table_info(wal)").fetchall()}
            has_chain = "sig" in cols and "prev_sig" in cols

            if has_chain:
                cursor = conn.execute(
                    "SELECT id, bytes, ts_ns, idem, checksum, sig, prev_sig "
                    "FROM wal ORDER BY id LIMIT ?",
                    (batch_size,),
                )
            else:
                cursor = conn.execute(
                    "SELECT id, bytes, ts_ns, idem, checksum "
                    "FROM wal ORDER BY id LIMIT ?",
                    (batch_size,),
                )
            rows = cursor.fetchall()

            if not rows:
                conn.close()
                return 0

            processed_ids = []
            processed = 0

            # Batch mode: single commit for all inserts in this batch
            self.store.begin_batch()

            for row in rows:
                row_id, env_bytes, ts_ns, idem, stored_checksum = row[:5]
                stored_sig = row[5] if len(row) > 5 else None
                stored_prev_sig = row[6] if len(row) > 6 else None
                raw = bytes(env_bytes)

                # ── P0-S2: BLAKE2b verification before processing ──
                if stored_checksum is not None:
                    stored_cs = bytes(stored_checksum)
                    expected = hashlib.blake2b(raw, digest_size=32).digest()

                    if len(stored_cs) != 32:
                        logger.error(
                            "CHECKSUM_INVALID_SIZE: WAL row %d has %d-byte checksum "
                            "(expected 32), quarantining",
                            row_id,
                            len(stored_cs),
                        )
                        self._quarantine(row_id, raw, "invalid checksum size")
                        processed_ids.append(row_id)
                        continue

                    if stored_cs != expected:
                        logger.error(
                            "CHECKSUM_MISMATCH: WAL row %d data corrupted, quarantining",
                            row_id,
                        )
                        self._quarantine(row_id, raw, "BLAKE2b checksum mismatch")
                        processed_ids.append(row_id)
                        continue

                # ── A2.2: Hash chain verification ──
                if stored_sig is not None and stored_prev_sig is not None:
                    prev = bytes(stored_prev_sig)
                    expected_sig = hashlib.blake2b(raw + prev, digest_size=32).digest()
                    if bytes(stored_sig) != expected_sig:
                        logger.error(
                            "CHAIN_BREAK: WAL row %d hash chain signature "
                            "mismatch — possible tampering, quarantining",
                            row_id,
                        )
                        self._quarantine(row_id, raw, "hash chain signature mismatch")
                        self.chain_break_count += 1
                        processed_ids.append(row_id)
                        continue

                try:
                    # Parse envelope
                    envelope = telemetry_pb2.UniversalEnvelope()
                    envelope.ParseFromString(raw)

                    self._store_envelope_truth(
                        envelope=envelope,
                        raw_bytes=raw,
                        ts_ns=ts_ns,
                        idem=idem,
                        wal_row_id=row_id,
                        wal_checksum=stored_checksum,
                        wal_sig=stored_sig,
                        wal_prev_sig=stored_prev_sig,
                    )

                    # Process based on content type
                    if envelope.HasField("device_telemetry"):
                        self._process_device_telemetry(
                            envelope.device_telemetry, ts_ns, idem
                        )
                    elif envelope.HasField("process"):
                        self._process_process_event(envelope.process, ts_ns, idem)
                    elif envelope.HasField("flow"):
                        self._process_flow_event(envelope.flow, ts_ns)

                    processed_ids.append(row_id)
                    processed += 1

                except Exception as e:
                    logger.error(f"Failed to process WAL entry {row_id}: {e}")
                    self.error_count += 1
                    # ── P0-S1: Dead letter quarantine instead of silent loss ──
                    self._quarantine(row_id, raw, str(e))
                    processed_ids.append(row_id)

            # Flush all buffered inserts with a single commit
            try:
                self.store.end_batch()
            except Exception as e:
                logger.error("Batch commit failed: %s", e)
                # On commit failure, don't ACK WAL entries — they'll retry
                return 0

            # Delete processed entries from WAL (ACK-after-store)
            if processed_ids:
                placeholders = ",".join("?" * len(processed_ids))
                conn.execute(
                    f"DELETE FROM wal WHERE id IN ({placeholders})", processed_ids
                )
                conn.commit()

            conn.close()
            conn = None
            self.processed_count += processed
            return processed

        except sqlite3.OperationalError as e:
            # Database locked or corrupt — propagate so caller can back off
            logger.error(f"WAL database error: {e}")
            raise
        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            return 0
        finally:
            # Ensure batch mode is exited even on error
            if self.store._batch_mode:
                self.store._batch_mode = False
                self.store._batch_count = 0
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    logger.debug("WAL connection close failed", exc_info=True)

    def _quarantine(self, row_id: int, raw_bytes: bytes, error_msg: str) -> None:
        """Move a failed WAL entry to the dead letter table.

        Preserves the original bytes for forensic analysis and replay.
        If quarantine itself fails, the entry stays in WAL for retry.

        Args:
            row_id: WAL row identifier
            raw_bytes: Original envelope bytes
            error_msg: Description of failure
        """
        try:
            reason_code = self._classify_reason_code(error_msg)
            replay_cmd = (
                "python -m amoskys.storage.wal_processor "
                f"--replay-dead-letter --row-id {row_id}"
            )
            self.store.db.execute(
                "INSERT INTO wal_dead_letter "
                "(row_id, error_msg, reason_code, replay_cmd, envelope_bytes, "
                "quarantined_at, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row_id,
                    error_msg,
                    reason_code,
                    replay_cmd,
                    raw_bytes,
                    datetime.now(timezone.utc).isoformat(),
                    "wal_processor",
                ),
            )
            self.store.db.commit()
            self.quarantine_count += 1
        except Exception as dl_err:
            logger.error(f"Failed to quarantine WAL entry {row_id}: {dl_err}")

    @staticmethod
    def _classify_reason_code(error_msg: str) -> str:
        """Classify dead-letter reason into stable reason codes."""
        msg = (error_msg or "").lower()
        if "checksum" in msg:
            return "CHECKSUM_FAILURE"
        if "hash chain" in msg or "chain" in msg:
            return "CHAIN_INTEGRITY_FAILURE"
        if "parse" in msg or "protobuf" in msg:
            return "PROTO_PARSE_FAILURE"
        if "signature" in msg:
            return "SIGNATURE_FAILURE"
        return "PROCESSING_FAILURE"

    def process_local_queues(
        self,
        queue_dir: str = "data/queue",
        max_entries: int | None = None,
        max_seconds: float | None = None,
    ) -> int:
        """Drain agent local queues directly into TelemetryStore.

        When EventBus is not running, agents buffer DeviceTelemetry in local
        SQLite queues (data/queue/<agent>.db). This method reads those queues
        and feeds the protobuf through the same routing logic as process_batch(),
        populating device_telemetry, security_events, peripheral_events, etc.

        Args:
            queue_dir: Directory containing agent queue .db files.
            max_entries: Optional maximum number of queue entries to process
                across all queue files for this drain cycle.
            max_seconds: Optional timeout budget for this drain cycle.

        Returns:
            Total number of events processed across all queues.
        """
        import glob

        if max_entries is not None and max_entries <= 0:
            max_entries = None

        queue_files = sorted(glob.glob(f"{queue_dir}/*.db"))
        total_processed = 0
        remaining = max_entries
        stopped_for_limit = False
        stopped_for_timeout = False
        deadline = (
            time.monotonic() + max_seconds
            if max_seconds is not None and max_seconds > 0
            else None
        )

        for qf in queue_files:
            if remaining is not None and remaining <= 0:
                stopped_for_limit = True
                break
            if deadline is not None and time.monotonic() >= deadline:
                stopped_for_timeout = True
                break

            agent_name = Path(qf).stem
            conn = None
            try:
                conn = sqlite3.connect(qf, timeout=5.0)

                query = "SELECT id, ts_ns, bytes FROM queue ORDER BY id"
                params = []
                if remaining is not None:
                    query += " LIMIT ?"
                    params.append(remaining)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                if not rows:
                    continue

                processed_ids = []
                for row_id, ts_ns, payload_bytes in rows:
                    if deadline is not None and time.monotonic() >= deadline:
                        stopped_for_timeout = True
                        break

                    try:
                        dt = telemetry_pb2.DeviceTelemetry()
                        dt.ParseFromString(bytes(payload_bytes))
                        self._process_device_telemetry(
                            dt, ts_ns, f"local-queue-{agent_name}-{row_id}"
                        )
                        processed_ids.append(row_id)
                    except Exception as e:
                        logger.error(
                            "Failed to process queue entry %s/%d: %s",
                            agent_name,
                            row_id,
                            e,
                        )
                        self.error_count += 1
                        self._quarantine(
                            row_id,
                            bytes(payload_bytes),
                            str(e),
                        )
                        processed_ids.append(row_id)

                # Remove processed entries from queue
                if processed_ids:
                    placeholders = ",".join("?" * len(processed_ids))
                    conn.execute(
                        f"DELETE FROM queue WHERE id IN ({placeholders})",
                        processed_ids,
                    )
                    conn.commit()

                count = len(processed_ids)
                total_processed += count
                if remaining is not None:
                    remaining -= count
                logger.info("Drained %d events from %s", count, agent_name)

                if remaining is not None and remaining <= 0:
                    pending = conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
                    if pending > 0:
                        logger.warning(
                            "Queue drain budget exhausted for %s (%d entries pending)",
                            agent_name,
                            pending,
                        )
                    stopped_for_limit = True

            except Exception as e:
                logger.error("Failed to process queue %s: %s", qf, e)
            finally:
                if conn is not None:
                    conn.close()

            if stopped_for_timeout or stopped_for_limit:
                break

        if stopped_for_timeout:
            logger.warning(
                "Stopped local queue drain after timeout budget (%ss)",
                max_seconds,
            )
        if stopped_for_limit:
            logger.warning(
                "Stopped local queue drain after reaching max_entries=%s",
                max_entries,
            )

        return total_processed

    def run(self, interval: int = 5) -> None:
        """Run processor in continuous loop

        Args:
            interval: Seconds between processing batches
        """
        logger.info("WAL Processor starting...")
        logger.info(f"WAL: {self.wal_path}")
        logger.info(f"Store: {self.store.db_path}")
        logger.info(f"Interval: {interval}s")

        # Start SomaBrain daemon thread
        if self._brain:
            self._brain.start()
            logger.info(
                "SomaBrain daemon started (training every %ds)", self._brain._interval
            )

        cycle = 0
        retention_interval = (
            720  # Run retention cleanup every 720 cycles (~1 hour at 5s)
        )
        while True:
            cycle += 1
            try:
                # Process EventBus WAL (batch mode: single commit per batch)
                processed = self.process_batch(batch_size=500)

                # Also drain agent local queues (data/queue/*.db)
                queue_processed = self.process_local_queues("data/queue")
                processed += queue_processed

                if processed > 0:
                    logger.info(
                        f"Cycle #{cycle}: Processed {processed} events "
                        f"(total: {self.processed_count}, errors: {self.error_count})"
                    )
                elif cycle % 12 == 0:  # Log every minute when idle
                    logger.debug(f"Cycle #{cycle}: No events to process")

                # SOMA: Periodic fusion evaluation (every 60s, async)
                now = time.time()
                if (
                    self._fusion
                    and (now - self._last_fusion_eval) >= self._fusion_eval_interval
                    and (
                        self._fusion_thread is None
                        or not self._fusion_thread.is_alive()
                    )
                ):
                    self._last_fusion_eval = now
                    self._fusion_thread = threading.Thread(
                        target=self._run_fusion_eval, daemon=True
                    )
                    self._fusion_thread.start()

                # Periodic stale process sweep (every ~5 min)
                if cycle % 60 == 0:
                    self._sweep_stale_processes()

                # Periodic data retention cleanup
                if cycle % retention_interval == 0:
                    try:
                        self.store.cleanup_old_data(max_age_days=90)
                    except Exception as e:
                        logger.warning("Retention cleanup error: %s", e)

                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Cycle error: {e}")
                time.sleep(interval)

        # Stop SomaBrain daemon
        if self._brain:
            self._brain.stop()

        # Show final stats
        stats = self.store.get_statistics()
        logger.info(f"Final statistics: {stats}")
        self.store.close()
        if self._pipeline is not None:
            self._pipeline.close()

    def backfill_enrichment(self, batch_size: int = 500) -> int:
        """One-time enrichment backfill for historical events missing enrichment.

        Reads events where enrichment_status IS NULL or 'raw', runs them
        through the EnrichmentPipeline, and updates both the JSON indicators
        column and the dedicated enrichment columns.

        Returns:
            Total number of events updated.
        """
        if self._pipeline is None:
            logger.error("EnrichmentPipeline unavailable — cannot backfill")
            return 0

        total_updated = 0
        while True:
            rows = self.store.db.execute(
                "SELECT id, indicators FROM security_events "
                "WHERE enrichment_status IS NULL OR enrichment_status = 'raw' "
                "LIMIT ?",
                (batch_size,),
            ).fetchall()

            if not rows:
                break

            for row in rows:
                row_id = row[0]
                indicators_json = row[1]
                try:
                    indicators = json.loads(indicators_json) if indicators_json else {}
                except (json.JSONDecodeError, TypeError):
                    indicators = {}

                try:
                    self._pipeline.enrich(indicators)
                except Exception:
                    indicators["enrichment_status"] = "raw"

                geo_country = indicators.get("geo_src_country") or indicators.get(
                    "geo_dst_country"
                )
                asn_org = indicators.get("asn_src_org") or indicators.get("asn_dst_org")
                self.store.db.execute(
                    "UPDATE security_events SET "
                    "indicators=?, enrichment_status=?, "
                    "threat_intel_match=?, geo_src_country=?, asn_src_org=? "
                    "WHERE id=?",
                    (
                        json.dumps(indicators),
                        indicators.get("enrichment_status", "raw"),
                        indicators.get("threat_intel_match", False),
                        geo_country,
                        asn_org,
                        row_id,
                    ),
                )
                total_updated += 1

            self.store.db.commit()
            logger.info(
                "Backfill batch: updated %d events (total: %d)",
                len(rows),
                total_updated,
            )

        logger.info("Enrichment backfill complete: %d events updated", total_updated)
        return total_updated


def main():
    """Entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS WAL Processor")
    parser.add_argument(
        "--backfill-enrichment",
        action="store_true",
        help="One-time enrichment backfill for historical events",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Processing interval in seconds (default: 5)",
    )
    args = parser.parse_args()

    processor = WALProcessor()

    if args.backfill_enrichment:
        count = processor.backfill_enrichment()
        print(f"Enrichment backfill complete: {count} events updated")
        return

    processor.run(interval=args.interval)


if __name__ == "__main__":
    main()
