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
from amoskys.storage.dedup import EventDeduplicator
from amoskys.storage.observation_shaper import ObservationShaper
from amoskys.storage.telemetry_store import TelemetryStore

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WALProcessor")


class WALProcessor:
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
                    pass

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

    def _extract_metrics(self, events: List[Any]) -> tuple:
        """Extract aggregate metrics from TelemetryEvent list.

        Returns:
            (total_processes, cpu_percent, mem_percent)
        """
        total_processes = 0
        cpu_percent = 0.0
        mem_percent = 0.0

        for event in events:
            if event.event_type != "METRIC" or not event.HasField("metric_data"):
                continue
            metric = event.metric_data
            if metric.metric_name == "process_count":
                total_processes = int(metric.numeric_value)
            elif metric.metric_name == "system_cpu_percent":
                cpu_percent = metric.numeric_value
            elif metric.metric_name == "system_memory_percent":
                mem_percent = metric.numeric_value

        return total_processes, cpu_percent, mem_percent

    @staticmethod
    def _payload_kind(envelope: telemetry_pb2.UniversalEnvelope) -> str:
        if envelope.HasField("device_telemetry"):
            return "device_telemetry"
        if envelope.HasField("process"):
            return "process"
        if envelope.HasField("flow"):
            return "flow"
        if envelope.HasField("telemetry_batch"):
            return "telemetry_batch"
        return "unknown"

    @staticmethod
    def _quality_rank(quality_state: str) -> int:
        order = {"valid": 0, "degraded": 1, "invalid": 2}
        return order.get((quality_state or "valid").lower(), 0)

    def _evaluate_event_contract(
        self,
        event: Any,
        *,
        device_type: str,
        collection_agent: str,
        annotate: bool = True,
    ) -> tuple[str, str, list[str]]:
        """Evaluate one TelemetryEvent against runtime contract rules."""
        attrs = event.attributes
        missing_required: list[str] = []
        missing_degraded: list[str] = []
        violation_code = "NONE"

        event_type = (event.event_type or "").upper()
        severity = (event.severity or "").upper()
        dev_type = (device_type or "UNKNOWN").upper()

        if not event.event_id:
            missing_degraded.append("event_id")
        if not event.event_type:
            missing_required.append("event_type")
        if not event.severity:
            missing_degraded.append("severity")
        if not event.event_timestamp_ns:
            missing_degraded.append("event_timestamp_ns")
        if not event.source_component and not event.probe_class:
            missing_degraded.append("probe_name")

        if event_type and event_type not in self._ALLOWED_EVENT_TYPES:
            missing_required.append(f"event_type:{event_type}")
            violation_code = "CONTRACT_UNKNOWN_EVENT_TYPE"
        if severity and severity not in self._ALLOWED_SEVERITY:
            missing_required.append(f"severity:{severity}")
            violation_code = "CONTRACT_UNKNOWN_SEVERITY"
        if dev_type and dev_type not in self._ALLOWED_DEVICE_TYPES:
            missing_required.append(f"device_type:{dev_type}")
            violation_code = "CONTRACT_UNKNOWN_DEVICE_TYPE"

        if event_type == "OBSERVATION":
            domain = (attrs.get("_domain", "") or "").strip().lower()
            if domain not in self._OBSERVATION_ROUTERS:
                missing_required.append(f"_domain:{domain or 'missing'}")
                violation_code = "CONTRACT_UNKNOWN_OBSERVATION_DOMAIN"

        probe_name = event.probe_class or event.source_component
        if probe_name:
            try:
                from amoskys.observability.probe_registry import (
                    get_probe_contract_registry,
                )

                registry = get_probe_contract_registry()
                contract = registry.get_contract(probe_name)
                if contract is not None:
                    # NOTE: requires_fields describes probe *input* context
                    # (shared_data keys), not required *output* event attributes.
                    # Treat all probe contract fields as degraded, not invalid.
                    all_contract_fields = set(contract.requires_fields) | set(
                        contract.degraded_without
                    )
                    for field_name in sorted(all_contract_fields):
                        if field_name not in attrs:
                            missing_degraded.append(f"probe:{field_name}")
            except Exception:
                pass

        existing_quality = (attrs.get("quality_state", "valid") or "valid").lower()
        existing_violation = attrs.get("contract_violation_code", "NONE")
        existing_missing_raw = attrs.get("missing_fields", "")
        existing_missing = [m for m in existing_missing_raw.split(",") if m]

        quality_state = "valid"
        if missing_required:
            quality_state = "invalid"
            if violation_code == "NONE":
                violation_code = "CONTRACT_MISSING_REQUIRED_FIELDS"
        elif missing_degraded:
            quality_state = "degraded"
            if violation_code == "NONE":
                violation_code = "CONTRACT_DEGRADED_FIELDS"

        if self._quality_rank(existing_quality) > self._quality_rank(quality_state):
            quality_state = existing_quality
            if existing_violation and existing_violation != "NONE":
                violation_code = existing_violation

        missing_fields = sorted(
            set(existing_missing + missing_required + missing_degraded)
        )
        if quality_state == "valid":
            violation_code = "NONE"

        if annotate:
            attrs["quality_state"] = quality_state
            attrs["contract_violation_code"] = violation_code
            if missing_fields:
                attrs["missing_fields"] = ",".join(missing_fields)
            elif "missing_fields" in attrs:
                del attrs["missing_fields"]
            if quality_state != "valid":
                attrs["training_exclude"] = "true"

        return quality_state, violation_code, missing_fields

    def _extract_quality(
        self,
        envelope: telemetry_pb2.UniversalEnvelope,
    ) -> tuple[str, str, str]:
        """Read envelope contract quality by aggregating all contained events."""
        if not envelope.HasField("device_telemetry"):
            return "valid", "NONE", ""
        dt = envelope.device_telemetry
        if not dt.events:
            return "degraded", "CONTRACT_EMPTY_EVENTS", "events"

        overall_quality = "valid"
        overall_violation = "NONE"
        missing: list[str] = []
        for event in dt.events:
            quality, violation, missing_fields = self._evaluate_event_contract(
                event,
                device_type=dt.device_type,
                collection_agent=dt.collection_agent,
                annotate=True,
            )
            if self._quality_rank(quality) > self._quality_rank(overall_quality):
                overall_quality = quality
                overall_violation = violation
            missing.extend(missing_fields)

        return overall_quality, overall_violation, ",".join(sorted(set(missing)))

    def _store_envelope_truth(
        self,
        *,
        envelope: telemetry_pb2.UniversalEnvelope,
        raw_bytes: bytes,
        ts_ns: int,
        idem: str,
        wal_row_id: int,
        wal_checksum: bytes | None,
        wal_sig: bytes | None,
        wal_prev_sig: bytes | None,
    ) -> None:
        """Persist canonical envelope metadata into telemetry_events."""
        try:
            payload_kind = self._payload_kind(envelope)
            quality_state, violation, missing = self._extract_quality(envelope)
            device_id = (
                envelope.device_telemetry.device_id
                if envelope.HasField("device_telemetry")
                else ""
            )
            agent_id = (
                envelope.device_telemetry.collection_agent
                if envelope.HasField("device_telemetry")
                else ""
            )
            probe_name = ""
            event_type = payload_kind.upper()
            probe_version = envelope.version or "unknown"
            device_type = "UNKNOWN"
            if envelope.HasField("device_telemetry"):
                dt = envelope.device_telemetry
                device_type = dt.device_type or "UNKNOWN"
                probe_version = dt.agent_version or probe_version
                if dt.events:
                    first_event = dt.events[0]
                    probe_name = (
                        first_event.probe_class
                        or first_event.source_component
                        or dt.collection_agent
                    )
                    event_type = first_event.event_type or event_type
            elif envelope.HasField("flow"):
                probe_name = "legacy_flow_probe"
                event_type = "FLOW"
            elif envelope.HasField("process"):
                probe_name = "legacy_process_probe"
                event_type = "PROCESS"

            event_id = envelope.idempotency_key or idem
            self.store.insert_telemetry_event(
                {
                    "event_id": event_id,
                    "idempotency_key": idem,
                    "timestamp_ns": ts_ns,
                    "ingest_timestamp_ns": int(time.time() * 1e9),
                    "timestamp_dt": datetime.fromtimestamp(
                        ts_ns / 1e9, tz=timezone.utc
                    ).isoformat(),
                    "device_id": device_id,
                    "agent_id": agent_id,
                    "probe_name": probe_name,
                    "probe_version": probe_version,
                    "event_type": event_type,
                    "device_type": device_type,
                    "payload_kind": payload_kind,
                    "schema_version": int(envelope.schema_version or 1),
                    "quality_state": quality_state,
                    "contract_violation_code": violation,
                    "missing_fields": missing,
                    "envelope_bytes": raw_bytes,
                    "wal_row_id": wal_row_id,
                    "wal_checksum": (
                        bytes(wal_checksum) if wal_checksum is not None else None
                    ),
                    "wal_sig": bytes(wal_sig) if wal_sig is not None else None,
                    "wal_prev_sig": (
                        bytes(wal_prev_sig) if wal_prev_sig is not None else None
                    ),
                }
            )

            # Receipt ledger checkpoint 3: WAL accepted the envelope
            self.store.receipt_wal(event_id, agent_id or "unknown")

        except Exception:
            logger.debug("Failed to persist canonical telemetry event", exc_info=True)

    def _feed_fusion_engine(self, events: Any, device_id: str) -> None:
        """Convert protobuf TelemetryEvents to TelemetryEventView and feed to FusionEngine.

        Args:
            events: List of protobuf TelemetryEvent messages
            device_id: Device that generated these events
        """
        if self._fusion is None:
            return
        fed = 0
        for event in events:
            try:
                view = TelemetryEventView.from_protobuf(event, device_id)
                self._fusion.add_event(view)
                fed += 1
            except Exception as e:
                logger.debug("Fusion feed skip: %s", e)
        if fed > 0:
            logger.debug("Fed %d events to FusionEngine for %s", fed, device_id)

    def _hydrate_bridged_ids(self) -> None:
        """Load already-bridged fusion incident IDs from the dashboard DB.

        Survives process restarts — reads the indicators JSON column to find
        fusion_incident_id values that were previously bridged.
        """
        if self._bridged_incident_ids:
            return
        try:
            import json as _json

            rows = self.store.db.execute(
                "SELECT indicators FROM incidents WHERE indicators LIKE '%fusion_incident_id%'"
            ).fetchall()
            for (raw,) in rows:
                ind = _json.loads(raw) if isinstance(raw, str) else raw
                fid = ind.get("fusion_incident_id") if isinstance(ind, dict) else None
                if fid:
                    self._bridged_incident_ids.add(fid)
        except Exception:
            pass  # Table may not have indicators column yet

    def _bridge_fusion_incidents(self) -> None:
        """Copy new FusionEngine incidents to TelemetryStore for dashboard visibility.

        FusionEngine persists to fusion.db; the dashboard reads from telemetry.db.
        This method bridges the gap by creating TelemetryStore incidents from
        newly detected fusion incidents, with dedup tracking.
        """
        if self._fusion is None:
            return

        self._hydrate_bridged_ids()
        recent = self._fusion.get_recent_incidents(limit=50)

        bridged = 0
        for inc in recent:
            fid = inc["incident_id"]
            if fid in self._bridged_incident_ids:
                continue
            try:
                self.store.create_incident(
                    {
                        "title": f"[{inc['rule_name']}] {inc['summary'][:120]}",
                        "description": inc["summary"],
                        "severity": inc["severity"].lower(),
                        "source_event_ids": inc["event_ids"],
                        "mitre_techniques": inc["techniques"],
                        "indicators": {
                            "rule_name": inc["rule_name"],
                            "tactics": inc["tactics"],
                            "weighted_confidence": inc.get("weighted_confidence", 1.0),
                            "contributing_agents": inc.get("contributing_agents", []),
                            "fusion_incident_id": fid,
                        },
                    }
                )
                self._bridged_incident_ids.add(fid)
                bridged += 1

                # Back-label contributing events as high-trust for SOMA training.
                # Events that contributed to a fusion incident get label_source='incident'
                # so GradientBoostingClassifier can train on analyst-grade labels (G2).
                self._label_incident_events(inc.get("event_ids", []))
            except Exception as e:
                logger.error("Failed to bridge incident %s: %s", fid, e)
        if bridged > 0:
            logger.info("Bridged %d fusion incidents to dashboard", bridged)

    def _label_incident_events(self, event_ids: list) -> None:
        """Back-label events that contributed to a fusion incident.

        Sets label_source='incident' on matching security_events rows so SOMA's
        GradientBoostingClassifier can use them as high-trust training labels (G2).
        """
        if not event_ids:
            return
        try:
            # event_ids may contain duplicates and non-string types
            unique_ids = list({str(eid) for eid in event_ids if eid})
            if not unique_ids:
                return

            # Match by event_id column in security_events
            placeholders = ",".join("?" for _ in unique_ids)
            updated = self.store.db.execute(
                f"UPDATE security_events SET label_source = 'incident' "
                f"WHERE event_id IN ({placeholders}) "
                f"AND (label_source IS NULL OR label_source = '' OR label_source = 'heuristic')",
                unique_ids,
            ).rowcount
            if updated > 0:
                self.store.db.commit()
                logger.info(
                    "SOMA label: marked %d events as label_source='incident'",
                    updated,
                )
        except Exception as e:
            logger.debug("Failed to back-label incident events: %s", e)

    def _run_fusion_eval(self) -> None:
        """Run fusion evaluation + incident bridging in a background thread.

        This prevents the correlation engine from blocking the main
        WAL processing loop, which is critical for throughput at 2M+ events/day.
        """
        if self._fusion is None:
            return
        try:
            self._fusion.evaluate_all_devices()
            self._bridge_fusion_incidents()
        except Exception as e:
            logger.error("Async fusion evaluation failed: %s", e)

    def _sweep_stale_processes(self) -> None:
        """Mark processes as exited if they no longer appear in the OS process table.

        Runs periodically (~every 5 min) to catch exits missed by the realtime
        sensor (e.g., sensor not running, kqueue fd limit, race conditions).
        """
        try:
            import psutil

            live_pids = set(psutil.pids())
            rows = self.store.db.execute(
                "SELECT DISTINCT device_id FROM process_genealogy " "WHERE is_alive = 1"
            ).fetchall()
            total_swept = 0
            for row in rows:
                total_swept += self.store.sweep_stale_processes(
                    row["device_id"],
                    live_pids,
                    time.time_ns(),
                )
            if total_swept > 0:
                logger.info(
                    "Genealogy sweep: marked %d processes as exited", total_swept
                )
        except Exception as e:
            logger.debug("Stale process sweep failed: %s", e)

    # Domain routers for OBSERVATION events → domain tables
    # P1/P2 domains have dedicated tables; P3 domains use generic observation_events
    _OBSERVATION_ROUTERS = {
        # P1/P2: dedicated domain tables
        "process": "_insert_process_observation",
        "flow": "_insert_flow_observation",
        "dns": "_insert_dns_observation",
        "auth": "_insert_auth_observation",
        "filesystem": "_insert_fim_observation",
        "persistence": "_insert_persistence_observation",
        "peripheral": "_insert_peripheral_observation",
        # P3: generic observation_events table
        "applog": "_insert_generic_observation",
        "db_activity": "_insert_generic_observation",
        "discovery": "_insert_generic_observation",
        "http": "_insert_generic_observation",
        "internet_activity": "_insert_generic_observation",
        "security_monitor": "_insert_generic_observation",
        "unified_log": "_insert_generic_observation",
        # macOS Shield agents
        "infostealer": "_insert_generic_observation",
        "quarantine": "_insert_generic_observation",
        "provenance": "_insert_generic_observation",
        # Event-driven / sentinel agents
        "network_sentinel": "_insert_generic_observation",
        "realtime_sensor": "_insert_generic_observation",
    }

    # Receipt ledger: domain → destination table name
    _OBSERVATION_DEST_TABLE = {
        "process": "process_events",
        "flow": "flow_events",
        "dns": "dns_events",
        "auth": "audit_events",
        "filesystem": "fim_events",
        "persistence": "persistence_events",
        "peripheral": "observation_events",
        "applog": "observation_events",
        "db_activity": "observation_events",
        "discovery": "observation_events",
        "http": "observation_events",
        "internet_activity": "observation_events",
        "security_monitor": "observation_events",
        "unified_log": "observation_events",
        "infostealer": "observation_events",
        "quarantine": "observation_events",
        "provenance": "observation_events",
        "network_sentinel": "observation_events",
        "realtime_sensor": "observation_events",
    }

    def _route_events(
        self,
        events: List[Any],
        device_id: str,
        ts_ns: int,
        timestamp_dt: str,
        collection_agent: str,
        agent_version: str,
        device_type: str = "UNKNOWN",
    ) -> None:
        """Route individual TelemetryEvents to the correct table processors."""
        for event in events:
            quality_state, _, _ = self._evaluate_event_contract(
                event,
                device_type=device_type,
                collection_agent=collection_agent,
                annotate=True,
            )
            if quality_state == "invalid":
                logger.warning(
                    "Dropping invalid-quality event before routing: type=%s source=%s",
                    event.event_type,
                    event.source_component,
                )
                continue
            if quality_state == "degraded":
                event.attributes["training_exclude"] = "true"

            # OBSERVATION events → domain tables directly (raw observability)
            # Bypass dedup and scoring — these are raw collector data, not detections
            if event.event_type == "OBSERVATION":
                self._route_observation(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    agent_version,
                )
                continue

            # Peripheral STATUS events → peripheral_events table
            if (
                event.event_type == "STATUS"
                and event.source_component == "peripheral_agent"
            ):
                self._process_peripheral_event(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    agent_version,
                )

            # SecurityEvent sub-message → security_events table
            if event.HasField("security_event"):
                # Extract and enrich attrs ONCE before both consumers
                enriched_attrs = {k: event.attributes[k] for k in event.attributes}
                if self._pipeline is not None:
                    try:
                        self._pipeline.enrich(enriched_attrs)
                    except Exception:
                        logger.debug(
                            "Enrichment failed for event — continuing",
                            exc_info=True,
                        )

                self._process_security_event(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    enriched_attrs=enriched_attrs,
                )
                self._route_security_to_domain_tables(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    agent_version,
                    enriched_attrs=enriched_attrs,
                )

    # Agent-name tokens that map to each domain extractor.
    _PROCESS_AGENTS = frozenset(
        {
            "proc-agent",
            "proc_agent",
            "proc",
            "macos_process",
            "process",
            "realtime_sensor",
        }
    )
    _FLOW_TOKENS = frozenset({"flow", "network"})
    _FIM_TOKENS = frozenset({"fim", "filesystem"})

    def _agent_matches(self, collection_agent: str, tokens: frozenset) -> bool:
        """Check if collection_agent contains any of the given tokens."""
        return any(tok in collection_agent for tok in tokens)

    def _route_security_to_domain_tables(
        self,
        event,
        device_id,
        ts_ns,
        timestamp_dt,
        collection_agent,
        agent_version,
        enriched_attrs: dict | None = None,
    ) -> None:
        """Extract structured data from security events into domain-specific tables."""
        if enriched_attrs is not None:
            attrs = enriched_attrs
        else:
            attrs = {k: event.attributes[k] for k in event.attributes}

        se = event.security_event
        cat = se.event_category or ""
        mitre = list(se.mitre_techniques) if se.mitre_techniques else []

        self._dispatch_domain_extraction(
            attrs,
            se,
            cat,
            mitre,
            device_id,
            ts_ns,
            timestamp_dt,
            collection_agent,
            agent_version,
        )

    def _dispatch_domain_extraction(
        self,
        attrs,
        se,
        cat,
        mitre,
        device_id,
        ts_ns,
        timestamp_dt,
        collection_agent,
        agent_version,
    ) -> None:
        """Dispatch to domain-specific extractors based on agent and attributes."""
        common = (device_id, ts_ns, timestamp_dt, collection_agent, agent_version)

        if attrs.get("pid") and collection_agent in self._PROCESS_AGENTS:
            self._extract_process_from_security(attrs, *common, cat)

        if attrs.get("dst_ip") and self._agent_matches(
            collection_agent, self._FLOW_TOKENS
        ):
            self._extract_flow_from_security(attrs, device_id, ts_ns, timestamp_dt)

        if "usb" in cat or "peripheral" in collection_agent:
            self._extract_peripheral_from_security(attrs, *common)

        if "dns" in collection_agent or attrs.get("domain"):
            self._extract_dns_from_security(attrs, se, *common, cat, mitre)

        if "kernel" in collection_agent or cat.startswith("kernel_"):
            self._extract_audit_from_security(attrs, se, *common, cat, mitre)

        if self._is_persistence_event(collection_agent, cat, mitre):
            self._extract_persistence_from_security(attrs, se, *common, cat, mitre)

        if self._agent_matches(collection_agent, self._FIM_TOKENS) and attrs.get(
            "path"
        ):
            self._extract_fim_from_security(attrs, se, *common, cat, mitre)

    # Persistence probe name prefixes — matches macos_launchagent, macos_cron, etc.
    _PERSISTENCE_PROBE_PREFIXES = (
        "macos_launchagent",
        "macos_launchdaemon",
        "macos_login_item",
        "macos_cron",
        "macos_shell_profile",
        "macos_ssh_key",
        "macos_auth_plugin",
        "macos_folder_action",
        "macos_system_extension",
        "macos_periodic_script",
    )
    # MITRE techniques that indicate persistence regardless of source agent
    _PERSISTENCE_TECHNIQUES = frozenset(
        {
            "T1543",
            "T1543.001",
            "T1543.004",  # Launch Agent/Daemon
            "T1053",
            "T1053.003",  # Cron
            "T1546",
            "T1546.004",
            "T1546.015",  # Shell profile, folder action
            "T1547",
            "T1547.002",
            "T1547.015",  # Login items, system ext
            "T1098",
            "T1098.004",  # SSH authorized keys
        }
    )

    def _is_persistence_event(
        self, collection_agent: str, cat: str, mitre: list
    ) -> bool:
        """Check if an event should route to persistence_events.

        Matches by:
          1. Agent name contains "persistence"
          2. Category starts with a known persistence probe prefix
          3. Any MITRE technique is persistence-related (T1543, T1053, etc.)
        """
        if "persistence" in collection_agent:
            return True
        if "persistence_" in cat:
            return True
        if any(cat.startswith(prefix) for prefix in self._PERSISTENCE_PROBE_PREFIXES):
            return True
        if mitre and self._PERSISTENCE_TECHNIQUES.intersection(mitre):
            return True
        return False

    def _route_observation(
        self,
        event,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Route OBSERVATION events to domain-specific tables.

        Observations are raw collector data — no dedup, no scoring, no security_event.
        They go directly to domain tables with event_source='observation'.
        Flow/DNS observations get enrichment (GeoIP/ASN) before storage.
        """
        attrs = {k: event.attributes[k] for k in event.attributes}
        domain = attrs.get("_domain", "")
        router = self._OBSERVATION_ROUTERS.get(domain)
        if router:
            try:
                decision = self._observation_shaper.decide(domain, attrs, ts_ns)
                if not decision.store_raw:
                    self.store.upsert_observation_rollup(
                        {
                            "window_start_ns": decision.window_start_ns,
                            "window_end_ns": decision.window_end_ns,
                            "domain": decision.domain,
                            "fingerprint": decision.fingerprint,
                            "sample_attributes": {
                                k: v for k, v in attrs.items() if not k.startswith("_")
                            },
                            "total_count": 1,
                            "first_seen_ns": ts_ns,
                            "last_seen_ns": ts_ns,
                            "device_id": device_id,
                            "collection_agent": agent,
                        }
                    )
                    return
                getattr(self, router)(
                    attrs, device_id, ts_ns, timestamp_dt, agent, version
                )
                # Receipt ledger checkpoint 4: persisted to domain table
                event_id = event.event_id
                if event_id:
                    dest = self._OBSERVATION_DEST_TABLE.get(
                        domain, "observation_events"
                    )
                    try:
                        self.store.receipt_persisted(
                            event_id,
                            agent,
                            dest,
                            attrs.get("quality_state", "valid"),
                        )
                    except Exception:
                        pass
            except Exception as e:
                logger.error("Observation routing failed for domain=%s: %s", domain, e)
        else:
            logger.debug("No observation router for domain=%s", domain)

    @staticmethod
    def _quality_payload(attrs: dict[str, Any]) -> dict[str, Any]:
        quality_state = attrs.get("quality_state", "valid")
        training_exclude = (
            str(attrs.get("training_exclude", "")).lower()
            in {
                "true",
                "1",
                "yes",
            }
            or quality_state != "valid"
        )
        missing = attrs.get("missing_fields", "")
        return {
            "quality_state": quality_state,
            "training_exclude": training_exclude,
            "contract_violation_code": attrs.get("contract_violation_code", "NONE"),
            "missing_fields": missing,
            "raw_attributes_json": json.dumps(
                {k: v for k, v in attrs.items() if not k.startswith("_")},
                sort_keys=True,
            ),
        }

    def _insert_process_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert raw process observation into process_events."""
        quality = self._quality_payload(attrs)
        username = attrs.get("username", "")
        if username == "root":
            user_type = "root"
        elif username:
            user_type = "user"
        else:
            user_type = "unknown"

        pid = int(attrs["pid"]) if attrs.get("pid") else None
        ppid = int(attrs["ppid"]) if attrs.get("ppid") else None
        create_time = float(attrs["create_time"]) if attrs.get("create_time") else None

        self.store.insert_process_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "pid": pid,
                "ppid": ppid,
                "name": attrs.get("name", ""),
                "parent_name": attrs.get("parent_name", ""),
                "exe": attrs.get("exe", ""),
                "cmdline": attrs.get("cmdline", ""),
                "username": username,
                "cpu_percent": (
                    float(attrs["cpu_percent"]) if attrs.get("cpu_percent") else None
                ),
                "memory_percent": (
                    float(attrs["memory_percent"])
                    if attrs.get("memory_percent")
                    else None
                ),
                "num_threads": int(attrs.get("num_threads", 0)) or None,
                "num_fds": int(attrs.get("num_fds", 0)) or None,
                "user_type": user_type,
                "process_category": "observed",
                "is_suspicious": False,
                "create_time": create_time,
                "status": attrs.get("status", ""),
                "cwd": attrs.get("cwd", ""),
                "is_own_user": attrs.get("is_own_user", "False") == "True",
                "process_guid": attrs.get("process_guid", ""),
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
            }
        )

        # Feed process genealogy — durable spawn chain
        if pid is not None:
            try:
                self.store.upsert_genealogy(
                    {
                        "device_id": device_id,
                        "pid": pid,
                        "ppid": ppid,
                        "name": attrs.get("name", ""),
                        "exe": attrs.get("exe", ""),
                        "cmdline": attrs.get("cmdline", ""),
                        "username": username,
                        "parent_name": attrs.get("parent_name", ""),
                        "create_time": create_time,
                        "is_alive": True,
                        "first_seen_ns": ts_ns,
                        "last_seen_ns": ts_ns,
                        "process_guid": attrs.get("process_guid", ""),
                    }
                )
            except Exception:
                logger.debug("Genealogy upsert failed for PID %s", pid, exc_info=True)

    # Socket states that are NOT real traffic — filter at WAL level as defense-in-depth
    _LISTEN_STATES = frozenset({"LISTEN", "NONE", ""})

    def _insert_flow_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert raw flow observation into flow_events with GeoIP/ASN enrichment.

        Filters out LISTEN/bind sockets — they're socket inventory, not traffic.
        Defense-in-depth: agents should also filter, but WAL catches stragglers.
        """
        state = (attrs.get("state") or "").strip().upper()
        dst_ip = (attrs.get("dst_ip") or "").strip()
        # Drop LISTEN/bind sockets and entries with no destination
        if state in ("LISTEN", "NONE", "") or not dst_ip:
            return

        quality = self._quality_payload(attrs)
        # Enrich flow observations (GeoIP + ASN for dst_ip)
        if self._pipeline is not None:
            try:
                self._pipeline.enrich(attrs)
            except Exception:
                logger.debug("Enrichment failed for flow observation", exc_info=True)

        self.store.insert_flow_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "src_ip": attrs.get("src_ip"),
                "dst_ip": attrs.get("dst_ip"),
                "src_port": int(attrs["src_port"]) if attrs.get("src_port") else None,
                "dst_port": int(attrs["dst_port"]) if attrs.get("dst_port") else None,
                "protocol": attrs.get("protocol"),
                "pid": int(attrs["pid"]) if attrs.get("pid") else None,
                "process_name": attrs.get("process_name"),
                "conn_user": attrs.get("conn_user"),
                "state": attrs.get("state"),
                "bytes_tx": int(attrs["bytes_tx"]) if attrs.get("bytes_tx") else None,
                "bytes_rx": int(attrs["bytes_rx"]) if attrs.get("bytes_rx") else None,
                "is_suspicious": False,
                "threat_score": 0.0,
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
                # GeoIP enrichment
                "geo_src_country": attrs.get("geo_src_country"),
                "geo_src_city": attrs.get("geo_src_city"),
                "geo_src_latitude": attrs.get("geo_src_latitude"),
                "geo_src_longitude": attrs.get("geo_src_longitude"),
                "geo_dst_country": attrs.get("geo_dst_country"),
                "geo_dst_city": attrs.get("geo_dst_city"),
                "geo_dst_latitude": attrs.get("geo_dst_latitude"),
                "geo_dst_longitude": attrs.get("geo_dst_longitude"),
                # ASN enrichment
                "asn_src_number": attrs.get("asn_src_number"),
                "asn_src_org": attrs.get("asn_src_org"),
                "asn_src_network_type": attrs.get("asn_src_network_type"),
                "asn_dst_number": attrs.get("asn_dst_number"),
                "asn_dst_org": attrs.get("asn_dst_org"),
                "asn_dst_network_type": attrs.get("asn_dst_network_type"),
                # ThreatIntel enrichment
                "threat_intel_match": attrs.get("threat_intel_match", False),
                "threat_source": attrs.get("threat_source"),
                "threat_severity": attrs.get("threat_severity"),
            }
        )

    def _insert_dns_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert raw DNS observation into dns_events."""
        quality = self._quality_payload(attrs)
        domain = attrs.get("domain", "")
        if not domain:
            return

        self.store.insert_dns_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "domain": domain,
                "query_type": attrs.get("query_type"),
                "response_code": attrs.get("response_code"),
                "source_ip": None,
                "process_name": attrs.get("source_process"),
                "pid": int(attrs["source_pid"]) if attrs.get("source_pid") else None,
                "event_type": "observation",
                "response_ips": attrs.get("response_ips"),
                "ttl": int(attrs["ttl"]) if attrs.get("ttl") else None,
                "response_size": (
                    int(attrs["response_size"]) if attrs.get("response_size") else None
                ),
                "is_reverse": attrs.get("is_reverse", "False") == "True",
                "dga_score": None,
                "is_beaconing": False,
                "is_tunneling": False,
                "risk_score": 0.0,
                "confidence": 0.0,
                "mitre_techniques": [],
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
            }
        )

    def _insert_auth_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert raw auth observation into audit_events."""
        quality = self._quality_payload(attrs)
        self.store.insert_audit_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "host": device_id,
                "syscall": "",
                "event_type": attrs.get("event_type", "observation"),
                "pid": None,
                "ppid": None,
                "uid": None,
                "euid": None,
                "gid": None,
                "egid": None,
                "exe": attrs.get("process", ""),
                "comm": attrs.get("process", ""),
                "cmdline": attrs.get("message", ""),
                "cwd": None,
                "target_path": None,
                "target_pid": None,
                "target_comm": None,
                "risk_score": 0.0,
                "confidence": 0.0,
                "mitre_techniques": [],
                "reason": attrs.get("category", ""),
                "source_ip": attrs.get("source_ip"),
                "username": attrs.get("username"),
                "collector_timestamp": attrs.get("timestamp"),
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
            }
        )

    def _insert_fim_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert raw filesystem observation into fim_events."""
        quality = self._quality_payload(attrs)
        self.store.insert_fim_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "event_type": "observation",
                "path": attrs.get("path", ""),
                "change_type": "snapshot",
                "old_hash": None,
                "new_hash": attrs.get("sha256", ""),
                "old_mode": None,
                "new_mode": attrs.get("mode"),
                "file_extension": (
                    attrs.get("name", "").rsplit(".", 1)[-1]
                    if "." in attrs.get("name", "")
                    else None
                ),
                "owner_uid": int(attrs["uid"]) if attrs.get("uid") else None,
                "owner_gid": None,
                "is_suid": attrs.get("is_suid", "False") == "True",
                "mtime": float(attrs["mtime"]) if attrs.get("mtime") else None,
                "size": int(attrs["size"]) if attrs.get("size") else None,
                "risk_score": 0.0,
                "confidence": 0.0,
                "mitre_techniques": [],
                "reason": None,
                "patterns_matched": [],
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
            }
        )

    def _insert_persistence_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert raw persistence observation into persistence_events."""
        quality = self._quality_payload(attrs)
        self.store.insert_persistence_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "event_type": "observation",
                "mechanism": attrs.get("category", ""),
                "entry_id": attrs.get("name", ""),
                "path": attrs.get("path", ""),
                "command": attrs.get("program", ""),
                "schedule": None,
                "user": None,
                "change_type": "snapshot",
                "old_command": None,
                "new_command": None,
                "content_hash": attrs.get("content_hash", ""),
                "program": attrs.get("program", ""),
                "label": attrs.get("label", ""),
                "run_at_load": attrs.get("run_at_load", "False") == "True",
                "keep_alive": attrs.get("keep_alive", "False") == "True",
                "risk_score": 0.0,
                "confidence": 0.0,
                "mitre_techniques": [],
                "reason": None,
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
            }
        )

    def _insert_peripheral_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert raw peripheral observation into peripheral_events."""
        quality = self._quality_payload(attrs)
        self.store.insert_peripheral_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "peripheral_device_id": f"{attrs.get('vendor_id', '')}:{attrs.get('product_id', '')}",
                "event_type": "OBSERVATION",
                "device_name": attrs.get("name", ""),
                "device_type": attrs.get("device_type", "UNKNOWN").upper(),
                "vendor_id": attrs.get("vendor_id"),
                "product_id": attrs.get("product_id"),
                "serial_number": attrs.get("serial"),
                "manufacturer": attrs.get("manufacturer"),
                "address": attrs.get("address"),
                "connection_status": (
                    "CONNECTED"
                    if attrs.get("connected", "True") == "True"
                    else "DISCONNECTED"
                ),
                "is_authorized": True,
                "risk_score": 0.0,
                "is_storage": attrs.get("is_storage", "False") == "True",
                "mount_point": attrs.get("mount_point", ""),
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
            }
        )

    def _insert_generic_observation(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Insert P3 domain observation into generic observation_events table."""
        quality = self._quality_payload(attrs)
        domain = attrs.get("_domain", "unknown")
        # Remove internal routing hint from stored attributes
        clean_attrs = {k: v for k, v in attrs.items() if not k.startswith("_")}
        self.store.insert_observation_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "domain": domain,
                "event_type": "observation",
                "attributes": clean_attrs,
                "risk_score": 0.0,
                "event_source": "observation",
                "collection_agent": agent,
                "agent_version": version,
                **quality,
            }
        )

    def _process_device_telemetry(
        self, dt: telemetry_pb2.DeviceTelemetry, ts_ns: int, idem: str
    ) -> None:
        """Process DeviceTelemetry message"""
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()

        # Extract aggregate metrics
        total_processes, cpu_percent, mem_percent = self._extract_metrics(dt.events)

        # Route individual events to their target tables
        self._route_events(
            dt.events,
            dt.device_id,
            ts_ns,
            timestamp_dt,
            dt.collection_agent,
            dt.agent_version,
            dt.device_type or "UNKNOWN",
        )

        # SOMA: Feed events to FusionEngine for correlation
        self._feed_fusion_engine(dt.events, dt.device_id)

        # Store device telemetry
        try:
            self.store.db.execute(
                """
                INSERT OR REPLACE INTO device_telemetry (
                    timestamp_ns, timestamp_dt, device_id, device_type, protocol,
                    manufacturer, model, ip_address, total_processes,
                    total_cpu_percent, total_memory_percent, metric_events,
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    ts_ns,
                    timestamp_dt,
                    dt.device_id,
                    dt.device_type,
                    dt.protocol,
                    dt.metadata.manufacturer if dt.HasField("metadata") else None,
                    dt.metadata.model if dt.HasField("metadata") else None,
                    dt.metadata.ip_address if dt.HasField("metadata") else None,
                    total_processes,
                    cpu_percent,
                    mem_percent,
                    len(dt.events),
                    dt.collection_agent,
                    dt.agent_version,
                ),
            )
            self.store._commit()
        except Exception as e:
            logger.error(f"Failed to insert device telemetry: {e}")

    @staticmethod
    def _classify_risk(risk: float) -> str:
        """Map numeric risk score to classification label."""
        if risk >= 0.75:
            return "malicious"
        if risk >= 0.5:
            return "suspicious"
        return "legitimate"

    @staticmethod
    def _build_security_event_dict(
        se: Any,
        event: Any,
        device_id: str,
        ts_ns: int,
        timestamp_dt: str,
        collection_agent: str,
    ) -> dict:
        """Build event dict from protobuf SecurityEvent for storage."""
        mitre = list(se.mitre_techniques) if se.mitre_techniques else []
        risk = se.risk_score

        description = se.analyst_notes or ""
        if event.source_component and event.source_component not in description:
            description = f"[{event.source_component}] {description}"

        indicators = {key: event.attributes[key] for key in event.attributes}
        if collection_agent and "agent" not in indicators:
            indicators["agent"] = collection_agent

        # Preserve probe-local detection timestamp (previously lost here)
        evt_ts_ns = event.event_timestamp_ns if event.event_timestamp_ns else None
        evt_id = event.event_id if event.event_id else None
        latency = (ts_ns - evt_ts_ns) if evt_ts_ns else None

        return {
            "timestamp_ns": ts_ns,
            "timestamp_dt": timestamp_dt,
            "device_id": device_id,
            "event_category": se.event_category or event.event_type,
            "event_action": se.event_action or None,
            "event_outcome": se.event_outcome or None,
            "risk_score": risk,
            "confidence": event.confidence_score,
            "mitre_techniques": mitre,
            "final_classification": WALProcessor._classify_risk(risk),
            "description": description,
            "indicators": indicators,
            "requires_investigation": se.requires_investigation or risk >= 0.7,
            "collection_agent": collection_agent,
            "agent_version": None,
            "event_timestamp_ns": evt_ts_ns,
            "event_id": evt_id,
            "probe_latency_ns": latency,
        }

    def _process_security_event(
        self,
        event: Any,
        device_id: str,
        ts_ns: int,
        timestamp_dt: str,
        collection_agent: str,
        enriched_attrs: dict | None = None,
    ) -> None:
        """Extract SecurityEvent from TelemetryEvent and insert into security_events table.

        This is the critical bridge: agent probes detect threats, wrap them as
        SecurityEvent inside TelemetryEvent, publish via EventBus → WAL.
        This method completes the pipeline by persisting them for dashboard queries.

        Args:
            enriched_attrs: Pre-enriched attributes dict (GeoIP/ASN/ThreatIntel/MITRE).
                When provided, replaces the raw indicators with enriched data so that
                ScoringEngine sees threat intel matches and enrichment is persisted.
        """
        try:
            se = event.security_event
            event_data = self._build_security_event_dict(
                se,
                event,
                device_id,
                ts_ns,
                timestamp_dt,
                collection_agent,
            )

            # Merge enrichment data into event_data so ScoringEngine and
            # storage both see GeoIP, ASN, ThreatIntel, and MITRE results.
            if enriched_attrs is not None:
                event_data["indicators"] = enriched_attrs
                event_data["enrichment_status"] = enriched_attrs.get(
                    "enrichment_status", "raw"
                )
                event_data["threat_intel_match"] = enriched_attrs.get(
                    "threat_intel_match", False
                )
                event_data["geo_src_country"] = enriched_attrs.get(
                    "geo_src_country"
                ) or enriched_attrs.get("geo_dst_country")
                event_data["geo_src_city"] = enriched_attrs.get(
                    "geo_src_city"
                ) or enriched_attrs.get("geo_dst_city")
                event_data["geo_src_latitude"] = enriched_attrs.get(
                    "geo_src_latitude"
                ) or enriched_attrs.get("geo_dst_latitude")
                event_data["geo_src_longitude"] = enriched_attrs.get(
                    "geo_src_longitude"
                ) or enriched_attrs.get("geo_dst_longitude")
                event_data["asn_src_org"] = enriched_attrs.get(
                    "asn_src_org"
                ) or enriched_attrs.get("asn_dst_org")
                event_data["asn_src_number"] = enriched_attrs.get(
                    "asn_src_number"
                ) or enriched_attrs.get("asn_dst_number")
                event_data["asn_src_network_type"] = enriched_attrs.get(
                    "asn_src_network_type"
                ) or enriched_attrs.get("asn_dst_network_type")
                # Promote enriched MITRE techniques to top-level list
                if enriched_attrs.get("mitre_techniques"):
                    existing = set(event_data.get("mitre_techniques") or [])
                    for t in enriched_attrs["mitre_techniques"]:
                        if t not in existing:
                            event_data.setdefault("mitre_techniques", []).append(t)

            indicators = event_data.get("indicators", {})
            if isinstance(indicators, str):
                try:
                    indicators = json.loads(indicators)
                except (json.JSONDecodeError, TypeError):
                    indicators = {}
            quality_state = indicators.get("quality_state", "valid")
            contract_violation_code = indicators.get("contract_violation_code", "NONE")
            missing_fields = indicators.get("missing_fields", "")
            training_exclude = (
                str(indicators.get("training_exclude", "")).lower()
                in (
                    "true",
                    "1",
                    "yes",
                )
                or quality_state != "valid"
            )
            event_data["quality_state"] = quality_state
            event_data["training_exclude"] = training_exclude
            event_data["contract_violation_code"] = contract_violation_code
            event_data["missing_fields"] = missing_fields
            indicators["quality_state"] = quality_state
            indicators["training_exclude"] = str(training_exclude).lower()
            indicators["contract_violation_code"] = contract_violation_code
            if missing_fields:
                indicators["missing_fields"] = missing_fields
            event_data["indicators"] = indicators
            event_data["raw_attributes_json"] = json.dumps(indicators, sort_keys=True)

            mitre_source_parts = []
            if se.mitre_techniques:
                mitre_source_parts.append("probe")
            if enriched_attrs and enriched_attrs.get("mitre_techniques"):
                mitre_source_parts.append("enricher")
            if any(k.startswith("analyst_") for k in indicators):
                mitre_source_parts.append("analyst")
            event_data["mitre_source"] = (
                "|".join(sorted(set(mitre_source_parts)))
                if mitre_source_parts
                else "probe"
            )
            event_data["mitre_confidence"] = event.confidence_score or 0.0
            event_data["mitre_evidence"] = [
                {
                    "source_component": event.source_component,
                    "event_category": se.event_category,
                    "event_action": se.event_action,
                    "event_id": event.event_id,
                }
            ]

            # Deduplicate: skip if semantically identical event seen within TTL
            if self._dedup.is_duplicate(event_data):
                logger.debug(
                    "Dedup: suppressed %s/%s from %s",
                    event_data.get("event_category", ""),
                    event_data.get("event_action", ""),
                    collection_agent,
                )
                return
            self._dedup.record(event_data)

            # Score event for signal/noise classification
            if self._scorer is not None and not training_exclude:
                try:
                    self._scorer.score_event(event_data)
                except Exception:
                    logger.warning(
                        "Scoring failed for event — continuing", exc_info=True
                    )

            # Extract sequence match score from scoring factors into indicators
            # so SOMA Brain can use it as a training feature (Step 4)
            score_factors = event_data.get("score_factors", [])
            for factor in score_factors:
                if factor.get("name") == "Attack Sequence Detected":
                    ind = event_data.get("indicators", {})
                    if isinstance(ind, str):
                        try:
                            ind = json.loads(ind)
                        except (json.JSONDecodeError, TypeError):
                            ind = {}
                    ind["sequence_match_score"] = factor.get("contribution", 0.0)
                    ind["sequence_detail"] = factor.get("detail", "")
                    event_data["indicators"] = ind
                    break

            # Feed AutoCalibrator for autonomous FP detection
            if self._brain and self._brain._auto_calibrator and not training_exclude:
                try:
                    self._brain._auto_calibrator.observe(event_data)
                except Exception:
                    pass

            self.store.insert_security_event(event_data)

            # Receipt ledger checkpoint 4: persisted to security_events
            self.store.receipt_persisted(
                event.event_id or event_data.get("event_id", ""),
                collection_agent,
                "security_events",
                event_data.get("quality_state", "valid"),
            )

            logger.debug(
                "Stored security event: %s (risk=%.2f, agent=%s)",
                se.event_category,
                se.risk_score,
                collection_agent,
            )
        except Exception as e:
            logger.error("Failed to insert security event: %s", e)

    def _process_peripheral_event(
        self,
        event: Any,
        device_id: str,
        ts_ns: int,
        timestamp_dt: str,
        agent: str,
        version: str,
    ) -> None:
        """Process peripheral connection/disconnection event"""
        try:
            attrs = event.attributes
            status_data = event.status_data if event.HasField("status_data") else None

            self.store.db.execute(
                """
                INSERT INTO peripheral_events (
                    timestamp_ns, timestamp_dt, device_id, peripheral_device_id,
                    event_type, device_name, device_type, vendor_id, product_id,
                    serial_number, manufacturer, connection_status, previous_status,
                    is_authorized, risk_score, confidence_score,
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    ts_ns,
                    timestamp_dt,
                    device_id,
                    attrs.get("device_id", ""),
                    status_data.status if status_data else "UNKNOWN",
                    status_data.component_name if status_data else "Unknown Device",
                    attrs.get("device_type", "UNKNOWN"),
                    attrs.get("vendor_id", ""),
                    attrs.get("product_id", ""),
                    "",  # serial_number not in attributes
                    attrs.get("manufacturer", ""),
                    status_data.status if status_data else "UNKNOWN",
                    status_data.previous_status if status_data else "",
                    attrs.get("is_authorized", "False") == "True",
                    float(attrs.get("risk_score", 0.0)),
                    event.confidence_score,
                    agent,
                    version,
                ),
            )
            self.store._commit()
            logger.debug(
                f"Stored peripheral event: {attrs.get('device_type')} {status_data.status if status_data else 'N/A'}"
            )
        except Exception as e:
            logger.error(f"Failed to insert peripheral event: {e}")

    def _extract_process_from_security(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
        category,
    ) -> None:
        """Extract process data from proc-agent security event attributes."""
        try:
            exe = attrs.get("exe", attrs.get("binary", ""))
            cmdline = attrs.get("cmdline", "")
            pid = int(attrs["pid"]) if attrs.get("pid") else None
            ppid = int(attrs["ppid"]) if attrs.get("ppid") else None
            username = attrs.get("username", "")

            self.store.insert_process_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "pid": pid,
                    "ppid": ppid,
                    "exe": exe,
                    "cmdline": cmdline,
                    "username": username,
                    "cpu_percent": None,
                    "memory_percent": None,
                    "num_threads": int(attrs.get("num_threads", 0)) or None,
                    "num_fds": int(attrs.get("num_fds", 0)) or None,
                    "user_type": "root" if username == "root" else "user",
                    "process_category": category,
                    "is_suspicious": True,
                    "anomaly_score": None,
                    "confidence_score": None,
                    "collection_agent": agent,
                    "agent_version": version,
                }
            )

            # Feed process genealogy from security-path events
            if pid is not None:
                event_type = attrs.get("event_type", "")
                is_exit = (
                    category == "process_exit"
                    or "exit" in category
                    or "exit" in event_type
                )
                if is_exit:
                    self.store.mark_process_exited(
                        device_id,
                        pid,
                        ts_ns,
                        exit_status=(
                            int(attrs["exit_status"])
                            if attrs.get("exit_status")
                            else None
                        ),
                    )
                else:
                    self.store.upsert_genealogy(
                        {
                            "device_id": device_id,
                            "pid": pid,
                            "ppid": ppid,
                            "name": attrs.get("name", attrs.get("process_name", "")),
                            "exe": exe,
                            "cmdline": cmdline,
                            "username": username,
                            "parent_name": attrs.get("parent_name", ""),
                            "create_time": (
                                float(attrs["create_time"])
                                if attrs.get("create_time")
                                else None
                            ),
                            "is_alive": True,
                            "first_seen_ns": ts_ns,
                            "last_seen_ns": ts_ns,
                            "process_guid": attrs.get("process_guid", ""),
                        }
                    )
        except Exception as e:
            logger.error("Failed to extract process from security event: %s", e)

    def _extract_flow_from_security(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
    ) -> None:
        """Extract flow data from flow-agent security event attributes."""
        try:
            self.store.insert_flow_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "src_ip": attrs.get("src_ip"),
                    "dst_ip": attrs.get("dst_ip"),
                    "src_port": (
                        int(attrs["src_port"]) if attrs.get("src_port") else None
                    ),
                    "dst_port": (
                        int(attrs["dst_port"]) if attrs.get("dst_port") else None
                    ),
                    "protocol": attrs.get("protocol"),
                    "bytes_tx": int(attrs.get("bytes_tx", 0)),
                    "bytes_rx": int(attrs.get("bytes_rx", 0)),
                    "is_suspicious": True,
                    "threat_score": float(attrs.get("threat_score", 0.0)),
                    # Enrichment: GeoIP
                    "geo_src_country": attrs.get("geo_src_country"),
                    "geo_src_city": attrs.get("geo_src_city"),
                    "geo_src_latitude": attrs.get("geo_src_latitude"),
                    "geo_src_longitude": attrs.get("geo_src_longitude"),
                    "geo_dst_country": attrs.get("geo_dst_country"),
                    "geo_dst_city": attrs.get("geo_dst_city"),
                    "geo_dst_latitude": attrs.get("geo_dst_latitude"),
                    "geo_dst_longitude": attrs.get("geo_dst_longitude"),
                    # Enrichment: ASN
                    "asn_src_number": attrs.get("asn_src_number"),
                    "asn_src_org": attrs.get("asn_src_org"),
                    "asn_src_network_type": attrs.get("asn_src_network_type"),
                    "asn_dst_number": attrs.get("asn_dst_number"),
                    "asn_dst_org": attrs.get("asn_dst_org"),
                    "asn_dst_network_type": attrs.get("asn_dst_network_type"),
                    # Enrichment: ThreatIntel
                    "threat_intel_match": attrs.get("threat_intel_match", False),
                    "threat_source": attrs.get("threat_source"),
                    "threat_severity": attrs.get("threat_severity"),
                }
            )
        except Exception as e:
            logger.error("Failed to extract flow from security event: %s", e)

    def _extract_peripheral_from_security(
        self,
        attrs,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
    ) -> None:
        """Extract peripheral data from peripheral-agent security event attributes."""
        try:
            devices_str = attrs.get("devices", "[]")
            try:
                devices = json.loads(devices_str) if devices_str != "[]" else []
            except (json.JSONDecodeError, TypeError):
                devices = []

            if not devices:
                # Store the inventory snapshot itself as a peripheral event
                self.store.insert_peripheral_event(
                    {
                        "timestamp_ns": ts_ns,
                        "timestamp_dt": timestamp_dt,
                        "device_id": device_id,
                        "peripheral_device_id": "inventory-snapshot",
                        "event_type": "INVENTORY",
                        "device_name": "USB Inventory",
                        "device_type": "INVENTORY",
                        "connection_status": "SCANNED",
                        "is_authorized": True,
                        "risk_score": 0.0,
                        "collection_agent": agent,
                        "agent_version": version,
                    }
                )
                return

            for dev in devices:
                if isinstance(dev, dict):
                    self.store.insert_peripheral_event(
                        {
                            "timestamp_ns": ts_ns,
                            "timestamp_dt": timestamp_dt,
                            "device_id": device_id,
                            "peripheral_device_id": dev.get("id", "unknown"),
                            "event_type": "CONNECTED",
                            "device_name": dev.get("name", "Unknown"),
                            "device_type": dev.get("type", "USB"),
                            "vendor_id": dev.get("vendor_id"),
                            "product_id": dev.get("product_id"),
                            "manufacturer": dev.get("manufacturer"),
                            "connection_status": "CONNECTED",
                            "is_authorized": dev.get("authorized", True),
                            "risk_score": float(dev.get("risk_score", 0.0)),
                            "collection_agent": agent,
                            "agent_version": version,
                        }
                    )
        except Exception as e:
            logger.error("Failed to extract peripheral from security event: %s", e)

    def _extract_dns_from_security(
        self,
        attrs,
        se,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
        cat,
        mitre,
    ) -> None:
        """Extract DNS data from dns-agent security event attributes."""
        try:
            domain = attrs.get("domain", "")
            if not domain:
                return
            self.store.insert_dns_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "domain": domain,
                    "query_type": attrs.get("query_type"),
                    "response_code": attrs.get("response_code"),
                    "source_ip": attrs.get("source_ip"),
                    "process_name": attrs.get("process"),
                    "pid": int(attrs["pid"]) if attrs.get("pid") else None,
                    "event_type": cat,
                    "dga_score": (
                        float(attrs["dga_score"]) if attrs.get("dga_score") else None
                    ),
                    "is_beaconing": "beacon" in cat.lower() if cat else False,
                    "beacon_interval_seconds": (
                        float(attrs["avg_interval_seconds"])
                        if attrs.get("avg_interval_seconds")
                        else None
                    ),
                    "is_tunneling": "tunnel" in cat.lower() if cat else False,
                    "risk_score": se.risk_score,
                    "confidence": float(attrs.get("confidence", 0.0)),
                    "mitre_techniques": mitre,
                    "collection_agent": agent,
                    "agent_version": version,
                }
            )
        except Exception as e:
            logger.error("Failed to extract DNS from security event: %s", e)

    def _extract_audit_from_security(
        self,
        attrs,
        se,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
        cat,
        mitre,
    ) -> None:
        """Extract kernel audit data from kernel_audit-agent security event attributes."""
        try:
            self.store.insert_audit_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "host": attrs.get("host"),
                    "syscall": attrs.get("syscall", ""),
                    "event_type": cat,
                    "pid": int(attrs["pid"]) if attrs.get("pid") else None,
                    "ppid": int(attrs["ppid"]) if attrs.get("ppid") else None,
                    "uid": int(attrs["uid"]) if attrs.get("uid") else None,
                    "euid": int(attrs["euid"]) if attrs.get("euid") else None,
                    "gid": int(attrs["gid"]) if attrs.get("gid") else None,
                    "egid": int(attrs["egid"]) if attrs.get("egid") else None,
                    "exe": attrs.get("exe", attrs.get("attacker_exe", "")),
                    "comm": attrs.get("comm", attrs.get("attacker_comm", "")),
                    "cmdline": attrs.get("cmdline"),
                    "cwd": attrs.get("cwd"),
                    "target_path": attrs.get("target_path"),
                    "target_pid": (
                        int(attrs["target_pid"]) if attrs.get("target_pid") else None
                    ),
                    "target_comm": attrs.get("target_comm"),
                    "risk_score": se.risk_score,
                    "confidence": float(attrs.get("confidence", 0.0)),
                    "mitre_techniques": mitre,
                    "reason": attrs.get("reason"),
                    "collection_agent": agent,
                    "agent_version": version,
                }
            )
        except Exception as e:
            logger.error("Failed to extract audit from security event: %s", e)

    def _extract_persistence_from_security(
        self,
        attrs,
        se,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
        cat,
        mitre,
    ) -> None:
        """Extract persistence data from persistence-agent security event attributes."""
        try:
            self.store.insert_persistence_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "event_type": cat,
                    "mechanism": attrs.get("mechanism"),
                    "entry_id": attrs.get("entry_id"),
                    "path": attrs.get("path"),
                    "command": attrs.get("command"),
                    "schedule": attrs.get("schedule"),
                    "user": attrs.get("user"),
                    "change_type": attrs.get("change_type"),
                    "old_command": attrs.get("old_command"),
                    "new_command": attrs.get("new_command"),
                    "risk_score": se.risk_score,
                    "confidence": float(attrs.get("confidence", 0.0)),
                    "mitre_techniques": mitre,
                    "reason": attrs.get("reason"),
                    "collection_agent": agent,
                    "agent_version": version,
                }
            )
        except Exception as e:
            logger.error("Failed to extract persistence from security event: %s", e)

    def _extract_fim_from_security(
        self,
        attrs,
        se,
        device_id,
        ts_ns,
        timestamp_dt,
        agent,
        version,
        cat,
        mitre,
    ) -> None:
        """Extract FIM data from fim-agent security event attributes."""
        try:
            self.store.insert_fim_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "event_type": cat,
                    "path": attrs.get("path", ""),
                    "change_type": attrs.get("change_type"),
                    "old_hash": attrs.get("old_hash"),
                    "new_hash": attrs.get("new_hash"),
                    "old_mode": attrs.get("old_mode"),
                    "new_mode": attrs.get("new_mode"),
                    "file_extension": attrs.get("extension"),
                    "owner_uid": (
                        int(attrs["owner_uid"]) if attrs.get("owner_uid") else None
                    ),
                    "owner_gid": (
                        int(attrs["owner_gid"]) if attrs.get("owner_gid") else None
                    ),
                    "risk_score": se.risk_score,
                    "confidence": float(attrs.get("confidence", 0.0)),
                    "mitre_techniques": mitre,
                    "reason": attrs.get("reason"),
                    "patterns_matched": (
                        attrs.get("patterns_matched", "").split(",")
                        if attrs.get("patterns_matched")
                        else []
                    ),
                    "collection_agent": agent,
                    "agent_version": version,
                }
            )
        except Exception as e:
            logger.error("Failed to extract FIM from security event: %s", e)

    def _process_process_event(self, proc: Any, ts_ns: int, idem: str) -> None:
        """Process ProcessEvent message"""
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()

        # Classify user type
        if proc.uid == 0:
            user_type = "root"
        elif proc.uid < 500:
            user_type = "system"
        else:
            user_type = "user"

        # Classify process category with comprehensive rules
        exe = proc.exe if proc.exe else ""
        exe_lower = exe.lower()
        exe_name = exe.split("/")[-1] if exe else ""

        # Daemon detection (most specific first)
        if (
            exe_name.endswith("d")
            and not exe_name.endswith(".app")
            or "daemon" in exe_lower
            or "/usr/sbin/" in exe
            or "/usr/libexec/" in exe
            or exe_name in ["launchd", "systemstats", "kernel_task"]
        ):
            category = "daemon"
        # System libraries and frameworks
        elif (
            "/System/Library/" in exe
            or "/Library/Apple/" in exe
            or "CoreServices" in exe
            or "PrivateFrameworks" in exe
            or exe_name.startswith("com.apple.")
        ):
            category = "system"
        # User applications
        elif "/Applications/" in exe and ".app/" in exe:
            category = "application"
        # Helper processes
        elif "Helper" in exe or "helper" in exe_lower:
            category = "helper"
        # Kernel and core
        elif exe_name in ["kernel_task", "launchd"] or "/kernel" in exe_lower:
            category = "kernel"
        # Fallback to unknown
        else:
            category = "unknown"

        # Extract cmdline
        cmdline = " ".join(proc.args) if proc.args else ""

        try:
            # Get device hostname for identification
            device_id = socket.gethostname()

            self.store.insert_process_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "pid": proc.pid,
                    "ppid": proc.ppid,
                    "exe": proc.exe,
                    "cmdline": cmdline,
                    "username": None,
                    "cpu_percent": None,
                    "memory_percent": None,
                    "num_threads": None,
                    "num_fds": None,
                    "user_type": user_type,
                    "process_category": category,
                    "is_suspicious": False,
                    "anomaly_score": None,
                    "confidence_score": None,
                    "collection_agent": "mac_telemetry",
                    "agent_version": "1.0.0",
                }
            )
        except Exception as e:
            logger.error(f"Failed to insert process event: {e}")

    def _process_flow_event(self, flow: Any, ts_ns: int) -> None:
        """Process FlowEvent message with enrichment."""
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()

        try:
            flow_data = {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": "unknown",
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "bytes_tx": flow.bytes_tx,
                "bytes_rx": flow.bytes_rx,
                "is_suspicious": False,
            }

            # Enrich with GeoIP/ASN/ThreatIntel
            if self._pipeline is not None:
                try:
                    self._pipeline.enrich(flow_data)
                except Exception:
                    logger.debug("Enrichment failed for flow event", exc_info=True)

            self.store.insert_flow_event(flow_data)
        except Exception as e:
            logger.error(f"Failed to insert flow event: {e}")

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
