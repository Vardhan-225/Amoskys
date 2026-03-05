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
from amoskys.storage.telemetry_store import TelemetryStore

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WALProcessor")


class WALProcessor:
    """Processes events from WAL to permanent storage"""

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

        # SOMA: FusionEngine for single-device correlation
        try:
            self._fusion = FusionEngine(db_path="data/intel/fusion.db")
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
            self.store.db.execute(
                "INSERT INTO wal_dead_letter "
                "(row_id, error_msg, envelope_bytes, quarantined_at, source) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    row_id,
                    error_msg,
                    raw_bytes,
                    datetime.now(timezone.utc).isoformat(),
                    "wal_processor",
                ),
            )
            self.store.db.commit()
            self.quarantine_count += 1
        except Exception as dl_err:
            logger.error(f"Failed to quarantine WAL entry {row_id}: {dl_err}")

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

    def _bridge_fusion_incidents(self) -> None:
        """Copy new FusionEngine incidents to TelemetryStore for dashboard visibility.

        FusionEngine persists to fusion.db; the dashboard reads from telemetry.db.
        This method bridges the gap by creating TelemetryStore incidents from
        newly detected fusion incidents, with dedup tracking.
        """
        if self._fusion is None:
            return
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
            except Exception as e:
                logger.error("Failed to bridge incident %s: %s", fid, e)
        if bridged > 0:
            logger.info("Bridged %d fusion incidents to dashboard", bridged)

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

    def _route_events(
        self,
        events: List[Any],
        device_id: str,
        ts_ns: int,
        timestamp_dt: str,
        collection_agent: str,
        agent_version: str,
    ) -> None:
        """Route individual TelemetryEvents to the correct table processors."""
        for event in events:
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
        # Use pre-enriched attrs from caller, or extract fresh (fallback)
        attrs = (
            enriched_attrs
            if enriched_attrs is not None
            else {k: event.attributes[k] for k in event.attributes}
        )

        cat = event.security_event.event_category or ""
        se = event.security_event
        mitre = list(se.mitre_techniques) if se.mitre_techniques else []

        # Process events from proc-agent probes
        if attrs.get("pid") and collection_agent in (
            "proc-agent",
            "proc_agent",
            "proc",
        ):
            self._extract_process_from_security(
                attrs,
                device_id,
                ts_ns,
                timestamp_dt,
                collection_agent,
                agent_version,
                cat,
            )

        # Flow events from flow-agent probes
        if attrs.get("dst_ip") and "flow" in collection_agent:
            self._extract_flow_from_security(
                attrs,
                device_id,
                ts_ns,
                timestamp_dt,
            )

        # Peripheral events from peripheral-agent probes
        if "usb" in cat or "peripheral" in collection_agent:
            self._extract_peripheral_from_security(
                attrs,
                device_id,
                ts_ns,
                timestamp_dt,
                collection_agent,
                agent_version,
            )

        # DNS events from dns-agent probes
        if "dns" in collection_agent or attrs.get("domain"):
            self._extract_dns_from_security(
                attrs,
                se,
                device_id,
                ts_ns,
                timestamp_dt,
                collection_agent,
                agent_version,
                cat,
                mitre,
            )

        # Kernel audit events from kernel_audit-agent probes
        if "kernel" in collection_agent or cat.startswith("kernel_"):
            self._extract_audit_from_security(
                attrs,
                se,
                device_id,
                ts_ns,
                timestamp_dt,
                collection_agent,
                agent_version,
                cat,
                mitre,
            )

        # Persistence events from persistence-agent probes
        if "persistence" in collection_agent or "persistence_" in cat:
            self._extract_persistence_from_security(
                attrs,
                se,
                device_id,
                ts_ns,
                timestamp_dt,
                collection_agent,
                agent_version,
                cat,
                mitre,
            )

        # FIM events from fim-agent probes
        if "fim" in collection_agent and attrs.get("path"):
            self._extract_fim_from_security(
                attrs,
                se,
                device_id,
                ts_ns,
                timestamp_dt,
                collection_agent,
                agent_version,
                cat,
                mitre,
            )

    def _process_device_telemetry(
        self, dt: telemetry_pb2.DeviceTelemetry, ts_ns: int, idem: str
    ) -> None:
        """Process DeviceTelemetry message"""
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9).isoformat()

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
                event_data["geo_src_country"] = enriched_attrs.get("geo_src_country")
                event_data["asn_src_org"] = enriched_attrs.get("asn_src_org")
                # Promote enriched MITRE techniques to top-level list
                if enriched_attrs.get("mitre_techniques"):
                    existing = set(event_data.get("mitre_techniques") or [])
                    for t in enriched_attrs["mitre_techniques"]:
                        if t not in existing:
                            event_data.setdefault("mitre_techniques", []).append(t)

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
            if self._scorer is not None:
                try:
                    self._scorer.score_event(event_data)
                except Exception:
                    logger.warning(
                        "Scoring failed for event — continuing", exc_info=True
                    )

            # Feed AutoCalibrator for autonomous FP detection
            if self._brain and self._brain._auto_calibrator:
                try:
                    self._brain._auto_calibrator.observe(event_data)
                except Exception:
                    pass

            self.store.insert_security_event(event_data)
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
                    "num_threads": None,
                    "num_fds": None,
                    "user_type": "root" if username == "root" else "user",
                    "process_category": category,
                    "is_suspicious": True,
                    "anomaly_score": None,
                    "confidence_score": None,
                    "collection_agent": agent,
                    "agent_version": version,
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
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9).isoformat()

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
        """Process FlowEvent message"""
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9).isoformat()

        try:
            self.store.db.execute(
                """
                INSERT OR REPLACE INTO flow_events (
                    timestamp_ns, timestamp_dt, device_id,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    bytes_tx, bytes_rx, is_suspicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    ts_ns,
                    timestamp_dt,
                    "unknown",
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    flow.protocol,
                    flow.bytes_tx,
                    flow.bytes_rx,
                    False,
                ),
            )
            self.store._commit()
        except Exception as e:
            logger.error(f"Failed to insert flow event: {e}")

    def process_local_queues(self, queue_dir: str = "data/queue") -> int:
        """Drain agent local queues directly into TelemetryStore.

        When EventBus is not running, agents buffer DeviceTelemetry in local
        SQLite queues (data/queue/<agent>.db). This method reads those queues
        and feeds the protobuf through the same routing logic as process_batch(),
        populating device_telemetry, security_events, peripheral_events, etc.

        Args:
            queue_dir: Directory containing agent queue .db files.

        Returns:
            Total number of events processed across all queues.
        """
        import glob

        queue_files = glob.glob(f"{queue_dir}/*.db")
        total_processed = 0

        for qf in sorted(queue_files):
            agent_name = Path(qf).stem
            try:
                conn = sqlite3.connect(qf, timeout=5.0)
                cursor = conn.execute("SELECT id, ts_ns, bytes FROM queue ORDER BY id")
                rows = cursor.fetchall()

                if not rows:
                    conn.close()
                    continue

                processed_ids = []
                for row_id, ts_ns, payload_bytes in rows:
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
                logger.info("Drained %d events from %s", count, agent_name)
                conn.close()

            except Exception as e:
                logger.error("Failed to process queue %s: %s", qf, e)

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

                self.store.db.execute(
                    "UPDATE security_events SET "
                    "indicators=?, enrichment_status=?, "
                    "threat_intel_match=?, geo_src_country=?, asn_src_org=? "
                    "WHERE id=?",
                    (
                        json.dumps(indicators),
                        indicators.get("enrichment_status", "raw"),
                        indicators.get("threat_intel_match", False),
                        indicators.get("geo_src_country"),
                        indicators.get("asn_src_org"),
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
