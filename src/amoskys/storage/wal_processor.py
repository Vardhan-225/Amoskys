#!/usr/bin/env python3
"""
WAL Processor - Moves data from WAL queue to permanent storage

This processor runs continuously, draining events from the EventBus WAL
and storing them in the permanent telemetry database for dashboard queries.
"""

import hashlib
import json
import logging
import socket
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from amoskys.enrichment import EnrichmentPipeline
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
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

        # A4.4: Enrichment pipeline (GeoIP → ASN → ThreatIntel)
        try:
            self._pipeline = EnrichmentPipeline()
            logger.info("Enrichment pipeline initialized: %s", self._pipeline.status())
        except Exception as e:
            logger.warning("Enrichment pipeline unavailable: %s", e)
            self._pipeline = None

    def process_batch(self, batch_size: int = 100) -> int:
        """Process a batch of events from WAL with BLAKE2b integrity verification.

        Each event's checksum is verified before processing. Events that fail
        checksum verification are quarantined to the dead letter table with the
        error reason, preserving the original bytes for forensic analysis.

        Args:
            batch_size: Number of events to process in one batch (max 500)

        Returns:
            Number of events successfully processed

        Raises:
            sqlite3.OperationalError: If WAL database is locked or corrupt
        """
        batch_size = min(
            batch_size, 500
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
                self._process_security_event(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                )
                self._route_security_to_domain_tables(
                    event,
                    device_id,
                    ts_ns,
                    timestamp_dt,
                    collection_agent,
                    agent_version,
                )

    def _route_security_to_domain_tables(
        self,
        event,
        device_id,
        ts_ns,
        timestamp_dt,
        collection_agent,
        agent_version,
    ) -> None:
        """Extract structured data from security events into domain-specific tables."""
        attrs = {k: event.attributes[k] for k in event.attributes}

        # A4.4: Enrich attributes with GeoIP, ASN, and threat intelligence
        if self._pipeline is not None:
            try:
                self._pipeline.enrich(attrs)
            except Exception:
                logger.debug("Enrichment failed for event — continuing", exc_info=True)

        cat = event.security_event.event_category or ""
        se = event.security_event
        mitre = list(se.mitre_techniques) if se.mitre_techniques else []

        # Process events from proc-agent probes
        if attrs.get("pid") and collection_agent in (
            "proc-agent-v3",
            "proc_agent_v3",
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
        if "kernel" in collection_agent and attrs.get("syscall"):
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
            self.store.db.commit()
        except Exception as e:
            logger.error(f"Failed to insert device telemetry: {e}")

    def _process_security_event(
        self,
        event: Any,
        device_id: str,
        ts_ns: int,
        timestamp_dt: str,
        collection_agent: str,
    ) -> None:
        """Extract SecurityEvent from TelemetryEvent and insert into security_events table.

        This is the critical bridge: agent probes detect threats, wrap them as
        SecurityEvent inside TelemetryEvent, publish via EventBus → WAL.
        This method completes the pipeline by persisting them for dashboard queries.
        """
        try:
            se = event.security_event
            mitre = list(se.mitre_techniques) if se.mitre_techniques else []

            # Map risk_score to classification
            risk = se.risk_score
            if risk >= 0.75:
                classification = "malicious"
            elif risk >= 0.5:
                classification = "suspicious"
            else:
                classification = "legitimate"

            # Build description from analyst_notes + source_component
            description = se.analyst_notes or ""
            if event.source_component and event.source_component not in description:
                description = f"[{event.source_component}] {description}"

            # Build indicators from event attributes
            indicators = {}
            for key in event.attributes:
                indicators[key] = event.attributes[key]

            self.store.insert_security_event(
                {
                    "timestamp_ns": ts_ns,
                    "timestamp_dt": timestamp_dt,
                    "device_id": device_id,
                    "event_category": se.event_category or event.event_type,
                    "event_action": se.event_action or None,
                    "event_outcome": se.event_outcome or None,
                    "risk_score": risk,
                    "confidence": event.confidence_score,
                    "mitre_techniques": mitre,
                    "final_classification": classification,
                    "description": description,
                    "indicators": indicators,
                    "requires_investigation": se.requires_investigation or risk >= 0.7,
                    "collection_agent": collection_agent,
                    "agent_version": None,
                }
            )
            logger.debug(
                "Stored security event: %s (risk=%.2f, agent=%s)",
                se.event_category,
                risk,
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
            self.store.db.commit()
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
            self.store.db.commit()
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

        queue_files = glob.glob(f"{queue_dir}/*_v2.db") + glob.glob(
            f"{queue_dir}/*_v3.db"
        )
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

        cycle = 0
        while True:
            cycle += 1
            try:
                processed = self.process_batch(batch_size=100)

                if processed > 0:
                    logger.info(
                        f"Cycle #{cycle}: Processed {processed} events (total: {self.processed_count}, errors: {self.error_count})"
                    )
                elif cycle % 12 == 0:  # Log every minute when idle
                    logger.debug(f"Cycle #{cycle}: No events to process")

                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Cycle error: {e}")
                time.sleep(interval)

        # Show final stats
        stats = self.store.get_statistics()
        logger.info(f"Final statistics: {stats}")
        self.store.close()
        if self._pipeline is not None:
            self._pipeline.close()


def main():
    """Entry point"""
    processor = WALProcessor()
    processor.run(interval=5)


if __name__ == "__main__":
    main()
