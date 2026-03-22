"""Insert methods mixin for TelemetryStore."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("TelemetryStore")


class InsertMixin:
    """All insert/upsert methods for domain event tables."""

    def insert_telemetry_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert canonical ingress envelope event into telemetry_events."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO telemetry_events (
                    event_id, idempotency_key, timestamp_ns, ingest_timestamp_ns,
                    timestamp_dt, device_id, agent_id, probe_name, probe_version,
                    event_type, device_type, payload_kind, schema_version,
                    quality_state, contract_violation_code, missing_fields,
                    envelope_bytes, wal_row_id, wal_checksum, wal_sig, wal_prev_sig
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("event_id"),
                    event_data.get("idempotency_key"),
                    event_data.get("timestamp_ns"),
                    event_data.get("ingest_timestamp_ns"),
                    event_data.get("timestamp_dt"),
                    event_data.get("device_id"),
                    event_data.get("agent_id"),
                    event_data.get("probe_name"),
                    event_data.get("probe_version"),
                    event_data.get("event_type"),
                    event_data.get("device_type"),
                    event_data.get("payload_kind"),
                    event_data.get("schema_version", 1),
                    event_data.get("quality_state", "valid"),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("envelope_bytes"),
                    event_data.get("wal_row_id"),
                    event_data.get("wal_checksum"),
                    event_data.get("wal_sig"),
                    event_data.get("wal_prev_sig"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert telemetry event: %s", e)
            return None

    def insert_process_event(self, event_data: dict[str, Any]) -> Optional[int]:
        """Insert a process event (with unified snapshot dedup).

        Process scans are full-table snapshots — same PID/exe/cmdline combo
        repeats every cycle.  Dedup key: (device_id, pid, exe).  Content hash:
        fingerprint of (cmdline, username, cpu_percent, memory_percent, status).
        """
        try:
            timestamp_ns = event_data.get("timestamp_ns") or int(time.time() * 1e9)
            device_id = event_data.get("device_id") or "unknown"
            pid = event_data.get("pid")
            exe = event_data.get("exe") or ""

            # Unified snapshot dedup — process events are always snapshots
            if device_id and pid is not None:
                key = self._dedup_key(device_id, pid, exe)
                fingerprint = self._content_fingerprint(
                    event_data.get("cmdline"),
                    event_data.get("username"),
                    event_data.get("status"),
                    event_data.get("ppid"),
                )
                if self._check_snapshot_dedup(
                    "process_events", key, fingerprint, timestamp_ns
                ):
                    self._commit()
                    return None  # suppressed duplicate

            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO process_events (
                    timestamp_ns, timestamp_dt, device_id, pid, ppid, exe, cmdline,
                    username, cpu_percent, memory_percent, num_threads, num_fds,
                    user_type, process_category, is_suspicious, anomaly_score,
                    confidence_score, collection_agent, agent_version,
                    name, parent_name, create_time, status, cwd,
                    is_own_user, process_guid, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event_data.get("timestamp_ns"),
                    event_data.get("timestamp_dt"),
                    event_data.get("device_id"),
                    event_data.get("pid"),
                    event_data.get("ppid"),
                    event_data.get("exe"),
                    event_data.get("cmdline"),
                    event_data.get("username"),
                    event_data.get("cpu_percent"),
                    event_data.get("memory_percent"),
                    event_data.get("num_threads"),
                    event_data.get("num_fds"),
                    event_data.get("user_type"),
                    event_data.get("process_category"),
                    event_data.get("is_suspicious", False),
                    event_data.get("anomaly_score"),
                    event_data.get("confidence_score"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("name"),
                    event_data.get("parent_name"),
                    event_data.get("create_time"),
                    event_data.get("status"),
                    event_data.get("cwd"),
                    event_data.get("is_own_user", False),
                    event_data.get("process_guid"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert process event: %s", e)
            return None

    @staticmethod
    def _extract_typed_features(event_data: Dict[str, Any]) -> None:
        """Extract key features from raw_attributes_json into typed columns.

        Runs BEFORE insert. Populates typed columns for ML training
        so models don't need to parse JSON at query time.
        Only sets values that aren't already explicitly provided.
        """
        raw = event_data.get("raw_attributes_json")
        if not raw:
            return
        try:
            attrs = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(attrs, dict):
            return

        # Map: (typed_column, json_key, converter)
        _int = lambda v: int(v) if v else None  # noqa: E731
        _str2k = lambda v: str(v)[:2000]  # noqa: E731
        extractions = [
            # Process context
            ("pid", "pid", _int),
            ("process_name", "process_name", str),
            ("exe", "exe", str),
            ("cmdline", "cmdline", _str2k),
            ("ppid", "ppid", _int),
            ("parent_name", "parent_name", str),
            ("username", "username", str),
            ("trust_disposition", "trust_disposition", str),
            # Network context
            ("remote_ip", "remote_ip", str),
            ("remote_port", "remote_port", _int),
            ("local_port", "local_port", _int),
            ("protocol", "protocol", str),
            ("connection_state", "connection_state", str),
            ("bytes_out", "bytes_out", _int),
            ("bytes_in", "bytes_in", _int),
            ("domain", "domain", str),
            # File context
            ("path", "path", str),
            ("file_name", "name", str),
            ("file_extension", "extension", str),
            ("sha256", "sha256", str),
            ("file_mtime", "mtime", lambda v: float(v) if v else None),
            ("file_owner", "file_owner", str),
            ("file_permissions", "mode", str),
            # Chain context
            ("kill_chain_stage", "chain_stage", str),
            (
                "stages_hit",
                "stages_hit",
                lambda v: len(v) if isinstance(v, list) else None,
            ),
            # Identity/attribution
            ("probe_name", "probe_name", str),
            ("detection_source", "detection_source", str),
        ]

        for col, key, conv in extractions:
            if event_data.get(col) is not None:
                continue  # Already set explicitly
            val = attrs.get(key)
            if val is not None and str(val).strip() and str(val) != "None":
                try:
                    event_data[col] = conv(val)
                except (ValueError, TypeError):
                    pass

        # Auto-generate description if empty
        if not event_data.get("description"):
            cat = event_data.get("event_category", "")
            proc = attrs.get("process_name", attrs.get("name", ""))
            exe = attrs.get("exe", "")
            desc_parts = [f"[{cat}]"]
            if proc:
                desc_parts.append(proc)
            if exe and exe != proc:
                desc_parts.append(exe)
            cmdline = attrs.get("cmdline", "")
            if cmdline:
                cmd_str = str(cmdline)[:200]
                desc_parts.append(f"cmd={cmd_str}")
            event_data["description"] = " ".join(desc_parts)

    def insert_security_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a security event.

        Args:
            event_data: Dictionary with security event fields.

        Returns:
            Row ID of inserted event, or None if failed.
        """
        # Extract typed features from JSON before insert
        self._extract_typed_features(event_data)

        try:
            cursor = self.db.execute(
                """
                INSERT INTO security_events (
                    timestamp_ns, timestamp_dt, device_id,
                    event_category, event_action, event_outcome,
                    risk_score, confidence, mitre_techniques,
                    geometric_score, temporal_score, behavioral_score,
                    final_classification, description, indicators,
                    requires_investigation, collection_agent, agent_version,
                    enrichment_status, threat_intel_match,
                    geo_src_country, geo_src_city,
                    geo_src_latitude, geo_src_longitude,
                    asn_src_org, asn_src_number, asn_src_network_type,
                    event_timestamp_ns, event_id, probe_latency_ns,
                    quality_state, training_exclude,
                    contract_violation_code, missing_fields,
                    mitre_source, mitre_confidence, mitre_evidence,
                    raw_attributes_json,
                    exe, cmdline, parent_name, ppid, process_name,
                    remote_ip, remote_port, bytes_out, bytes_in,
                    trust_disposition, domain, path, sha256,
                    kill_chain_stage, stages_hit, composite_score,
                    threat_source, threat_severity, label_source,
                    pid, username, probe_name, detection_source,
                    mitre_tactics, local_port, protocol,
                    connection_state, file_name, file_extension,
                    file_owner, file_mtime, file_permissions
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("event_category"),
                    event_data.get("event_action"),
                    event_data.get("event_outcome"),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("geometric_score", 0.0),
                    event_data.get("temporal_score", 0.0),
                    event_data.get("behavioral_score", 0.0),
                    event_data.get("final_classification", "legitimate"),
                    event_data.get("description"),
                    json.dumps(event_data.get("indicators", {})),
                    event_data.get("requires_investigation", False),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("enrichment_status", "raw"),
                    event_data.get("threat_intel_match", False),
                    event_data.get("geo_src_country"),
                    event_data.get("geo_src_city"),
                    event_data.get("geo_src_latitude"),
                    event_data.get("geo_src_longitude"),
                    event_data.get("asn_src_org"),
                    event_data.get("asn_src_number"),
                    event_data.get("asn_src_network_type"),
                    event_data.get("event_timestamp_ns"),
                    event_data.get("event_id"),
                    event_data.get("probe_latency_ns"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("mitre_source", "probe"),
                    event_data.get(
                        "mitre_confidence", event_data.get("confidence", 0.0)
                    ),
                    json.dumps(event_data.get("mitre_evidence", [])),
                    event_data.get("raw_attributes_json"),
                    # Typed feature columns
                    event_data.get("exe"),
                    event_data.get("cmdline"),
                    event_data.get("parent_name"),
                    event_data.get("ppid"),
                    event_data.get("process_name"),
                    event_data.get("remote_ip"),
                    event_data.get("remote_port"),
                    event_data.get("bytes_out"),
                    event_data.get("bytes_in"),
                    event_data.get("trust_disposition"),
                    event_data.get("domain"),
                    event_data.get("path"),
                    event_data.get("sha256"),
                    event_data.get("kill_chain_stage"),
                    event_data.get("stages_hit"),
                    event_data.get("composite_score", 0.0),
                    event_data.get("threat_source"),
                    event_data.get("threat_severity"),
                    event_data.get("label_source"),
                    # Mandate v1.0 columns
                    event_data.get("pid"),
                    event_data.get("username"),
                    event_data.get("probe_name"),
                    event_data.get("detection_source"),
                    json.dumps(event_data.get("mitre_tactics", [])),
                    event_data.get("local_port"),
                    event_data.get("protocol"),
                    event_data.get("connection_state"),
                    event_data.get("file_name"),
                    event_data.get("file_extension"),
                    event_data.get("file_owner"),
                    event_data.get("file_mtime"),
                    event_data.get("file_permissions"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert security event: %s", e)
            return None

    def insert_flow_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a network flow event.

        Rejects LISTEN/bind sockets — single gate for all call paths.
        """
        state = (event_data.get("state") or "").strip().upper()
        dst_ip = (event_data.get("dst_ip") or "").strip()
        if state == "LISTEN" or (not dst_ip and state in ("", "NONE")):
            return None  # Not a real connection — socket inventory

        try:
            cursor = self.db.execute(
                """
                INSERT OR IGNORE INTO flow_events (
                    timestamp_ns, timestamp_dt, device_id,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    bytes_tx, bytes_rx, packets_tx, packets_rx,
                    is_suspicious, threat_score,
                    geo_src_country, geo_src_city, geo_src_latitude, geo_src_longitude,
                    geo_dst_country, geo_dst_city, geo_dst_latitude, geo_dst_longitude,
                    asn_src_number, asn_src_org, asn_src_network_type,
                    asn_dst_number, asn_dst_org, asn_dst_network_type,
                    threat_intel_match, threat_source, threat_severity,
                    pid, process_name, conn_user, state,
                    collection_agent, agent_version, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("src_ip"),
                    event_data.get("dst_ip"),
                    event_data.get("src_port"),
                    event_data.get("dst_port"),
                    event_data.get("protocol"),
                    event_data.get("bytes_tx", 0),
                    event_data.get("bytes_rx", 0),
                    event_data.get("packets_tx", 0),
                    event_data.get("packets_rx", 0),
                    event_data.get("is_suspicious", False),
                    event_data.get("threat_score", 0.0),
                    event_data.get("geo_src_country"),
                    event_data.get("geo_src_city"),
                    event_data.get("geo_src_latitude"),
                    event_data.get("geo_src_longitude"),
                    event_data.get("geo_dst_country"),
                    event_data.get("geo_dst_city"),
                    event_data.get("geo_dst_latitude"),
                    event_data.get("geo_dst_longitude"),
                    event_data.get("asn_src_number"),
                    event_data.get("asn_src_org"),
                    event_data.get("asn_src_network_type"),
                    event_data.get("asn_dst_number"),
                    event_data.get("asn_dst_org"),
                    event_data.get("asn_dst_network_type"),
                    event_data.get("threat_intel_match", False),
                    event_data.get("threat_source"),
                    event_data.get("threat_severity"),
                    event_data.get("pid"),
                    event_data.get("process_name"),
                    event_data.get("conn_user"),
                    event_data.get("state"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert flow event: %s", e)
            return None

    def insert_peripheral_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a peripheral (USB/Bluetooth) event (with unified snapshot dedup).

        Peripheral scans are full-table snapshots — same device appears
        every cycle.  Dedup key: (device_id, peripheral_device_id).
        """
        try:
            timestamp_ns = event_data.get("timestamp_ns", int(time.time() * 1e9))
            device_id = event_data.get("device_id", "unknown")
            peripheral_id = event_data.get("peripheral_device_id", "unknown")

            # Unified snapshot dedup
            if device_id and peripheral_id:
                key = self._dedup_key(device_id, peripheral_id)
                fingerprint = self._content_fingerprint(
                    event_data.get("connection_status"),
                    event_data.get("device_name"),
                    event_data.get("vendor_id"),
                    event_data.get("product_id"),
                )
                if self._check_snapshot_dedup(
                    "peripheral_events", key, fingerprint, timestamp_ns
                ):
                    self._commit()
                    return None  # suppressed duplicate

            cursor = self.db.execute(
                """
                INSERT INTO peripheral_events (
                    timestamp_ns, timestamp_dt, device_id, peripheral_device_id,
                    event_type, device_name, device_type, vendor_id, product_id,
                    serial_number, manufacturer, address, connection_status, previous_status,
                    mount_point, files_transferred, bytes_transferred,
                    is_authorized, risk_score, confidence_score, threat_indicators,
                    collection_agent, agent_version, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("peripheral_device_id", "unknown"),
                    event_data.get("event_type", "CONNECTED"),
                    event_data.get("device_name"),
                    event_data.get("device_type"),
                    event_data.get("vendor_id"),
                    event_data.get("product_id"),
                    event_data.get("serial_number"),
                    event_data.get("manufacturer"),
                    event_data.get("address"),
                    event_data.get("connection_status"),
                    event_data.get("previous_status"),
                    event_data.get("mount_point"),
                    event_data.get("files_transferred", 0),
                    event_data.get("bytes_transferred", 0),
                    event_data.get("is_authorized", True),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence_score", 0.0),
                    json.dumps(event_data.get("threat_indicators", [])),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert peripheral event: %s", e)
            return None

    def insert_dns_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a DNS event (query, DGA detection, beaconing, etc.)."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR IGNORE INTO dns_events (
                    timestamp_ns, timestamp_dt, device_id, domain, query_type,
                    response_code, source_ip, process_name, pid, event_type,
                    dga_score, is_beaconing, beacon_interval_seconds, is_tunneling,
                    risk_score, confidence, mitre_techniques,
                    collection_agent, agent_version,
                    response_ips, ttl, response_size, is_reverse, event_source,
                    quality_state, training_exclude, contract_violation_code,
                    missing_fields, raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("domain", ""),
                    event_data.get("query_type"),
                    event_data.get("response_code"),
                    event_data.get("source_ip"),
                    event_data.get("process_name"),
                    event_data.get("pid"),
                    event_data.get("event_type"),
                    event_data.get("dga_score"),
                    event_data.get("is_beaconing", False),
                    event_data.get("beacon_interval_seconds"),
                    event_data.get("is_tunneling", False),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    (
                        json.dumps(event_data.get("response_ips", []))
                        if event_data.get("response_ips")
                        else None
                    ),
                    event_data.get("ttl"),
                    event_data.get("response_size"),
                    event_data.get("is_reverse", False),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert DNS event: %s", e)
            return None

    def insert_audit_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a kernel audit event (syscall monitoring)."""
        try:
            cursor = self.db.execute(
                """
                INSERT INTO audit_events (
                    timestamp_ns, timestamp_dt, device_id, host, syscall,
                    event_type, pid, ppid, uid, euid, gid, egid,
                    exe, comm, cmdline, cwd, target_path, target_pid,
                    target_comm, risk_score, confidence, mitre_techniques,
                    reason, source_ip, username, collector_timestamp,
                    collection_agent, agent_version, event_source, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("host"),
                    event_data.get("syscall", ""),
                    event_data.get("event_type", ""),
                    event_data.get("pid"),
                    event_data.get("ppid"),
                    event_data.get("uid"),
                    event_data.get("euid"),
                    event_data.get("gid"),
                    event_data.get("egid"),
                    event_data.get("exe"),
                    event_data.get("comm"),
                    event_data.get("cmdline"),
                    event_data.get("cwd"),
                    event_data.get("target_path"),
                    event_data.get("target_pid"),
                    event_data.get("target_comm"),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("reason"),
                    event_data.get("source_ip"),
                    event_data.get("username"),
                    event_data.get("collector_timestamp"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert audit event: %s", e)
            return None

    def insert_persistence_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a persistence mechanism event (with unified snapshot dedup)."""
        try:
            timestamp_ns = event_data.get("timestamp_ns", int(time.time() * 1e9))
            device_id = event_data.get("device_id", "unknown")
            mechanism = event_data.get("mechanism") or ""
            entry_id = event_data.get("entry_id") or ""
            content_hash = event_data.get("content_hash") or ""
            command = event_data.get("command")
            change_type = event_data.get("change_type")

            # Unified snapshot dedup
            if change_type == "snapshot" and device_id and mechanism and entry_id:
                key = self._dedup_key(device_id, mechanism, entry_id)
                if self._check_snapshot_dedup(
                    "persistence_events", key, content_hash, timestamp_ns
                ):
                    self._commit()
                    return None  # suppressed duplicate

            cursor = self.db.execute(
                """
                INSERT INTO persistence_events (
                    timestamp_ns, timestamp_dt, device_id, event_type,
                    mechanism, entry_id, path, command, schedule, user,
                    change_type, old_command, new_command,
                    risk_score, confidence, mitre_techniques, reason,
                    collection_agent, agent_version,
                    content_hash, program, label, run_at_load, keep_alive,
                    event_source, quality_state, training_exclude,
                    contract_violation_code, missing_fields, raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp_ns,
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    device_id,
                    event_data.get("event_type", ""),
                    mechanism,
                    entry_id,
                    event_data.get("path"),
                    command,
                    event_data.get("schedule"),
                    event_data.get("user"),
                    change_type,
                    event_data.get("old_command"),
                    event_data.get("new_command"),
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("reason"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    content_hash,
                    event_data.get("program"),
                    event_data.get("label"),
                    event_data.get("run_at_load", False),
                    event_data.get("keep_alive", False),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert persistence event: %s", e)
            return None

    def insert_fim_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a file integrity monitoring event (with unified snapshot dedup)."""
        try:
            timestamp_ns = event_data.get("timestamp_ns", int(time.time() * 1e9))
            device_id = event_data.get("device_id", "unknown")
            path = event_data.get("path", "")
            new_hash = event_data.get("new_hash") or ""
            mtime = event_data.get("mtime")
            size = event_data.get("size")
            change_type = event_data.get("change_type")

            # Unified snapshot dedup
            if change_type == "snapshot" and device_id and path:
                key = self._dedup_key(device_id, path)
                if self._check_snapshot_dedup(
                    "fim_events", key, new_hash, timestamp_ns
                ):
                    self._commit()
                    return None  # suppressed duplicate

            cursor = self.db.execute(
                """
                INSERT INTO fim_events (
                    timestamp_ns, timestamp_dt, device_id, event_type, path,
                    change_type, old_hash, new_hash, old_mode, new_mode,
                    file_extension, owner_uid, owner_gid, is_suid, mtime, size,
                    risk_score, confidence, mitre_techniques, reason,
                    patterns_matched, collection_agent, agent_version,
                    event_source, quality_state, training_exclude,
                    contract_violation_code, missing_fields, raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp_ns,
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    device_id,
                    event_data.get("event_type", ""),
                    path,
                    change_type,
                    event_data.get("old_hash"),
                    new_hash,
                    event_data.get("old_mode"),
                    event_data.get("new_mode"),
                    event_data.get("file_extension"),
                    event_data.get("owner_uid"),
                    event_data.get("owner_gid"),
                    event_data.get("is_suid", False),
                    mtime,
                    size,
                    event_data.get("risk_score", 0.0),
                    event_data.get("confidence", 0.0),
                    json.dumps(event_data.get("mitre_techniques", [])),
                    event_data.get("reason"),
                    json.dumps(event_data.get("patterns_matched", [])),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("event_source", "observation"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert FIM event: %s", e)
            return None

    # Snapshot-like observation domains — these scan full state every cycle
    _SNAPSHOT_OBSERVATION_DOMAINS = frozenset(
        {"discovery", "internet_activity", "db_activity"}
    )

    def insert_observation_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert an observation event (with unified snapshot dedup for scan domains).

        Domains like 'discovery' and 'internet_activity' produce full-state
        snapshots every cycle.  Log domains like 'unified_log' are true
        append-only events and bypass dedup.
        """
        try:
            timestamp_ns = event_data.get("timestamp_ns", int(time.time() * 1e9))
            device_id = event_data.get("device_id", "unknown")
            domain = event_data.get("domain", "unknown")
            attributes = event_data.get("attributes", {})
            attrs_json = (
                json.dumps(attributes)
                if isinstance(attributes, dict)
                else str(attributes)
            )

            # Unified snapshot dedup for scan-type domains
            if domain in self._SNAPSHOT_OBSERVATION_DOMAINS and device_id:
                fingerprint = self._content_fingerprint(attrs_json)
                key = self._dedup_key(device_id, domain, fingerprint)
                if self._check_snapshot_dedup(
                    "observation_events", key, fingerprint, timestamp_ns
                ):
                    self._commit()
                    return None  # suppressed duplicate

            cursor = self.db.execute(
                """
                INSERT INTO observation_events (
                    timestamp_ns, timestamp_dt, device_id, domain,
                    event_type, attributes, risk_score, event_source,
                    collection_agent, agent_version, quality_state,
                    training_exclude, contract_violation_code, missing_fields,
                    raw_attributes_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt", datetime.now(timezone.utc).isoformat()
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("domain", "unknown"),
                    event_data.get("event_type", "observation"),
                    json.dumps(event_data.get("attributes", {})),
                    event_data.get("risk_score", 0.0),
                    event_data.get("event_source", "observation"),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                    event_data.get("quality_state", "valid"),
                    event_data.get("training_exclude", False),
                    event_data.get("contract_violation_code", "NONE"),
                    event_data.get("missing_fields"),
                    event_data.get("raw_attributes_json"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert observation event: %s", e)
            return None

    def upsert_observation_rollup(self, rollup_data: Dict[str, Any]) -> Optional[int]:
        """Upsert observation rollup bucket for adaptive shaping."""
        try:
            self.db.execute(
                """
                INSERT INTO observation_rollups (
                    window_start_ns, window_end_ns, domain, fingerprint,
                    sample_attributes, total_count, first_seen_ns, last_seen_ns,
                    device_id, collection_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, window_start_ns, fingerprint) DO UPDATE SET
                    window_end_ns=excluded.window_end_ns,
                    total_count=observation_rollups.total_count + excluded.total_count,
                    last_seen_ns=excluded.last_seen_ns,
                    sample_attributes=excluded.sample_attributes,
                    device_id=excluded.device_id,
                    collection_agent=excluded.collection_agent
                """,
                (
                    rollup_data.get("window_start_ns"),
                    rollup_data.get("window_end_ns"),
                    rollup_data.get("domain"),
                    rollup_data.get("fingerprint"),
                    json.dumps(rollup_data.get("sample_attributes", {})),
                    int(rollup_data.get("total_count", 1)),
                    rollup_data.get("first_seen_ns"),
                    rollup_data.get("last_seen_ns"),
                    rollup_data.get("device_id"),
                    rollup_data.get("collection_agent"),
                ),
            )
            self._commit()
            return 1
        except sqlite3.Error as e:
            logger.error("Failed to upsert observation rollup: %s", e)
            return None

    def insert_device_telemetry(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a device telemetry snapshot."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO device_telemetry (
                    timestamp_ns, timestamp_dt, device_id, device_type,
                    protocol, manufacturer, model, ip_address, mac_address,
                    total_processes, total_cpu_percent, total_memory_percent,
                    metric_events, log_events, security_events,
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("device_id", "unknown"),
                    event_data.get("device_type"),
                    event_data.get("protocol"),
                    event_data.get("manufacturer"),
                    event_data.get("model"),
                    event_data.get("ip_address"),
                    event_data.get("mac_address"),
                    event_data.get("total_processes", 0),
                    event_data.get("total_cpu_percent", 0.0),
                    event_data.get("total_memory_percent", 0.0),
                    event_data.get("metric_events", 0),
                    event_data.get("log_events", 0),
                    event_data.get("security_events", 0),
                    event_data.get("collection_agent"),
                    event_data.get("agent_version"),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert device telemetry: %s", e)
            return None

    def insert_metrics_timeseries(self, event_data: Dict[str, Any]) -> Optional[int]:
        """Insert a metrics timeseries data point."""
        try:
            cursor = self.db.execute(
                """
                INSERT OR REPLACE INTO metrics_timeseries (
                    timestamp_ns, timestamp_dt, metric_name, metric_type,
                    device_id, value, unit, min_value, max_value,
                    avg_value, sample_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_data.get("timestamp_ns", int(time.time() * 1e9)),
                    event_data.get(
                        "timestamp_dt",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    event_data.get("metric_name"),
                    event_data.get("metric_type", "GAUGE"),
                    event_data.get("device_id"),
                    event_data.get("value", 0.0),
                    event_data.get("unit"),
                    event_data.get("min_value"),
                    event_data.get("max_value"),
                    event_data.get("avg_value"),
                    event_data.get("sample_count", 1),
                ),
            )
            self._commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error("Failed to insert metrics timeseries: %s", e)
            return None
