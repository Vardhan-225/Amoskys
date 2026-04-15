"""WAL Processor — security event processing mixin."""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any, List

logger = logging.getLogger("WALProcessor")


class SecurityMixin:
    """Security event processing, extraction, and domain-specific extractors."""

    # Persistence probe name prefixes -- matches macos_launchagent, macos_cron, etc.
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

        # Promote process/network context from attributes to top-level
        # so SQL columns get populated (Observability Mandate v1.0).
        attrs = indicators
        pid_raw = attrs.get("pid")
        remote_ip = attrs.get("remote_ip") or attrs.get("source_ip") or None

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
            "final_classification": SecurityMixin._classify_risk(risk),
            "description": description,
            "indicators": indicators,
            "requires_investigation": se.requires_investigation or risk >= 0.7,
            "collection_agent": collection_agent,
            "agent_version": None,
            "event_timestamp_ns": evt_ts_ns,
            "event_id": evt_id,
            "probe_latency_ns": latency,
            # ── Mandate v1.0: process context ──
            "pid": int(pid_raw) if pid_raw else None,
            "process_name": attrs.get("process_name") or attrs.get("name") or None,
            "exe": attrs.get("exe") or attrs.get("binary") or None,
            "cmdline": attrs.get("cmdline") or None,
            "username": attrs.get("username") or attrs.get("user") or None,
            # ── Mandate v1.0: network context ──
            "remote_ip": remote_ip,
            "remote_port": attrs.get("remote_port") or attrs.get("dst_port") or None,
            "domain": attrs.get("domain") or None,
            # ── Mandate v1.0: attribution ──
            "probe_name": attrs.get("probe_name") or event.source_component or None,
            "detection_source": attrs.get("detection_source") or None,
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
        SecurityEvent inside TelemetryEvent, publish via EventBus -> WAL.
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

            # Forensic context: fill WHO/HOW/CHAIN from cross-agent data
            try:
                from amoskys.enrichment.forensic_context import ForensicContextEnricher

                if not hasattr(self, "_forensic"):
                    self._forensic = ForensicContextEnricher()
                self._forensic.enrich_event(event_data)
            except Exception:
                logger.debug("Forensic enrichment failed", exc_info=True)

            # Score event for signal/noise classification
            if self._scorer is not None and not training_exclude:
                try:
                    self._scorer.score_event(event_data)
                except Exception:
                    logger.warning(
                        "Scoring failed for event — continuing", exc_info=True
                    )

            # Sigma detection-as-code: evaluate against stateless rules
            try:
                from amoskys.detection.sigma_engine import SigmaEngine

                if not hasattr(self, "_sigma"):
                    self._sigma = SigmaEngine()
                    self._sigma_aliases = {
                        "macos_launchagent_new": "new_launch_agent",
                        "macos_launchagent_modified": "new_launch_agent",
                        "macos_cron_new": "cron_modification",
                        "macos_cron_modified": "cron_modification",
                        "macos_quarantine_bypass": "quarantine_bypass",
                        "macos_hidden_file_new": "hidden_file_created",
                        "log_tampering_detected": "log_timestamp_gap",
                        "suspicious_script": "suspicious_spawn",
                        "binary_from_temp": "suspicious_spawn",
                        "browser_to_terminal": "browser_to_terminal",
                        "browser_credential_theft": "credential_harvest",
                        "session_cookie_theft": "session_cookie_theft",
                        "keychain_cli_abuse": "credential_harvest",
                        "exfil_spike": "data_exfil_http",
                        "cloud_exfil_detected": "cloud_storage_connection",
                        "c2_beacon_suspect": "c2_web_beacon",
                        "connection_burst_detected": "c2_web_beacon",
                        "cleartext_protocol": "data_exfil_http",
                        "lateral_ssh": "outbound_ssh",
                        "fake_password_dialog": "fake_password_dialog",
                        "port_scan_detected": "schema_enumeration",
                        "long_lived_connection": "long_lived_connection",
                    }
                sigma_input = dict(event_data)
                cat = sigma_input.get("event_category", "")
                sigma_input["event_type"] = self._sigma_aliases.get(cat, cat)
                sigma_matches = self._sigma.evaluate(sigma_input)
                if sigma_matches:
                    best = max(
                        sigma_matches,
                        key=lambda m: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(m.level, 0),
                    )
                    event_data["detection_source"] = (
                        event_data.get("detection_source", "") + "|sigma"
                    )
                    ind = event_data.get("indicators", {})
                    if isinstance(ind, str):
                        ind = json.loads(ind)
                    ind["sigma_rule_id"] = best.rule_id
                    ind["sigma_rule_title"] = best.rule_title
                    ind["sigma_level"] = best.level
                    event_data["indicators"] = ind
                    # Merge sigma MITRE techniques into event
                    if best.mitre_techniques:
                        existing = set(event_data.get("mitre_techniques") or [])
                        merged = list(existing)
                        for t in best.mitre_techniques:
                            if t not in existing:
                                merged.append(t)
                        event_data["mitre_techniques"] = merged
            except Exception:
                logger.debug("Sigma evaluation failed", exc_info=True)

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
                    logger.debug("AutoCalibrator observation failed", exc_info=True)

            # ── WAL Processor Gate (Mandate Level 2) ──
            # Reject events that violate mandatory field contracts.
            # Rejected events go to rejected_events table, not discarded.
            rejection = self._validate_mandate(event_data, collection_agent)
            if rejection:
                self._store_rejected_event(event_data, rejection)
                return

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

    # ── Mandate Level 2: WAL Processor Gate ─────────────────────────

    @staticmethod
    def _validate_mandate(event_data: dict, collection_agent: str) -> str | None:
        """Validate event against Agent Observability Mandate v1.0.

        Returns rejection code string if event fails, None if it passes.
        Events that fail are routed to rejected_events (not discarded).
        """
        # REJECT_NO_AGENT: collection_agent is null or empty
        if not collection_agent and not event_data.get("collection_agent"):
            return "REJECT_NO_AGENT"

        # REJECT_NO_CATEGORY: event_category is null or empty
        if not event_data.get("event_category"):
            return "REJECT_NO_CATEGORY"

        # REJECT_NO_TIMESTAMP: event_timestamp_ns is null or zero
        ts = event_data.get("event_timestamp_ns")
        if not ts or ts == 0:
            return "REJECT_NO_TIMESTAMP"

        # REJECT_NOISE_ROUTING: app_launch in security_events
        cat = event_data.get("event_category", "")
        if cat in ("app_launch", "app_quit", "app_focus_changed"):
            return "REJECT_NOISE_ROUTING"

        # REJECT_SELF_DETECTION: event from AMOSKYS process
        from amoskys.agents.common.self_identity import self_identity

        cmdline = event_data.get("cmdline", "")
        exe = event_data.get("exe", "")
        pid_val = event_data.get("pid")
        if pid_val and self_identity.is_self_process(
            pid=int(pid_val) if pid_val else None,
            cmdline=str(cmdline),
            exe=str(exe),
        ):
            return "REJECT_SELF_DETECTION"

        # REJECT_LOCAL_IP: remote_ip is link-local/loopback/APIPA
        remote_ip = event_data.get("remote_ip", "")
        if remote_ip:
            ip_lower = str(remote_ip).lower().strip("[]")
            if (
                ip_lower.startswith("fe80:")
                or ip_lower.startswith("169.254.")
                or ip_lower in ("127.0.0.1", "::1", "0.0.0.0", "::")
            ):
                return "REJECT_LOCAL_IP"

        return None  # Passes all checks

    def _store_rejected_event(self, event_data: dict, rejection_code: str) -> None:
        """Store rejected event in rejected_events table for audit.

        Per mandate: rejected events are NOT discarded. They go to a
        separate table so we can audit what's being rejected and fix
        the offending agent.
        """
        try:
            self.store.db.execute(
                """INSERT OR IGNORE INTO rejected_events
                   (timestamp_ns, device_id, event_category, collection_agent,
                    rejection_code, raw_attributes_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    event_data.get("timestamp_ns", 0),
                    event_data.get("device_id", ""),
                    event_data.get("event_category", ""),
                    event_data.get("collection_agent", ""),
                    rejection_code,
                    event_data.get("raw_attributes_json", ""),
                ),
            )
            self.store._commit()
            logger.info(
                "WAL Gate REJECTED: %s — %s from %s",
                rejection_code,
                event_data.get("event_category", ""),
                event_data.get("collection_agent", ""),
            )
        except Exception as e:
            logger.debug("Failed to store rejected event: %s", e)

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
