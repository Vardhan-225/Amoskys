"""WAL Processor — observation insert mixin."""

from __future__ import annotations

import logging

logger = logging.getLogger("WALProcessor")


class ObservationMixin:
    """Insert methods for all observation domain tables."""

    # Per-cycle nanosecond counter — ensures each event within a batch
    # gets a unique timestamp_ns even when the cycle timestamp is shared.
    _obs_ns_counter: int = 0

    # Domain routers for OBSERVATION events -> domain tables
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

    # Receipt ledger: domain -> destination table name
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

    # Socket states that are NOT real traffic -- filter at WAL level as defense-in-depth
    _LISTEN_STATES = frozenset({"LISTEN", "NONE", ""})

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

        # Feed process genealogy -- durable spawn chain
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

        Filters out LISTEN/bind sockets -- they're socket inventory, not traffic.
        Defense-in-depth: agents should also filter, but WAL catches stragglers.

        Each event gets a unique timestamp_ns (cycle_ts + nanosecond offset)
        to avoid UNIQUE constraint collisions when the same connection tuple
        appears across collection cycles.
        """
        state = (attrs.get("state") or "").strip().upper()
        dst_ip = (attrs.get("dst_ip") or "").strip()
        # Drop LISTEN sockets and entries with no destination.
        # Empty state is ALLOWED — macOS lsof often omits state for
        # established TCP connections. Only drop explicit LISTEN.
        if state == "LISTEN" or not dst_ip:
            return

        quality = self._quality_payload(attrs)
        # Enrich flow observations (GeoIP + ASN for dst_ip)
        if self._pipeline is not None:
            try:
                self._pipeline.enrich(attrs)
            except Exception:
                logger.debug("Enrichment failed for flow observation", exc_info=True)

        # Unique nanosecond offset per event within a batch — prevents
        # UNIQUE(device_id, src_ip, dst_ip, src_port, dst_port, timestamp_ns)
        # from silently dropping repeated connections across cycles.
        ObservationMixin._obs_ns_counter += 1
        unique_ts_ns = ts_ns + (ObservationMixin._obs_ns_counter % 1_000_000)

        self.store.insert_flow_event(
            {
                "timestamp_ns": unique_ts_ns,
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
        """Insert raw auth observation into audit_events.

        Maps AuthEvent fields from the collector into audit_events columns:
            process   → exe, comm
            message   → cmdline
            category  → reason
            client_exe → target_path (authorization client binary)
            client_pid → target_pid
            right/service → syscall (authorization right or TCC service)
            decision  → event_type
        """
        quality = self._quality_payload(attrs)

        # Parse client_pid safely
        client_pid_raw = attrs.get("client_pid", "")
        client_pid = int(client_pid_raw) if client_pid_raw and client_pid_raw.isdigit() else None

        self.store.insert_audit_event(
            {
                "timestamp_ns": ts_ns,
                "timestamp_dt": timestamp_dt,
                "device_id": device_id,
                "host": device_id,
                "syscall": attrs.get("right") or attrs.get("service") or "",
                "event_type": attrs.get("event_type") or attrs.get("decision") or "observation",
                "pid": client_pid,
                "ppid": None,
                "uid": None,
                "euid": None,
                "gid": None,
                "egid": None,
                "exe": attrs.get("client_exe") or attrs.get("process") or "",
                "comm": attrs.get("process", ""),
                "cmdline": attrs.get("message", ""),
                "cwd": None,
                "target_path": attrs.get("client_exe") or None,
                "target_pid": client_pid,
                "target_comm": attrs.get("service") or None,
                "risk_score": 0.0,
                "confidence": 0.0,
                "mitre_techniques": [],
                "reason": attrs.get("category", ""),
                "source_ip": attrs.get("source_ip") or None,
                "username": attrs.get("username") or None,
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
