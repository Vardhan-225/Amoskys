"""WAL Processor — fusion/enrichment mixin."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, List

logger = logging.getLogger("WALProcessor")


class EnrichmentMixin:
    """Fusion engine feeding, incident bridging, device telemetry, and stale process sweep."""

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
                from amoskys.intel.models import TelemetryEventView

                view = TelemetryEventView.from_protobuf(event, device_id)
                self._fusion.add_event(view)
                fed += 1
            except Exception as e:
                logger.debug("Fusion feed skip: %s", e)
        if fed > 0:
            logger.debug("Fed %d events to FusionEngine for %s", fed, device_id)

    def _hydrate_bridged_ids(self) -> None:
        """Load already-bridged fusion incident IDs from the dashboard DB.

        Survives process restarts -- reads the indicators JSON column to find
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

    def _process_device_telemetry(
        self, dt, ts_ns: int, idem: str
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
