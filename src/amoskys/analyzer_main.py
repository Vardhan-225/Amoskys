#!/usr/bin/env python3
"""AMOSKYS Analyzer Daemon — Tier 2.

Reads events from WAL files written by the Collector (Tier 1) and runs
the full analysis pipeline:
  1. Enrichment (GeoIP, ASN, threat intel, MITRE mapping)
  2. Scoring (geometric, temporal, behavioral, sequence)
  3. Detection (180 probes, 56 Sigma rules)
  4. Correlation (13 fusion rules, kill chain tracking)
  5. Storage (telemetry.db domain tables, incidents, rollups)
  6. IGRIS (coherence assessment, signal emission, autonomous defense)

Usage:
    PYTHONPATH=src python -m amoskys.analyzer_main
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

logger = logging.getLogger("amoskys.analyzer")

DATA_DIR = Path("data")
WAL_DIR = DATA_DIR / "wal"
TELEMETRY_DB = DATA_DIR / "telemetry.db"
FUSION_DB = DATA_DIR / "intel" / "fusion.db"


def main() -> int:
    """Analyzer process entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("AMOSKYS Analyzer Daemon starting (pid=%d)", os.getpid())

    shutdown_event = threading.Event()

    def handle_signal(signum, frame):
        logger.info("Analyzer received signal %d, shutting down", signum)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # ── Initialize pipeline components ──
    try:
        from amoskys.storage.telemetry_store import TelemetryStore

        store = TelemetryStore(str(TELEMETRY_DB))
        logger.info("TelemetryStore initialized: %s", TELEMETRY_DB)
    except Exception as e:
        logger.error("Failed to initialize TelemetryStore: %s", e)
        return 1

    # Enrichment pipeline (GeoIP, ASN, ThreatIntel, MITRE)
    enrichment = None
    try:
        from amoskys.enrichment import EnrichmentPipeline

        enrichment = EnrichmentPipeline()
        logger.info("EnrichmentPipeline initialized: %s", enrichment.status())
    except Exception as e:
        logger.warning("EnrichmentPipeline not available: %s", e)

    try:
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()
        logger.info("ScoringEngine initialized")
    except Exception as e:
        logger.warning("ScoringEngine not available: %s", e)
        scorer = None

    try:
        from amoskys.intel.fusion_engine import FusionEngine

        fusion = FusionEngine(db_path=str(FUSION_DB))
        logger.info("FusionEngine initialized: %s", FUSION_DB)
    except Exception as e:
        logger.warning("FusionEngine not available: %s", e)
        fusion = None

    try:
        from amoskys.agents.common.kill_chain import KillChainTracker

        kill_chain = KillChainTracker(ttl_seconds=3600)
        logger.info("KillChainTracker initialized")
    except Exception as e:
        logger.warning("KillChainTracker not available: %s", e)
        kill_chain = None

    # ── IGRIS ──
    igris = None
    try:
        from amoskys.igris.supervisor import Igris

        igris = Igris()
        logger.info("IGRIS supervisor initialized")
    except Exception as e:
        logger.warning("IGRIS supervisor not available: %s", e)

    # ── IGRIS Tactical Engine (the minister) ──
    tactical = None
    try:
        from amoskys.igris.tactical import IGRISTacticalEngine

        tactical = IGRISTacticalEngine()
        logger.info("IGRIS tactical engine initialized — the minister is awake")
    except Exception as e:
        logger.warning("IGRIS tactical not available: %s", e)

    # ── WAL Processor (if available) ──
    wal_processor = None
    try:
        from amoskys.storage.wal_processor import WALProcessor

        wal_path = str(WAL_DIR / "flowagent.db")
        if Path(wal_path).exists():
            wal_processor = WALProcessor(
                wal_path=wal_path,
                store_path=str(TELEMETRY_DB),
            )
            logger.info("WAL processor initialized: %s", wal_path)
    except Exception as e:
        logger.warning("WAL processor not available: %s", e)

    # ── Direct Queue Reader (single-machine mode, bypasses EventBus) ──
    queue_dir = DATA_DIR / "queue"

    def _drain_agent_queues():
        """Read events directly from per-agent queue DBs into telemetry.db.

        This bypasses the EventBus → WAL path for single-machine deployment.
        Each agent writes DeviceTelemetry protobufs to its own queue DB.
        We read them, deserialize, and store directly.
        """
        import glob
        import sqlite3 as _sqlite3

        from amoskys.proto import universal_telemetry_pb2 as pb2

        total = 0
        for qdb_path in glob.glob(str(queue_dir / "*.db")):
            try:
                conn = _sqlite3.connect(qdb_path, timeout=2)
                rows = conn.execute(
                    "SELECT id, bytes FROM queue ORDER BY id LIMIT 100"
                ).fetchall()

                if not rows:
                    conn.close()
                    continue

                processed_ids = []
                for row_id, raw_bytes in rows:
                    try:
                        dt = pb2.DeviceTelemetry()
                        dt.ParseFromString(raw_bytes)

                        for ev in dt.events:
                            if ev.event_type == "SECURITY" and ev.HasField(
                                "security_event"
                            ):
                                se = ev.security_event
                                attrs = dict(ev.attributes)

                                # Enrich with GeoIP/ASN/ThreatIntel
                                if enrichment is not None:
                                    try:
                                        enrichment.enrich(attrs)
                                    except Exception:
                                        pass

                                # Derive detection_source for agent
                                # attribution when collection_agent
                                # is empty
                                agent = dt.collection_agent or attrs.get(
                                    "detection_source", ""
                                )

                                event_data = {
                                    "event_id": ev.event_id,
                                    "device_id": dt.device_id,
                                    "event_type": ev.event_type,
                                    "event_category": se.event_category,
                                    "event_action": attrs.get(
                                        "event_action", se.event_category
                                    ),
                                    "event_outcome": "alert",
                                    "risk_score": se.risk_score,
                                    "confidence": float(attrs.get("confidence", "0.5")),
                                    "mitre_techniques": json.dumps(
                                        list(se.mitre_techniques)
                                    ),
                                    "collection_agent": agent,
                                    "description": attrs.get("description", ""),
                                    "raw_attributes_json": json.dumps(attrs),
                                    "event_timestamp_ns": ev.event_timestamp_ns
                                    or dt.timestamp_ns,
                                    # Enrichment results
                                    "geo_src_country": attrs.get("geo_src_country"),
                                    "asn_src_org": attrs.get("asn_src_org"),
                                    "asn_src_number": attrs.get("asn_src_number"),
                                    "threat_intel_match": attrs.get(
                                        "threat_intel_match", False
                                    ),
                                    "enrichment_status": attrs.get(
                                        "enrichment_status", "raw"
                                    ),
                                }

                                # Score the event before storage
                                if scorer is not None:
                                    try:
                                        scorer.score_event(event_data)
                                    except Exception:
                                        pass
                                store.insert_security_event(event_data)

                                # Feed fusion engine
                                if fusion:
                                    from datetime import datetime

                                    from amoskys.intel.models import TelemetryEventView

                                    try:
                                        fusion.add_event(
                                            TelemetryEventView(
                                                event_id=ev.event_id,
                                                event_type=ev.event_type,
                                                device_id=dt.device_id,
                                                severity=ev.severity or "MEDIUM",
                                                timestamp=datetime.now(),
                                                security_event={
                                                    "event_category": se.event_category,
                                                    "event_action": se.event_category,
                                                    "risk_score": se.risk_score,
                                                    "mitre_techniques": list(
                                                        se.mitre_techniques
                                                    ),
                                                },
                                                attributes=dict(ev.attributes),
                                            )
                                        )
                                    except Exception as e:
                                        logger.warning(
                                            "Failed to insert security event: %s", e
                                        )

                            elif ev.event_type == "OBSERVATION":
                                try:
                                    store.insert_observation_event(
                                        {
                                            "event_id": ev.event_id,
                                            "device_id": dt.device_id,
                                            "domain": ev.attributes.get(
                                                "_domain",
                                                dt.collection_agent,
                                            ),
                                            "event_timestamp_ns": ev.event_timestamp_ns
                                            or dt.timestamp_ns,
                                            "raw_attributes_json": json.dumps(
                                                dict(ev.attributes)
                                            ),
                                        }
                                    )
                                except Exception as e:
                                    logger.warning(
                                        "Failed to insert observation event: %s", e
                                    )

                        processed_ids.append(row_id)
                        total += 1
                    except Exception as e:
                        logger.warning("Skipping corrupted queue row %s: %s", row_id, e)
                        processed_ids.append(row_id)  # Skip corrupted

                # Delete processed rows
                if processed_ids:
                    placeholders = ",".join("?" * len(processed_ids))
                    conn.execute(
                        f"DELETE FROM queue WHERE id IN ({placeholders})",
                        processed_ids,
                    )
                    conn.commit()
                conn.close()
            except Exception as e:
                logger.warning("Queue processing failed for %s: %s", qdb_path, e)
        return total

    logger.info("Direct queue reader enabled (single-machine mode)")

    # ── Analysis loop ──
    cycle = 0
    total_events_processed = 0

    while not shutdown_event.is_set():
        try:
            cycle += 1
            t0 = time.time()
            events_this_cycle = 0

            # Process WAL batches (EventBus path)
            if wal_processor:
                try:
                    processed = wal_processor.process_batch(batch_size=500)
                    events_this_cycle += processed
                except Exception:
                    logger.error("WAL processing failed", exc_info=True)

            # Direct queue drain (single-machine path — bypasses EventBus)
            try:
                drained = _drain_agent_queues()
                events_this_cycle += drained
            except Exception:
                logger.error("Queue drain failed", exc_info=True)

            # IGRIS tactical assessment (every 10s — the minister reads the battlefield)
            if tactical and cycle % 5 == 0:  # 5 * 2s = 10s
                try:
                    state = tactical.assess()
                    if state.hunt_mode:
                        logger.warning(
                            "IGRIS HUNT MODE: posture=%s directives=%d pids=%s",
                            state.posture,
                            len(state.active_directives),
                            state.watched_pids[:5],
                        )
                except Exception:
                    logger.debug("IGRIS tactical assessment failed", exc_info=True)

            # IGRIS observation cycle (every 60s — organism coherence)
            if igris and cycle % 30 == 0:  # 30 * 2s = 60s
                try:
                    igris.observe()
                except Exception:
                    logger.debug("IGRIS observation failed", exc_info=True)

            # Run fusion evaluation (every 60s)
            if fusion and cycle % 30 == 0:
                try:
                    # Evaluate all devices with recent events
                    for device_id in fusion.get_active_devices():
                        incidents = fusion.evaluate_device(device_id)
                        if incidents:
                            logger.info(
                                "Fusion created %d incidents for %s",
                                len(incidents),
                                device_id,
                            )
                except Exception:
                    logger.debug("Fusion evaluation failed", exc_info=True)

            total_events_processed += events_this_cycle
            dt = (time.time() - t0) * 1000

            if events_this_cycle > 0 or cycle % 30 == 1:
                logger.info(
                    "Cycle %d: processed %d events in %.0fms (total: %d)",
                    cycle,
                    events_this_cycle,
                    dt,
                    total_events_processed,
                )

            # Write heartbeat
            _write_heartbeat(cycle, events_this_cycle, total_events_processed, dt)

        except Exception:
            logger.error("Analysis cycle %d failed", cycle, exc_info=True)

        shutdown_event.wait(timeout=2.0)

    # ── Shutdown ──
    logger.info(
        "Analyzer shutting down after %d cycles, %d total events",
        cycle,
        total_events_processed,
    )
    return 0


def _write_heartbeat(cycle: int, events_this_cycle: int, total: int, latency_ms: float):
    """Write heartbeat file for watchdog liveness check."""
    heartbeat_dir = Path("data/heartbeats")
    heartbeat_dir.mkdir(parents=True, exist_ok=True)
    heartbeat = {
        "agent": "analyzer",
        "cycle": cycle,
        "events_this_cycle": events_this_cycle,
        "total_events": total,
        "latency_ms": round(latency_ms, 1),
        "timestamp": time.time(),
        "pid": os.getpid(),
    }
    try:
        (heartbeat_dir / "analyzer.json").write_text(json.dumps(heartbeat))
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
