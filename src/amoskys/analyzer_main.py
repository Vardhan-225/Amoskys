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
        logger.warning("IGRIS not available: %s", e)

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

    # ── Analysis loop ──
    cycle = 0
    total_events_processed = 0

    while not shutdown_event.is_set():
        try:
            cycle += 1
            t0 = time.time()
            events_this_cycle = 0

            # Process WAL batches
            if wal_processor:
                try:
                    processed = wal_processor.process_batch(batch_size=500)
                    events_this_cycle += processed
                except Exception:
                    logger.error("WAL processing failed", exc_info=True)

            # Run IGRIS observation cycle (every 60s)
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
