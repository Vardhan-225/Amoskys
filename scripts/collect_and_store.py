#!/usr/bin/env python3
"""
Collect real data from all agents and store directly in TelemetryStore.

Bypasses EventBus by calling each agent's collect_data() method and
feeding the resulting DeviceTelemetry protobuf through WALProcessor's
routing logic into the permanent telemetry database.

Usage:
    python scripts/collect_and_store.py              # Collect from all agents
    python scripts/collect_and_store.py --clear      # Clear DB first
"""

import argparse
import logging
import sqlite3
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from amoskys.storage.wal_processor import WALProcessor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("CollectAndStore")

DB_PATH = str(Path(__file__).parent.parent / "data" / "telemetry.db")
QUEUE_DIR = str(Path(__file__).parent.parent / "data" / "queue")


def collect_from_agent(agent_cls, agent_name, **kwargs):
    """Instantiate agent, call collect_data(), return DeviceTelemetry list."""
    try:
        agent = agent_cls(**kwargs)
        items = agent.collect_data() or []
        logger.info("%s: collected %d DeviceTelemetry items", agent_name, len(items))
        return items
    except Exception as e:
        logger.error("%s: collection failed: %s", agent_name, e)
        return []


def main():
    parser = argparse.ArgumentParser(description="Collect & store real agent data")
    parser.add_argument("--clear", action="store_true", help="Clear DB before storing")
    args = parser.parse_args()

    processor = WALProcessor(store_path=DB_PATH)

    if args.clear:
        tables = [
            "security_events",
            "process_events",
            "flow_events",
            "peripheral_events",
            "device_telemetry",
            "metrics_timeseries",
        ]
        for t in tables:
            processor.store.db.execute(f"DELETE FROM {t}")
        processor.store.db.commit()
        logger.info("Cleared all tables")

    # Step 1: Drain any existing local queue data (from prior agent runs)
    logger.info("=" * 60)
    logger.info("STEP 1: Draining existing local queues")
    logger.info("=" * 60)
    drained = processor.process_local_queues(QUEUE_DIR)
    logger.info("Drained %d events from local queues", drained)

    # Step 2: Run each agent and process output directly
    logger.info("=" * 60)
    logger.info("STEP 2: Running agents and collecting fresh data")
    logger.info("=" * 60)

    total_items = 0
    total_security = 0

    agents = []

    # macOS Observatory core agents
    try:
        from amoskys.agents.os.macos.process.agent import MacOSProcessAgent

        agents.append(("MacOSProcess", MacOSProcessAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import MacOSProcessAgent: %s", e)

    try:
        from amoskys.agents.os.macos.network.agent import MacOSNetworkAgent

        agents.append(("MacOSNetwork", MacOSNetworkAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import MacOSNetworkAgent: %s", e)

    try:
        from amoskys.agents.os.macos.dns.agent import MacOSDNSAgent

        agents.append(("MacOSDNS", MacOSDNSAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import MacOSDNSAgent: %s", e)

    try:
        from amoskys.agents.os.macos.auth.agent import MacOSAuthAgent

        agents.append(("MacOSAuth", MacOSAuthAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import MacOSAuthAgent: %s", e)

    try:
        from amoskys.agents.os.macos.filesystem.agent import MacOSFileAgent

        agents.append(("MacOSFilesystem", MacOSFileAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import MacOSFilesystemAgent: %s", e)

    try:
        from amoskys.agents.os.macos.persistence.agent import MacOSPersistenceAgent

        agents.append(("MacOSPersistence", MacOSPersistenceAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import MacOSPersistenceAgent: %s", e)

    try:
        from amoskys.agents.os.macos.peripheral.agent import MacOSPeripheralAgent

        agents.append(("MacOSPeripheral", MacOSPeripheralAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import MacOSPeripheralAgent: %s", e)

    # Extended Observatory agents
    try:
        from amoskys.agents.os.macos.unified_log.agent import MacOSUnifiedLogAgent

        agents.append(("UnifiedLog", MacOSUnifiedLogAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import UnifiedLog: %s", e)

    try:
        from amoskys.agents.os.macos.applog.agent import MacOSAppLogAgent

        agents.append(("AppLog", MacOSAppLogAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import AppLog: %s", e)

    try:
        from amoskys.agents.os.macos.discovery.agent import MacOSDiscoveryAgent

        agents.append(("Discovery", MacOSDiscoveryAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import Discovery: %s", e)

    try:
        from amoskys.agents.os.macos.internet_activity.agent import MacOSInternetActivityAgent

        agents.append(("InternetActivity", MacOSInternetActivityAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import InternetActivity: %s", e)

    try:
        from amoskys.agents.os.macos.db_activity.agent import MacOSDBActivityAgent

        agents.append(("DBActivity", MacOSDBActivityAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import DBActivity: %s", e)

    try:
        from amoskys.agents.os.macos.http_inspector.agent import MacOSHTTPInspectorAgent

        agents.append(("HTTPInspector", MacOSHTTPInspectorAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import HTTPInspector: %s", e)

    # NetworkSentinel — HTTP access log analysis, scan detection
    try:
        from amoskys.agents.os.macos.network_sentinel.agent import NetworkSentinelAgent

        agents.append(("NetworkSentinel", NetworkSentinelAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import NetworkSentinel: %s", e)

    # macOS Shield — InfostealerGuard, QuarantineGuard, ProvenanceEngine
    if sys.platform == "darwin":
        try:
            from amoskys.agents.os.macos.infostealer_guard.agent import (
                MacOSInfostealerGuardAgent,
            )

            agents.append(("InfostealerGuard", MacOSInfostealerGuardAgent, {}))
        except ImportError as e:
            logger.warning("Cannot import InfostealerGuard: %s", e)

        try:
            from amoskys.agents.os.macos.quarantine_guard.agent import (
                MacOSQuarantineGuardAgent,
            )

            agents.append(("QuarantineGuard", MacOSQuarantineGuardAgent, {}))
        except ImportError as e:
            logger.warning("Cannot import QuarantineGuard: %s", e)

        try:
            from amoskys.agents.os.macos.provenance.agent import MacOSProvenanceAgent

            agents.append(("ProvenanceEngine", MacOSProvenanceAgent, {}))
        except ImportError as e:
            logger.warning("Cannot import ProvenanceEngine: %s", e)

    for name, cls, kwargs in agents:
        logger.info("--- %s ---", name)
        items = collect_from_agent(cls, name, **kwargs)
        for dt in items:
            ts_ns = dt.timestamp_ns or int(time.time() * 1e9)
            idem = f"collect-{name}-{ts_ns}"
            processor._process_device_telemetry(dt, ts_ns, idem)
            total_items += 1
            # Count security events in this DeviceTelemetry
            for ev in dt.events:
                if ev.HasField("security_event"):
                    total_security += 1

    # Step 3: Run FusionEngine correlation (connects independent detections)
    if processor._fusion is not None:
        logger.info("=" * 60)
        logger.info("STEP 3: Running FusionEngine correlation")
        logger.info("=" * 60)
        for device_id in list(processor._fusion.device_state.keys()):
            incidents, _ = processor._fusion.evaluate_device(device_id)
            for inc in incidents:
                processor._fusion.persist_incident(inc)
                logger.info(
                    "  INCIDENT [%s] %s: %s (%d events linked)",
                    inc.severity.name,
                    inc.rule_name,
                    inc.summary[:80],
                    len(inc.event_ids),
                )
        # Bridge fusion incidents to dashboard
        processor._bridge_fusion_incidents()

    # Step 4: SOMA Brain training on fresh data
    logger.info("=" * 60)
    logger.info("STEP 4: Training SOMA Brain on collected telemetry")
    logger.info("=" * 60)
    if processor._brain is not None:
        try:
            metrics = processor._brain.train_once()
            status = metrics.get("status", "unknown")
            event_count = metrics.get("event_count", 0)
            if status == "completed":
                if_metrics = metrics.get("isolation_forest", {})
                gbc_metrics = metrics.get("gradient_boost", {})
                logger.info(
                    "SOMA training cycle %d: %d events, IF anomaly_rate=%.3f, GBC=%s (%.1fs)",
                    metrics.get("cycle", 0),
                    event_count,
                    if_metrics.get("anomaly_rate", -1),
                    gbc_metrics.get("status", "skipped"),
                    metrics.get("elapsed_seconds", 0),
                )
            elif status == "cold_start":
                logger.warning(
                    "SOMA cold start: only %d events (need %d). "
                    "Run more collection cycles to accumulate data.",
                    event_count,
                    processor._brain.MIN_EVENTS_FOR_TRAINING,
                )
            else:
                logger.warning("SOMA training status: %s", status)
        except Exception as e:
            logger.error("SOMA training failed: %s", e)
    else:
        logger.warning("SOMA Brain not available — skipping training")

    # Step 5: Report results
    logger.info("=" * 60)
    logger.info("RESULTS")
    logger.info("=" * 60)
    logger.info("DeviceTelemetry items processed: %d", total_items)
    logger.info("Security events extracted: %d", total_security)
    logger.info("Local queue events drained: %d", drained)

    conn = sqlite3.connect(DB_PATH)
    for t in [
        "security_events",
        "process_events",
        "flow_events",
        "peripheral_events",
        "device_telemetry",
        "metrics_timeseries",
    ]:
        cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        logger.info("  %s: %d rows", t, cnt)

    # Show fusion incidents
    fusion_db = sqlite3.connect("data/intel/fusion.db")
    inc_count = fusion_db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    logger.info("  fusion_incidents: %d rows", inc_count)
    fusion_db.close()

    conn.close()


if __name__ == "__main__":
    main()
