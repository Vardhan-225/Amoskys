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

    # ProcAgentV3
    try:
        from amoskys.agents.proc.proc_agent import ProcAgent

        agents.append(("ProcAgent", ProcAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import ProcAgent: %s", e)

    # FlowAgentV2
    try:
        from amoskys.agents.flow.flow_agent import FlowAgent

        agents.append(("FlowAgent", FlowAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import FlowAgent: %s", e)

    # DNSAgentV2
    try:
        from amoskys.agents.dns.dns_agent import DNSAgent

        agents.append(("DNSAgent", DNSAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import DNSAgent: %s", e)

    # AuthGuardAgentV2
    try:
        from amoskys.agents.auth.auth_guard_agent import AuthGuardAgent

        agents.append(("AuthGuardAgent", AuthGuardAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import AuthGuardAgent: %s", e)

    # FIMAgentV2
    try:
        from amoskys.agents.fim.fim_agent import FIMAgent

        agents.append(("FIMAgent", FIMAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import FIMAgent: %s", e)

    # PersistenceGuardV2
    try:
        from amoskys.agents.persistence.persistence_agent import PersistenceGuard

        agents.append(("PersistenceGuard", PersistenceGuard, {}))
    except ImportError as e:
        logger.warning("Cannot import PersistenceGuard: %s", e)

    # PeripheralAgentV2
    try:
        from amoskys.agents.peripheral.peripheral_agent import PeripheralAgent

        agents.append(("PeripheralAgent", PeripheralAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import PeripheralAgent: %s", e)

    # NetworkSentinel — HTTP access log analysis, scan detection
    try:
        from amoskys.agents.shared.network_sentinel.agent import NetworkSentinelAgent

        agents.append(("NetworkSentinel", NetworkSentinelAgent, {}))
    except ImportError as e:
        logger.warning("Cannot import NetworkSentinel: %s", e)

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

    # Step 3: Report results
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
    conn.close()


if __name__ == "__main__":
    main()
