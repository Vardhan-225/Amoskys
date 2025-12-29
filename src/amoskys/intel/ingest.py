"""
Telemetry Ingestion Adapter

Bridges agent telemetry sources (EventBus, WAL databases, LocalQueues)
to the FusionEngine. Converts protobuf messages to TelemetryEventView
and feeds them into correlation windows.

Architecture:
    Agent DBs/Queues → Ingest Adapter → FusionEngine → Incidents + Risk
"""

import logging
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.models import TelemetryEventView
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

logger = logging.getLogger(__name__)


class TelemetryIngestor:
    """Ingests telemetry from agent data sources into FusionEngine

    Supports two modes:
    1. Database polling: Read from agent SQLite databases/queues
    2. EventBus subscription: Stream from gRPC EventBus (future)

    Attributes:
        fusion_engine: FusionEngine instance to feed events into
        agent_sources: List of agent data source paths
        last_seen_ids: Per-source tracking of processed event IDs
        poll_interval: Seconds between polls
    """

    def __init__(
        self,
        fusion_engine: FusionEngine,
        agent_sources: Optional[List[str]] = None,
        poll_interval: int = 10,
    ):
        """Initialize telemetry ingestor

        Args:
            fusion_engine: FusionEngine to feed events into
            agent_sources: List of agent DB/queue paths to poll
            poll_interval: Seconds between polling cycles
        """
        self.fusion_engine = fusion_engine
        self.poll_interval = poll_interval

        # Default agent sources (LocalQueue databases)
        self.agent_sources = agent_sources or [
            "data/queue/proc_agent.db",
            "data/queue/auth_agent.db",
            "data/queue/persistence_agent.db",
            "data/wal/flowagent.db",
        ]

        # Track last processed event per source to avoid duplicates
        self.last_seen_ids: Dict[str, Set[str]] = {
            source: set() for source in self.agent_sources
        }

        # Metrics
        self.events_ingested = 0
        self.last_ingest_time: Optional[datetime] = None

        logger.info(
            f"TelemetryIngestor initialized with {len(self.agent_sources)} sources"
        )

    def _read_events_from_queue(
        self, db_path: str, limit: int = 1000
    ) -> List[telemetry_pb2.DeviceTelemetry]:
        """Read telemetry from agent LocalQueue database

        LocalQueue schema:
            CREATE TABLE queue (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                retries INTEGER
            )

        Args:
            db_path: Path to LocalQueue database
            limit: Maximum events to read

        Returns:
            List of DeviceTelemetry protobuf messages
        """
        if not Path(db_path).exists():
            logger.debug(f"Queue DB not found: {db_path}")
            return []

        try:
            db = sqlite3.connect(db_path, timeout=2.0)

            # Query recent events (last 30 minutes to match fusion window)
            cutoff = int((datetime.now() - timedelta(minutes=30)).timestamp() * 1e9)

            rows = db.execute(
                "SELECT id, idem, bytes FROM queue WHERE ts_ns > ? ORDER BY ts_ns DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()

            events = []
            for row_id, idem, bytes_col in rows:
                # Skip if already processed
                if idem in self.last_seen_ids[db_path]:
                    continue

                try:
                    # Deserialize DeviceTelemetry
                    device_telem = telemetry_pb2.DeviceTelemetry()
                    device_telem.ParseFromString(bytes(bytes_col))
                    events.append(device_telem)

                    # Mark as seen
                    self.last_seen_ids[db_path].add(idem)

                except Exception as e:
                    logger.error(
                        f"Failed to parse telemetry from {db_path} (idem={idem}): {e}"
                    )

            db.close()

            if events:
                logger.debug(f"Read {len(events)} events from {db_path}")

            return events

        except sqlite3.OperationalError as e:
            logger.warning(f"Database locked or unavailable: {db_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to read from {db_path}: {e}")
            return []

    def _read_events_from_wal(
        self, db_path: str, limit: int = 1000
    ) -> List[telemetry_pb2.DeviceTelemetry]:
        """Read telemetry from FlowAgent WAL database

        FlowAgent WAL schema:
            CREATE TABLE wal (
                id INTEGER PRIMARY KEY,
                idem TEXT UNIQUE,
                ts_ns INTEGER,
                bytes BLOB,
                checksum BLOB
            )

        Args:
            db_path: Path to WAL database
            limit: Maximum events to read

        Returns:
            List of DeviceTelemetry protobuf messages (wrapped in Envelope)
        """
        if not Path(db_path).exists():
            logger.debug(f"WAL DB not found: {db_path}")
            return []

        try:
            db = sqlite3.connect(db_path, timeout=2.0)

            # Query recent events
            cutoff = int((datetime.now() - timedelta(minutes=30)).timestamp() * 1e9)

            rows = db.execute(
                "SELECT id, idem, bytes FROM wal WHERE ts_ns > ? ORDER BY ts_ns DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()

            events = []
            for row_id, idem, blob in rows:
                # Skip if already processed
                if idem in self.last_seen_ids[db_path]:
                    continue

                try:
                    # FlowAgent uses messaging_schema_pb2.Envelope, but for now
                    # we'll assume it's been migrated to UniversalEnvelope with DeviceTelemetry
                    # If not, this is where we'd handle the conversion

                    # Try parsing as UniversalEnvelope
                    envelope = telemetry_pb2.UniversalEnvelope()
                    envelope.ParseFromString(bytes(blob))

                    if envelope.HasField("device_telemetry"):
                        events.append(envelope.device_telemetry)
                        self.last_seen_ids[db_path].add(idem)

                except Exception as e:
                    logger.debug(
                        f"Failed to parse WAL entry from {db_path} (idem={idem}): {e}"
                    )

            db.close()

            if events:
                logger.debug(f"Read {len(events)} events from WAL {db_path}")

            return events

        except sqlite3.OperationalError as e:
            logger.warning(f"Database locked or unavailable: {db_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to read from WAL {db_path}: {e}")
            return []

    def _convert_to_event_views(
        self, device_telem: telemetry_pb2.DeviceTelemetry
    ) -> List[TelemetryEventView]:
        """Convert DeviceTelemetry protobuf to TelemetryEventView objects

        Args:
            device_telem: DeviceTelemetry protobuf message

        Returns:
            List of TelemetryEventView objects (one per event in the telemetry)
        """
        views = []
        device_id = device_telem.device_id

        for pb_event in device_telem.events:
            try:
                view = TelemetryEventView.from_protobuf(pb_event, device_id)
                views.append(view)
            except Exception as e:
                logger.error(
                    f"Failed to convert event {pb_event.event_id} to view: {e}"
                )

        return views

    def poll_once(self) -> int:
        """Poll all agent sources once and ingest events

        Returns:
            Number of events ingested
        """
        start = time.time()
        total_events = 0

        for source in self.agent_sources:
            try:
                # Determine source type by path convention
                if "wal" in source.lower():
                    device_telems = self._read_events_from_wal(source)
                else:
                    device_telems = self._read_events_from_queue(source)

                # Convert to event views and feed to fusion engine
                for device_telem in device_telems:
                    event_views = self._convert_to_event_views(device_telem)

                    for view in event_views:
                        self.fusion_engine.add_event(view)
                        total_events += 1

            except Exception as e:
                logger.error(f"Failed to poll source {source}: {e}", exc_info=True)

        # Update metrics
        self.events_ingested += total_events
        self.last_ingest_time = datetime.now()

        # Cleanup old tracking data (keep last 1 hour)
        for source in self.last_seen_ids:
            if len(self.last_seen_ids[source]) > 10000:
                # Clear half to prevent unbounded growth
                self.last_seen_ids[source] = set(
                    list(self.last_seen_ids[source])[-5000:]
                )

        duration = time.time() - start

        if total_events > 0:
            logger.info(
                f"Ingested {total_events} events from {len(self.agent_sources)} sources in {duration:.2f}s"
            )
        else:
            logger.debug(f"No new events in poll cycle ({duration:.2f}s)")

        return total_events

    def run(self):
        """Main ingestion loop

        Continuously polls agent sources and feeds FusionEngine.
        Also triggers periodic FusionEngine evaluation.
        """
        logger.info("=" * 70)
        logger.info("AMOSKYS Telemetry Ingestor starting...")
        logger.info("=" * 70)
        logger.info(f"Polling interval: {self.poll_interval}s")
        logger.info(f"Agent sources: {len(self.agent_sources)}")
        for source in self.agent_sources:
            logger.info(f"  - {source}")
        logger.info("")

        cycle = 0
        last_eval = time.time()

        while True:
            cycle += 1
            logger.info(f"Cycle #{cycle} - {datetime.now().isoformat()}")

            try:
                # Poll and ingest events
                events_ingested = self.poll_once()

                # Trigger FusionEngine evaluation every ~60 seconds
                if time.time() - last_eval >= 60:
                    logger.info("Triggering FusionEngine evaluation...")
                    self.fusion_engine.evaluate_all_devices()
                    last_eval = time.time()

                    # Print summary
                    logger.info(f"Total events ingested: {self.events_ingested}")
                    logger.info(
                        f"Devices tracked: {len(self.fusion_engine.device_state)}"
                    )

            except KeyboardInterrupt:
                logger.info("Shutting down ingestor...")
                break
            except Exception as e:
                logger.error(f"Ingestion cycle failed: {e}", exc_info=True)

            logger.info(f"Next poll in {self.poll_interval}s...")
            time.sleep(self.poll_interval)


def main():
    """CLI entrypoint for standalone ingestion service"""
    import argparse

    parser = argparse.ArgumentParser(description="AMOSKYS Telemetry Ingestor")
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=10,
        help="Seconds between polling agent sources",
    )
    parser.add_argument(
        "--fusion-db",
        type=str,
        default="data/intel/fusion.db",
        help="FusionEngine database path",
    )
    parser.add_argument(
        "--fusion-window",
        type=int,
        default=30,
        help="FusionEngine correlation window in minutes",
    )
    parser.add_argument(
        "--sources", nargs="+", help="Agent data source paths (overrides defaults)"
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Initialize FusionEngine
    logger.info("Initializing FusionEngine...")
    fusion_engine = FusionEngine(
        db_path=args.fusion_db, window_minutes=args.fusion_window
    )

    # Initialize Ingestor
    ingestor = TelemetryIngestor(
        fusion_engine=fusion_engine,
        agent_sources=args.sources,
        poll_interval=args.poll_interval,
    )

    # Run
    try:
        ingestor.run()
    except KeyboardInterrupt:
        logger.info("Ingestor stopped by user")


if __name__ == "__main__":
    main()
