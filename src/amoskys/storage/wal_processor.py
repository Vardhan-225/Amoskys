#!/usr/bin/env python3
"""
WAL Processor - Moves data from WAL queue to permanent storage

This processor runs continuously, draining events from the EventBus WAL
and storing them in the permanent telemetry database for dashboard queries.
"""

import sqlite3
import logging
import time
import sys
import socket
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.storage.telemetry_store import TelemetryStore

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("WALProcessor")


class WALProcessor:
    """Processes events from WAL to permanent storage"""

    def __init__(self, wal_path: str = "data/wal/flowagent.db", store_path: str = "data/telemetry.db"):
        """Initialize processor

        Args:
            wal_path: Path to WAL database
            store_path: Path to permanent telemetry store
        """
        self.wal_path = wal_path
        self.store = TelemetryStore(store_path)
        self.processed_count = 0
        self.error_count = 0

    def process_batch(self, batch_size: int = 100) -> int:
        """Process a batch of events from WAL

        Args:
            batch_size: Number of events to process in one batch

        Returns:
            Number of events successfully processed
        """
        try:
            # Connect to WAL database
            conn = sqlite3.connect(self.wal_path, timeout=5.0)
            cursor = conn.execute(
                "SELECT id, bytes, ts_ns, idem FROM wal ORDER BY id LIMIT ?",
                (batch_size,)
            )
            rows = cursor.fetchall()

            if not rows:
                conn.close()
                return 0

            processed_ids = []
            processed = 0

            for row_id, env_bytes, ts_ns, idem in rows:
                try:
                    # Parse envelope
                    envelope = telemetry_pb2.UniversalEnvelope()
                    envelope.ParseFromString(bytes(env_bytes))

                    # Process based on content type
                    if envelope.HasField('device_telemetry'):
                        self._process_device_telemetry(envelope.device_telemetry, ts_ns, idem)
                    elif envelope.HasField('process'):
                        self._process_process_event(envelope.process, ts_ns, idem)
                    elif envelope.HasField('flow'):
                        self._process_flow_event(envelope.flow, ts_ns)

                    processed_ids.append(row_id)
                    processed += 1

                except Exception as e:
                    logger.error(f"Failed to process WAL entry {row_id}: {e}")
                    self.error_count += 1
                    # Still mark as processed to avoid blocking the queue
                    processed_ids.append(row_id)

            # Delete processed entries from WAL
            if processed_ids:
                placeholders = ','.join('?' * len(processed_ids))
                conn.execute(f"DELETE FROM wal WHERE id IN ({placeholders})", processed_ids)
                conn.commit()

            conn.close()
            self.processed_count += processed
            return processed

        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            return 0

    def _process_device_telemetry(self, dt: telemetry_pb2.DeviceTelemetry, ts_ns: int, idem: str):
        """Process DeviceTelemetry message"""
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9).isoformat()

        # Extract metrics from events
        total_processes = 0
        cpu_percent = 0.0
        mem_percent = 0.0

        # Process peripheral events separately
        for event in dt.events:
            if event.event_type == "METRIC" and event.HasField('metric_data'):
                metric = event.metric_data
                if metric.metric_name == "process_count":
                    total_processes = int(metric.numeric_value)
                elif metric.metric_name == "system_cpu_percent":
                    cpu_percent = metric.numeric_value
                elif metric.metric_name == "system_memory_percent":
                    mem_percent = metric.numeric_value

            # Handle peripheral STATUS events (connection/disconnection)
            elif event.event_type == "STATUS" and event.source_component == "peripheral_agent":
                self._process_peripheral_event(event, dt.device_id, ts_ns, timestamp_dt, dt.collection_agent, dt.agent_version)

        # Store device telemetry
        try:
            self.store.db.execute("""
                INSERT OR REPLACE INTO device_telemetry (
                    timestamp_ns, timestamp_dt, device_id, device_type, protocol,
                    manufacturer, model, ip_address, total_processes,
                    total_cpu_percent, total_memory_percent, metric_events,
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts_ns, timestamp_dt, dt.device_id, dt.device_type, dt.protocol,
                dt.metadata.manufacturer if dt.HasField('metadata') else None,
                dt.metadata.model if dt.HasField('metadata') else None,
                dt.metadata.ip_address if dt.HasField('metadata') else None,
                total_processes, cpu_percent, mem_percent, len(dt.events),
                dt.collection_agent, dt.agent_version
            ))
            self.store.db.commit()
        except Exception as e:
            logger.error(f"Failed to insert device telemetry: {e}")

    def _process_peripheral_event(self, event: any, device_id: str, ts_ns: int, timestamp_dt: str, agent: str, version: str):
        """Process peripheral connection/disconnection event"""
        try:
            attrs = event.attributes
            status_data = event.status_data if event.HasField('status_data') else None

            self.store.db.execute("""
                INSERT INTO peripheral_events (
                    timestamp_ns, timestamp_dt, device_id, peripheral_device_id,
                    event_type, device_name, device_type, vendor_id, product_id,
                    serial_number, manufacturer, connection_status, previous_status,
                    is_authorized, risk_score, confidence_score,
                    collection_agent, agent_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts_ns, timestamp_dt, device_id,
                attrs.get('device_id', ''),
                status_data.status if status_data else 'UNKNOWN',
                status_data.component_name if status_data else 'Unknown Device',
                attrs.get('device_type', 'UNKNOWN'),
                attrs.get('vendor_id', ''),
                attrs.get('product_id', ''),
                '', # serial_number not in attributes
                attrs.get('manufacturer', ''),
                status_data.status if status_data else 'UNKNOWN',
                status_data.previous_status if status_data else '',
                attrs.get('is_authorized', 'False') == 'True',
                float(attrs.get('risk_score', 0.0)),
                event.confidence_score,
                agent, version
            ))
            self.store.db.commit()
            logger.debug(f"Stored peripheral event: {attrs.get('device_type')} {status_data.status if status_data else 'N/A'}")
        except Exception as e:
            logger.error(f"Failed to insert peripheral event: {e}")

    def _process_process_event(self, proc: any, ts_ns: int, idem: str):
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
        exe_name = exe.split('/')[-1] if exe else ""

        # Daemon detection (most specific first)
        if (exe_name.endswith('d') and not exe_name.endswith('.app') or
            'daemon' in exe_lower or
            '/usr/sbin/' in exe or
            '/usr/libexec/' in exe or
            exe_name in ['launchd', 'systemstats', 'kernel_task']):
            category = "daemon"
        # System libraries and frameworks
        elif ('/System/Library/' in exe or
              '/Library/Apple/' in exe or
              'CoreServices' in exe or
              'PrivateFrameworks' in exe or
              exe_name.startswith('com.apple.')):
            category = "system"
        # User applications
        elif '/Applications/' in exe and '.app/' in exe:
            category = "application"
        # Helper processes
        elif 'Helper' in exe or 'helper' in exe_lower:
            category = "helper"
        # Kernel and core
        elif exe_name in ['kernel_task', 'launchd'] or '/kernel' in exe_lower:
            category = "kernel"
        # Fallback to unknown
        else:
            category = "unknown"

        # Extract cmdline
        cmdline = " ".join(proc.args) if proc.args else ""

        try:
            # Get device hostname for identification
            device_id = socket.gethostname()

            self.store.insert_process_event({
                'timestamp_ns': ts_ns,
                'timestamp_dt': timestamp_dt,
                'device_id': device_id,
                'pid': proc.pid,
                'ppid': proc.ppid,
                'exe': proc.exe,
                'cmdline': cmdline,
                'username': None,
                'cpu_percent': None,
                'memory_percent': None,
                'num_threads': None,
                'num_fds': None,
                'user_type': user_type,
                'process_category': category,
                'is_suspicious': False,
                'anomaly_score': None,
                'confidence_score': None,
                'collection_agent': 'mac_telemetry',
                'agent_version': '1.0.0'
            })
        except Exception as e:
            logger.error(f"Failed to insert process event: {e}")

    def _process_flow_event(self, flow: any, ts_ns: int):
        """Process FlowEvent message"""
        timestamp_dt = datetime.fromtimestamp(ts_ns / 1e9).isoformat()

        try:
            self.store.db.execute("""
                INSERT OR REPLACE INTO flow_events (
                    timestamp_ns, timestamp_dt, device_id,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    bytes_tx, bytes_rx, is_suspicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts_ns, timestamp_dt, 'unknown',
                flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
                flow.protocol, flow.bytes_tx, flow.bytes_rx, False
            ))
            self.store.db.commit()
        except Exception as e:
            logger.error(f"Failed to insert flow event: {e}")

    def run(self, interval: int = 5):
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
                    logger.info(f"Cycle #{cycle}: Processed {processed} events (total: {self.processed_count}, errors: {self.error_count})")
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


def main():
    """Entry point"""
    processor = WALProcessor()
    processor.run(interval=5)


if __name__ == '__main__':
    main()
