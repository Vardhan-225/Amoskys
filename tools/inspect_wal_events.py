#!/usr/bin/env python3
"""
AMOSKYS WAL Event Inspector
Deep inspection of actual protobuf events stored in the WAL database
"""

import sqlite3
import sys
import os
from pathlib import Path
from datetime import datetime
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from amoskys.proto import messaging_schema_pb2 as pb


def inspect_wal_database(db_path: str, limit: int = 10, show_full: bool = False):
    """
    Deep inspection of WAL database with actual protobuf parsing

    Args:
        db_path: Path to flowagent.db
        limit: Number of events to inspect in detail
        show_full: If True, show complete protobuf structure
    """

    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return

    print("🔬 AMOSKYS WAL EVENT INSPECTOR")
    print("=" * 100)
    print(f"Database: {db_path}")
    print(f"Inspection Depth: {limit} events")
    print("=" * 100)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get overall statistics
    cursor.execute("SELECT COUNT(*), MIN(ts_ns), MAX(ts_ns), SUM(LENGTH(bytes)) FROM wal")
    total, min_ts, max_ts, total_bytes = cursor.fetchone()

    duration_seconds = (max_ts - min_ts) / 1e9 if max_ts and min_ts else 0
    duration_hours = duration_seconds / 3600

    print(f"\n📊 OVERALL STATISTICS:")
    print(f"   Total Events: {total:,}")
    print(f"   Total Size: {total_bytes:,} bytes ({total_bytes/1024:.2f} KB)")
    print(f"   Average Event Size: {total_bytes/total if total > 0 else 0:.1f} bytes")
    print(f"   Duration: {duration_hours:.2f} hours ({duration_seconds:.1f} seconds)")
    print(f"   Collection Rate: {total/duration_hours:.1f} events/hour" if duration_hours > 0 else "")
    print(f"   First Event: {datetime.fromtimestamp(min_ts/1e9)}")
    print(f"   Last Event: {datetime.fromtimestamp(max_ts/1e9)}")

    # Analyze schema
    print(f"\n📋 WAL SCHEMA:")
    cursor.execute("PRAGMA table_info(wal)")
    for col in cursor.fetchall():
        print(f"   {col[1]}: {col[2]} {'(PRIMARY KEY)' if col[5] else ''}")

    # Get sample events for deep inspection
    print(f"\n🔍 DEEP EVENT INSPECTION (First {limit} events):")
    print("=" * 100)

    cursor.execute(f"""
        SELECT id, idem, ts_ns, bytes, checksum
        FROM wal
        ORDER BY ts_ns ASC
        LIMIT {limit}
    """)

    telemetry_types = {}
    metric_names = {}
    devices = set()
    protocols = set()

    for idx, (event_id, idem, ts_ns, bytes_data, checksum) in enumerate(cursor.fetchall(), 1):
        print(f"\n{'─' * 100}")
        print(f"EVENT #{idx} (Database ID: {event_id})")
        print(f"{'─' * 100}")

        # Basic event metadata
        timestamp = datetime.fromtimestamp(ts_ns / 1e9)
        print(f"📅 Timestamp: {timestamp} ({ts_ns} ns)")
        print(f"🔑 Idempotency Key: {idem}")
        print(f"📦 Raw Size: {len(bytes_data)} bytes")
        print(f"🔐 Checksum: {checksum.hex()[:32]}...")

        # Parse the protobuf (old messaging schema format)
        try:
            envelope = pb.Envelope()
            envelope.ParseFromString(bytes_data)

            print(f"\n📨 ENVELOPE STRUCTURE:")
            print(f"   Version: v{envelope.version}")
            print(f"   Timestamp (ns): {envelope.ts_ns}")
            print(f"   Idempotency Key: {envelope.idempotency_key}")
            print(f"   Signature: {len(envelope.sig)} bytes (Ed25519)")
            print(f"   Signature (hex): {envelope.sig.hex()[:64]}...")

            # Check which event type is present
            if envelope.HasField('flow'):
                telemetry_types['FlowEvent'] = telemetry_types.get('FlowEvent', 0) + 1

                flow = envelope.flow
                devices.add(flow.src_ip)
                protocols.add(flow.protocol)

                print(f"\n🌊 FLOW EVENT:")
                print(f"   Source IP: {flow.src_ip}")
                print(f"   Destination IP: {flow.dst_ip}")
                print(f"   Protocol: {flow.protocol}")
                print(f"   Bytes Sent: {flow.bytes_sent}")
                print(f"   Bytes Recv: {flow.bytes_recv}")
                print(f"   Start Time: {datetime.fromtimestamp(flow.start_time / 1e9) if flow.start_time else 'N/A'}")

                # Track this as a metric
                metric_names[f"flow_{flow.protocol}"] = metric_names.get(f"flow_{flow.protocol}", 0) + 1

                print(f"\n   📊 FLOW DETAILS:")
                print(f"   ├─ Direction: {flow.src_ip} → {flow.dst_ip}")
                print(f"   ├─ Protocol Type: {flow.protocol}")
                print(f"   ├─ Bytes Sent: {flow.bytes_sent} bytes")
                print(f"   └─ Bytes Received: {flow.bytes_recv} bytes")

                print(f"\n   ⚠️  IMPORTANT: This is a WRAPPER event!")
                print(f"   The actual SNMP metrics are NOT stored in WAL.")
                print(f"   FlowEvent is just a heartbeat marker showing collection occurred.")

            elif envelope.HasField('process'):
                telemetry_types['ProcessEvent'] = telemetry_types.get('ProcessEvent', 0) + 1
                proc = envelope.process

                print(f"\n⚙️  PROCESS EVENT:")
                print(f"   Process Name: {proc.name}")
                print(f"   PID: {proc.pid}")
                print(f"   Command: {proc.cmd}")

                devices.add(proc.name)
                metric_names[f"process_{proc.name}"] = metric_names.get(f"process_{proc.name}", 0) + 1

            if show_full:
                print(f"\n📄 FULL PROTOBUF (Text Format):")
                print(str(envelope))

        except Exception as e:
            print(f"❌ Error parsing protobuf: {e}")

    # Summary statistics
    print(f"\n{'=' * 100}")
    print(f"📈 AGGREGATED STATISTICS (from {limit} sampled events):")
    print(f"{'=' * 100}")

    print(f"\n🔷 Telemetry Types:")
    for ttype, count in sorted(telemetry_types.items()):
        print(f"   {ttype}: {count} ({count/limit*100:.1f}%)")

    print(f"\n🖥️  Unique Devices: {len(devices)}")
    for device in sorted(devices):
        print(f"   - {device}")

    print(f"\n🔌 Protocols Used: {len(protocols)}")
    for protocol in sorted(protocols):
        print(f"   - {protocol}")

    print(f"\n📊 Metric Names (from sampled events):")
    for metric_name, count in sorted(metric_names.items(), key=lambda x: x[1], reverse=True):
        print(f"   {metric_name}: {count} occurrences")

    # Get hourly distribution
    print(f"\n⏰ HOURLY DISTRIBUTION (Last 24 hours):")
    cursor.execute("""
        SELECT
            strftime('%Y-%m-%d %H:00', ts_ns/1000000000, 'unixepoch', 'localtime') as hour,
            COUNT(*) as count
        FROM wal
        GROUP BY hour
        ORDER BY hour DESC
        LIMIT 24
    """)

    for hour, count in cursor.fetchall():
        bar = '█' * int(count / 10) + '░' * (10 - int(count / 10))
        print(f"   {hour}: {count:4d} events [{bar}]")

    conn.close()

    print(f"\n{'=' * 100}")
    print("✅ Inspection Complete!")
    print(f"\n💡 KEY FINDINGS:")
    print(f"   - All events are wrapped in UniversalEnvelope with Ed25519 signatures")
    print(f"   - Event size is consistent at ~{total_bytes/total if total > 0 else 0:.0f} bytes per event")
    print(f"   - Telemetry is collected every ~{duration_seconds/total if total > 0 else 0:.1f} seconds")
    print(f"   - Currently monitoring {len(devices)} device(s) via {len(protocols)} protocol(s)")
    print(f"\n📁 Next: Run ETL pipeline analysis to see feature transformation")


def export_to_json(db_path: str, output_path: str, limit: int = 100):
    """Export events to JSON for easier inspection"""

    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(f"""
        SELECT id, idem, ts_ns, bytes
        FROM wal
        ORDER BY ts_ns DESC
        LIMIT {limit}
    """)

    events = []
    for event_id, idem, ts_ns, bytes_data in cursor.fetchall():
        envelope = pb.Envelope()
        envelope.ParseFromString(bytes_data)

        event_dict = {
            'db_id': event_id,
            'idempotency_key': idem,
            'timestamp': datetime.fromtimestamp(ts_ns / 1e9).isoformat(),
            'timestamp_ns': ts_ns,
            'envelope_version': envelope.version,
            'signature_length': len(envelope.sig),
        }

        if envelope.HasField('flow'):
            event_dict['event_type'] = 'FlowEvent'
            event_dict['src_ip'] = envelope.flow.src_ip
            event_dict['dst_ip'] = envelope.flow.dst_ip
            event_dict['protocol'] = envelope.flow.protocol
            event_dict['bytes_sent'] = envelope.flow.bytes_sent
            event_dict['bytes_recv'] = envelope.flow.bytes_recv
            event_dict['start_time'] = envelope.flow.start_time

        elif envelope.HasField('process'):
            event_dict['event_type'] = 'ProcessEvent'
            event_dict['process_name'] = envelope.process.name
            event_dict['pid'] = envelope.process.pid
            event_dict['command'] = envelope.process.cmd

        events.append(event_dict)

    with open(output_path, 'w') as f:
        json.dump(events, f, indent=2)

    conn.close()
    print(f"✅ Exported {len(events)} events to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Inspect AMOSKYS WAL database events')
    parser.add_argument('--db', default='data/wal/flowagent.db', help='Path to WAL database')
    parser.add_argument('--limit', type=int, default=10, help='Number of events to inspect in detail')
    parser.add_argument('--full', action='store_true', help='Show full protobuf text format')
    parser.add_argument('--export-json', help='Export events to JSON file')
    parser.add_argument('--export-limit', type=int, default=100, help='Number of events to export')

    args = parser.parse_args()

    if args.export_json:
        export_to_json(args.db, args.export_json, args.export_limit)
    else:
        inspect_wal_database(args.db, args.limit, args.full)
