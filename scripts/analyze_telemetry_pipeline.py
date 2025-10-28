#!/usr/bin/env python3
"""
AMOSKYS Telemetry Pipeline Analysis
Comprehensive analysis of device telemetry collection and ML pipeline readiness
"""

import sqlite3
import sys
import os
from pathlib import Path
from datetime import datetime
from collections import Counter

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from amoskys.proto import messaging_schema_pb2 as pb


def analyze_wal_database(db_path):
    """Comprehensive analysis of WAL database"""

    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return

    print("🧠⚡ AMOSKYS TELEMETRY PIPELINE ANALYSIS")
    print("=" * 80)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get basic statistics
    cursor.execute("SELECT COUNT(*), MIN(ts_ns), MAX(ts_ns), SUM(LENGTH(bytes)) FROM wal")
    total, min_ts, max_ts, total_bytes = cursor.fetchone()

    duration_hours = (max_ts - min_ts) / 1e9 / 3600 if max_ts and min_ts else 0

    print(f"\n📊 DATABASE STATISTICS:")
    print(f"   Location: {db_path}")
    print(f"   Total Events: {total:,}")
    print(f"   Total Size: {total_bytes:,} bytes ({total_bytes/1024:.2f} KB)")
    print(f"   First Event: {datetime.fromtimestamp(min_ts/1e9) if min_ts else 'N/A'}")
    print(f"   Last Event: {datetime.fromtimestamp(max_ts/1e9) if max_ts else 'N/A'}")
    print(f"   Duration: {duration_hours:.2f} hours")
    print(f"   Collection Rate: {total/duration_hours:.1f} events/hour" if duration_hours > 0 else "")

    # Analyze event types
    print(f"\n📦 EVENT TYPE ANALYSIS:")
    cursor.execute("SELECT idem, bytes FROM wal")

    event_types = Counter()
    devices = Counter()
    protocols = Counter()
    sizes = []

    for idem, bytes_data in cursor.fetchall():
        try:
            env = pb.Envelope()
            env.ParseFromString(bytes_data)

            # Extract device from idem (format: device_timestamp)
            device = idem.split('_')[0]
            devices[device] += 1

            # Determine event type
            if env.HasField('flow'):
                event_types['FlowEvent'] += 1
                protocols[env.flow.protocol] += 1
            elif env.HasField('process'):
                event_types['ProcessEvent'] += 1
            else:
                event_types['Unknown'] += 1

            sizes.append(len(bytes_data))

        except Exception as e:
            event_types['ParseError'] += 1

    for event_type, count in event_types.most_common():
        print(f"   {event_type}: {count:,} ({count/total*100:.1f}%)")

    # Device statistics
    print(f"\n🖥️  DEVICE STATISTICS:")
    print(f"   Unique Devices: {len(devices)}")
    for device, count in devices.most_common():
        print(f"   {device}: {count:,} events")

    # Protocol statistics
    if protocols:
        print(f"\n🔌 PROTOCOL BREAKDOWN:")
        for protocol, count in protocols.most_common():
            print(f"   {protocol}: {count:,} ({count/sum(protocols.values())*100:.1f}%)")

    # Size statistics
    if sizes:
        avg_size = sum(sizes) / len(sizes)
        min_size = min(sizes)
        max_size = max(sizes)
        print(f"\n📏 EVENT SIZE STATISTICS:")
        print(f"   Average: {avg_size:.1f} bytes")
        print(f"   Min: {min_size} bytes")
        print(f"   Max: {max_size} bytes")

    # Time distribution
    print(f"\n⏰ TIME DISTRIBUTION:")
    cursor.execute("""
        SELECT
            strftime('%Y-%m-%d %H:00', ts_ns/1000000000, 'unixepoch', 'localtime') as hour,
            COUNT(*) as count
        FROM wal
        GROUP BY hour
        ORDER BY hour DESC
        LIMIT 24
    """)

    hour_counts = cursor.fetchall()
    if hour_counts:
        print(f"   Last 24 hours (by hour):")
        for hour, count in hour_counts:
            print(f"      {hour}: {count:,} events")

    # Sample recent events
    print(f"\n🔍 RECENT EVENTS SAMPLE (Last 5):")
    cursor.execute("SELECT idem, ts_ns, bytes FROM wal ORDER BY ts_ns DESC LIMIT 5")

    for idx, (idem, ts_ns, bytes_data) in enumerate(cursor.fetchall(), 1):
        env = pb.Envelope()
        env.ParseFromString(bytes_data)

        ts = datetime.fromtimestamp(ts_ns / 1e9)
        print(f"\n   Event #{idx}:")
        print(f"      ID: {idem}")
        print(f"      Time: {ts}")
        print(f"      Version: v{env.version}")
        print(f"      Signed: ✅ ({len(env.sig)} bytes)")

        if env.HasField('flow'):
            print(f"      Type: FlowEvent")
            print(f"      Flow: {env.flow.src_ip} → {env.flow.dst_ip}")
            print(f"      Protocol: {env.flow.protocol}")
        elif env.HasField('process'):
            print(f"      Type: ProcessEvent")
            print(f"      Process: {env.process.name} (PID: {env.process.pid})")

    # ML Pipeline Readiness
    print(f"\n🧠 ML PIPELINE READINESS:")
    if total >= 100:
        print(f"   ✅ Sufficient data for training ({total:,} events)")
    else:
        print(f"   ⚠️  More data recommended (have {total}, recommend 100+)")

    if duration_hours >= 1:
        print(f"   ✅ Sufficient temporal coverage ({duration_hours:.1f} hours)")
    else:
        print(f"   ⚠️  More temporal data recommended (have {duration_hours:.1f}h, recommend 1h+)")

    if len(devices) >= 1:
        print(f"   ✅ Multi-device data available ({len(devices)} devices)")
    else:
        print(f"   ⚠️  Only single device data")

    events_per_hour = total / duration_hours if duration_hours > 0 else 0
    if events_per_hour >= 10:
        print(f"   ✅ Good collection frequency ({events_per_hour:.1f} events/hour)")
    else:
        print(f"   ⚠️  Low collection frequency ({events_per_hour:.1f} events/hour)")

    conn.close()

    print(f"\n{'=' * 80}")
    print(f"✅ Analysis complete!")
    print(f"\n💡 NEXT STEPS:")
    print(f"   1. Run ML transformation pipeline: notebooks/ml_transformation_pipeline.ipynb")
    print(f"   2. Train ML models on collected telemetry")
    print(f"   3. Deploy models for real-time threat detection")
    print(f"   4. View dashboard: http://localhost:8000")


if __name__ == "__main__":
    db_path = "data/wal/flowagent.db"

    if len(sys.argv) > 1:
        db_path = sys.argv[1]

    analyze_wal_database(db_path)
