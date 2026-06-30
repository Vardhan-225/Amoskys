#!/usr/bin/env python3
"""
AMOSKYS Timeline Visualizer
Creates visual timeline of event collection patterns
"""

import sqlite3
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def visualize_timeline(db_path: str):
    """Create ASCII timeline visualization of event collection"""

    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return

    print("📈 AMOSKYS TIMELINE VISUALIZATION")
    print("=" * 120)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get basic stats
    cursor.execute("SELECT COUNT(*), MIN(ts_ns), MAX(ts_ns) FROM wal")
    total, min_ts, max_ts = cursor.fetchone()

    if not min_ts or not max_ts:
        print("❌ No data in database")
        return

    duration_hours = (max_ts - min_ts) / 1e9 / 3600
    start_time = datetime.fromtimestamp(min_ts / 1e9)
    end_time = datetime.fromtimestamp(max_ts / 1e9)

    print(f"\n📊 Collection Summary:")
    print(f"   Total Events: {total:,}")
    print(f"   Start: {start_time}")
    print(f"   End: {end_time}")
    print(f"   Duration: {duration_hours:.2f} hours ({duration_hours/24:.2f} days)")
    print(f"   Rate: {total/duration_hours:.1f} events/hour")

    # Hourly distribution
    print(f"\n⏰ HOURLY EVENT DISTRIBUTION:")
    print(f"{'─' * 120}")

    cursor.execute("""
        SELECT
            strftime('%Y-%m-%d %H:00', ts_ns/1000000000, 'unixepoch', 'localtime') as hour,
            COUNT(*) as count
        FROM wal
        GROUP BY hour
        ORDER BY hour
    """)

    hour_data = cursor.fetchall()

    # Find max for scaling
    max_count = max(count for _, count in hour_data)
    bar_width = 80

    print(f"   {'Hour':<20} {'Events':>8}  {'Distribution':<{bar_width}}")
    print(f"   {'-' * 20} {'-' * 8}  {'-' * bar_width}")

    for hour, count in hour_data:
        bar_length = int((count / max_count) * bar_width) if max_count > 0 else 0
        bar = '█' * bar_length
        print(f"   {hour:<20} {count:>8}  {bar}")

    # Daily summary
    print(f"\n📅 DAILY SUMMARY:")
    print(f"{'─' * 120}")

    cursor.execute("""
        SELECT
            strftime('%Y-%m-%d', ts_ns/1000000000, 'unixepoch', 'localtime') as day,
            COUNT(*) as count,
            MIN(ts_ns) as first_ts,
            MAX(ts_ns) as last_ts
        FROM wal
        GROUP BY day
        ORDER BY day
    """)

    print(f"   {'Date':<15} {'Events':>8}  {'First Event':<20}  {'Last Event':<20}  {'Active Hours':<15}")
    print(f"   {'-' * 15} {'-' * 8}  {'-' * 20}  {'-' * 20}  {'-' * 15}")

    for day, count, first_ts, last_ts in cursor.fetchall():
        first_time = datetime.fromtimestamp(first_ts / 1e9)
        last_time = datetime.fromtimestamp(last_ts / 1e9)
        active_hours = (last_ts - first_ts) / 1e9 / 3600

        print(f"   {day:<15} {count:>8}  {first_time.strftime('%H:%M:%S'):<20}  "
              f"{last_time.strftime('%H:%M:%S'):<20}  {active_hours:>6.1f} hours")

    # Inter-arrival time analysis
    print(f"\n⏱️  INTER-ARRIVAL TIME ANALYSIS:")
    print(f"{'─' * 120}")

    cursor.execute("""
        SELECT
            ts_ns,
            LAG(ts_ns) OVER (ORDER BY ts_ns) as prev_ts
        FROM wal
        ORDER BY ts_ns
    """)

    inter_arrival_times = []
    for ts, prev_ts in cursor.fetchall():
        if prev_ts:
            delta_seconds = (ts - prev_ts) / 1e9
            inter_arrival_times.append(delta_seconds)

    if inter_arrival_times:
        import statistics

        avg_interval = statistics.mean(inter_arrival_times)
        median_interval = statistics.median(inter_arrival_times)
        min_interval = min(inter_arrival_times)
        max_interval = max(inter_arrival_times)
        stdev_interval = statistics.stdev(inter_arrival_times) if len(inter_arrival_times) > 1 else 0

        print(f"   Average: {avg_interval:.1f} seconds ({avg_interval/60:.1f} minutes)")
        print(f"   Median: {median_interval:.1f} seconds")
        print(f"   Min: {min_interval:.1f} seconds")
        print(f"   Max: {max_interval:.1f} seconds ({max_interval/3600:.1f} hours)")
        print(f"   Std Dev: {stdev_interval:.1f} seconds")

        # Detect gaps (intervals > 5 minutes)
        gaps = [(i, delta) for i, delta in enumerate(inter_arrival_times) if delta > 300]

        if gaps:
            print(f"\n   ⚠️  Detected {len(gaps)} collection gaps (> 5 minutes):")

            cursor.execute("SELECT ts_ns FROM wal ORDER BY ts_ns")
            timestamps = [ts for (ts,) in cursor.fetchall()]

            for event_idx, gap_seconds in gaps[:10]:  # Show first 10
                if event_idx < len(timestamps) - 1:
                    gap_start = datetime.fromtimestamp(timestamps[event_idx] / 1e9)
                    gap_end = datetime.fromtimestamp(timestamps[event_idx + 1] / 1e9)
                    print(f"      Gap {event_idx}: {gap_seconds/60:.1f} minutes "
                          f"({gap_start.strftime('%Y-%m-%d %H:%M:%S')} → "
                          f"{gap_end.strftime('%Y-%m-%d %H:%M:%S')})")

    # Collection consistency analysis
    print(f"\n🎯 COLLECTION CONSISTENCY:")
    print(f"{'─' * 120}")

    expected_interval = 60  # Expected 60 seconds between collections
    tolerance = 10  # ±10 seconds tolerance

    consistent = sum(1 for delta in inter_arrival_times
                    if expected_interval - tolerance <= delta <= expected_interval + tolerance)

    fast = sum(1 for delta in inter_arrival_times if delta < expected_interval - tolerance)
    slow = sum(1 for delta in inter_arrival_times if delta > expected_interval + tolerance)

    total_intervals = len(inter_arrival_times)

    print(f"   Expected Interval: {expected_interval} seconds (±{tolerance}s tolerance)")
    print(f"   Consistent: {consistent}/{total_intervals} ({consistent/total_intervals*100:.1f}%)")
    print(f"   Too Fast: {fast} ({fast/total_intervals*100:.1f}%)")
    print(f"   Too Slow: {slow} ({slow/total_intervals*100:.1f}%)")

    # Health score
    health_score = (consistent / total_intervals * 100) if total_intervals > 0 else 0

    print(f"\n   📊 Collection Health Score: {health_score:.1f}/100")

    if health_score >= 90:
        print(f"   ✅ EXCELLENT - Collection is very consistent")
    elif health_score >= 70:
        print(f"   ✅ GOOD - Collection is mostly consistent")
    elif health_score >= 50:
        print(f"   ⚠️  FAIR - Collection has some irregularities")
    else:
        print(f"   ❌ POOR - Collection is highly irregular")

    # 24-hour heatmap
    print(f"\n🔥 24-HOUR HEATMAP:")
    print(f"{'─' * 120}")

    cursor.execute("""
        SELECT
            CAST(strftime('%H', ts_ns/1000000000, 'unixepoch', 'localtime') AS INTEGER) as hour,
            COUNT(*) as count
        FROM wal
        GROUP BY hour
        ORDER BY hour
    """)

    hourly_counts = defaultdict(int)
    for hour, count in cursor.fetchall():
        hourly_counts[hour] = count

    max_hourly = max(hourly_counts.values()) if hourly_counts else 1

    print(f"   {'Hour':>4}  {'Events':>8}  {'Intensity':<60}")
    print(f"   {'-' * 4}  {'-' * 8}  {'-' * 60}")

    for hour in range(24):
        count = hourly_counts.get(hour, 0)
        intensity = int((count / max_hourly) * 50) if max_hourly > 0 else 0
        bar = '▓' * intensity + '░' * (50 - intensity)
        print(f"   {hour:02d}:00  {count:>8}  {bar}")

    conn.close()

    print(f"\n{'=' * 120}")
    print("✅ Timeline visualization complete!")


def export_timeline_csv(db_path: str, output_path: str):
    """Export timeline data to CSV for external visualization"""

    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            idem,
            datetime(ts_ns/1000000000, 'unixepoch', 'localtime') as timestamp,
            ts_ns,
            LENGTH(bytes) as size_bytes
        FROM wal
        ORDER BY ts_ns
    """)

    import csv

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'idempotency_key', 'timestamp', 'timestamp_ns', 'size_bytes'])

        for row in cursor.fetchall():
            writer.writerow(row)

    conn.close()
    print(f"✅ Exported timeline to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Visualize AMOSKYS event timeline')
    parser.add_argument('--db', default='data/wal/flowagent.db', help='Path to WAL database')
    parser.add_argument('--export-csv', help='Export timeline to CSV file')

    args = parser.parse_args()

    if args.export_csv:
        export_timeline_csv(args.db, args.export_csv)
    else:
        visualize_timeline(args.db)
