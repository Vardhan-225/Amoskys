#!/usr/bin/env python3
"""
Build Canonical Process Table from WAL

Extracts all ProcessEvent data from WAL and creates a normalized canonical table.
This is Stage 7: Raw validated neurons → Structured neuron table
"""
import sys
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

DB_PATH = project_root / "data/wal/flowagent.db"
OUTPUT_DIR = project_root / "data/ml_pipeline"

def extract_process_events_from_wal():
    """Extract all ProcessEvent data from WAL"""

    print("="*70)
    print("Building Canonical Process Table from WAL")
    print("="*70)
    print(f"Input:  {DB_PATH}")
    print(f"Output: {OUTPUT_DIR}/process_canonical_full.parquet")
    print()

    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Connect to WAL
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("SELECT id, bytes, ts_ns, idem FROM wal ORDER BY id ASC;")

    records = []
    process_count = 0
    other_count = 0
    parse_errors = 0

    print("📊 Extracting ProcessEvents from WAL...")

    for row_id, blob, ts_ns, idem_key in cur:
        env = telemetry_pb2.UniversalEnvelope()
        try:
            env.ParseFromString(blob)
        except Exception as e:
            parse_errors += 1
            continue

        if env.HasField("process"):
            process_count += 1
            p = env.process

            # Extract exe basename
            exe_basename = Path(p.exe).name if p.exe else ""

            # Classify user type
            if p.uid == 0:
                user_type = "root"
            elif p.uid < 500:
                user_type = "system"
            else:
                user_type = "user"

            # Classify process by path
            if p.exe:
                if "/System/" in p.exe:
                    process_class = "system"
                elif "/Applications/" in p.exe:
                    process_class = "application"
                elif "/usr/libexec/" in p.exe or "/usr/sbin/" in p.exe:
                    process_class = "daemon"
                elif "/opt/" in p.exe or ".venv" in p.exe:
                    process_class = "third_party"
                else:
                    process_class = "other"
            else:
                process_class = "unknown"

            records.append({
                'wal_id': row_id,
                'ts_ns': ts_ns,
                'idempotency_key': idem_key,
                'pid': p.pid,
                'ppid': p.ppid,
                'exe': p.exe,
                'exe_basename': exe_basename,
                'args_count': len(p.args),
                'args_str': ' '.join(p.args) if p.args else "",
                'uid': p.uid,
                'gid': p.gid,
                'user_type': user_type,
                'process_class': process_class,
                'cgroup': p.cgroup,
                'container_id': p.container_id
            })
        else:
            other_count += 1

    conn.close()

    print(f"  ✅ ProcessEvents extracted: {process_count}")
    print(f"  ℹ️  Other event types: {other_count}")
    if parse_errors > 0:
        print(f"  ⚠️  Parse errors: {parse_errors}")
    print()

    # Create DataFrame
    if not records:
        print("❌ ERROR: No ProcessEvents found in WAL!")
        return False

    df = pd.DataFrame(records)

    # Add derived time columns
    df['timestamp'] = pd.to_datetime(df['ts_ns'], unit='ns')
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek

    # Sort by timestamp
    df = df.sort_values('ts_ns').reset_index(drop=True)

    # Print summary statistics
    print("📈 Canonical Table Statistics:")
    print(f"  Total rows: {len(df)}")
    print(f"  Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    print(f"  Unique PIDs: {df['pid'].nunique()}")
    print(f"  Unique executables: {df['exe_basename'].nunique()}")
    print()

    print("👥 User Type Distribution:")
    print(df['user_type'].value_counts())
    print()

    print("🏷️  Process Class Distribution:")
    print(df['process_class'].value_counts())
    print()

    # Save to parquet and CSV
    parquet_path = OUTPUT_DIR / "process_canonical_full.parquet"
    csv_path = OUTPUT_DIR / "process_canonical_full.csv"

    df.to_parquet(parquet_path, index=False)
    df.to_csv(csv_path, index=False)

    print(f"✅ Saved canonical table:")
    print(f"  Parquet: {parquet_path} ({parquet_path.stat().st_size / 1024:.1f} KB)")
    print(f"  CSV:     {csv_path} ({csv_path.stat().st_size / 1024:.1f} KB)")
    print()

    # Sample rows
    print("🔍 Sample rows (first 5):")
    print(df[['timestamp', 'pid', 'ppid', 'exe_basename', 'user_type', 'process_class']].head())
    print()

    print("="*70)
    print("✅ Canonical process table build complete!")
    print("="*70)

    return True

if __name__ == "__main__":
    success = extract_process_events_from_wal()
    sys.exit(0 if success else 1)
