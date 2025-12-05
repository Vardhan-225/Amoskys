#!/usr/bin/env python3
"""
Validate Mac Process Telemetry in WAL
Inspects ProcessEvents to ensure they contain real Mac data
"""
import sys
import sqlite3
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2
from amoskys.proto import messaging_schema_pb2 as msg_pb2

DB_PATH = project_root / "data/wal/flowagent.db"

def validate_process_events():
    """Validate ProcessEvents in WAL"""

    print("="*70)
    print("Mac Process Telemetry Validation")
    print("="*70)
    print(f"Database: {DB_PATH}")
    print()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("SELECT id, bytes, ts_ns FROM wal ORDER BY id DESC LIMIT 500;")

    process_count = 0
    other_count = 0
    sample_processes = []

    for row_id, blob, ts_ns in cur:
        env = telemetry_pb2.UniversalEnvelope()
        try:
            env.ParseFromString(blob)
        except Exception as e:
            print(f"⚠️  Failed to parse envelope {row_id}: {e}")
            continue

        if env.HasField("process"):
            process_count += 1
            p = env.process

            # Collect sample for display
            if len(sample_processes) < 20:
                sample_processes.append({
                    'id': row_id,
                    'pid': p.pid,
                    'ppid': p.ppid,
                    'exe': p.exe,
                    'args': list(p.args)[:3],  # First 3 args
                    'uid': p.uid,
                    'gid': p.gid,
                    'ts_ns': ts_ns
                })
        else:
            other_count += 1

    print(f"📊 Summary")
    print(f"  ProcessEvents: {process_count}")
    print(f"  Other events: {other_count}")
    print(f"  Total scanned: {process_count + other_count}")
    print()

    if sample_processes:
        print(f"🔍 Sample ProcessEvents (most recent 20):")
        print()
        for i, proc in enumerate(sample_processes, 1):
            args_str = ' '.join(proc['args']) if proc['args'] else '(no args)'
            if len(args_str) > 50:
                args_str = args_str[:50] + '...'

            print(f"  {i:2d}. PID {proc['pid']:6d} | PPID {proc['ppid']:6d} | UID {proc['uid']:5d}")
            print(f"      EXE: {proc['exe']}")
            if proc['args']:
                print(f"      ARGS: {args_str}")
            print()

    # Validation checks
    print("✅ Validation Results:")
    print()

    issues = []

    if process_count == 0:
        issues.append("❌ No ProcessEvents found in WAL")
    else:
        print(f"  ✅ Found {process_count} ProcessEvents")

    # Check for variety in PIDs
    unique_pids = len(set(p['pid'] for p in sample_processes))
    if unique_pids < 10:
        issues.append(f"⚠️  Only {unique_pids} unique PIDs in sample (expected diverse processes)")
    else:
        print(f"  ✅ Diverse processes: {unique_pids} unique PIDs in sample")

    # Check for valid executables
    valid_exes = [p for p in sample_processes if p['exe'] and '/' in p['exe']]
    if len(valid_exes) < len(sample_processes) * 0.5:
        issues.append(f"⚠️  Many processes missing valid exe paths ({len(valid_exes)}/{len(sample_processes)})")
    else:
        print(f"  ✅ Valid exe paths: {len(valid_exes)}/{len(sample_processes)}")

    # Check for Mac-specific paths
    mac_paths = [p for p in sample_processes if p['exe'] and ('/Applications/' in p['exe'] or '/System/' in p['exe'] or '/usr/' in p['exe'])]
    if mac_paths:
        print(f"  ✅ Mac-specific paths detected: {len(mac_paths)} processes")
    else:
        issues.append("⚠️  No Mac-specific paths found (expected /Applications, /System, /usr)")

    print()

    if issues:
        print("⚠️  Issues detected:")
        for issue in issues:
            print(f"  {issue}")
    else:
        print("🎉 All validation checks passed!")

    print()
    print("="*70)

    return process_count > 0 and len(issues) == 0

if __name__ == "__main__":
    success = validate_process_events()
    sys.exit(0 if success else 1)
