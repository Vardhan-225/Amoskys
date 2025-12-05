"""
AMOSKYS Process Telemetry API
Fetches and displays Mac process telemetry from EventBus WAL
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from .rate_limiter import require_rate_limit
import sqlite3
import os
import sys
from pathlib import Path

process_bp = Blueprint('process_telemetry', __name__, url_prefix='/process-telemetry')

# Path to EventBus WAL database
WAL_DB_PATH = os.path.join(os.path.dirname(__file__), '../../../data/wal/flowagent.db')

# Add project root to import protobuf schemas
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2


def safe_int(value, default=0, min_val=None, max_val=None):
    """Safely parse integer from request parameter"""
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return max_val
        return result
    except (ValueError, TypeError):
        return default


def get_db_connection():
    """Create connection to WAL database"""
    if not os.path.exists(WAL_DB_PATH):
        return None
    conn = sqlite3.connect(WAL_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@process_bp.route('/recent', methods=['GET'])
def get_recent_processes():
    """Get recent ProcessEvents from WAL"""
    limit = safe_int(request.args.get('limit', 100), default=100, min_val=1, max_val=500)

    conn = get_db_connection()
    if not conn:
        return jsonify({'processes': [], 'message': 'No data available'}), 200

    try:
        cursor = conn.cursor()
        cursor.execute('SELECT id, bytes, ts_ns FROM wal ORDER BY id DESC LIMIT ?', (limit * 2,))

        processes = []
        for row in cursor.fetchall():
            env = telemetry_pb2.UniversalEnvelope()
            try:
                env.ParseFromString(row['bytes'])
            except Exception:
                continue

            if env.HasField('process'):
                p = env.process

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

                exe_basename = os.path.basename(p.exe) if p.exe else ""

                processes.append({
                    'wal_id': row['id'],
                    'timestamp': datetime.fromtimestamp(row['ts_ns'] / 1e9).isoformat(),
                    'pid': p.pid,
                    'ppid': p.ppid,
                    'exe': p.exe,
                    'exe_basename': exe_basename,
                    'args_count': len(p.args),
                    'uid': p.uid,
                    'gid': p.gid,
                    'user_type': user_type,
                    'process_class': process_class,
                    'age_seconds': int(datetime.now().timestamp() - row['ts_ns'] / 1e9)
                })

                if len(processes) >= limit:
                    break

        return jsonify({
            'processes': processes,
            'count': len(processes),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@process_bp.route('/stats', methods=['GET'])
@require_rate_limit(max_requests=100, window_seconds=60)
def get_process_stats():
    """Get aggregated process statistics for dashboard"""
    conn = get_db_connection()
    if not conn:
        return jsonify({
            'total_process_events': 0,
            'unique_pids': 0,
            'unique_executables': 0,
            'user_type_distribution': {'root': 0, 'system': 0, 'user': 0},
            'process_class_distribution': {'system': 0, 'application': 0, 'daemon': 0, 'third_party': 0, 'other': 0},
            'top_executables': [],
            'collection_period': {'duration_hours': 0}
        }), 200

    try:
        cursor = conn.cursor()
        
        # Get all process events
        cursor.execute('SELECT bytes, ts_ns FROM wal ORDER BY id DESC')
        all_rows = cursor.fetchall()
        
        pids = set()
        exes = set()
        user_dist = {'root': 0, 'system': 0, 'user': 0}
        class_dist = {'system': 0, 'application': 0, 'daemon': 0, 'third_party': 0, 'other': 0}
        exe_freq = {}
        timestamps = []
        
        for row in all_rows:
            env = telemetry_pb2.UniversalEnvelope()
            try:
                env.ParseFromString(row['bytes'])
            except Exception:
                continue
            
            if env.HasField('process'):
                p = env.process
                pids.add(p.pid)
                if p.exe:
                    exes.add(p.exe)
                    exe_basename = os.path.basename(p.exe)
                    exe_freq[exe_basename] = exe_freq.get(exe_basename, 0) + 1
                
                timestamps.append(row['ts_ns'])
                
                # User type
                if p.uid == 0:
                    user_dist['root'] += 1
                elif p.uid < 500:
                    user_dist['system'] += 1
                else:
                    user_dist['user'] += 1
                
                # Process class
                if p.exe:
                    if "/System/" in p.exe:
                        class_dist['system'] += 1
                    elif "/Applications/" in p.exe:
                        class_dist['application'] += 1
                    elif "/usr/libexec/" in p.exe or "/usr/sbin/" in p.exe:
                        class_dist['daemon'] += 1
                    elif "/opt/" in p.exe or ".venv" in p.exe:
                        class_dist['third_party'] += 1
                    else:
                        class_dist['other'] += 1
                else:
                    class_dist['other'] += 1
        
        # Calculate duration
        duration_hours = 0
        if timestamps:
            min_ts = min(timestamps)
            max_ts = max(timestamps)
            duration_hours = (max_ts - min_ts) / (1e9 * 3600)
        
        # Top executables
        top_exes = sorted(exe_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        top_exes_list = [
            {'name': name, 'count': count}
            for name, count in top_exes
        ]
        
        return jsonify({
            'total_process_events': len(all_rows),
            'unique_pids': len(pids),
            'unique_executables': len(exes),
            'user_type_distribution': user_dist,
            'process_class_distribution': class_dist,
            'top_executables': top_exes_list,
            'collection_period': {
                'duration_hours': round(duration_hours, 1),
                'start': datetime.fromtimestamp(min(timestamps) / 1e9).isoformat() if timestamps else None,
                'end': datetime.fromtimestamp(max(timestamps) / 1e9).isoformat() if timestamps else None
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@process_bp.route('/top-executables', methods=['GET'])
def get_top_executables():
    """Get most frequently seen executables"""
    limit = safe_int(request.args.get('limit', 20), default=20, min_val=1, max_val=100)

    conn = get_db_connection()
    if not conn:
        return jsonify({'executables': [], 'message': 'No data available'}), 200

    try:
        cursor = conn.cursor()
        cursor.execute('SELECT bytes FROM wal ORDER BY id ASC')

        exe_counts = {}

        for row in cursor.fetchall():
            env = telemetry_pb2.UniversalEnvelope()
            try:
                env.ParseFromString(row['bytes'])
            except Exception:
                continue

            if env.HasField('process'):
                p = env.process
                if p.exe:
                    exe_basename = os.path.basename(p.exe)
                    exe_counts[exe_basename] = exe_counts.get(exe_basename, 0) + 1

        # Sort by count
        top_exes = sorted(exe_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

        executables = [
            {'name': name, 'count': count, 'percentage': round(count / sum(exe_counts.values()) * 100, 2)}
            for name, count in top_exes
        ]

        return jsonify({
            'executables': executables,
            'count': len(executables),
            'total_unique': len(exe_counts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@process_bp.route('/search', methods=['GET'])
def search_processes():
    """Search processes by executable name, PID, or user type"""
    exe_filter = request.args.get('exe', '').lower()
    user_type_filter = request.args.get('user_type', '').lower()
    process_class_filter = request.args.get('process_class', '').lower()
    limit = safe_int(request.args.get('limit', 100), default=100, min_val=1, max_val=500)

    conn = get_db_connection()
    if not conn:
        return jsonify({'processes': [], 'message': 'No data available'}), 200

    try:
        cursor = conn.cursor()
        cursor.execute('SELECT id, bytes, ts_ns FROM wal ORDER BY id DESC LIMIT 10000')

        processes = []

        for row in cursor.fetchall():
            env = telemetry_pb2.UniversalEnvelope()
            try:
                env.ParseFromString(row['bytes'])
            except Exception:
                continue

            if env.HasField('process'):
                p = env.process

                # Classify
                if p.uid == 0:
                    user_type = "root"
                elif p.uid < 500:
                    user_type = "system"
                else:
                    user_type = "user"

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

                # Apply filters
                if exe_filter and exe_filter not in p.exe.lower():
                    continue
                if user_type_filter and user_type_filter != user_type:
                    continue
                if process_class_filter and process_class_filter != process_class:
                    continue

                exe_basename = os.path.basename(p.exe) if p.exe else ""

                processes.append({
                    'wal_id': row['id'],
                    'timestamp': datetime.fromtimestamp(row['ts_ns'] / 1e9).isoformat(),
                    'pid': p.pid,
                    'ppid': p.ppid,
                    'exe': p.exe,
                    'exe_basename': exe_basename,
                    'args_count': len(p.args),
                    'uid': p.uid,
                    'gid': p.gid,
                    'user_type': user_type,
                    'process_class': process_class
                })

                if len(processes) >= limit:
                    break

        return jsonify({
            'processes': processes,
            'count': len(processes),
            'filters_applied': {
                'exe': exe_filter or None,
                'user_type': user_type_filter or None,
                'process_class': process_class_filter or None
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@process_bp.route('/canonical-summary', methods=['GET'])
def get_canonical_summary():
    """Get summary from canonical parquet table if it exists"""
    import pandas as pd

    canonical_path = os.path.join(os.path.dirname(__file__), '../../../data/ml_pipeline/process_canonical_full.parquet')

    if not os.path.exists(canonical_path):
        return jsonify({'message': 'Canonical table not yet generated. Run build_process_canonical.py first.'}), 404

    try:
        df = pd.read_parquet(canonical_path)

        return jsonify({
            'total_rows': len(df),
            'unique_pids': int(df['pid'].nunique()),
            'unique_executables': int(df['exe_basename'].nunique()),
            'time_range': {
                'start': df['timestamp'].min().isoformat(),
                'end': df['timestamp'].max().isoformat()
            },
            'user_type_distribution': df['user_type'].value_counts().to_dict(),
            'process_class_distribution': df['process_class'].value_counts().to_dict(),
            'top_executables': df['exe_basename'].value_counts().head(10).to_dict(),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@process_bp.route('/features-summary', methods=['GET'])
def get_features_summary():
    """Get summary from ML feature tables if they exist"""
    import pandas as pd

    features_path = os.path.join(os.path.dirname(__file__), '../../../data/ml_pipeline/process_features_full.parquet')

    if not os.path.exists(features_path):
        return jsonify({'message': 'Feature table not yet generated. Run build_process_features.py first.'}), 404

    try:
        df = pd.read_parquet(features_path)

        # Get feature statistics
        numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
        feature_stats = {}

        for col in numeric_cols[:10]:  # First 10 features
            feature_stats[col] = {
                'mean': float(df[col].mean()),
                'std': float(df[col].std()),
                'min': float(df[col].min()),
                'max': float(df[col].max())
            }

        return jsonify({
            'total_windows': len(df),
            'total_features': len(df.columns),
            'window_sizes': df['window_size'].unique().tolist() if 'window_size' in df.columns else [],
            'time_range': {
                'start': df['window_start'].min().isoformat() if 'window_start' in df.columns else None,
                'end': df['window_end'].max().isoformat() if 'window_end' in df.columns else None
            },
            'feature_statistics': feature_stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
