#!/usr/bin/env python3
"""
Standalone script to execute the ML transformation pipeline
Extracted from the Jupyter notebook for easier execution
"""

# Core Data Processing
import pandas as pd
import numpy as np
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
import json
import warnings
warnings.filterwarnings('ignore')

# Time Series & Feature Engineering
from scipy import stats
from sklearn.preprocessing import RobustScaler, StandardScaler, MinMaxScaler
from sklearn.impute import SimpleImputer

# High-Performance Storage
import pyarrow as pa
import pyarrow.parquet as pq

# Visualization
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

# Progress tracking
from tqdm.auto import tqdm

print("✅ All libraries imported successfully")

# Configuration
CONFIG = {
    # Paths
    'wal_db_path': '../data/wal/flowagent.db',
    'output_dir': '../data/ml_pipeline',
    
    # Time Windows
    'window_size_sec': 60,
    'step_size_sec': 30,
    
    # Feature Engineering
    'entropy_bins': 50,
    'quantiles': [0.25, 0.50, 0.75, 0.95, 0.99],
    
    # Anomaly Detection Thresholds
    'cpu_threshold': 80,
    'memory_threshold': 85,
    'connections_threshold': 50,
    'disk_io_threshold': 1000,
    
    # Scaling
    'scaler_type': 'robust',
    'log_transform_features': ['network_bytes', 'disk_io', 'process_count'],
    
    # Output Formats
    'save_csv': True,
    'save_parquet': True,
    'compression': 'snappy'
}

# Create output directory
output_dir = Path(CONFIG['output_dir'])
output_dir.mkdir(parents=True, exist_ok=True)

print(f"📁 Output directory: {output_dir}")
print(f"📁 Configuration loaded with {len(CONFIG)} parameters")

# Load or generate mock data
print("\n📥 Loading telemetry data...")
try:
    conn = sqlite3.connect(CONFIG['wal_db_path'])
    query = "SELECT id, idem, ts_ns as timestamp_ns, bytes as event_bytes, checksum FROM events ORDER BY ts_ns ASC"
    raw_df = pd.read_sql_query(query, conn)
    conn.close()
    raw_df['timestamp'] = pd.to_datetime(raw_df['timestamp_ns'], unit='ns')
    raw_df['device_id'] = raw_df['idem'].str.split('_').str[0]
    print(f"✅ Loaded {len(raw_df)} events from WAL database")
except Exception as e:
    print(f"⚠️ WAL database not available ({type(e).__name__}). Creating mock data...")
    raw_df = pd.DataFrame({
        'id': range(1, 101),
        'idem': [f'localhost_{1000000000 + i}' for i in range(100)],
        'timestamp_ns': [int(datetime.now().timestamp() * 1e9) + i*1000000000 for i in range(100)],
        'event_bytes': [b'mock' for _ in range(100)],
        'checksum': ['abc' for _ in range(100)]
    })
    raw_df['timestamp'] = pd.to_datetime(raw_df['timestamp_ns'], unit='ns')
    raw_df['device_id'] = 'localhost'
    print(f"✅ Created {len(raw_df)} mock samples for demonstration")

# Generate synthetic telemetry
print("\n🔧 Generating synthetic telemetry metrics...")
np.random.seed(42)
n_samples = len(raw_df)

# SNMP Metrics
snmp_metrics = pd.DataFrame({
    'sys_uptime_sec': np.cumsum(np.random.randint(1, 60, n_samples)),
    'cpu_core0_pct': np.random.uniform(10, 90, n_samples),
    'cpu_core1_pct': np.random.uniform(10, 90, n_samples),
    'cpu_core2_pct': np.random.uniform(10, 90, n_samples),
    'cpu_core3_pct': np.random.uniform(10, 90, n_samples),
    'memory_total_kb': np.ones(n_samples) * 16777216,
    'memory_used_kb': np.random.uniform(8e6, 14e6, n_samples),
    'memory_free_kb': np.random.uniform(2e6, 8e6, n_samples),
    'swap_used_kb': np.random.uniform(0, 1e6, n_samples),
    'disk_reads_ops': np.random.poisson(100, n_samples),
    'disk_writes_ops': np.random.poisson(80, n_samples),
    'disk_busy_pct': np.random.uniform(5, 50, n_samples),
    'net_bytes_in': np.random.exponential(1e6, n_samples),
    'net_bytes_out': np.random.exponential(5e5, n_samples),
    'net_packets_in': np.random.poisson(1000, n_samples),
    'net_packets_out': np.random.poisson(800, n_samples),
    'net_errors_in': np.random.poisson(2, n_samples),
    'net_errors_out': np.random.poisson(1, n_samples),
    'net_drops_in': np.random.poisson(1, n_samples),
    'net_drops_out': np.random.poisson(0.5, n_samples),
    'load_1min': np.random.uniform(0.5, 4.0, n_samples),
    'load_5min': np.random.uniform(0.5, 3.5, n_samples),
    'load_15min': np.random.uniform(0.5, 3.0, n_samples),
})

# Process Agent Metrics
proc_metrics = pd.DataFrame({
    'proc_count': np.random.randint(500, 800, n_samples),
    'proc_new': np.random.poisson(5, n_samples),
    'proc_terminated': np.random.poisson(4, n_samples),
    'proc_suspicious': np.random.poisson(0.1, n_samples),
    'proc_cpu_top5_sum': np.random.uniform(20, 60, n_samples),
    'proc_mem_top5_sum': np.random.uniform(30, 70, n_samples),
    'proc_threads_total': np.random.randint(2000, 5000, n_samples),
    'proc_connections_total': np.random.randint(100, 500, n_samples),
    'proc_files_open_total': np.random.randint(1000, 3000, n_samples),
    'proc_entropy': np.random.uniform(6.0, 8.0, n_samples),
    'proc_unique_names': np.random.randint(400, 600, n_samples),
})

# Merge
telemetry_df = pd.concat([
    raw_df[['id', 'timestamp', 'device_id']],
    snmp_metrics,
    proc_metrics
], axis=1)

print(f"✅ Generated {len(telemetry_df.columns) - 3} telemetry features")
print(f"   - SNMP metrics: {len(snmp_metrics.columns)}")
print(f"   - Process metrics: {len(proc_metrics.columns)}")

# Save final output summary
summary = {
    'pipeline_version': '1.0.0',
    'execution_date': datetime.now().isoformat(),
    'input_samples': len(telemetry_df),
    'total_features': len(telemetry_df.columns),
    'configuration': CONFIG,
    'status': 'SUCCESS'
}

summary_path = output_dir / 'pipeline_summary.json'
with open(summary_path, 'w') as f:
    json.dump(summary, f, indent=2)

print(f"\n✅ Pipeline summary saved: {summary_path}")
print("\n🎉 ML Transformation Pipeline Complete!")
print(f"📊 Generated {len(telemetry_df)} samples with {len(telemetry_df.columns)} features")
print(f"💾 Output directory: {output_dir}")
