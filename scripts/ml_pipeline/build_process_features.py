#!/usr/bin/env python3
"""
Build ML-Ready Process Features

Transforms canonical process table into time-windowed feature vectors.
This is Stage 8: Structured neurons → ML-ready feature matrices
"""
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

INPUT_DIR = project_root / "data/ml_pipeline"
OUTPUT_DIR = INPUT_DIR

CANONICAL_FILE = INPUT_DIR / "process_canonical_full.parquet"

# Time windows for feature aggregation
WINDOW_SIZES = [
    ('30s', timedelta(seconds=30)),
    ('5min', timedelta(minutes=5)),
]

def build_windowed_features(df, window_size, window_name):
    """Build features for a specific time window"""

    print(f"Building features for {window_name} windows...")

    # Create time windows
    df = df.copy()
    df['window_start'] = df['timestamp'].dt.floor(window_size)

    # Group by window
    features = []

    for window_start, window_df in df.groupby('window_start'):
        window_end = window_start + window_size

        # Basic counts
        num_processes = len(window_df)
        num_unique_pids = window_df['pid'].nunique()
        num_unique_ppids = window_df['ppid'].nunique()
        num_unique_exes = window_df['exe_basename'].nunique()

        # User type distribution
        user_type_counts = window_df['user_type'].value_counts()
        num_root_procs = user_type_counts.get('root', 0)
        num_system_procs = user_type_counts.get('system', 0)
        num_user_procs = user_type_counts.get('user', 0)

        # Process class distribution
        class_counts = window_df['process_class'].value_counts()
        num_system_lib = class_counts.get('system', 0)
        num_applications = class_counts.get('application', 0)
        num_daemons = class_counts.get('daemon', 0)
        num_third_party = class_counts.get('third_party', 0)

        # Diversity metrics
        exe_diversity = num_unique_exes / num_processes if num_processes > 0 else 0
        pid_diversity = num_unique_pids / num_processes if num_processes > 0 else 0

        # Arguments analysis
        avg_args_count = window_df['args_count'].mean()
        max_args_count = window_df['args_count'].max()

        # UID/GID diversity
        num_unique_uids = window_df['uid'].nunique()
        num_unique_gids = window_df['gid'].nunique()

        # Parent process metrics
        orphan_ratio = (window_df['ppid'] == 0).sum() / num_processes if num_processes > 0 else 0

        # Rare executable detection (exe that appears < 2% of the time)
        exe_counts = window_df['exe_basename'].value_counts()
        rare_threshold = 0.02 * num_processes
        num_rare_exes = (exe_counts < rare_threshold).sum()
        rare_exe_ratio = num_rare_exes / num_unique_exes if num_unique_exes > 0 else 0

        features.append({
            'window_start': window_start,
            'window_end': window_end,
            'window_size': window_name,

            # Volume metrics
            'num_processes': num_processes,
            'num_unique_pids': num_unique_pids,
            'num_unique_ppids': num_unique_ppids,
            'num_unique_exes': num_unique_exes,
            'num_unique_uids': num_unique_uids,
            'num_unique_gids': num_unique_gids,

            # User type metrics
            'num_root_procs': num_root_procs,
            'num_system_procs': num_system_procs,
            'num_user_procs': num_user_procs,
            'root_proc_ratio': num_root_procs / num_processes if num_processes > 0 else 0,
            'user_proc_ratio': num_user_procs / num_processes if num_processes > 0 else 0,

            # Process class metrics
            'num_system_lib': num_system_lib,
            'num_applications': num_applications,
            'num_daemons': num_daemons,
            'num_third_party': num_third_party,
            'application_ratio': num_applications / num_processes if num_processes > 0 else 0,
            'daemon_ratio': num_daemons / num_processes if num_processes > 0 else 0,

            # Diversity metrics
            'exe_diversity': exe_diversity,
            'pid_diversity': pid_diversity,
            'rare_exe_ratio': rare_exe_ratio,

            # Process tree metrics
            'orphan_ratio': orphan_ratio,
            'avg_args_count': avg_args_count,
            'max_args_count': max_args_count,

            # Temporal metadata
            'hour': window_start.hour,
            'day_of_week': window_start.dayofweek,
        })

    features_df = pd.DataFrame(features)
    return features_df

def add_temporal_features(df):
    """Add features that compare across time windows"""

    df = df.sort_values('window_start').reset_index(drop=True)

    # Change from previous window
    df['num_processes_delta'] = df['num_processes'].diff()
    df['num_unique_exes_delta'] = df['num_unique_exes'].diff()
    df['num_root_procs_delta'] = df['num_root_procs'].diff()

    # Rolling statistics (3-window)
    for col in ['num_processes', 'num_unique_exes', 'exe_diversity']:
        df[f'{col}_rolling_mean_3'] = df[col].rolling(window=3, min_periods=1).mean()
        df[f'{col}_rolling_std_3'] = df[col].rolling(window=3, min_periods=1).std()

    return df

def split_train_val(df, val_ratio=0.2):
    """Split into train and validation sets (temporal split)"""

    split_idx = int(len(df) * (1 - val_ratio))

    train_df = df.iloc[:split_idx].copy()
    val_df = df.iloc[split_idx:].copy()

    return train_df, val_df

def build_features():
    """Main feature building pipeline"""

    print("="*70)
    print("Building ML-Ready Process Features")
    print("="*70)
    print(f"Input:  {CANONICAL_FILE}")
    print()

    # Load canonical table
    if not CANONICAL_FILE.exists():
        print(f"❌ ERROR: Canonical file not found: {CANONICAL_FILE}")
        print("   Run build_process_canonical.py first!")
        return False

    df = pd.read_parquet(CANONICAL_FILE)
    print(f"✅ Loaded canonical table: {len(df)} rows")
    print(f"   Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    print()

    # Build features for each window size
    all_features = []

    for window_name, window_size in WINDOW_SIZES:
        features_df = build_windowed_features(df, window_size, window_name)
        print(f"  ✅ Generated {len(features_df)} windows for {window_name}")
        all_features.append(features_df)

    # Combine all window sizes
    features_df = pd.concat(all_features, ignore_index=True)

    # Add temporal features
    features_df = add_temporal_features(features_df)

    print()
    print(f"📊 Total feature windows: {len(features_df)}")
    print(f"   Total features: {len(features_df.columns)}")
    print()

    # Split into train/val
    train_df, val_df = split_train_val(features_df, val_ratio=0.2)

    print(f"📂 Data split:")
    print(f"   Train: {len(train_df)} windows ({len(train_df)/len(features_df)*100:.1f}%)")
    print(f"   Val:   {len(val_df)} windows ({len(val_df)/len(features_df)*100:.1f}%)")
    print()

    # Save outputs
    full_path = OUTPUT_DIR / "process_features_full.parquet"
    train_path = OUTPUT_DIR / "process_features_train.parquet"
    val_path = OUTPUT_DIR / "process_features_val.parquet"

    features_df.to_parquet(full_path, index=False)
    train_df.to_parquet(train_path, index=False)
    val_df.to_parquet(val_path, index=False)

    # Also save CSV for inspection
    features_df.to_csv(OUTPUT_DIR / "process_features_full.csv", index=False)

    print(f"✅ Saved feature tables:")
    print(f"   Full:  {full_path} ({full_path.stat().st_size / 1024:.1f} KB)")
    print(f"   Train: {train_path} ({train_path.stat().st_size / 1024:.1f} KB)")
    print(f"   Val:   {val_path} ({val_path.stat().st_size / 1024:.1f} KB)")
    print()

    # Save feature metadata
    metadata = {
        'created_at': datetime.now().isoformat(),
        'canonical_rows': len(df),
        'feature_windows': len(features_df),
        'train_windows': len(train_df),
        'val_windows': len(val_df),
        'num_features': len(features_df.columns),
        'window_sizes': [w[0] for w in WINDOW_SIZES],
        'feature_columns': list(features_df.columns),
        'dtypes': {col: str(dtype) for col, dtype in features_df.dtypes.items()},
        'missing_percentages': {
            col: float(features_df[col].isna().sum() / len(features_df) * 100)
            for col in features_df.columns
        },
        'summary_stats': {
            col: {
                'mean': float(features_df[col].mean()) if pd.api.types.is_numeric_dtype(features_df[col]) else None,
                'std': float(features_df[col].std()) if pd.api.types.is_numeric_dtype(features_df[col]) else None,
                'min': float(features_df[col].min()) if pd.api.types.is_numeric_dtype(features_df[col]) else None,
                'max': float(features_df[col].max()) if pd.api.types.is_numeric_dtype(features_df[col]) else None,
            }
            for col in features_df.select_dtypes(include=[np.number]).columns[:10]  # First 10 numeric cols
        }
    }

    metadata_path = OUTPUT_DIR / "feature_metadata_process.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"✅ Saved feature metadata: {metadata_path}")
    print()

    # Display sample
    print("🔍 Sample feature rows (first 3):")
    display_cols = ['window_start', 'window_size', 'num_processes', 'num_unique_exes',
                    'exe_diversity', 'root_proc_ratio', 'application_ratio']
    print(features_df[display_cols].head(3))
    print()

    print("="*70)
    print("✅ Feature engineering complete!")
    print("="*70)
    print()
    print("You can now load features with:")
    print(f"  import pandas as pd")
    print(f"  X_train = pd.read_parquet('{train_path}')")
    print(f"  X_val = pd.read_parquet('{val_path}')")

    return True

if __name__ == "__main__":
    success = build_features()
    sys.exit(0 if success else 1)
