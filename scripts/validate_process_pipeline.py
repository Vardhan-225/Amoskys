#!/usr/bin/env python3
"""
Validate Complete Process Data Pipeline

Verifies that the full pipeline from WAL → Canonical → Features works correctly.
This is Stage 9: Pipeline health checks and guardrails
"""
import sys
import pandas as pd
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

ML_PIPELINE_DIR = project_root / "data/ml_pipeline"

# Expected files
EXPECTED_FILES = {
    'canonical': ML_PIPELINE_DIR / "process_canonical_full.parquet",
    'features_full': ML_PIPELINE_DIR / "process_features_full.parquet",
    'features_train': ML_PIPELINE_DIR / "process_features_train.parquet",
    'features_val': ML_PIPELINE_DIR / "process_features_val.parquet",
    'metadata': ML_PIPELINE_DIR / "feature_metadata_process.json",
}

# Quality thresholds
THRESHOLDS = {
    'max_missing_percent': 5.0,  # Max % missing values allowed
    'min_canonical_rows': 100,    # Minimum rows in canonical table
    'min_feature_windows': 5,     # Minimum feature windows
    'min_unique_exes': 10,        # Minimum unique executables
}

def check_file_exists(name, path):
    """Check if file exists"""
    if path.exists():
        size_kb = path.stat().st_size / 1024
        print(f"  ✅ {name}: {path.name} ({size_kb:.1f} KB)")
        return True
    else:
        print(f"  ❌ {name}: {path.name} (NOT FOUND)")
        return False

def validate_canonical_table():
    """Validate canonical process table"""

    print("\n📊 Validating Canonical Table...")

    path = EXPECTED_FILES['canonical']
    if not path.exists():
        print(f"  ❌ Canonical table not found: {path}")
        return False

    df = pd.read_parquet(path)

    issues = []

    # Check row count
    if len(df) < THRESHOLDS['min_canonical_rows']:
        issues.append(f"Too few rows: {len(df)} < {THRESHOLDS['min_canonical_rows']}")
    else:
        print(f"  ✅ Row count: {len(df)} rows")

    # Check required columns
    required_cols = ['ts_ns', 'pid', 'ppid', 'exe', 'exe_basename', 'uid', 'gid',
                     'user_type', 'process_class', 'timestamp']
    missing_cols = set(required_cols) - set(df.columns)
    if missing_cols:
        issues.append(f"Missing columns: {missing_cols}")
    else:
        print(f"  ✅ All required columns present")

    # Check data quality
    num_unique_pids = df['pid'].nunique()
    num_unique_exes = df['exe_basename'].nunique()

    if num_unique_exes < THRESHOLDS['min_unique_exes']:
        issues.append(f"Too few unique exes: {num_unique_exes} < {THRESHOLDS['min_unique_exes']}")
    else:
        print(f"  ✅ Unique executables: {num_unique_exes}")
        print(f"  ✅ Unique PIDs: {num_unique_pids}")

    # Check time range
    time_range = df['timestamp'].max() - df['timestamp'].min()
    print(f"  ✅ Time range: {time_range}")

    # Check for nulls
    null_counts = df.isnull().sum()
    critical_nulls = null_counts[['pid', 'exe', 'uid', 'gid']]
    if critical_nulls.any():
        issues.append(f"Nulls in critical columns: {critical_nulls[critical_nulls > 0].to_dict()}")
    else:
        print(f"  ✅ No nulls in critical columns")

    return len(issues) == 0, issues

def validate_feature_tables():
    """Validate feature tables"""

    print("\n🧠 Validating Feature Tables...")

    # Load all feature tables
    tables = {}
    for key in ['features_full', 'features_train', 'features_val']:
        path = EXPECTED_FILES[key]
        if not path.exists():
            print(f"  ❌ {key} not found: {path}")
            return False, [f"{key} missing"]
        tables[key] = pd.read_parquet(path)

    issues = []

    full_df = tables['features_full']
    train_df = tables['features_train']
    val_df = tables['features_val']

    # Check row counts
    if len(full_df) < THRESHOLDS['min_feature_windows']:
        issues.append(f"Too few feature windows: {len(full_df)} < {THRESHOLDS['min_feature_windows']}")
    else:
        print(f"  ✅ Feature windows: {len(full_df)}")

    # Check train/val split
    expected_total = len(train_df) + len(val_df)
    if expected_total != len(full_df):
        issues.append(f"Train+Val ({expected_total}) != Full ({len(full_df)})")
    else:
        print(f"  ✅ Train/Val split: {len(train_df)}/{len(val_df)}")

    # Check required feature columns
    required_features = ['window_start', 'window_end', 'num_processes', 'num_unique_exes',
                        'exe_diversity', 'root_proc_ratio', 'user_proc_ratio']
    missing_features = set(required_features) - set(full_df.columns)
    if missing_features:
        issues.append(f"Missing features: {missing_features}")
    else:
        print(f"  ✅ All core features present ({len(full_df.columns)} total)")

    # Check for excessive missing values
    missing_pct = full_df.isnull().sum() / len(full_df) * 100
    high_missing = missing_pct[missing_pct > THRESHOLDS['max_missing_percent']]
    if len(high_missing) > 0:
        issues.append(f"High missing values: {high_missing.to_dict()}")
    else:
        max_missing = missing_pct.max()
        print(f"  ✅ Missing values: max {max_missing:.2f}%")

    # Check numeric columns have reasonable ranges
    numeric_cols = full_df.select_dtypes(include=['number']).columns
    for col in ['num_processes', 'num_unique_exes', 'exe_diversity']:
        if col in numeric_cols:
            if (full_df[col] < 0).any():
                issues.append(f"Negative values in {col}")
            elif col == 'exe_diversity' and (full_df[col] > 1.0).any():
                issues.append(f"{col} > 1.0 (should be ratio)")

    if not issues:
        print(f"  ✅ All numeric ranges valid")

    return len(issues) == 0, issues

def validate_metadata():
    """Validate feature metadata"""

    print("\n📋 Validating Feature Metadata...")

    path = EXPECTED_FILES['metadata']
    if not path.exists():
        print(f"  ❌ Metadata not found: {path}")
        return False, ["Metadata file missing"]

    with open(path, 'r') as f:
        metadata = json.load(f)

    issues = []

    # Check required keys
    required_keys = ['created_at', 'canonical_rows', 'feature_windows', 'num_features',
                     'feature_columns', 'dtypes', 'missing_percentages']
    missing_keys = set(required_keys) - set(metadata.keys())
    if missing_keys:
        issues.append(f"Missing metadata keys: {missing_keys}")
    else:
        print(f"  ✅ All metadata keys present")

    # Check metadata values
    if metadata.get('canonical_rows', 0) < THRESHOLDS['min_canonical_rows']:
        issues.append(f"Metadata canonical_rows too low: {metadata.get('canonical_rows')}")
    else:
        print(f"  ✅ Canonical rows: {metadata.get('canonical_rows')}")

    if metadata.get('feature_windows', 0) < THRESHOLDS['min_feature_windows']:
        issues.append(f"Metadata feature_windows too low: {metadata.get('feature_windows')}")
    else:
        print(f"  ✅ Feature windows: {metadata.get('feature_windows')}")

    print(f"  ✅ Num features: {metadata.get('num_features')}")

    return len(issues) == 0, issues

def generate_pipeline_summary(all_issues):
    """Generate pipeline summary JSON"""

    summary = {
        'validation_timestamp': datetime.now().isoformat(),
        'status': 'SUCCESS' if len(all_issues) == 0 else 'FAILED',
        'issues': all_issues,
        'files_validated': [str(p) for p in EXPECTED_FILES.values()],
        'thresholds': THRESHOLDS,
    }

    summary_path = ML_PIPELINE_DIR / "pipeline_summary_process.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n✅ Saved pipeline summary: {summary_path}")

    return summary

def main():
    """Main validation pipeline"""

    print("="*70)
    print("Process Data Pipeline Validation")
    print("="*70)
    print(f"Pipeline directory: {ML_PIPELINE_DIR}")
    print()

    all_issues = []

    # Check file existence
    print("📁 Checking Files...")
    all_exist = True
    for name, path in EXPECTED_FILES.items():
        if not check_file_exists(name, path):
            all_exist = False
            all_issues.append(f"{name} file missing")

    if not all_exist:
        print("\n❌ FAILED: Missing required files")
        print("   Run the pipeline scripts first:")
        print("   1. python scripts/ml_pipeline/build_process_canonical.py")
        print("   2. python scripts/ml_pipeline/build_process_features.py")
        return False

    # Validate canonical table
    canonical_ok, canonical_issues = validate_canonical_table()
    all_issues.extend(canonical_issues)

    # Validate feature tables
    features_ok, features_issues = validate_feature_tables()
    all_issues.extend(features_issues)

    # Validate metadata
    metadata_ok, metadata_issues = validate_metadata()
    all_issues.extend(metadata_issues)

    # Generate summary
    summary = generate_pipeline_summary(all_issues)

    # Final verdict
    print("\n" + "="*70)
    if len(all_issues) == 0:
        print("✅ VALIDATION PASSED")
        print("="*70)
        print("\n🎉 Complete Mac process data pipeline is healthy!")
        print()
        print("You can now load ML-ready features:")
        print("  import pandas as pd")
        print("  X_train = pd.read_parquet('data/ml_pipeline/process_features_train.parquet')")
        print("  X_val = pd.read_parquet('data/ml_pipeline/process_features_val.parquet')")
        print()
        return True
    else:
        print("❌ VALIDATION FAILED")
        print("="*70)
        print(f"\n{len(all_issues)} issues found:")
        for i, issue in enumerate(all_issues, 1):
            print(f"  {i}. {issue}")
        print()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
