#!/usr/bin/env python3
"""
AMOSKYS ML Transformation Pipeline - Complete 5-Stage Implementation
================================================================================
Transforms raw multi-agent telemetry into ML-ready features for cybersecurity
threat detection in healthcare, pharmaceutical, and supply chain environments.

Stages:
  1. Data Ingestion & Validation (WAL + Synthetic Fallback)
  2. Canonical Transform (Deduplication + Schema Normalization)
  3. Feature Engineering (100+ temporal, statistical, behavioral features)
  4. Anomaly-Aware Preprocessing (Scaling + Encoding + Imputation)
  5. Train/Val Split & Export (CSV + Parquet + Metadata)

Author: Athanneeru
Date: October 26, 2025
"""

import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
import json
import warnings
import sqlite3
from typing import Dict, List, Tuple, Optional

# Core Data Processing
import pandas as pd
import numpy as np
from scipy import stats
from sklearn.preprocessing import RobustScaler, StandardScaler, MinMaxScaler
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split

# High-Performance Storage
import pyarrow as pa
import pyarrow.parquet as pq

# Visualization
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Progress Tracking
from tqdm.auto import tqdm

warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    # Paths
    'wal_db_path': str(Path(__file__).parent.parent / 'data' / 'wal' / 'flowagent.db'),
    'output_dir': str(Path(__file__).parent.parent / 'data' / 'ml_pipeline'),
    
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
    'scaler_type': 'robust',  # 'robust', 'standard', 'minmax'
    'log_transform_features': ['network_bytes', 'disk_io', 'process_count'],
    
    # Train/Val Split
    'validation_split': 0.2,
    'random_seed': 42,
    'stratify_by': 'device_id',
    
    # Output Formats
    'save_csv': True,
    'save_parquet': True,
    'compression': 'snappy',
    
    # Mock Data Settings (if WAL unavailable)
    'mock_samples': 1000,
    'mock_devices': 5,
    'mock_timespan_hours': 24,
}

# ============================================================================
# STAGE 1: DATA INGESTION & VALIDATION
# ============================================================================

def load_wal_data(db_path: str) -> Optional[pd.DataFrame]:
    """Load telemetry from WAL database."""
    try:
        conn = sqlite3.connect(db_path)
        query = """
            SELECT 
                id,
                idem,
                ts_ns as timestamp_ns,
                bytes as event_bytes,
                checksum
            FROM events 
            ORDER BY ts_ns ASC
        """
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        df['timestamp'] = pd.to_datetime(df['timestamp_ns'], unit='ns')
        df['device_id'] = df['idem'].str.split('_').str[0]
        
        return df
    except Exception as e:
        print(f"⚠️ WAL database error: {e}")
        return None


def generate_mock_telemetry(n_samples: int, n_devices: int, 
                             timespan_hours: int) -> pd.DataFrame:
    """Generate synthetic multi-agent telemetry for testing."""
    print(f"🔧 Generating {n_samples} mock samples across {n_devices} devices...")
    
    np.random.seed(CONFIG['random_seed'])
    
    # Timeline
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=timespan_hours)
    timestamps = pd.date_range(start_time, end_time, periods=n_samples)
    
    # Device IDs
    devices = [f"device_{i:03d}" for i in range(1, n_devices + 1)]
    device_ids = np.random.choice(devices, n_samples)
    
    # Base DataFrame
    df = pd.DataFrame({
        'id': range(1, n_samples + 1),
        'timestamp': timestamps,
        'device_id': device_ids,
    })
    
    # ========================================================================
    # SNMP METRICS (29 features)
    # ========================================================================
    
    # CPU Metrics (4 cores)
    for i in range(4):
        df[f'cpu_core{i}_pct'] = np.clip(
            np.random.normal(50, 20, n_samples) + 
            np.sin(np.linspace(0, 4*np.pi, n_samples)) * 15,
            0, 100
        )
    
    df['cpu_avg_pct'] = df[[f'cpu_core{i}_pct' for i in range(4)]].mean(axis=1)
    df['cpu_max_pct'] = df[[f'cpu_core{i}_pct' for i in range(4)]].max(axis=1)
    df['cpu_std_pct'] = df[[f'cpu_core{i}_pct' for i in range(4)]].std(axis=1)
    
    # Memory Metrics
    df['memory_total_kb'] = 16777216  # 16 GB
    df['memory_used_kb'] = np.random.uniform(8e6, 14e6, n_samples)
    df['memory_free_kb'] = df['memory_total_kb'] - df['memory_used_kb']
    df['memory_used_pct'] = (df['memory_used_kb'] / df['memory_total_kb']) * 100
    df['swap_used_kb'] = np.random.exponential(5e5, n_samples)
    
    # Disk I/O Metrics
    df['disk_reads_ops'] = np.random.poisson(100, n_samples)
    df['disk_writes_ops'] = np.random.poisson(80, n_samples)
    df['disk_busy_pct'] = np.random.uniform(5, 50, n_samples)
    df['disk_io_total'] = df['disk_reads_ops'] + df['disk_writes_ops']
    
    # Network Metrics
    df['net_bytes_in'] = np.random.exponential(1e6, n_samples)
    df['net_bytes_out'] = np.random.exponential(5e5, n_samples)
    df['net_packets_in'] = np.random.poisson(1000, n_samples)
    df['net_packets_out'] = np.random.poisson(800, n_samples)
    df['net_errors_in'] = np.random.poisson(2, n_samples)
    df['net_errors_out'] = np.random.poisson(1, n_samples)
    df['net_drops_in'] = np.random.poisson(1, n_samples)
    df['net_drops_out'] = np.random.poisson(0.5, n_samples)
    
    # System Load
    df['load_1min'] = np.random.uniform(0.5, 4.0, n_samples)
    df['load_5min'] = np.random.uniform(0.5, 3.5, n_samples)
    df['load_15min'] = np.random.uniform(0.5, 3.0, n_samples)
    df['sys_uptime_sec'] = np.cumsum(np.random.randint(30, 60, n_samples))
    
    # ========================================================================
    # PROCESS AGENT METRICS (15 features)
    # ========================================================================
    
    df['proc_count'] = np.random.randint(500, 800, n_samples)
    df['proc_new'] = np.random.poisson(5, n_samples)
    df['proc_terminated'] = np.random.poisson(4, n_samples)
    df['proc_suspicious'] = np.random.poisson(0.1, n_samples)
    
    # Resource Usage by Processes
    df['proc_cpu_top5_sum'] = np.random.uniform(20, 60, n_samples)
    df['proc_mem_top5_sum'] = np.random.uniform(30, 70, n_samples)
    df['proc_threads_total'] = np.random.randint(2000, 5000, n_samples)
    df['proc_connections_total'] = np.random.randint(100, 500, n_samples)
    df['proc_files_open_total'] = np.random.randint(1000, 3000, n_samples)
    
    # Process Diversity & Entropy
    df['proc_entropy'] = np.random.uniform(6.0, 8.0, n_samples)
    df['proc_unique_names'] = np.random.randint(400, 600, n_samples)
    df['proc_name_diversity'] = df['proc_unique_names'] / df['proc_count']
    
    # Process Behavior Anomalies
    df['proc_short_lived'] = np.random.poisson(3, n_samples)
    df['proc_high_cpu'] = np.random.poisson(2, n_samples)
    df['proc_high_mem'] = np.random.poisson(2, n_samples)
    
    # ========================================================================
    # INJECT SYNTHETIC ANOMALIES (10% of data)
    # ========================================================================
    
    anomaly_mask = np.random.random(n_samples) < 0.1
    df.loc[anomaly_mask, 'cpu_avg_pct'] *= 1.5
    df.loc[anomaly_mask, 'memory_used_pct'] *= 1.3
    df.loc[anomaly_mask, 'net_bytes_in'] *= 5.0
    df.loc[anomaly_mask, 'proc_suspicious'] += np.random.randint(1, 5, anomaly_mask.sum())
    df['is_anomaly'] = anomaly_mask.astype(int)
    
    return df


def validate_data(df: pd.DataFrame) -> Tuple[bool, List[str]]:
    """Validate data quality and integrity."""
    issues = []
    
    # Check for required columns
    required = ['timestamp', 'device_id']
    missing = [col for col in required if col not in df.columns]
    if missing:
        issues.append(f"Missing required columns: {missing}")
    
    # Check for nulls
    null_counts = df.isnull().sum()
    high_null_cols = null_counts[null_counts > len(df) * 0.5].index.tolist()
    if high_null_cols:
        issues.append(f"Columns with >50% nulls: {high_null_cols}")
    
    # Check timestamp ordering
    if not df['timestamp'].is_monotonic_increasing:
        issues.append("Timestamps not in chronological order")
    
    is_valid = len(issues) == 0
    return is_valid, issues


# ============================================================================
# STAGE 2: CANONICAL TRANSFORM
# ============================================================================

def deduplicate_events(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate events based on device + timestamp."""
    original_len = len(df)
    df_deduped = df.drop_duplicates(subset=['device_id', 'timestamp'], keep='first')
    removed = original_len - len(df_deduped)
    
    if removed > 0:
        print(f"   ℹ️ Removed {removed} duplicate events")
    
    return df_deduped


def normalize_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize column names and data types."""
    df = df.copy()
    
    # Lowercase column names
    df.columns = df.columns.str.lower().str.replace(' ', '_')
    
    # Ensure timestamp is datetime
    if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Sort by timestamp
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    return df


# ============================================================================
# STAGE 3: FEATURE ENGINEERING
# ============================================================================

class FeatureEngineer:
    """Generate temporal, statistical, and behavioral features."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.feature_metadata = {}
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply all feature engineering transformations."""
        print("   🔧 Computing rolling statistics...")
        df = self._add_rolling_features(df)
        
        print("   🔧 Computing rate-of-change features...")
        df = self._add_rate_features(df)
        
        print("   🔧 Computing cross-metric ratios...")
        df = self._add_ratio_features(df)
        
        print("   🔧 Computing temporal features...")
        df = self._add_temporal_features(df)
        
        print("   🔧 Computing statistical aggregations...")
        df = self._add_statistical_features(df)
        
        return df
    
    def _add_rolling_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute rolling window statistics."""
        windows = [5, 10, 30]  # Number of samples
        metrics = ['cpu_avg_pct', 'memory_used_pct', 'net_bytes_in', 'proc_count']
        
        for metric in metrics:
            if metric not in df.columns:
                continue
            
            for window in windows:
                # Rolling mean
                df[f'{metric}_roll_mean_{window}'] = df[metric].rolling(
                    window=window, min_periods=1
                ).mean()
                
                # Rolling std
                df[f'{metric}_roll_std_{window}'] = df[metric].rolling(
                    window=window, min_periods=1
                ).std().fillna(0)
                
                # Rolling max
                df[f'{metric}_roll_max_{window}'] = df[metric].rolling(
                    window=window, min_periods=1
                ).max()
        
        return df
    
    def _add_rate_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute rate-of-change (first derivative)."""
        metrics = ['cpu_avg_pct', 'memory_used_kb', 'net_bytes_in', 'disk_io_total']
        
        for metric in metrics:
            if metric not in df.columns:
                continue
            
            df[f'{metric}_rate'] = df[metric].diff().fillna(0)
            df[f'{metric}_rate_abs'] = df[f'{metric}_rate'].abs()
        
        return df
    
    def _add_ratio_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute cross-metric ratios."""
        # Network efficiency
        if 'net_bytes_in' in df.columns and 'net_packets_in' in df.columns:
            df['net_bytes_per_packet_in'] = (
                df['net_bytes_in'] / (df['net_packets_in'] + 1)
            )
        
        # Disk I/O ratio
        if 'disk_reads_ops' in df.columns and 'disk_writes_ops' in df.columns:
            df['disk_read_write_ratio'] = (
                df['disk_reads_ops'] / (df['disk_writes_ops'] + 1)
            )
        
        # Process efficiency
        if 'proc_threads_total' in df.columns and 'proc_count' in df.columns:
            df['threads_per_process'] = (
                df['proc_threads_total'] / (df['proc_count'] + 1)
            )
        
        # CPU vs Memory balance
        if 'cpu_avg_pct' in df.columns and 'memory_used_pct' in df.columns:
            df['cpu_memory_ratio'] = (
                df['cpu_avg_pct'] / (df['memory_used_pct'] + 1)
            )
        
        return df
    
    def _add_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract time-based features."""
        if 'timestamp' not in df.columns:
            return df
        
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)
        df['minute'] = df['timestamp'].dt.minute
        df['second'] = df['timestamp'].dt.second
        
        return df
    
    def _add_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute statistical aggregations per device."""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        agg_features = []
        
        for device in df['device_id'].unique():
            device_mask = df['device_id'] == device
            device_data = df[device_mask][numeric_cols]
            
            # Z-scores relative to device baseline
            for col in ['cpu_avg_pct', 'memory_used_pct', 'net_bytes_in']:
                if col not in device_data.columns:
                    continue
                
                mean = device_data[col].mean()
                std = device_data[col].std()
                
                if std > 0:
                    z_scores = (device_data[col] - mean) / std
                    df.loc[device_mask, f'{col}_zscore'] = z_scores
                else:
                    df.loc[device_mask, f'{col}_zscore'] = 0.0
        
        return df


# ============================================================================
# STAGE 4: ANOMALY-AWARE PREPROCESSING
# ============================================================================

class AnomalyAwarePreprocessor:
    """Scaling, encoding, and imputation with anomaly preservation."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.scalers = {}
        self.imputers = {}
        self.feature_stats = {}
    
    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform preprocessing."""
        df = df.copy()
        
        print("   🔧 Imputing missing values...")
        df = self._impute_missing(df)
        
        print("   🔧 Scaling numeric features...")
        df = self._scale_features(df)
        
        print("   🔧 Encoding categorical features...")
        df = self._encode_categorical(df)
        
        return df
    
    def _impute_missing(self, df: pd.DataFrame) -> pd.DataFrame:
        """Impute missing values."""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            if df[col].isnull().sum() > 0:
                median_value = df[col].median()
                df[col].fillna(median_value, inplace=True)
                self.imputers[col] = median_value
        
        return df
    
    def _scale_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Scale numeric features using configured scaler."""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        cols_to_scale = [col for col in numeric_cols if col not in ['id', 'is_anomaly']]
        
        if len(cols_to_scale) == 0:
            return df
        
        # Choose scaler
        scaler_type = self.config.get('scaler_type', 'robust')
        if scaler_type == 'robust':
            scaler = RobustScaler()
        elif scaler_type == 'standard':
            scaler = StandardScaler()
        else:
            scaler = MinMaxScaler()
        
        # Fit and transform
        scaled_values = scaler.fit_transform(df[cols_to_scale])
        df.loc[:, cols_to_scale] = scaled_values
        self.scalers['main'] = scaler
        
        return df
    
    def _encode_categorical(self, df: pd.DataFrame) -> pd.DataFrame:
        """One-hot encode categorical features."""
        categorical_cols = df.select_dtypes(include=['object', 'category']).columns
        
        for col in categorical_cols:
            if col in ['device_id', 'timestamp']:
                continue
            
            dummies = pd.get_dummies(df[col], prefix=col, drop_first=True)
            df = pd.concat([df, dummies], axis=1)
            df.drop(col, axis=1, inplace=True)
        
        return df


# ============================================================================
# STAGE 5: TRAIN/VAL SPLIT & EXPORT
# ============================================================================

def split_train_val(df: pd.DataFrame, config: Dict) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Split data into training and validation sets."""
    val_split = config.get('validation_split', 0.2)
    random_seed = config.get('random_seed', 42)
    
    # Temporal split (most realistic for time series)
    split_idx = int(len(df) * (1 - val_split))
    train_df = df.iloc[:split_idx].copy()
    val_df = df.iloc[split_idx:].copy()
    
    print(f"   📊 Training samples: {len(train_df)}")
    print(f"   📊 Validation samples: {len(val_df)}")
    
    return train_df, val_df


def export_datasets(train_df: pd.DataFrame, val_df: pd.DataFrame, 
                    output_dir: Path, config: Dict) -> Dict[str, str]:
    """Export datasets to CSV and Parquet formats."""
    output_files = {}
    
    # Export canonical full dataset
    full_df = pd.concat([train_df, val_df], ignore_index=True)
    
    if config.get('save_csv', True):
        csv_path = output_dir / 'canonical_telemetry_full.csv'
        full_df.to_csv(csv_path, index=False)
        output_files['full_csv'] = str(csv_path)
        print(f"   💾 Saved: {csv_path.name} ({csv_path.stat().st_size / 1024:.1f} KB)")
    
    if config.get('save_parquet', True):
        parquet_path = output_dir / 'canonical_telemetry_full.parquet'
        full_df.to_parquet(
            parquet_path, 
            compression=config.get('compression', 'snappy'),
            index=False
        )
        output_files['full_parquet'] = str(parquet_path)
        print(f"   💾 Saved: {parquet_path.name} ({parquet_path.stat().st_size / 1024:.1f} KB)")
    
    # Export train split
    if config.get('save_csv', True):
        train_csv = output_dir / 'train_features.csv'
        train_df.to_csv(train_csv, index=False)
        output_files['train_csv'] = str(train_csv)
        print(f"   💾 Saved: {train_csv.name} ({train_csv.stat().st_size / 1024:.1f} KB)")
    
    if config.get('save_parquet', True):
        train_parquet = output_dir / 'train_features.parquet'
        train_df.to_parquet(train_parquet, compression=config.get('compression', 'snappy'), index=False)
        output_files['train_parquet'] = str(train_parquet)
        print(f"   💾 Saved: {train_parquet.name} ({train_parquet.stat().st_size / 1024:.1f} KB)")
    
    # Export validation split
    if config.get('save_csv', True):
        val_csv = output_dir / 'val_features.csv'
        val_df.to_csv(val_csv, index=False)
        output_files['val_csv'] = str(val_csv)
        print(f"   💾 Saved: {val_csv.name} ({val_csv.stat().st_size / 1024:.1f} KB)")
    
    if config.get('save_parquet', True):
        val_parquet = output_dir / 'val_features.parquet'
        val_df.to_parquet(val_parquet, compression=config.get('compression', 'snappy'), index=False)
        output_files['val_parquet'] = str(val_parquet)
        print(f"   💾 Saved: {val_parquet.name} ({val_parquet.stat().st_size / 1024:.1f} KB)")
    
    return output_files


def save_feature_metadata(df: pd.DataFrame, output_dir: Path) -> str:
    """Save feature metadata for model training."""
    numeric_features = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_features = df.select_dtypes(include=['object', 'category']).columns.tolist()
    
    metadata = {
        'total_features': len(df.columns),
        'numeric_features': numeric_features,
        'categorical_features': categorical_features,
        'feature_count': {
            'numeric': len(numeric_features),
            'categorical': len(categorical_features)
        },
        'sample_statistics': {
            'mean': df[numeric_features].mean().to_dict() if numeric_features else {},
            'std': df[numeric_features].std().to_dict() if numeric_features else {},
            'min': df[numeric_features].min().to_dict() if numeric_features else {},
            'max': df[numeric_features].max().to_dict() if numeric_features else {},
        }
    }
    
    metadata_path = output_dir / 'feature_metadata.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2, default=str)
    
    print(f"   💾 Saved: {metadata_path.name}")
    return str(metadata_path)


# ============================================================================
# VISUALIZATION
# ============================================================================

def create_visualizations(train_df: pd.DataFrame, output_dir: Path):
    """Generate diagnostic visualizations."""
    print("\n📊 Generating visualizations...")
    
    # Select key numeric features for visualization
    viz_features = [
        'cpu_avg_pct', 'memory_used_pct', 'net_bytes_in', 
        'proc_count', 'disk_io_total'
    ]
    viz_features = [f for f in viz_features if f in train_df.columns]
    
    if len(viz_features) < 2:
        print("   ⚠️ Insufficient features for visualization")
        return
    
    # 1. Feature Correlations
    try:
        plt.figure(figsize=(12, 10))
        corr_matrix = train_df[viz_features].corr()
        sns.heatmap(corr_matrix, annot=True, fmt='.2f', cmap='coolwarm', 
                    center=0, square=True, linewidths=1)
        plt.title('Feature Correlation Matrix', fontsize=16, fontweight='bold')
        plt.tight_layout()
        
        corr_path = output_dir / 'feature_correlations.png'
        plt.savefig(corr_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Saved: {corr_path.name}")
    except Exception as e:
        print(f"   ⚠️ Could not create correlation plot: {e}")
    
    # 2. Distribution Histograms
    try:
        n_features = len(viz_features)
        fig, axes = plt.subplots(n_features, 1, figsize=(12, 4 * n_features))
        
        if n_features == 1:
            axes = [axes]
        
        for ax, feature in zip(axes, viz_features):
            train_df[feature].hist(bins=50, ax=ax, edgecolor='black', alpha=0.7)
            ax.set_title(f'Distribution: {feature}', fontweight='bold')
            ax.set_xlabel(feature)
            ax.set_ylabel('Frequency')
            ax.grid(alpha=0.3)
        
        plt.tight_layout()
        
        dist_path = output_dir / 'normalized_distributions.png'
        plt.savefig(dist_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"   ✅ Saved: {dist_path.name}")
    except Exception as e:
        print(f"   ⚠️ Could not create distribution plots: {e}")
    
    # 3. Temporal Patterns
    try:
        if 'timestamp' in train_df.columns:
            fig, axes = plt.subplots(len(viz_features), 1, figsize=(14, 4 * len(viz_features)))
            
            if len(viz_features) == 1:
                axes = [axes]
            
            for ax, feature in zip(axes, viz_features):
                # Sample down if too many points
                plot_df = train_df if len(train_df) < 1000 else train_df.sample(1000).sort_values('timestamp')
                
                ax.plot(plot_df['timestamp'], plot_df[feature], linewidth=0.8, alpha=0.7)
                ax.set_title(f'Temporal Pattern: {feature}', fontweight='bold')
                ax.set_xlabel('Timestamp')
                ax.set_ylabel(feature)
                ax.grid(alpha=0.3)
                ax.tick_params(axis='x', rotation=45)
            
            plt.tight_layout()
            
            temporal_path = output_dir / 'temporal_patterns.png'
            plt.savefig(temporal_path, dpi=150, bbox_inches='tight')
            plt.close()
            print(f"   ✅ Saved: {temporal_path.name}")
    except Exception as e:
        print(f"   ⚠️ Could not create temporal plots: {e}")


# ============================================================================
# MAIN PIPELINE ORCHESTRATION
# ============================================================================

def main():
    """Execute the complete 5-stage ML transformation pipeline."""
    print("=" * 80)
    print("AMOSKYS ML TRANSFORMATION PIPELINE - COMPLETE EXECUTION")
    print("=" * 80)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Setup output directory
    output_dir = Path(CONFIG['output_dir'])
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # ========================================================================
    # STAGE 1: DATA INGESTION & VALIDATION
    # ========================================================================
    print("📥 STAGE 1: Data Ingestion & Validation")
    print("-" * 80)
    
    # Try loading from WAL
    df = load_wal_data(CONFIG['wal_db_path'])
    
    if df is None or len(df) < 10:
        print("   ℹ️ WAL data unavailable or insufficient, generating mock telemetry...")
        df = generate_mock_telemetry(
            n_samples=CONFIG['mock_samples'],
            n_devices=CONFIG['mock_devices'],
            timespan_hours=CONFIG['mock_timespan_hours']
        )
        data_source = 'mock'
    else:
        print(f"   ✅ Loaded {len(df)} events from WAL database")
        data_source = 'wal'
    
    # Validate data
    is_valid, issues = validate_data(df)
    if not is_valid:
        print(f"   ⚠️ Data validation issues: {issues}")
    else:
        print(f"   ✅ Data validation passed")
    
    print(f"   📊 Total samples: {len(df)}")
    print(f"   📊 Features: {len(df.columns)}")
    print(f"   📊 Devices: {df['device_id'].nunique()}")
    print(f"   📊 Time span: {df['timestamp'].max() - df['timestamp'].min()}")
    print()
    
    # ========================================================================
    # STAGE 2: CANONICAL TRANSFORM
    # ========================================================================
    print("🔄 STAGE 2: Canonical Transform")
    print("-" * 80)
    
    df = deduplicate_events(df)
    df = normalize_schema(df)
    
    print(f"   ✅ Schema normalized: {len(df)} events")
    print()
    
    # ========================================================================
    # STAGE 3: FEATURE ENGINEERING
    # ========================================================================
    print("🧬 STAGE 3: Feature Engineering")
    print("-" * 80)
    
    engineer = FeatureEngineer(CONFIG)
    df = engineer.engineer_features(df)
    
    print(f"   ✅ Engineered features: {len(df.columns)} total")
    print()
    
    # ========================================================================
    # STAGE 4: ANOMALY-AWARE PREPROCESSING
    # ========================================================================
    print("⚙️ STAGE 4: Anomaly-Aware Preprocessing")
    print("-" * 80)
    
    preprocessor = AnomalyAwarePreprocessor(CONFIG)
    df = preprocessor.fit_transform(df)
    
    print(f"   ✅ Preprocessing complete")
    print()
    
    # ========================================================================
    # STAGE 5: TRAIN/VAL SPLIT & EXPORT
    # ========================================================================
    print("💾 STAGE 5: Train/Val Split & Export")
    print("-" * 80)
    
    train_df, val_df = split_train_val(df, CONFIG)
    output_files = export_datasets(train_df, val_df, output_dir, CONFIG)
    metadata_file = save_feature_metadata(df, output_dir)
    print()
    
    # ========================================================================
    # VISUALIZATION
    # ========================================================================
    create_visualizations(train_df, output_dir)
    print()
    
    # ========================================================================
    # PIPELINE SUMMARY
    # ========================================================================
    print("📋 PIPELINE SUMMARY")
    print("-" * 80)
    
    summary = {
        'pipeline_version': '2.0.0',
        'execution_date': datetime.now().isoformat(),
        'data_source': data_source,
        'input_samples': len(df),
        'train_samples': len(train_df),
        'val_samples': len(val_df),
        'total_features': len(df.columns),
        'numeric_features': len(df.select_dtypes(include=[np.number]).columns),
        'categorical_features': len(df.select_dtypes(include=['object', 'category']).columns),
        'devices': df['device_id'].nunique(),
        'time_span_hours': (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600,
        'configuration': CONFIG,
        'output_files': output_files,
        'metadata_file': metadata_file,
        'status': 'SUCCESS'
    }
    
    summary_path = output_dir / 'pipeline_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"   ✅ Pipeline summary: {summary_path}")
    print()
    
    # ========================================================================
    # SUCCESS MESSAGE
    # ========================================================================
    print("=" * 80)
    print("🎉 ML TRANSFORMATION PIPELINE COMPLETE!")
    print("=" * 80)
    print(f"✅ Total samples processed: {len(df)}")
    print(f"✅ Total features: {len(df.columns)}")
    print(f"✅ Training samples: {len(train_df)}")
    print(f"✅ Validation samples: {len(val_df)}")
    print(f"✅ Output directory: {output_dir}")
    print()
    print("📂 Generated Files:")
    for file_type, file_path in output_files.items():
        print(f"   - {file_type}: {Path(file_path).name}")
    print(f"   - metadata: {Path(metadata_file).name}")
    print()
    print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Pipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
