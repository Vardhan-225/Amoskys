#!/bin/bash
# AMOSKYS ML Pipeline - Quick Execution Commands
# ================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🎯 AMOSKYS ML Pipeline - Quick Start"
echo "======================================"
echo ""

# Activate virtual environment
echo "📦 Activating virtual environment..."
source .venv/bin/activate

# Command menu
echo "Select an option:"
echo ""
echo "  1. Run Complete ML Pipeline (1-2 min)"
echo "  2. Train Anomaly Detection Models (2-3 min)"
echo "  3. View Pipeline Outputs"
echo "  4. View Training Results"
echo "  5. Load and Test Models (Interactive Python)"
echo "  6. Generate Summary Report"
echo "  7. Clean All Generated Files"
echo "  8. Run Full Workflow (Pipeline + Training)"
echo ""
read -p "Enter choice [1-8]: " choice

case $choice in
  1)
    echo ""
    echo "🔄 Executing ML Transformation Pipeline..."
    echo "=========================================="
    python notebooks/run_ml_pipeline_complete.py
    echo ""
    echo "✅ Pipeline complete! Check data/ml_pipeline/ for outputs"
    ;;
    
  2)
    echo ""
    echo "🤖 Training Anomaly Detection Models..."
    echo "========================================"
    python notebooks/train_anomaly_models.py
    echo ""
    echo "✅ Training complete! Check models/anomaly_detection/ for saved models"
    ;;
    
  3)
    echo ""
    echo "📊 Pipeline Outputs:"
    echo "===================="
    echo ""
    echo "📁 Data Files:"
    ls -lh data/ml_pipeline/*.{csv,parquet,json} 2>/dev/null | awk '{print "   "$9" ("$5")"}'
    echo ""
    echo "📈 Visualizations:"
    ls -lh data/ml_pipeline/*.png 2>/dev/null | awk '{print "   "$9" ("$5")"}'
    echo ""
    echo "📋 Summary:"
    cat data/ml_pipeline/pipeline_summary.json | python3 -m json.tool
    ;;
    
  4)
    echo ""
    echo "🏆 Training Results:"
    echo "===================="
    echo ""
    if [ -f "models/anomaly_detection/xgboost.pkl" ]; then
      echo "✅ Trained Models:"
      ls -lh models/anomaly_detection/*.pkl | awk '{print "   "$9" ("$5")"}'
    else
      echo "⚠️  No models found. Run option 2 to train models."
    fi
    echo ""
    if [ -f "data/ml_pipeline/training_results/training_summary.json" ]; then
      echo "📊 Performance Summary:"
      cat data/ml_pipeline/training_results/training_summary.json | python3 -m json.tool
    fi
    ;;
    
  5)
    echo ""
    echo "🐍 Starting Interactive Python Session..."
    echo "=========================================="
    python3 << 'EOF'
import pickle
import pandas as pd
import numpy as np

print("\n📦 Loading trained models...")

# Load XGBoost
try:
    with open('models/anomaly_detection/xgboost.pkl', 'rb') as f:
        xgb_model = pickle.load(f)
    print("✅ XGBoost model loaded")
except:
    print("⚠️  XGBoost model not found")
    xgb_model = None

# Load Isolation Forest
try:
    with open('models/anomaly_detection/isolation_forest.pkl', 'rb') as f:
        iso_model = pickle.load(f)
    print("✅ Isolation Forest model loaded")
except:
    print("⚠️  Isolation Forest model not found")
    iso_model = None

# Load validation data
print("\n📊 Loading validation data...")
try:
    val_df = pd.read_parquet('data/ml_pipeline/val_features.parquet')
    print(f"✅ Loaded {len(val_df)} validation samples")
    
    # Prepare features
    drop_cols = ['id', 'timestamp', 'device_id', 'is_anomaly']
    feature_cols = [col for col in val_df.columns if col not in drop_cols]
    X_val = val_df[feature_cols].values
    
    if 'is_anomaly' in val_df.columns:
        y_val = val_df['is_anomaly'].values
        print(f"   True anomalies: {y_val.sum()} ({y_val.mean():.1%})")
    
    # Test predictions
    print("\n🔮 Making predictions on validation set...")
    
    if xgb_model:
        xgb_pred = xgb_model.predict(X_val)
        xgb_proba = xgb_model.predict_proba(X_val)[:, 1]
        print(f"\n✅ XGBoost:")
        print(f"   Predicted anomalies: {xgb_pred.sum()} ({xgb_pred.mean():.1%})")
        print(f"   Mean anomaly score: {xgb_proba.mean():.4f}")
        print(f"   Max anomaly score: {xgb_proba.max():.4f}")
        
        if 'is_anomaly' in val_df.columns:
            accuracy = (xgb_pred == y_val).mean()
            print(f"   Accuracy: {accuracy:.2%}")
    
    if iso_model:
        iso_pred_raw = iso_model.predict(X_val)
        iso_pred = (iso_pred_raw == -1).astype(int)
        iso_scores = -iso_model.score_samples(X_val)
        print(f"\n✅ Isolation Forest:")
        print(f"   Predicted anomalies: {iso_pred.sum()} ({iso_pred.mean():.1%})")
        print(f"   Mean anomaly score: {iso_scores.mean():.4f}")
        print(f"   Max anomaly score: {iso_scores.max():.4f}")
        
        if 'is_anomaly' in val_df.columns:
            accuracy = (iso_pred == y_val).mean()
            print(f"   Accuracy: {accuracy:.2%}")
    
    print("\n🎉 Model testing complete!")
    
except Exception as e:
    print(f"⚠️  Error: {e}")

print("\n" + "="*60)
print("Models are loaded and ready for inference!")
print("="*60)
EOF
    ;;
    
  6)
    echo ""
    echo "📄 Generating Summary Report..."
    echo "================================"
    python3 << 'EOF'
import json
from pathlib import Path
from datetime import datetime

print("\n📊 AMOSKYS ML Pipeline Summary Report")
print("=" * 70)
print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# Pipeline Status
pipeline_file = Path('data/ml_pipeline/pipeline_summary.json')
if pipeline_file.exists():
    with open(pipeline_file) as f:
        pipeline_data = json.load(f)
    
    print("🔄 ML Pipeline Status: ✅ COMPLETE")
    print("-" * 70)
    print(f"   Total Samples: {pipeline_data.get('input_samples', 'N/A')}")
    print(f"   Total Features: {pipeline_data.get('total_features', 'N/A')}")
    print(f"   Train Samples: {pipeline_data.get('train_samples', 'N/A')}")
    print(f"   Val Samples: {pipeline_data.get('val_samples', 'N/A')}")
    print(f"   Execution Date: {pipeline_data.get('execution_date', 'N/A')}")
else:
    print("🔄 ML Pipeline Status: ⚠️  NOT RUN")
    print("   Run option 1 to execute pipeline")

print()

# Training Status
training_file = Path('data/ml_pipeline/training_results/training_summary.json')
if training_file.exists():
    with open(training_file) as f:
        training_data = json.load(f)
    
    print("🤖 Model Training Status: ✅ COMPLETE")
    print("-" * 70)
    print(f"   Models Trained: {', '.join(training_data.get('models_trained', []))}")
    print()
    
    results = training_data.get('results', {})
    for model_name, metrics in results.items():
        print(f"   📈 {model_name}:")
        if 'val_f1' in metrics:
            print(f"      F1 Score: {metrics['val_f1']:.4f}")
        if 'val_auc_roc' in metrics:
            print(f"      AUC-ROC: {metrics['val_auc_roc']:.4f}")
        if 'val_accuracy' in metrics:
            print(f"      Accuracy: {metrics['val_accuracy']:.4f}")
        print()
else:
    print("🤖 Model Training Status: ⚠️  NOT RUN")
    print("   Run option 2 to train models")

print()

# File Inventory
print("📁 Generated Files:")
print("-" * 70)

ml_dir = Path('data/ml_pipeline')
if ml_dir.exists():
    files = sorted(ml_dir.glob('*'))
    total_size = 0
    for f in files:
        if f.is_file():
            size = f.stat().st_size
            total_size += size
            size_mb = size / (1024 * 1024)
            print(f"   {f.name:40} {size_mb:8.2f} MB")
    print(f"\n   Total Size: {total_size / (1024 * 1024):.2f} MB")

models_dir = Path('models/anomaly_detection')
if models_dir.exists() and list(models_dir.glob('*.pkl')):
    print()
    print("🔮 Trained Models:")
    print("-" * 70)
    for f in sorted(models_dir.glob('*.pkl')):
        size_kb = f.stat().st_size / 1024
        print(f"   {f.name:40} {size_kb:8.1f} KB")

print()
print("=" * 70)
EOF
    ;;
    
  7)
    echo ""
    read -p "⚠️  This will delete ALL generated files. Continue? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
      echo ""
      echo "🧹 Cleaning generated files..."
      rm -f data/ml_pipeline/*.csv
      rm -f data/ml_pipeline/*.parquet
      rm -f data/ml_pipeline/*.json
      rm -f data/ml_pipeline/*.png
      rm -rf data/ml_pipeline/training_results/
      rm -rf models/anomaly_detection/*.pkl
      echo "✅ Cleanup complete!"
    else
      echo "Cancelled."
    fi
    ;;
    
  8)
    echo ""
    echo "🚀 Running Full ML Workflow..."
    echo "=============================="
    echo ""
    echo "Step 1/2: ML Pipeline"
    python notebooks/run_ml_pipeline_complete.py
    echo ""
    echo "Step 2/2: Model Training"
    python notebooks/train_anomaly_models.py
    echo ""
    echo "✅ Full workflow complete!"
    echo ""
    echo "📊 Summary:"
    ls -lh data/ml_pipeline/*.parquet models/anomaly_detection/*.pkl 2>/dev/null | awk '{print "   "$9" ("$5")"}'
    ;;
    
  *)
    echo "Invalid choice. Please run again and select 1-8."
    exit 1
    ;;
esac

echo ""
echo "✅ Done!"
