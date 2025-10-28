#!/usr/bin/env python3
"""
AMOSKYS ML Model Training - Phase 2
================================================================================
Train multiple anomaly detection models on transformed telemetry features.

Models:
  1. Isolation Forest (Unsupervised Anomaly Detection)
  2. XGBoost Classifier (Supervised Binary Classification)
  3. LSTM Autoencoder (Deep Learning Reconstruction-based)
  4. Ensemble Score Fusion (BDH: Bayesian + Deep + Heuristic)

Author: Athanneeru
Date: October 26, 2025
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import json
import pickle
import warnings
from typing import Dict, Tuple, List

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Scikit-learn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    roc_auc_score, roc_curve, precision_recall_curve,
    average_precision_score
)

# XGBoost
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("⚠️ XGBoost not installed. Run: pip install xgboost")

# Deep Learning (TensorFlow/Keras)
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False
    print("⚠️ TensorFlow not installed. Run: pip install tensorflow")

warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'data_dir': str(Path(__file__).parent.parent / 'data' / 'ml_pipeline'),
    'models_dir': str(Path(__file__).parent.parent / 'models' / 'anomaly_detection'),
    'output_dir': str(Path(__file__).parent.parent / 'data' / 'ml_pipeline' / 'training_results'),
    
    # Model Hyperparameters
    'isolation_forest': {
        'n_estimators': 100,
        'contamination': 0.1,
        'max_samples': 256,
        'random_state': 42,
    },
    
    'xgboost': {
        'n_estimators': 100,
        'max_depth': 6,
        'learning_rate': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'random_state': 42,
    },
    
    'lstm_autoencoder': {
        'encoding_dim': 32,
        'epochs': 50,
        'batch_size': 32,
        'learning_rate': 0.001,
    },
    
    # Training Settings
    'random_seed': 42,
    'verbose': True,
}

# ============================================================================
# DATA LOADING
# ============================================================================

def load_datasets(data_dir: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load training and validation datasets."""
    print("📂 Loading datasets...")
    
    train_path = Path(data_dir) / 'train_features.parquet'
    val_path = Path(data_dir) / 'val_features.parquet'
    
    if not train_path.exists():
        raise FileNotFoundError(f"Training data not found: {train_path}")
    if not val_path.exists():
        raise FileNotFoundError(f"Validation data not found: {val_path}")
    
    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)
    
    print(f"   ✅ Training samples: {len(train_df)}")
    print(f"   ✅ Validation samples: {len(val_df)}")
    print(f"   ✅ Features: {len(train_df.columns)}")
    
    return train_df, val_df


def prepare_features(train_df: pd.DataFrame, val_df: pd.DataFrame) -> Tuple:
    """Prepare feature matrices and target labels."""
    # Identify target column
    target_col = 'is_anomaly' if 'is_anomaly' in train_df.columns else None
    
    # Drop non-feature columns
    drop_cols = ['id', 'timestamp', 'device_id', 'is_anomaly']
    feature_cols = [col for col in train_df.columns if col not in drop_cols]
    
    X_train = train_df[feature_cols].values
    X_val = val_df[feature_cols].values
    
    if target_col:
        y_train = train_df[target_col].values
        y_val = val_df[target_col].values
    else:
        # No labels - unsupervised only
        y_train = np.zeros(len(X_train))
        y_val = np.zeros(len(X_val))
        print("   ℹ️ No anomaly labels found - using unsupervised methods only")
    
    print(f"   ✅ Feature matrix shape: {X_train.shape}")
    print(f"   ✅ Anomaly rate (train): {y_train.mean():.2%}")
    print(f"   ✅ Anomaly rate (val): {y_val.mean():.2%}")
    
    return X_train, X_val, y_train, y_val, feature_cols


# ============================================================================
# MODEL 1: ISOLATION FOREST
# ============================================================================

def train_isolation_forest(X_train: np.ndarray, X_val: np.ndarray, 
                           y_val: np.ndarray, config: Dict) -> Dict:
    """Train Isolation Forest for unsupervised anomaly detection."""
    print("\n🌲 Training Isolation Forest...")
    print("-" * 80)
    
    # Initialize model
    model = IsolationForest(**config['isolation_forest'])
    
    # Train
    model.fit(X_train)
    
    # Predict (-1 for anomalies, 1 for normal)
    train_pred = model.predict(X_train)
    val_pred = model.predict(X_val)
    
    # Convert to binary (1 for anomaly, 0 for normal)
    train_pred_binary = (train_pred == -1).astype(int)
    val_pred_binary = (val_pred == -1).astype(int)
    
    # Anomaly scores (negative = more anomalous)
    train_scores = -model.score_samples(X_train)
    val_scores = -model.score_samples(X_val)
    
    # Metrics
    train_anomaly_rate = train_pred_binary.mean()
    val_anomaly_rate = val_pred_binary.mean()
    
    results = {
        'model_name': 'Isolation Forest',
        'train_anomaly_rate': float(train_anomaly_rate),
        'val_anomaly_rate': float(val_anomaly_rate),
        'train_scores_mean': float(train_scores.mean()),
        'val_scores_mean': float(val_scores.mean()),
    }
    
    # If we have true labels, compute metrics
    if y_val.sum() > 0:
        val_accuracy = (val_pred_binary == y_val).mean()
        val_precision = (val_pred_binary & y_val).sum() / max(val_pred_binary.sum(), 1)
        val_recall = (val_pred_binary & y_val).sum() / max(y_val.sum(), 1)
        val_f1 = 2 * val_precision * val_recall / max(val_precision + val_recall, 1e-10)
        
        try:
            val_auc = roc_auc_score(y_val, val_scores)
            results['val_auc_roc'] = float(val_auc)
        except:
            pass
        
        results.update({
            'val_accuracy': float(val_accuracy),
            'val_precision': float(val_precision),
            'val_recall': float(val_recall),
            'val_f1': float(val_f1),
        })
    
    print(f"   ✅ Training anomaly rate: {train_anomaly_rate:.2%}")
    print(f"   ✅ Validation anomaly rate: {val_anomaly_rate:.2%}")
    if 'val_f1' in results:
        print(f"   ✅ Validation F1: {results['val_f1']:.4f}")
        print(f"   ✅ Validation AUC-ROC: {results.get('val_auc_roc', 0):.4f}")
    
    return {
        'model': model,
        'results': results,
        'val_predictions': val_pred_binary,
        'val_scores': val_scores,
    }


# ============================================================================
# MODEL 2: XGBOOST CLASSIFIER
# ============================================================================

def train_xgboost(X_train: np.ndarray, y_train: np.ndarray,
                  X_val: np.ndarray, y_val: np.ndarray, config: Dict) -> Dict:
    """Train XGBoost classifier for supervised anomaly detection."""
    if not HAS_XGBOOST:
        print("\n⚠️ Skipping XGBoost (not installed)")
        return None
    
    if y_train.sum() == 0:
        print("\n⚠️ Skipping XGBoost (no anomaly labels)")
        return None
    
    print("\n🚀 Training XGBoost Classifier...")
    print("-" * 80)
    
    # Initialize model
    model = xgb.XGBClassifier(**config['xgboost'])
    
    # Train
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    
    # Predictions
    train_pred = model.predict(X_train)
    val_pred = model.predict(X_val)
    
    # Probabilities
    train_proba = model.predict_proba(X_train)[:, 1]
    val_proba = model.predict_proba(X_val)[:, 1]
    
    # Metrics
    val_accuracy = (val_pred == y_val).mean()
    val_precision = (val_pred & y_val).sum() / max(val_pred.sum(), 1)
    val_recall = (val_pred & y_val).sum() / max(y_val.sum(), 1)
    val_f1 = 2 * val_precision * val_recall / max(val_precision + val_recall, 1e-10)
    
    try:
        val_auc = roc_auc_score(y_val, val_proba)
        val_ap = average_precision_score(y_val, val_proba)
    except:
        val_auc = 0.0
        val_ap = 0.0
    
    results = {
        'model_name': 'XGBoost Classifier',
        'val_accuracy': float(val_accuracy),
        'val_precision': float(val_precision),
        'val_recall': float(val_recall),
        'val_f1': float(val_f1),
        'val_auc_roc': float(val_auc),
        'val_avg_precision': float(val_ap),
    }
    
    print(f"   ✅ Validation Accuracy: {val_accuracy:.4f}")
    print(f"   ✅ Validation F1: {val_f1:.4f}")
    print(f"   ✅ Validation AUC-ROC: {val_auc:.4f}")
    print(f"   ✅ Validation Avg Precision: {val_ap:.4f}")
    
    return {
        'model': model,
        'results': results,
        'val_predictions': val_pred,
        'val_scores': val_proba,
    }


# ============================================================================
# MODEL 3: LSTM AUTOENCODER
# ============================================================================

def train_lstm_autoencoder(X_train: np.ndarray, X_val: np.ndarray,
                           y_val: np.ndarray, config: Dict) -> Dict:
    """Train LSTM Autoencoder for reconstruction-based anomaly detection."""
    if not HAS_TENSORFLOW:
        print("\n⚠️ Skipping LSTM Autoencoder (TensorFlow not installed)")
        return None
    
    print("\n🧠 Training LSTM Autoencoder...")
    print("-" * 80)
    
    # Reshape for LSTM (samples, timesteps, features)
    X_train_reshaped = X_train.reshape((X_train.shape[0], 1, X_train.shape[1]))
    X_val_reshaped = X_val.reshape((X_val.shape[0], 1, X_val.shape[1]))
    
    input_dim = X_train.shape[1]
    encoding_dim = config['lstm_autoencoder']['encoding_dim']
    
    # Build Autoencoder
    inputs = keras.Input(shape=(1, input_dim))
    
    # Encoder
    encoded = layers.LSTM(encoding_dim, activation='relu')(inputs)
    
    # Decoder
    decoded = layers.RepeatVector(1)(encoded)
    decoded = layers.LSTM(input_dim, activation='linear', return_sequences=True)(decoded)
    
    # Model
    autoencoder = models.Model(inputs, decoded)
    autoencoder.compile(
        optimizer=keras.optimizers.Adam(config['lstm_autoencoder']['learning_rate']),
        loss='mse'
    )
    
    # Train
    history = autoencoder.fit(
        X_train_reshaped, X_train_reshaped,
        epochs=config['lstm_autoencoder']['epochs'],
        batch_size=config['lstm_autoencoder']['batch_size'],
        validation_data=(X_val_reshaped, X_val_reshaped),
        verbose=0
    )
    
    # Compute reconstruction errors
    train_reconstructed = autoencoder.predict(X_train_reshaped, verbose=0)
    val_reconstructed = autoencoder.predict(X_val_reshaped, verbose=0)
    
    train_mse = np.mean(np.square(X_train_reshaped - train_reconstructed), axis=(1, 2))
    val_mse = np.mean(np.square(X_val_reshaped - val_reconstructed), axis=(1, 2))
    
    # Threshold at 95th percentile of training errors
    threshold = np.percentile(train_mse, 95)
    
    train_pred = (train_mse > threshold).astype(int)
    val_pred = (val_mse > threshold).astype(int)
    
    results = {
        'model_name': 'LSTM Autoencoder',
        'train_anomaly_rate': float(train_pred.mean()),
        'val_anomaly_rate': float(val_pred.mean()),
        'reconstruction_threshold': float(threshold),
        'train_mse_mean': float(train_mse.mean()),
        'val_mse_mean': float(val_mse.mean()),
    }
    
    # Metrics with true labels
    if y_val.sum() > 0:
        val_accuracy = (val_pred == y_val).mean()
        val_precision = (val_pred & y_val).sum() / max(val_pred.sum(), 1)
        val_recall = (val_pred & y_val).sum() / max(y_val.sum(), 1)
        val_f1 = 2 * val_precision * val_recall / max(val_precision + val_recall, 1e-10)
        
        try:
            val_auc = roc_auc_score(y_val, val_mse)
        except:
            val_auc = 0.0
        
        results.update({
            'val_accuracy': float(val_accuracy),
            'val_precision': float(val_precision),
            'val_recall': float(val_recall),
            'val_f1': float(val_f1),
            'val_auc_roc': float(val_auc),
        })
    
    print(f"   ✅ Reconstruction threshold: {threshold:.6f}")
    print(f"   ✅ Validation anomaly rate: {val_pred.mean():.2%}")
    if 'val_f1' in results:
        print(f"   ✅ Validation F1: {results['val_f1']:.4f}")
        print(f"   ✅ Validation AUC-ROC: {results.get('val_auc_roc', 0):.4f}")
    
    return {
        'model': autoencoder,
        'results': results,
        'val_predictions': val_pred,
        'val_scores': val_mse,
        'threshold': threshold,
    }


# ============================================================================
# ENSEMBLE FUSION
# ============================================================================

def ensemble_fusion(model_outputs: List[Dict], y_val: np.ndarray) -> Dict:
    """Combine multiple model predictions using weighted voting."""
    print("\n🎯 Computing Ensemble Fusion...")
    print("-" * 80)
    
    # Extract scores
    scores = []
    weights = []
    
    for output in model_outputs:
        if output is None:
            continue
        
        # Normalize scores to [0, 1]
        score = output['val_scores']
        score_norm = (score - score.min()) / (score.max() - score.min() + 1e-10)
        scores.append(score_norm)
        
        # Weight by F1 score if available
        weight = output['results'].get('val_f1', 0.5)
        weights.append(weight)
    
    if len(scores) == 0:
        print("   ⚠️ No valid models for ensemble")
        return None
    
    # Weighted average
    weights = np.array(weights) / np.sum(weights)
    ensemble_score = np.zeros_like(scores[0])
    
    for score, weight in zip(scores, weights):
        ensemble_score += weight * score
    
    # Threshold at 0.5
    ensemble_pred = (ensemble_score > 0.5).astype(int)
    
    # Metrics
    if y_val.sum() > 0:
        val_accuracy = (ensemble_pred == y_val).mean()
        val_precision = (ensemble_pred & y_val).sum() / max(ensemble_pred.sum(), 1)
        val_recall = (ensemble_pred & y_val).sum() / max(y_val.sum(), 1)
        val_f1 = 2 * val_precision * val_recall / max(val_precision + val_recall, 1e-10)
        
        try:
            val_auc = roc_auc_score(y_val, ensemble_score)
        except:
            val_auc = 0.0
        
        results = {
            'model_name': 'Ensemble Fusion',
            'n_models': len(scores),
            'model_weights': weights.tolist(),
            'val_accuracy': float(val_accuracy),
            'val_precision': float(val_precision),
            'val_recall': float(val_recall),
            'val_f1': float(val_f1),
            'val_auc_roc': float(val_auc),
        }
        
        print(f"   ✅ Ensemble size: {len(scores)} models")
        print(f"   ✅ Validation F1: {val_f1:.4f}")
        print(f"   ✅ Validation AUC-ROC: {val_auc:.4f}")
        
        return {
            'results': results,
            'val_predictions': ensemble_pred,
            'val_scores': ensemble_score,
        }
    
    return None


# ============================================================================
# MODEL PERSISTENCE
# ============================================================================

def save_models(model_outputs: Dict, models_dir: str):
    """Save trained models to disk."""
    print("\n💾 Saving models...")
    
    models_path = Path(models_dir)
    models_path.mkdir(parents=True, exist_ok=True)
    
    for name, output in model_outputs.items():
        if output is None:
            continue
        
        model_file = models_path / f"{name.lower().replace(' ', '_')}.pkl"
        
        try:
            with open(model_file, 'wb') as f:
                pickle.dump(output['model'], f)
            print(f"   ✅ Saved: {model_file.name}")
        except Exception as e:
            print(f"   ⚠️ Could not save {name}: {e}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Execute model training pipeline."""
    print("=" * 80)
    print("AMOSKYS ANOMALY DETECTION MODEL TRAINING")
    print("=" * 80)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Setup directories
    Path(CONFIG['models_dir']).mkdir(parents=True, exist_ok=True)
    Path(CONFIG['output_dir']).mkdir(parents=True, exist_ok=True)
    
    # Load data
    train_df, val_df = load_datasets(CONFIG['data_dir'])
    X_train, X_val, y_train, y_val, feature_cols = prepare_features(train_df, val_df)
    
    # Train models
    model_outputs = {}
    
    # 1. Isolation Forest
    iso_forest_output = train_isolation_forest(X_train, X_val, y_val, CONFIG)
    model_outputs['Isolation Forest'] = iso_forest_output
    
    # 2. XGBoost
    xgb_output = train_xgboost(X_train, y_train, X_val, y_val, CONFIG)
    model_outputs['XGBoost'] = xgb_output
    
    # 3. LSTM Autoencoder
    lstm_output = train_lstm_autoencoder(X_train, X_val, y_val, CONFIG)
    model_outputs['LSTM Autoencoder'] = lstm_output
    
    # 4. Ensemble
    ensemble_output = ensemble_fusion(
        [iso_forest_output, xgb_output, lstm_output],
        y_val
    )
    if ensemble_output:
        model_outputs['Ensemble'] = ensemble_output
    
    # Save models
    save_models(model_outputs, CONFIG['models_dir'])
    
    # Summary
    print("\n" + "=" * 80)
    print("🎉 MODEL TRAINING COMPLETE!")
    print("=" * 80)
    
    summary = {
        'timestamp': datetime.now().isoformat(),
        'n_training_samples': int(len(X_train)),
        'n_validation_samples': int(len(X_val)),
        'n_features': int(X_train.shape[1]),
        'models_trained': [name for name, out in model_outputs.items() if out is not None],
        'results': {
            name: output['results'] 
            for name, output in model_outputs.items() 
            if output is not None
        }
    }
    
    # Save summary
    summary_path = Path(CONFIG['output_dir']) / 'training_summary.json'
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n📊 Training Summary:")
    for name, output in model_outputs.items():
        if output is None:
            continue
        results = output['results']
        print(f"\n   {name}:")
        print(f"   - F1 Score: {results.get('val_f1', 'N/A')}")
        print(f"   - AUC-ROC: {results.get('val_auc_roc', 'N/A')}")
    
    print(f"\n💾 Models saved to: {CONFIG['models_dir']}")
    print(f"📊 Summary saved to: {summary_path}")
    print(f"\nEnd Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Training interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
