#!/usr/bin/env python3
"""
Quick inference script - Test trained models on new data
Fast execution, practical for real-time use
"""

import sys
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def load_models():
    """Load trained models"""
    models_dir = Path(__file__).parent.parent / 'models' / 'anomaly_detection'
    
    models = {}
    if (models_dir / 'isolation_forest.pkl').exists():
        with open(models_dir / 'isolation_forest.pkl', 'rb') as f:
            models['isolation_forest'] = pickle.load(f)
        print("✅ Loaded Isolation Forest")
    
    if (models_dir / 'ensemble.pkl').exists():
        with open(models_dir / 'ensemble.pkl', 'rb') as f:
            models['ensemble'] = pickle.load(f)
        print("✅ Loaded Ensemble Model")
    
    return models

def generate_test_sample():
    """Generate a single test sample with potential anomaly"""
    # Normal baseline
    sample = {
        'cpu_core0_pct': np.random.uniform(20, 60),
        'cpu_core1_pct': np.random.uniform(20, 60),
        'cpu_core2_pct': np.random.uniform(20, 60),
        'cpu_core3_pct': np.random.uniform(20, 60),
        'memory_used_kb': np.random.uniform(8e6, 12e6),
        'memory_free_kb': np.random.uniform(4e6, 8e6),
        'swap_used_kb': np.random.uniform(0, 5e5),
        'disk_reads_ops': np.random.poisson(100),
        'disk_writes_ops': np.random.poisson(80),
        'disk_busy_pct': np.random.uniform(10, 40),
        'net_bytes_in': np.random.exponential(1e6),
        'net_bytes_out': np.random.exponential(5e5),
        'net_packets_in': np.random.poisson(1000),
        'net_packets_out': np.random.poisson(800),
        'proc_count': np.random.randint(500, 700),
        'proc_connections_total': np.random.randint(100, 300),
    }
    
    # 30% chance of injecting anomaly
    if np.random.random() < 0.3:
        anomaly_type = np.random.choice(['cpu_spike', 'memory_leak', 'network_flood'])
        if anomaly_type == 'cpu_spike':
            sample['cpu_core0_pct'] = 95
            sample['cpu_core1_pct'] = 92
        elif anomaly_type == 'memory_leak':
            sample['memory_used_kb'] = 15e6
            sample['swap_used_kb'] = 2e6
        else:  # network_flood
            sample['net_bytes_in'] = 10e6
            sample['net_packets_in'] = 50000
    
    return sample

def run_inference(models, n_samples=10):
    """Run inference on test samples"""
    print(f"\n🔍 Running inference on {n_samples} test samples...\n")
    
    results = []
    for i in range(n_samples):
        sample = generate_test_sample()
        df = pd.DataFrame([sample])
        
        # Run predictions
        predictions = {}
        for name, model in models.items():
            pred = model.predict(df)[0]
            score = model.score_samples(df)[0] if hasattr(model, 'score_samples') else None
            predictions[name] = {'prediction': pred, 'score': score}
        
        # Determine if anomaly
        is_anomaly = any(p['prediction'] == -1 for p in predictions.values())
        
        results.append({
            'sample_id': i + 1,
            'is_anomaly': is_anomaly,
            'predictions': predictions,
            'sample': sample
        })
        
        # Print result
        status = "🚨 ANOMALY" if is_anomaly else "✅ NORMAL"
        print(f"Sample {i+1:2d}: {status}")
        
        if is_anomaly:
            # Show top suspicious metrics
            metrics = sorted(sample.items(), key=lambda x: x[1], reverse=True)[:3]
            print(f"           Top metrics: {', '.join([f'{k}={v:.0f}' for k, v in metrics])}")
    
    return results

def main():
    print("="*60)
    print("🎯 AMOSKYS Quick Inference Test")
    print("="*60)
    
    # Load models
    print("\n📦 Loading models...")
    models = load_models()
    
    if not models:
        print("❌ No trained models found!")
        print("   Run: python scripts/train_models.py")
        return
    
    print(f"✅ Loaded {len(models)} model(s)\n")
    
    # Run inference
    results = run_inference(models, n_samples=20)
    
    # Summary
    anomaly_count = sum(1 for r in results if r['is_anomaly'])
    print(f"\n{'='*60}")
    print(f"📊 Summary:")
    print(f"   Total samples: {len(results)}")
    print(f"   Anomalies detected: {anomaly_count} ({anomaly_count/len(results)*100:.1f}%)")
    print(f"   Normal samples: {len(results) - anomaly_count}")
    print(f"{'='*60}\n")
    
    print("✅ Inference test complete!")
    print("💡 Next: Integrate with EventBus for real-time detection")

if __name__ == '__main__':
    main()
