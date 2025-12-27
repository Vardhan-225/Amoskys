# 🎯 AMOSKYS: Realistic Next Steps
## Based on Actual Current State (October 26, 2025)

---

## ✅ WHAT'S ACTUALLY COMPLETE

### 1. ML Transformation Pipeline ✅
- **Status:** Partially executed (basic script only)
- **Output:** 100 mock samples with 37 features
- **Location:** `data/ml_pipeline/pipeline_summary.json`
- **Visualizations:** 3 PNG files generated (correlations, distributions, temporal)

### 2. Jupyter Notebook ✅
- **File:** `notebooks/ml_transformation_pipeline.ipynb`
- **Status:** Fixed (DataFrame assignment bug resolved)
- **Contents:** Complete 5-stage pipeline design
- **Not yet run:** Full execution pending

### 3. Documentation ✅
- **Created:** Comprehensive documentation (3 new markdown files)
- **ML_PIPELINE_COMPLETION_REPORT.md** - Complete architecture (19 KB)
- **ML_PIPELINE_QUICKSTART.md** - Quick reference (4.6 KB)
- **SESSION_SUMMARY_OCT26_ML_PIPELINE.md** - Session log (9.7 KB)
- **PIPELINES_AND_FRAMEWORKS.md** - Updated with ML pipeline details

### 4. Standalone Script ✅
- **File:** `notebooks/run_ml_pipeline.py`
- **Purpose:** Execute pipeline without Jupyter
- **Status:** Working (generates mock data + basic features)

---

## 🔴 WHAT'S NOT DONE YET

### Critical Gaps

1. **Full Notebook Execution** ❌
   - Only ran simplified standalone script
   - Complete 5-stage transformation not executed
   - No train/validation splits created
   - No CSV/Parquet exports generated

2. **Real Data Processing** ❌
   - Using 100 mock samples (not real telemetry)
   - WAL database exists but not connected
   - No actual SNMP data processed

3. **ML Models** ❌
   - No models trained (XGBoost, LSTM, Transformer)
   - No Isolation Forest
   - No threat detection active

4. **EventBus/Agents** ❌
   - Not currently running
   - No live data collection
   - No real-time processing

---

## 🚀 REALISTIC ACTION PLAN

### **PHASE 1: Complete the ML Pipeline** (1-2 hours)

#### Step 1: Execute Full Notebook (30 minutes)
```bash
cd /Users/athanneeru/Downloads/GitHub/Amoskys

# Option A: Run in Jupyter (recommended for interactive)
jupyter notebook notebooks/ml_transformation_pipeline.ipynb
# Then: Run All Cells

# Option B: Execute headless
jupyter nbconvert --to notebook --execute \
  notebooks/ml_transformation_pipeline.ipynb \
  --output ml_pipeline_executed.ipynb \
  --ExecutePreprocessor.timeout=600
```

**Expected Output:**
- `data/ml_pipeline/canonical_telemetry_full.csv` (~10-50 KB)
- `data/ml_pipeline/canonical_telemetry_full.parquet` (~1-5 KB)
- `data/ml_pipeline/train_features.csv` (80% of data)
- `data/ml_pipeline/val_features.csv` (20% of data)
- `data/ml_pipeline/feature_metadata.json` (complete schema)
- Additional visualizations (preprocessing_effects.png)

#### Step 2: Verify Outputs (5 minutes)
```bash
# Check generated files
ls -lh data/ml_pipeline/

# Verify feature count
python3 -c "import pandas as pd; df = pd.read_csv('data/ml_pipeline/train_features.csv'); print(f'Features: {len(df.columns)}, Samples: {len(df)}')"

# View metadata
cat data/ml_pipeline/feature_metadata.json | python3 -m json.tool | head -50
```

#### Step 3: Connect to Real Data (25 minutes)

**Option A: Use Existing WAL Database**
```bash
# Check if WAL has data
sqlite3 data/wal/flowagent.db "SELECT COUNT(*) FROM events;"

# If data exists, update notebook CONFIG:
# Change: 'wal_db_path': '../data/wal/flowagent.db'
# Then re-run notebook
```

**Option B: Generate Fresh Telemetry**
```bash
# Start EventBus
PYTHONPATH=src python3 -m amoskys.eventbus.server &
sleep 2

# Start SNMP Agent (collect real metrics)
PYTHONPATH=src python3 src/amoskys/agents/snmp/snmp_agent.py &

# Let it collect for 5-10 minutes
# Then run ML pipeline on real data
```

---

### **PHASE 2: Train First ML Model** (2-3 hours)

#### Step 1: Create Training Script (45 minutes)

Create `notebooks/train_baseline_model.py`:

```python
#!/usr/bin/env python3
"""
Train baseline anomaly detection model
Uses Isolation Forest for unsupervised learning
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import json
from pathlib import Path

# Configuration
DATA_DIR = Path('../data/ml_pipeline')
MODEL_DIR = Path('../data/models')
MODEL_DIR.mkdir(exist_ok=True)

print("🧠 AMOSKYS Baseline Model Training")
print("="*60)

# 1. Load preprocessed features
print("\n📥 Loading training data...")
train_df = pd.read_parquet(DATA_DIR / 'train_features.parquet')
val_df = pd.read_parquet(DATA_DIR / 'val_features.parquet')

# Exclude non-feature columns
feature_cols = [c for c in train_df.columns 
                if c not in ['window_id', 'device_id', 'window_start', 'window_end']]

X_train = train_df[feature_cols].values
X_val = val_df[feature_cols].values

print(f"   Training samples: {len(X_train)}")
print(f"   Validation samples: {len(X_val)}")
print(f"   Features: {len(feature_cols)}")

# 2. Train Isolation Forest
print("\n🌲 Training Isolation Forest...")
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,  # Expect 1% anomalies
    random_state=42,
    n_jobs=-1,
    verbose=1
)

model.fit(X_train)
print("   ✅ Training complete")

# 3. Evaluate on validation set
print("\n📊 Evaluating on validation set...")
val_predictions = model.predict(X_val)  # -1 = anomaly, 1 = normal
val_scores = model.decision_function(X_val)

# Convert to binary (0 = normal, 1 = anomaly)
val_pred_binary = (val_predictions == -1).astype(int)

anomaly_count = val_pred_binary.sum()
anomaly_pct = (anomaly_count / len(val_pred_binary)) * 100

print(f"   Detected anomalies: {anomaly_count} ({anomaly_pct:.2f}%)")
print(f"   Anomaly score range: [{val_scores.min():.3f}, {val_scores.max():.3f}]")

# 4. Save model
print("\n💾 Saving model...")
model_path = MODEL_DIR / 'isolation_forest_v1.pkl'
with open(model_path, 'wb') as f:
    pickle.dump(model, f)
print(f"   ✅ Model saved: {model_path}")

# 5. Save metadata
metadata = {
    'model_type': 'IsolationForest',
    'version': '1.0',
    'training_date': pd.Timestamp.now().isoformat(),
    'n_estimators': 100,
    'contamination': 0.01,
    'training_samples': len(X_train),
    'validation_samples': len(X_val),
    'n_features': len(feature_cols),
    'feature_names': feature_cols,
    'anomaly_threshold': val_scores.mean() - 2*val_scores.std(),
    'validation_anomalies_detected': int(anomaly_count),
    'validation_anomaly_rate': float(anomaly_pct)
}

metadata_path = MODEL_DIR / 'isolation_forest_v1_metadata.json'
with open(metadata_path, 'w') as f:
    json.dump(metadata, f, indent=2)
print(f"   ✅ Metadata saved: {metadata_path}")

# 6. Feature importance (approximate)
print("\n🎯 Feature Importance (Top 20)...")
# Isolation Forest doesn't have direct feature importance
# Use variance of decision scores when removing each feature
feature_importance = []

for i, feat_name in enumerate(feature_cols[:20]):  # Top 20 for speed
    # Remove feature and score
    X_val_copy = X_val.copy()
    X_val_copy[:, i] = X_val_copy[:, i].mean()  # Replace with mean
    scores_modified = model.decision_function(X_val_copy)
    
    # Importance = change in score variance
    importance = np.abs(val_scores.std() - scores_modified.std())
    feature_importance.append((feat_name, importance))

feature_importance.sort(key=lambda x: x[1], reverse=True)

for feat, importance in feature_importance[:10]:
    print(f"   {feat:40s} {importance:.4f}")

print("\n🎉 Baseline model training complete!")
print(f"📁 Model location: {model_path}")
print(f"📋 Metadata: {metadata_path}")
```

#### Step 2: Run Training (15 minutes)
```bash
cd notebooks
python3 train_baseline_model.py
```

#### Step 3: Test Inference (20 minutes)

Create `notebooks/test_inference.py`:

```python
#!/usr/bin/env python3
"""Test real-time inference with trained model"""

import pandas as pd
import numpy as np
import pickle
import json
from pathlib import Path

MODEL_DIR = Path('../data/models')
DATA_DIR = Path('../data/ml_pipeline')

# Load model
with open(MODEL_DIR / 'isolation_forest_v1.pkl', 'rb') as f:
    model = pickle.load(f)

# Load metadata
with open(MODEL_DIR / 'isolation_forest_v1_metadata.json') as f:
    metadata = json.load(f)

print("🧪 Testing Real-Time Inference")
print("="*60)
print(f"Model: {metadata['model_type']} v{metadata['version']}")
print(f"Trained on: {metadata['training_samples']} samples")
print(f"Features: {metadata['n_features']}")

# Load test data
val_df = pd.read_parquet(DATA_DIR / 'val_features.parquet')
feature_cols = metadata['feature_names']
X_val = val_df[feature_cols].values

# Simulate real-time processing
print("\n🔄 Simulating real-time inference...")
for i in range(min(10, len(X_val))):  # Test first 10 samples
    sample = X_val[i:i+1]
    
    # Predict
    prediction = model.predict(sample)[0]
    score = model.decision_function(sample)[0]
    
    # Interpret
    is_anomaly = prediction == -1
    threat_level = "🚨 ANOMALY" if is_anomaly else "✅ NORMAL"
    
    print(f"\nSample {i+1}:")
    print(f"  Score: {score:.3f}")
    print(f"  Status: {threat_level}")
    
    if is_anomaly:
        # Find most anomalous features
        sample_abs = np.abs(sample[0])
        top_features_idx = np.argsort(sample_abs)[-3:]
        
        print(f"  Top anomalous features:")
        for idx in reversed(top_features_idx):
            feat_name = feature_cols[idx]
            feat_value = sample[0, idx]
            print(f"    - {feat_name}: {feat_value:.3f}")

print("\n✅ Inference test complete!")
```

Run it:
```bash
python3 test_inference.py
```

---

### **PHASE 3: Integrate with Score Junction** (1-2 hours)

#### Step 1: Update Score Junction (30 minutes)

Edit `src/amoskys/intelligence/score_junction.py`:

```python
# Add at top of file
import pickle
from pathlib import Path

class ScoreJunction:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # ...existing code...
        
        # Load ML model if available
        self.ml_model = None
        self._load_ml_model()
    
    def _load_ml_model(self):
        """Load trained ML model for scoring"""
        model_path = Path('data/models/isolation_forest_v1.pkl')
        
        if model_path.exists():
            try:
                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                logger.info("✅ ML model loaded for threat scoring")
            except Exception as e:
                logger.warning(f"Could not load ML model: {e}")
    
    async def _calculate_ml_score(self, features: np.ndarray) -> float:
        """Get ML-based threat score"""
        if self.ml_model is None:
            return 0.5  # Neutral score if no model
        
        try:
            # Get anomaly score
            score = self.ml_model.decision_function(features)[0]
            
            # Convert to probability (0-1)
            # Lower score = more anomalous
            threat_prob = 1 / (1 + np.exp(score))
            
            return threat_prob
        except Exception as e:
            logger.error(f"ML scoring error: {e}")
            return 0.5
    
    async def process_telemetry(self, envelope: telemetry_pb2.UniversalEnvelope):
        """Enhanced processing with ML scoring"""
        # ...existing code...
        
        # Extract features for ML
        features = self._extract_features_from_envelope(envelope)
        
        if features is not None:
            ml_score = await self._calculate_ml_score(features)
            
            # Combine with rule-based score
            final_score = (baseline_score * 0.4) + (ml_score * 0.6)
            
            threat_score.score = final_score
```

---

### **PHASE 4: Real-Time Processing** (1 hour)

#### Step 1: Create Live Pipeline Script (30 minutes)

Create `scripts/run_live_ml_pipeline.py`:

```python
#!/usr/bin/env python3
"""
Real-time ML pipeline - processes live telemetry
"""

import asyncio
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
import sys

sys.path.insert(0, 'src')

from amoskys.eventbus.client import EventBusClient
from amoskys.proto import universal_telemetry_pb2 as telemetry_pb2

class LiveMLPipeline:
    def __init__(self):
        # Load model
        with open('data/models/isolation_forest_v1.pkl', 'rb') as f:
            self.model = pickle.load(f)
        
        # Connect to EventBus
        self.client = EventBusClient('localhost:50051')
        
        # Feature buffer
        self.feature_buffer = []
        self.window_size = 60  # seconds
        
    async def process_event(self, envelope):
        """Process incoming telemetry event"""
        # Extract features
        features = self._extract_features(envelope)
        
        # Add to buffer
        self.feature_buffer.append({
            'timestamp': envelope.timestamp_ns,
            'features': features
        })
        
        # Create time windows
        if len(self.feature_buffer) >= 10:  # Minimum window size
            window_features = self._create_window()
            
            # Run ML inference
            score = self.model.decision_function([window_features])[0]
            is_anomaly = score < -0.5
            
            if is_anomaly:
                print(f"🚨 ANOMALY DETECTED! Score: {score:.3f}")
                # Trigger alert
                await self._send_alert(score, window_features)
            else:
                print(f"✅ Normal. Score: {score:.3f}")
    
    async def run(self):
        """Start processing live data"""
        print("🚀 Starting live ML pipeline...")
        print("📡 Listening for telemetry on EventBus...")
        
        # Subscribe to telemetry stream
        async for envelope in self.client.subscribe():
            await self.process_event(envelope)

if __name__ == '__main__':
    pipeline = LiveMLPipeline()
    asyncio.run(pipeline.run())
```

#### Step 2: Test Live Processing (30 minutes)
```bash
# Terminal 1: Start EventBus
PYTHONPATH=src python3 -m amoskys.eventbus.server

# Terminal 2: Start SNMP Agent
PYTHONPATH=src python3 src/amoskys/agents/snmp/snmp_agent.py

# Terminal 3: Start Live ML Pipeline
python3 scripts/run_live_ml_pipeline.py

# Watch for real-time anomaly detection!
```

---

## 📊 PROGRESS TRACKING

### Completion Status

| Phase | Task | Status | Time Estimate |
|-------|------|--------|---------------|
| **Phase 1** | Execute full notebook | ⏳ Pending | 30 min |
| | Verify outputs | ⏳ Pending | 5 min |
| | Connect to real data | ⏳ Pending | 25 min |
| **Phase 2** | Create training script | ⏳ Pending | 45 min |
| | Train Isolation Forest | ⏳ Pending | 15 min |
| | Test inference | ⏳ Pending | 20 min |
| **Phase 3** | Update Score Junction | ⏳ Pending | 30 min |
| | Integration testing | ⏳ Pending | 30 min |
| **Phase 4** | Create live pipeline | ⏳ Pending | 30 min |
| | End-to-end testing | ⏳ Pending | 30 min |

**Total Estimated Time:** 4-5 hours to fully functional ML-powered threat detection

---

## 🎯 SUCCESS CRITERIA

### Phase 1 Complete When:
- ✅ Notebook executes without errors
- ✅ All CSV/Parquet files generated
- ✅ Feature metadata complete
- ✅ Visualizations created

### Phase 2 Complete When:
- ✅ Model trained and saved
- ✅ Validation anomaly detection working
- ✅ Inference latency <100ms

### Phase 3 Complete When:
- ✅ Score Junction uses ML scores
- ✅ Threat levels calculated correctly
- ✅ Integration tests passing

### Phase 4 Complete When:
- ✅ Live processing running
- ✅ Anomalies detected in real-time
- ✅ Alerts triggered correctly

---

## 🚫 WHAT NOT TO DO

1. **Don't skip the full notebook execution** - The standalone script only did basic processing
2. **Don't train on mock data** - Wait for real telemetry or use public datasets
3. **Don't deploy untested models** - Always validate first
4. **Don't assume EventBus is running** - Check process list first
5. **Don't overcomplicate** - Start with Isolation Forest, add complexity later

---

## 📚 REFERENCES

- **ML Pipeline Notebook:** `notebooks/ml_transformation_pipeline.ipynb`
- **Completion Report:** `ML_PIPELINE_COMPLETION_REPORT.md`
- **Quick Start:** `ML_PIPELINE_QUICKSTART.md`
- **Session Log:** `SESSION_SUMMARY_OCT26_ML_PIPELINE.md`
- **Pipeline Architecture:** `PIPELINES_AND_FRAMEWORKS.md`

---

## 💬 NEED HELP?

**If notebook won't run:**
```bash
# Check dependencies
pip install pandas numpy scikit-learn scipy pyarrow matplotlib seaborn tqdm jupyter

# Try standalone script first
cd notebooks && python3 run_ml_pipeline.py
```

**If model training fails:**
```bash
# Verify data files exist
ls -lh data/ml_pipeline/*.parquet

# Check data format
python3 -c "import pandas as pd; print(pd.read_parquet('data/ml_pipeline/train_features.parquet').info())"
```

**If integration fails:**
```bash
# Check Score Junction
python3 -c "from amoskys.intelligence.score_junction import ScoreJunction; print('✅ Import works')"

# Test EventBus connection
grpcurl -plaintext localhost:50051 list
```

---

**Status:** 📋 Ready to proceed with Phase 1  
**Next Command:** `jupyter notebook notebooks/ml_transformation_pipeline.ipynb`  
**Estimated Completion:** 4-5 hours to full ML-powered threat detection  

🎯 **Focus on completing Phase 1 first - everything else builds on this foundation!**
