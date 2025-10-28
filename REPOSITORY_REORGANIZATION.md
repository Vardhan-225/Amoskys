# AMOSKYS Repository Reorganization Plan

**Based on**: Data Flow Analysis of 1,403 real events
**Date**: October 28, 2025
**Goal**: Organize repository to mirror actual data flow and improve developer experience

---

## Current State Assessment

### Existing Structure

```
Amoskys/
├── amoskys-eventbus              # Executable
├── amoskys-snmp-agent            # Executable
├── data/
│   ├── wal/
│   │   ├── flowagent.db          # 1,403 events, 227 KB
│   │   └── sample_events.json    # Exported samples
│   └── ml_pipeline/              # ML outputs
├── notebooks/                    # Jupyter notebooks
├── proto/                        # Protobuf schemas
├── scripts/                      # Utility scripts
├── src/amoskys/
│   ├── agents/
│   │   └── snmp/
│   ├── eventbus/
│   ├── proto/
│   └── web/
├── tests/                        # Test files
└── web/                          # Flask dashboard
```

### Issues with Current Structure

1. ❌ **Mixed concerns**: Proto files in both `/proto` and `/src/amoskys/proto`
2. ❌ **Unclear data flow**: Hard to understand pipeline from directory structure
3. ❌ **Scripts scattered**: Analysis tools mixed with ML scripts mixed with utilities
4. ❌ **No clear separation**: Collection → Ingestion → Processing → Intelligence → Presentation
5. ❌ **Duplicate web folders**: `/web` and `/src/amoskys/web`

---

## Proposed Structure (Data Flow Aligned)

### Principle: **Directory Structure Mirrors Data Pipeline**

```
Amoskys/
│
├── 📋 DOCUMENTATION/
│   ├── README.md                              # Main project overview
│   ├── ARCHITECTURE.md                        # System architecture
│   ├── DATA_FLOW_ANALYSIS.md                  # ✅ Critical findings doc
│   ├── PIPELINE_STATUS_REPORT.md              # Operational status
│   ├── REPOSITORY_REORGANIZATION.md           # This file
│   ├── QUICK_START.md                         # Getting started guide
│   └── API_REFERENCE.md                       # API documentation
│
├── 🔧 CONFIGURATION/
│   ├── config.yaml                            # Main configuration
│   ├── snmp_oids.yaml                         # SNMP metric definitions
│   ├── ml_models_config.yaml                  # ML model parameters
│   └── deployment/
│       ├── docker-compose.yml
│       ├── kubernetes/
│       └── systemd/
│
├── 📊 SCHEMAS/
│   ├── proto/                                 # Protobuf definitions
│   │   ├── messaging_schema.proto             # Legacy FlowEvent schema
│   │   └── universal_telemetry.proto          # New telemetry schema
│   └── sql/
│       ├── wal_schema.sql                     # WAL database schema
│       └── telemetry_schema.sql               # Future: Rich telemetry DB
│
├── 🎯 PIPELINE STAGE 1: DATA COLLECTION/
│   ├── src/amoskys/collectors/                # Renamed from 'agents'
│   │   ├── __init__.py
│   │   ├── base_collector.py                  # Abstract base class
│   │   ├── snmp/
│   │   │   ├── __init__.py
│   │   │   ├── snmp_collector.py              # Main SNMP logic
│   │   │   ├── oid_definitions.py             # OID mappings
│   │   │   └── device_profiles.py             # Device-specific configs
│   │   ├── mqtt/
│   │   │   └── mqtt_collector.py
│   │   ├── pcap/
│   │   │   └── packet_collector.py
│   │   └── process/
│   │       └── process_collector.py
│   ├── bin/                                   # Executables
│   │   ├── amoskys-snmp-collector             # Renamed from amoskys-snmp-agent
│   │   ├── amoskys-mqtt-collector
│   │   └── amoskys-pcap-collector
│   └── tests/collectors/
│       └── test_snmp_collector.py
│
├── 🚀 PIPELINE STAGE 2: DATA INGESTION/
│   ├── src/amoskys/ingestion/                 # EventBus + WAL
│   │   ├── __init__.py
│   │   ├── eventbus/
│   │   │   ├── __init__.py
│   │   │   ├── server.py                      # gRPC EventBus server
│   │   │   ├── client.py                      # EventBus client
│   │   │   └── deduplication.py               # Idempotency logic
│   │   ├── wal/
│   │   │   ├── __init__.py
│   │   │   ├── storage.py                     # WAL write operations
│   │   │   ├── reader.py                      # WAL read operations
│   │   │   └── compaction.py                  # WAL maintenance
│   │   └── validation/
│   │       ├── signature_validator.py         # Ed25519 verification
│   │       └── schema_validator.py            # Protobuf validation
│   ├── bin/
│   │   └── amoskys-eventbus                   # EventBus executable
│   └── tests/ingestion/
│       ├── test_eventbus.py
│       └── test_wal.py
│
├── 🔄 PIPELINE STAGE 3: DATA TRANSFORMATION (ETL)/
│   ├── src/amoskys/transformation/
│   │   ├── __init__.py
│   │   ├── extraction/
│   │   │   ├── __init__.py
│   │   │   ├── wal_extractor.py               # Extract from WAL
│   │   │   └── protobuf_parser.py             # Parse protobuf events
│   │   ├── processing/
│   │   │   ├── __init__.py
│   │   │   ├── canonical_features.py          # Stage 1: Base features
│   │   │   ├── temporal_features.py           # Stage 2: Time-based
│   │   │   ├── cross_features.py              # Stage 3: Correlations
│   │   │   ├── domain_features.py             # Stage 4: Domain-specific
│   │   │   └── anomaly_features.py            # Stage 5: Outlier detection
│   │   ├── loading/
│   │   │   ├── __init__.py
│   │   │   ├── parquet_writer.py              # Export to Parquet
│   │   │   ├── csv_writer.py                  # Export to CSV
│   │   │   └── feature_store.py               # Feature database
│   │   └── pipeline.py                        # Orchestrates full ETL
│   ├── scripts/etl/                           # ETL execution scripts
│   │   ├── run_full_pipeline.py               # Main pipeline runner
│   │   ├── run_incremental.py                 # Process new data only
│   │   └── backfill_features.py               # Historical reprocessing
│   └── tests/transformation/
│       └── test_feature_engineering.py
│
├── 🧠 PIPELINE STAGE 4: INTELLIGENCE (ML)/
│   ├── src/amoskys/intelligence/
│   │   ├── __init__.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── isolation_forest.py            # Anomaly detection
│   │   │   ├── xgboost_classifier.py          # Supervised learning
│   │   │   ├── lstm_autoencoder.py            # Temporal patterns
│   │   │   └── ensemble.py                    # Multi-model fusion
│   │   ├── training/
│   │   │   ├── __init__.py
│   │   │   ├── trainer.py                     # Model training orchestrator
│   │   │   ├── hyperparameter_tuning.py       # AutoML
│   │   │   └── validation.py                  # Cross-validation
│   │   ├── inference/
│   │   │   ├── __init__.py
│   │   │   ├── realtime_scorer.py             # Live threat scoring
│   │   │   ├── batch_predictor.py             # Batch processing
│   │   │   └── model_loader.py                # Model management
│   │   └── fusion/
│   │       ├── __init__.py
│   │       ├── score_junction.py              # Multi-model aggregation
│   │       └── threat_ranker.py               # Priority scoring
│   ├── notebooks/                             # Research & experimentation
│   │   ├── exploratory_data_analysis.ipynb
│   │   ├── feature_engineering_research.ipynb
│   │   ├── model_training.ipynb
│   │   └── evaluation_metrics.ipynb
│   ├── scripts/ml/
│   │   ├── train_all_models.py
│   │   ├── evaluate_models.py
│   │   └── deploy_models.py
│   └── tests/intelligence/
│       ├── test_models.py
│       └── test_inference.py
│
├── 🎨 PIPELINE STAGE 5: PRESENTATION/
│   ├── src/amoskys/presentation/              # User interfaces
│   │   ├── __init__.py
│   │   ├── dashboard/
│   │   │   ├── __init__.py
│   │   │   ├── app.py                         # Flask application
│   │   │   ├── api/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── events_api.py              # Event endpoints
│   │   │   │   ├── metrics_api.py             # Metrics endpoints
│   │   │   │   ├── threats_api.py             # Threat endpoints
│   │   │   │   └── devices_api.py             # Device endpoints
│   │   │   ├── templates/                     # HTML templates
│   │   │   │   ├── index.html
│   │   │   │   ├── metrics.html
│   │   │   │   └── threats.html
│   │   │   └── static/                        # CSS, JS, images
│   │   │       ├── css/
│   │   │       ├── js/
│   │   │       └── img/
│   │   ├── cli/
│   │   │   ├── __init__.py
│   │   │   └── amoskys_cli.py                 # Command-line interface
│   │   └── alerts/
│   │       ├── __init__.py
│   │       ├── email_alerter.py
│   │       ├── slack_alerter.py
│   │       └── pagerduty_alerter.py
│   ├── bin/
│   │   ├── amoskys-dashboard                  # Dashboard server
│   │   └── amoskys                            # CLI tool
│   └── tests/presentation/
│       └── test_dashboard_api.py
│
├── 📦 DATA/                                   # All data artifacts
│   ├── wal/                                   # Write-Ahead Log database
│   │   ├── flowagent.db                       # 1,403 events
│   │   └── sample_events.json                 # Exported samples
│   ├── features/                              # Processed features
│   │   ├── canonical_telemetry.parquet
│   │   ├── train_features.parquet
│   │   ├── val_features.parquet
│   │   └── feature_metadata.json
│   ├── models/                                # Trained ML models
│   │   ├── isolation_forest_v1.pkl
│   │   ├── xgboost_v1.pkl
│   │   └── ensemble_v1.pkl
│   ├── checkpoints/                           # Training checkpoints
│   └── exports/                               # Data exports for analysis
│
├── 🔍 ANALYSIS TOOLS/                         # Data inspection & debugging
│   ├── scripts/
│   │   ├── inspect_wal_events.py              # ✅ Inspect WAL database
│   │   ├── visualize_timeline.py              # ✅ Timeline visualization
│   │   ├── analyze_telemetry_pipeline.py      # ✅ Pipeline health check
│   │   ├── verify_signatures.py               # Cryptographic validation
│   │   ├── benchmark_performance.py           # Performance testing
│   │   └── generate_reports.py                # Status reporting
│   └── tools/
│       ├── data_explorer.py                   # Interactive data browser
│       └── metric_simulator.py                # Generate test data
│
├── 🧪 TESTING/
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── unit/                              # Unit tests
│   │   ├── integration/                       # Integration tests
│   │   ├── performance/                       # Load & stress tests
│   │   └── fixtures/                          # Test data
│   ├── pytest.ini
│   ├── conftest.py
│   └── coverage.xml
│
├── 🚢 DEPLOYMENT/
│   ├── docker/
│   │   ├── Dockerfile.collector
│   │   ├── Dockerfile.eventbus
│   │   ├── Dockerfile.dashboard
│   │   └── docker-compose.yml
│   ├── kubernetes/
│   │   ├── collector-deployment.yaml
│   │   ├── eventbus-deployment.yaml
│   │   └── dashboard-deployment.yaml
│   └── systemd/
│       ├── amoskys-collector.service
│       └── amoskys-eventbus.service
│
├── 📚 SHARED LIBRARIES/
│   ├── src/amoskys/proto/                     # Generated protobuf code
│   │   ├── __init__.py
│   │   ├── messaging_schema_pb2.py
│   │   ├── messaging_schema_pb2_grpc.py
│   │   ├── universal_telemetry_pb2.py
│   │   └── universal_telemetry_pb2_grpc.py
│   ├── src/amoskys/common/                    # Shared utilities
│   │   ├── __init__.py
│   │   ├── crypto.py                          # Ed25519 signing
│   │   ├── logging_config.py                  # Logging setup
│   │   ├── metrics.py                         # Prometheus metrics
│   │   └── config_loader.py                   # Configuration management
│   └── src/amoskys/utils/                     # Helper functions
│       ├── __init__.py
│       ├── time_utils.py
│       ├── network_utils.py
│       └── file_utils.py
│
└── 📄 ROOT FILES/
    ├── .gitignore
    ├── .dockerignore
    ├── pyproject.toml                         # Python packaging
    ├── setup.py
    ├── requirements.txt                       # Core dependencies
    ├── requirements-dev.txt                   # Development dependencies
    ├── requirements-ml.txt                    # ML dependencies
    ├── LICENSE
    └── Makefile                               # Build automation
```

---

## Migration Plan

### Phase 1: Documentation & Configuration (1 hour)

```bash
# Create new directory structure
mkdir -p DOCUMENTATION CONFIGURATION SCHEMAS/{proto,sql}

# Move documentation files
mv *.md DOCUMENTATION/

# Move configuration files
mv config.yaml snmp_config.yaml CONFIGURATION/

# Move schema files
cp -r proto SCHEMAS/
```

### Phase 2: Pipeline Stages (2-3 hours)

```bash
# Stage 1: Collection
mkdir -p "PIPELINE STAGE 1: DATA COLLECTION"/{src/amoskys/collectors,bin,tests}
mv src/amoskys/agents "PIPELINE STAGE 1: DATA COLLECTION"/src/amoskys/collectors
mv amoskys-snmp-agent "PIPELINE STAGE 1: DATA COLLECTION"/bin/amoskys-snmp-collector

# Stage 2: Ingestion
mkdir -p "PIPELINE STAGE 2: DATA INGESTION"/{src/amoskys/ingestion,bin,tests}
mv src/amoskys/eventbus "PIPELINE STAGE 2: DATA INGESTION"/src/amoskys/ingestion/
mv amoskys-eventbus "PIPELINE STAGE 2: DATA INGESTION"/bin/

# Stage 3: Transformation
mkdir -p "PIPELINE STAGE 3: DATA TRANSFORMATION"/src/amoskys/transformation/{extraction,processing,loading}
mkdir -p "PIPELINE STAGE 3: DATA TRANSFORMATION"/scripts/etl

# Stage 4: Intelligence
mkdir -p "PIPELINE STAGE 4: INTELLIGENCE"/{src/amoskys/intelligence,notebooks,scripts/ml}
mv notebooks "PIPELINE STAGE 4: INTELLIGENCE"/

# Stage 5: Presentation
mkdir -p "PIPELINE STAGE 5: PRESENTATION"/src/amoskys/presentation/{dashboard,cli,alerts}
mv src/amoskys/web "PIPELINE STAGE 5: PRESENTATION"/src/amoskys/presentation/dashboard
mv web "PIPELINE STAGE 5: PRESENTATION"/src/amoskys/presentation/dashboard/static
```

### Phase 3: Data & Tools (30 minutes)

```bash
# Data artifacts
mkdir -p DATA/{wal,features,models,checkpoints,exports}
mv data/wal DATA/
mv data/ml_pipeline DATA/features

# Analysis tools
mkdir -p "ANALYSIS TOOLS"/{scripts,tools}
mv scripts/inspect_wal_events.py "ANALYSIS TOOLS"/scripts/
mv scripts/visualize_timeline.py "ANALYSIS TOOLS"/scripts/
mv scripts/analyze_telemetry_pipeline.py "ANALYSIS TOOLS"/scripts/
```

### Phase 4: Testing & Deployment (1 hour)

```bash
# Testing
mkdir -p TESTING/tests/{unit,integration,performance,fixtures}
mv tests/* TESTING/tests/unit/

# Deployment
mkdir -p DEPLOYMENT/{docker,kubernetes,systemd}
```

### Phase 5: Update Import Paths (2 hours)

Update all Python imports to reflect new structure:

```python
# OLD:
from amoskys.agents.snmp.snmp_agent import SNMPAgent
from amoskys.eventbus.server import EventBusServicer

# NEW:
from amoskys.collectors.snmp.snmp_collector import SNMPCollector
from amoskys.ingestion.eventbus.server import EventBusServicer
```

**Automated approach:**

```bash
# Create a migration script
python scripts/update_imports.py --dry-run
python scripts/update_imports.py --apply
```

### Phase 6: Update Build & Config Files (1 hour)

Update:
- `setup.py` - Package entry points
- `Makefile` - Build targets
- `docker-compose.yml` - Volume mounts and paths
- `.gitignore` - New directory patterns
- CI/CD pipelines - Test & build paths

---

## Benefits of New Structure

### 1. **Data Flow Visibility**

```
Collection → Ingestion → Transformation → Intelligence → Presentation
   ↓            ↓             ↓              ↓              ↓
 Stage 1     Stage 2       Stage 3        Stage 4       Stage 5
```

Anyone can understand the pipeline by reading directory names.

### 2. **Separation of Concerns**

Each pipeline stage is self-contained:
- Independent testing
- Clear interfaces between stages
- Easy to swap implementations

### 3. **Developer Experience**

```bash
# Want to work on SNMP collection?
cd "PIPELINE STAGE 1: DATA COLLECTION"/src/amoskys/collectors/snmp

# Need to debug ETL?
cd "PIPELINE STAGE 3: DATA TRANSFORMATION"

# Deploy to production?
cd DEPLOYMENT/docker
```

### 4. **Onboarding**

New developers can:
1. Read `DOCUMENTATION/ARCHITECTURE.md` - Understand system design
2. Read `DOCUMENTATION/DATA_FLOW_ANALYSIS.md` - See actual data pipeline
3. Follow directory structure Stage 1 → Stage 5 - Trace code execution
4. Run `scripts/quickstart.sh` - Get running in 5 minutes

### 5. **Scalability**

Easy to add new components:
- New collector? → Add to Stage 1
- New ML model? → Add to Stage 4
- New dashboard? → Add to Stage 5

No confusion about where code belongs.

---

## Alternative: Simplified Structure (If Stage Names Too Verbose)

```
Amoskys/
├── docs/                          # All documentation
├── config/                        # All configuration
├── schemas/                       # Protobuf & SQL schemas
│
├── collectors/                    # Stage 1: Data Collection
├── ingestion/                     # Stage 2: EventBus + WAL
├── transformation/                # Stage 3: ETL Pipeline
├── intelligence/                  # Stage 4: ML Models
├── presentation/                  # Stage 5: Dashboard & APIs
│
├── data/                          # All data artifacts
├── tools/                         # Analysis & debugging tools
├── tests/                         # All tests
└── deployment/                    # Docker, K8s, etc.
```

This is cleaner while maintaining the same logical grouping.

---

## Recommendation

**Use the Simplified Structure** - It achieves the same goals without overly long directory names.

### Immediate Action

1. Create `tools/` directory and move analysis scripts:
   ```bash
   mkdir tools
   mv scripts/inspect_wal_events.py tools/
   mv scripts/visualize_timeline.py tools/
   mv scripts/analyze_telemetry_pipeline.py tools/
   ```

2. Rename `agents` to `collectors`:
   ```bash
   mv src/amoskys/agents src/amoskys/collectors
   mv amoskys-snmp-agent bin/amoskys-snmp-collector
   ```

3. Create `ingestion` directory:
   ```bash
   mkdir -p src/amoskys/ingestion
   mv src/amoskys/eventbus src/amoskys/ingestion/
   ```

4. Update imports (create migration script)

5. Update documentation to reflect new structure

### Full Migration Timeline

- **Phase 1 (Immediate)**: Move analysis tools to `tools/` - **5 minutes**
- **Phase 2 (Today)**: Rename agents → collectors - **30 minutes**
- **Phase 3 (This Week)**: Full reorganization - **4-6 hours**
- **Phase 4 (Testing)**: Verify all imports work - **2 hours**
- **Phase 5 (Documentation)**: Update all docs - **1 hour**

**Total Effort**: 1 day of focused work

**Benefit**: Permanent improvement in code maintainability and developer onboarding

---

## Post-Migration Checklist

- [ ] All imports updated and working
- [ ] All tests passing
- [ ] Docker builds successfully
- [ ] Documentation reflects new structure
- [ ] CI/CD pipelines updated
- [ ] All executables work from new locations
- [ ] Git history preserved (use `git mv` not `mv`)
- [ ] Team notified of structure changes
- [ ] Migration guide shared with contributors

---

**Generated by**: Analysis of 1,403 real events and actual code structure
**Validated against**: Current repository state as of Oct 28, 2025
