"""
Unit tests for SOMA Brain — Autonomous Self-Training Intelligence Engine

Tests all 4 classes: SomaBrain, ModelScorerAdapter, EventEmbedder, AutoCalibrator
Verifies guardrails G1-G5.
"""

import json
import os
import shutil
import tempfile
import time

import numpy as np
import pandas as pd
import pytest

from amoskys.intel.soma_brain import (
    AutoCalibrator,
    EventEmbedder,
    ModelScorerAdapter,
    SomaBrain,
)


@pytest.fixture
def model_dir(tmp_path):
    """Temp directory for model artifacts."""
    d = tmp_path / "models"
    d.mkdir()
    return str(d)


@pytest.fixture
def sample_events_df():
    """Create a synthetic DataFrame matching telemetry.db schema."""
    n = 300
    rng = np.random.RandomState(42)
    categories = [
        "file_modified",
        "process_created",
        "dns_query",
        "auth_failure",
        "service_created",
    ]
    actions = ["detected", "blocked", "allowed", "monitored"]
    agents = ["fim_agent", "proc_agent", "dns_agent", "auth_agent"]
    classifications = ["legitimate", "suspicious", "malicious"]

    df = pd.DataFrame(
        {
            "timestamp_dt": pd.date_range(
                "2025-02-27 00:00:00", periods=n, freq="5min"
            ).astype(str),
            "device_id": [f"device_{i % 3}" for i in range(n)],
            "event_category": rng.choice(categories, n),
            "event_action": rng.choice(actions, n),
            "collection_agent": rng.choice(agents, n),
            "risk_score": rng.uniform(0, 10, n).round(2),
            "confidence": rng.uniform(0.3, 1.0, n).round(2),
            "geometric_score": rng.uniform(0, 0.5, n).round(4),
            "temporal_score": rng.uniform(0, 0.8, n).round(4),
            "behavioral_score": rng.uniform(0, 0.7, n).round(4),
            "final_classification": rng.choice(classifications, n),
            "indicators": [
                json.dumps({"source_ip": f"10.0.0.{i % 255}"}) for i in range(n)
            ],
            "mitre_techniques": [
                json.dumps(["T1059"] if rng.random() > 0.7 else []) for _ in range(n)
            ],
            "target_resource": [f"/usr/bin/test_{i}" for i in range(n)],
            "details": [json.dumps({"cmdline": f"command --arg{i}"}) for i in range(n)],
            "requires_investigation": [rng.random() > 0.8 for _ in range(n)],
        }
    )
    return df


@pytest.fixture
def temp_db(tmp_path, sample_events_df):
    """Create a temporary SQLite DB with sample events."""
    import sqlite3

    db_path = str(tmp_path / "test_telemetry.db")
    conn = sqlite3.connect(db_path)

    # Create table matching real schema
    conn.execute(
        """
        CREATE TABLE security_events (
            timestamp_dt TEXT,
            device_id TEXT,
            event_category TEXT,
            event_action TEXT,
            collection_agent TEXT,
            risk_score REAL,
            confidence REAL,
            geometric_score REAL,
            temporal_score REAL,
            behavioral_score REAL,
            final_classification TEXT,
            indicators TEXT,
            mitre_techniques TEXT,
            target_resource TEXT,
            details TEXT,
            requires_investigation INTEGER
        )
    """
    )

    for _, row in sample_events_df.iterrows():
        conn.execute(
            "INSERT INTO security_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                row["timestamp_dt"],
                row["device_id"],
                row["event_category"],
                row["event_action"],
                row["collection_agent"],
                row["risk_score"],
                row["confidence"],
                row["geometric_score"],
                row["temporal_score"],
                row["behavioral_score"],
                row["final_classification"],
                row["indicators"],
                row["mitre_techniques"],
                row["target_resource"],
                row["details"],
                int(row["requires_investigation"]),
            ),
        )
    conn.commit()
    conn.close()
    return db_path


# ── SomaBrain Tests ──────────────────────────────────────────────────


class TestSomaBrain:
    def test_init(self, model_dir):
        brain = SomaBrain(model_dir=model_dir)
        assert brain._status == "idle"
        assert brain._training_count == 0

    def test_cold_start_no_db(self, model_dir):
        brain = SomaBrain(
            telemetry_db_path="/nonexistent/path.db",
            model_dir=model_dir,
        )
        metrics = brain.train_once()
        assert metrics["status"] == "cold_start"

    def test_train_once_produces_models(self, temp_db, model_dir):
        brain = SomaBrain(
            telemetry_db_path=temp_db,
            model_dir=model_dir,
        )
        metrics = brain.train_once()

        assert metrics["status"] == "completed"
        assert metrics["event_count"] >= 200
        assert metrics["feature_count"] > 0

        # IF should be trained
        assert metrics["isolation_forest"]["status"] == "trained"
        assert 0 <= metrics["isolation_forest"]["anomaly_rate"] <= 1.0

        # Model files should exist
        assert os.path.exists(os.path.join(model_dir, "isolation_forest.joblib"))
        assert os.path.exists(os.path.join(model_dir, "if_calibration.json"))
        assert os.path.exists(os.path.join(model_dir, "label_encoders.joblib"))
        assert os.path.exists(os.path.join(model_dir, "feature_columns.joblib"))

    def test_if_calibration_quantiles_persisted(self, temp_db, model_dir):
        """G4: IF calibration p5/p95 quantiles saved."""
        brain = SomaBrain(telemetry_db_path=temp_db, model_dir=model_dir)
        brain.train_once()

        cal_path = os.path.join(model_dir, "if_calibration.json")
        assert os.path.exists(cal_path)
        with open(cal_path) as f:
            cal = json.load(f)
        assert "p5" in cal
        assert "p95" in cal
        assert cal["p5"] < cal["p95"]

    def test_training_history_appended(self, temp_db, model_dir):
        brain = SomaBrain(telemetry_db_path=temp_db, model_dir=model_dir)
        brain.train_once()
        brain.train_once()

        history_path = os.path.join(model_dir, "training_history.json")
        with open(history_path) as f:
            history = json.load(f)
        assert len(history) == 2

    def test_feature_extraction_no_heuristic_primary(self, temp_db, model_dir):
        """G3: Verify heuristic scores are auxiliary, not primary."""
        brain = SomaBrain(telemetry_db_path=temp_db, model_dir=model_dir)
        df = brain._query_training_data()
        X, feature_names = brain._extract_features(df)

        # Primary features should NOT include geometric_score, temporal_score, etc.
        primary_features = [f for f in feature_names if not f.startswith("aux_")]
        for pf in primary_features:
            assert pf not in (
                "geometric_score",
                "temporal_score",
                "behavioral_score",
                "risk_score",
            )

        # Auxiliary features should be present but labeled as aux_
        assert "aux_risk_score" in feature_names
        assert "aux_confidence" in feature_names

    def test_high_trust_labels_only(self, temp_db, model_dir):
        """G2: Supervised training should only use high-trust labels."""
        brain = SomaBrain(telemetry_db_path=temp_db, model_dir=model_dir)
        df = brain._query_training_data()

        # Our synthetic data has no label_source column and no threat_match indicators
        # so high-trust labels should be very few (only high risk_score + requires_investigation)
        y = brain._get_high_trust_labels(df)
        # The result depends on synthetic data, but the function should not
        # return ALL rows (that would mean it's using heuristic labels)
        if y is not None:
            assert len(y) < len(df), "Should not use ALL events as high-trust labels"

    def test_daemon_start_stop(self, model_dir):
        brain = SomaBrain(
            telemetry_db_path="/nonexistent.db",
            model_dir=model_dir,
            training_interval_seconds=1,
        )
        brain.start()
        assert brain._thread is not None
        assert brain._thread.is_alive()
        time.sleep(0.5)
        brain.stop()
        assert not brain._thread.is_alive()

    def test_status(self, model_dir):
        brain = SomaBrain(model_dir=model_dir)
        status = brain.status()
        assert "status" in status
        assert "training_count" in status
        assert status["status"] == "idle"


# ── ModelScorerAdapter Tests ─────────────────────────────────────────


class TestModelScorerAdapter:
    def test_available_is_method_not_property(self, model_dir):
        """G1: available() must be callable as a method."""
        adapter = ModelScorerAdapter(model_dir=model_dir)
        # Must be callable
        assert callable(adapter.available)
        # Should return False when no models
        assert adapter.available() is False

    def test_score_returns_zero_when_no_models(self, model_dir):
        adapter = ModelScorerAdapter(model_dir=model_dir)
        event = {
            "event_category": "test",
            "event_action": "test",
            "collection_agent": "test_agent",
            "timestamp_dt": "2025-02-27 12:00:00",
        }
        score, factors = adapter.score(event)
        assert score == 0.0
        assert factors == []

    def test_hot_reload_after_training(self, temp_db, model_dir):
        """Train models, then verify adapter picks them up."""
        brain = SomaBrain(telemetry_db_path=temp_db, model_dir=model_dir)
        brain.train_once()

        adapter = ModelScorerAdapter(model_dir=model_dir)
        assert adapter.available() is True

        event = {
            "event_category": "file_modified",
            "event_action": "detected",
            "collection_agent": "fim_agent",
            "timestamp_dt": "2025-02-27 14:00:00",
            "risk_score": 5.0,
            "confidence": 0.8,
            "indicators": json.dumps({"source_ip": "10.0.0.1"}),
            "mitre_techniques": json.dumps(["T1059"]),
            "target_resource": "/usr/bin/test",
            "details": json.dumps({"cmdline": "test --arg"}),
            "requires_investigation": False,
        }
        score, factors = adapter.score(event)
        assert 0.0 <= score <= 1.0
        assert len(factors) > 0

    def test_if_score_normalization_stable(self, temp_db, model_dir):
        """G4: Scores should be 0.0-1.0 via calibration quantiles."""
        brain = SomaBrain(telemetry_db_path=temp_db, model_dir=model_dir)
        brain.train_once()

        adapter = ModelScorerAdapter(model_dir=model_dir)
        assert adapter._if_calibration.get("p5") is not None
        assert adapter._if_calibration.get("p95") is not None

        # Test normalization
        raw_low = adapter._if_calibration["p5"] - 0.1
        raw_high = adapter._if_calibration["p95"] + 0.1
        assert adapter._normalize_if_score(raw_low) == 0.0
        assert adapter._normalize_if_score(raw_high) == 1.0

    def test_status(self, model_dir):
        adapter = ModelScorerAdapter(model_dir=model_dir)
        status = adapter.status()
        assert "if_loaded" in status
        assert "gbc_loaded" in status
        assert "available" in status
        assert status["available"] is False


# ── EventEmbedder Tests ──────────────────────────────────────────────


class TestEventEmbedder:
    def test_fit_and_similarity(self, sample_events_df, model_dir):
        embedder = EventEmbedder(model_dir=model_dir)
        metrics = embedder.fit(sample_events_df)

        assert metrics["status"] == "trained"
        assert metrics["vocab_size"] > 0

        # Should be able to find similar events
        similar = embedder.find_similar("file_modified", "detected", top_k=3)
        # May or may not find similar events depending on co-occurrence
        assert isinstance(similar, list)

    def test_novelty_score(self, sample_events_df, model_dir):
        embedder = EventEmbedder(model_dir=model_dir)
        embedder.fit(sample_events_df)

        # Known event should have a novelty score
        score = embedder.novelty_score("file_modified", "detected")
        assert 0.0 <= score <= 1.0

        # Unknown event should have maximum novelty
        score_unknown = embedder.novelty_score("totally_unknown", "never_seen")
        assert score_unknown == 1.0

    def test_save_load(self, sample_events_df, model_dir):
        embedder = EventEmbedder(model_dir=model_dir)
        embedder.fit(sample_events_df)
        embedder.save()

        # Load in new instance
        embedder2 = EventEmbedder(model_dir=model_dir)
        assert embedder2._fitted is True
        assert len(embedder2._vocabulary) == len(embedder._vocabulary)

    def test_small_vocab_skipped(self, model_dir):
        df = pd.DataFrame(
            {
                "event_category": ["a"],
                "event_action": ["b"],
                "collection_agent": ["c"],
                "device_id": ["d1"],
                "timestamp_dt": ["2025-01-01 00:00:00"],
            }
        )
        embedder = EventEmbedder(model_dir=model_dir)
        metrics = embedder.fit(df)
        assert metrics["status"] == "skipped"


# ── AutoCalibrator Tests ─────────────────────────────────────────────


class TestAutoCalibrator:
    def test_observe_and_oscillation(self, model_dir):
        """Detect classification oscillation."""
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()

        cal = AutoCalibrator(scoring_engine=scorer, model_dir=model_dir)

        # Simulate oscillating event (flips 4 times)
        for i, cls in enumerate(
            ["malicious", "legitimate", "malicious", "legitimate", "malicious"]
        ):
            cal.observe(
                {
                    "device_id": "dev1",
                    "event_category": "service_created",
                    "event_action": "detected",
                    "final_classification": cls,
                }
            )

        oscillations = cal._detect_oscillation()
        assert len(oscillations) > 0
        assert oscillations[0]["reason"] == "oscillation"

    def test_max_adjustments_per_cycle(self, model_dir):
        """G5: Max 10 adjustments per cycle."""
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()

        cal = AutoCalibrator(scoring_engine=scorer, model_dir=model_dir)

        # Create 20 FP candidates all with enough evidence
        candidates = [
            {
                "category": f"cat_{i}",
                "action": "act",
                "reason": "test",
                "evidence_count": 500,
            }
            for i in range(20)
        ]

        applied = cal._apply_adjustments(candidates)
        assert applied == AutoCalibrator.MAX_ADJUSTMENTS_PER_CYCLE  # 10

    def test_min_evidence_required(self, model_dir):
        """G5: Minimum 200 evidence before adjustment."""
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()

        cal = AutoCalibrator(scoring_engine=scorer, model_dir=model_dir)

        # Candidate with too few events
        candidates = [
            {
                "category": "test",
                "action": "test",
                "reason": "test",
                "evidence_count": 50,
            }  # Below MIN_EVIDENCE_COUNT=200
        ]
        applied = cal._apply_adjustments(candidates)
        assert applied == 0

    def test_rollback(self, model_dir):
        """G5: Adjustments should be rollbackable."""
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()

        cal = AutoCalibrator(scoring_engine=scorer, model_dir=model_dir)

        candidates = [
            {
                "category": "test_cat",
                "action": "test_act",
                "reason": "frequency_decay",
                "evidence_count": 500,
            }
        ]
        applied = cal._apply_adjustments(candidates)
        assert applied == 1
        assert len(cal._adjustment_history) == 1

        rolled = cal.rollback(n=1)
        assert rolled == 1
        assert len(cal._adjustment_history) == 0

    def test_log_persistence(self, model_dir):
        """G5: Adjustments logged to JSON."""
        from amoskys.intel.scoring import ScoringEngine

        scorer = ScoringEngine()

        cal = AutoCalibrator(scoring_engine=scorer, model_dir=model_dir)

        candidates = [
            {
                "category": "test_cat",
                "action": "test_act",
                "reason": "oscillation",
                "evidence_count": 300,
            }
        ]
        cal._apply_adjustments(candidates)

        log_path = os.path.join(model_dir, "auto_calibrator_log.json")
        assert os.path.exists(log_path)
        with open(log_path) as f:
            log = json.load(f)
        assert len(log) == 1
        assert log[0]["reason"] == "oscillation"
        assert log[0]["evidence_count"] == 300

    def test_status(self, model_dir):
        cal = AutoCalibrator(model_dir=model_dir)
        status = cal.status()
        assert "total_observed" in status
        assert "total_adjustments" in status


# ── Integration Tests ────────────────────────────────────────────────


class TestScoringEngineIntegration:
    def test_scoring_engine_has_model_adapter(self):
        """Verify ScoringEngine initializes with ModelScorerAdapter."""
        from amoskys.intel.scoring import ScoringEngine

        engine = ScoringEngine()
        assert engine._model_adapter is not None
        assert hasattr(engine._model_adapter, "available")
        assert callable(engine._model_adapter.available)

    def test_scoring_fallback_to_heuristic(self):
        """When no models loaded, heuristic scoring should work unchanged."""
        from amoskys.intel.scoring import ScoringEngine

        engine = ScoringEngine()

        event = {
            "device_id": "test_device",
            "event_category": "file_modified",
            "event_action": "detected",
            "collection_agent": "fim_agent",
            "risk_score": 5.0,
            "confidence": 0.8,
            "indicators": {},
            "mitre_techniques": [],
            "requires_investigation": False,
        }
        result = engine.score_event(event)
        assert "geometric_score" in result
        assert "temporal_score" in result
        assert "behavioral_score" in result
        assert "final_classification" in result

    def test_ml_factors_in_score_factors(self):
        """ML factors should be included in score_factors list."""
        from amoskys.intel.scoring import ScoringEngine

        engine = ScoringEngine()

        event = {
            "device_id": "test_device",
            "event_category": "test",
            "event_action": "test",
            "collection_agent": "test_agent",
            "risk_score": 1.0,
            "confidence": 0.5,
            "indicators": {},
            "mitre_techniques": [],
            "requires_investigation": False,
        }
        result = engine.score_event(event)
        # score_factors should be a list (even if empty ML factors)
        assert isinstance(result["score_factors"], list)

    def test_stats_includes_model_adapter(self):
        """stats() should report model_adapter status."""
        from amoskys.intel.scoring import ScoringEngine

        engine = ScoringEngine()
        stats = engine.stats()
        assert "model_adapter" in stats
        assert isinstance(stats["model_adapter"]["available"], bool)
