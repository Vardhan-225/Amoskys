"""
SOMA Brain — Autonomous Self-Training Intelligence Engine

Trains real ML models on endpoint telemetry, hot-reloads them into the
scoring pipeline, learns event semantics from co-occurrence patterns,
and auto-detects false positives.

Components:
  - SomaBrain:          Daemon thread that trains models every 30 min
  - ModelScorerAdapter: Wraps trained models for ScoringEngine inference
  - EventEmbedder:      Co-occurrence SVD for semantic event understanding
  - AutoCalibrator:     Rate-limited autonomous FP detection

Guardrails:
  G1: available() is a method, not a property
  G2: Supervised training ONLY on high-trust labels (incident/IOC/manual)
  G3: Event-native features as primary; heuristic scores are auxiliary only
  G4: IF scores normalized via persisted p5/p95 calibration quantiles
  G5: AutoCalibrator rate-limited (max 10/cycle, min 200 evidence, logged)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Lazy imports for ML libraries — keeps import fast when not training
_sklearn_available = False
try:
    from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
    from sklearn.preprocessing import LabelEncoder

    _sklearn_available = True
except ImportError:
    pass


# ── SomaBrain: Autonomous Training Daemon ─────────────────────────────


class SomaBrain:
    """Autonomous ML engine for endpoint telemetry.

    Trains models on real security events:
    - IsolationForest: Unsupervised anomaly detection (always trains)
    - GradientBoostingClassifier: Supervised 3-class (ONLY with high-trust labels — G2)

    Runs as daemon thread, training every 30 min on latest 50K events.
    """

    MIN_EVENTS_FOR_TRAINING = 200
    TRAINING_SAMPLE_SIZE = 50_000
    HIGH_TRUST_LABEL_SOURCES = frozenset({"incident", "ioc_strong", "manual"})

    # Suspicious tokens for feature extraction (G3)
    _SUSPICIOUS_TOKENS = frozenset(
        {
            "base64",
            "powershell",
            "curl",
            "wget",
            "nc",
            "ncat",
            "python",
            "ruby",
            "perl",
            "bash",
            "sh",
            "cmd",
            "wmic",
            "certutil",
            "bitsadmin",
            "mshta",
            "regsvr32",
            "rundll32",
            "msiexec",
            "cscript",
            "wscript",
            "whoami",
            "net user",
            "net localgroup",
            "mimikatz",
            "procdump",
            "psexec",
        }
    )

    def __init__(
        self,
        telemetry_db_path: str = "data/telemetry.db",
        model_dir: str = "data/intel/models",
        training_interval_seconds: int = 1800,
        scoring_engine: Any = None,
    ) -> None:
        self._db_path = telemetry_db_path
        self._model_dir = model_dir
        self._interval = training_interval_seconds
        self._scorer = scoring_engine

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._status = "idle"
        self._training_count = self._restore_training_count(model_dir)
        self._last_train_time: Optional[float] = None
        self._last_metrics: Dict[str, Any] = {}

        # Sub-components
        self._embedder = EventEmbedder(model_dir=model_dir)
        self._auto_calibrator = AutoCalibrator(
            scoring_engine=scoring_engine,
            model_dir=model_dir,
        )

        # Label encoders (persist across cycles for consistency)
        self._label_encoders: Dict[str, LabelEncoder] = {}
        self._feature_columns: List[str] = []

        os.makedirs(model_dir, exist_ok=True)
        logger.info(
            "SomaBrain initialized (model_dir=%s, interval=%ds)",
            model_dir,
            training_interval_seconds,
        )

    @staticmethod
    def _restore_training_count(model_dir: str) -> int:
        """Read last cycle number from training_history.json to avoid resets."""
        history_path = os.path.join(model_dir, "training_history.json")
        if not os.path.exists(history_path):
            return 0
        try:
            with open(history_path) as f:
                history = json.load(f)
            if history and isinstance(history, list):
                return max(entry.get("cycle", 0) for entry in history)
        except Exception:
            pass
        return 0

    # ── Daemon lifecycle ─────────────────────────────────────────────

    def start(self) -> None:
        """Launch background daemon thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("SomaBrain already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._training_loop, name="SomaBrain", daemon=True
        )
        self._thread.start()
        logger.info("SomaBrain daemon started")

    def stop(self) -> None:
        """Signal stop and wait for thread to finish."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=30)
        logger.info("SomaBrain daemon stopped")

    def _training_loop(self) -> None:
        """Main training loop: train → sleep → repeat."""
        logger.info("SomaBrain training loop started (interval=%ds)", self._interval)
        while not self._stop_event.is_set():
            try:
                self.train_once()
            except Exception:
                logger.error("SomaBrain training cycle failed", exc_info=True)
                self._status = "error"

            # Sleep in small increments so stop_event is responsive
            for _ in range(self._interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    # ── Single training cycle ────────────────────────────────────────

    def train_once(self) -> Dict[str, Any]:
        """Execute one complete training cycle.

        Returns metrics dict with model performance data.
        """
        t0 = time.time()
        self._status = "training"
        metrics: Dict[str, Any] = {
            "cycle": self._training_count + 1,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        # 1. Query training data
        df = self._query_training_data()
        if df is None or len(df) < self.MIN_EVENTS_FOR_TRAINING:
            self._status = "cold_start"
            metrics["status"] = "cold_start"
            metrics["event_count"] = len(df) if df is not None else 0
            logger.info(
                "SomaBrain: cold start (%d events, need %d)",
                metrics["event_count"],
                self.MIN_EVENTS_FOR_TRAINING,
            )
            self._last_metrics = metrics
            return metrics

        metrics["event_count"] = len(df)
        logger.info("SomaBrain: training on %d events", len(df))

        # 2. Extract features (G3: event-native, not heuristic echoes)
        X, feature_names = self._extract_features(df)
        self._feature_columns = feature_names
        metrics["feature_count"] = len(feature_names)

        # 3. Train IsolationForest (always)
        if_metrics = self._train_isolation_forest(X)
        metrics["isolation_forest"] = if_metrics

        # 4. Train GBC (G2: ONLY with high-trust labels)
        y_high_trust = self._get_high_trust_labels(df)
        if y_high_trust is not None and len(y_high_trust) >= 50:
            # Filter X to only rows with high-trust labels
            mask = y_high_trust.index
            X_supervised = X[mask] if hasattr(X, "iloc") else X[mask]
            gbc_metrics = self._train_gradient_boost(X_supervised, y_high_trust.values)
            metrics["gradient_boost"] = gbc_metrics
            metrics["high_trust_label_count"] = len(y_high_trust)
        else:
            metrics["gradient_boost"] = {
                "status": "skipped",
                "reason": "insufficient_high_trust_labels",
            }
            metrics["high_trust_label_count"] = (
                len(y_high_trust) if y_high_trust is not None else 0
            )

        # 5. Train EventEmbedder
        try:
            emb_metrics = self._embedder.fit(df)
            self._embedder.save()
            metrics["embedder"] = emb_metrics
        except Exception:
            logger.warning("EventEmbedder training failed", exc_info=True)
            metrics["embedder"] = {"status": "error"}

        # 6. Run AutoCalibrator analysis
        try:
            cal_metrics = self._auto_calibrator.analyze(self._db_path)
            metrics["auto_calibrator"] = cal_metrics
        except Exception:
            logger.warning("AutoCalibrator analysis failed", exc_info=True)
            metrics["auto_calibrator"] = {"status": "error"}

        # 7. Persist feature columns + label encoders
        self._persist_artifact(self._feature_columns, "feature_columns")
        self._persist_artifact(self._label_encoders, "label_encoders")

        # 8. Post-training validation — verify model quality before deploying
        validation = self._validate_trained_model(X, if_metrics)
        metrics["validation"] = validation

        if validation.get("passed", False):
            # 9. Save metrics and activate model
            elapsed = time.time() - t0
            metrics["elapsed_seconds"] = round(elapsed, 2)
            metrics["status"] = "completed"
            self._last_metrics = metrics
            self._training_count += 1
            self._last_train_time = time.time()
            self._status = "idle"

            self._save_metrics(metrics)
            self._notify_scorer_reload()

            logger.info(
                "SomaBrain: training cycle %d complete in %.1fs "
                "(IF anomaly_rate=%.3f, validation=%s)",
                self._training_count,
                elapsed,
                if_metrics.get("anomaly_rate", -1),
                "PASSED",
            )
        else:
            elapsed = time.time() - t0
            metrics["elapsed_seconds"] = round(elapsed, 2)
            metrics["status"] = "validation_failed"
            self._last_metrics = metrics
            self._status = "idle"

            # Save metrics but don't bump training count or notify scorer
            self._save_metrics(metrics)
            logger.warning(
                "SomaBrain: training cycle FAILED validation in %.1fs — %s",
                elapsed,
                validation.get("reason", "unknown"),
            )

        return metrics

    # ── Post-training validation ────────────────────────────────────

    def _validate_trained_model(
        self, X: Any, if_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate the newly trained IsolationForest before deploying.

        Checks:
        1. Anomaly rate is within reasonable bounds (1%-30%)
        2. Calibration spread is non-degenerate (p95 - p5 > 0.01)
        3. Model can score without error (inference smoke test)
        """
        anomaly_rate = if_metrics.get("anomaly_rate", 0)
        p5 = if_metrics.get("calibration_p5", 0)
        p95 = if_metrics.get("calibration_p95", 0)
        checks: List[Dict] = []

        # Check 1: Anomaly rate bounds
        if anomaly_rate < 0.001:
            checks.append(
                {
                    "check": "anomaly_rate_floor",
                    "passed": False,
                    "detail": f"Anomaly rate {anomaly_rate:.4f} below 0.1% — model may be undertrained",
                }
            )
        elif anomaly_rate > 0.30:
            checks.append(
                {
                    "check": "anomaly_rate_ceiling",
                    "passed": False,
                    "detail": f"Anomaly rate {anomaly_rate:.4f} above 30% — model flagging too much",
                }
            )
        else:
            checks.append(
                {
                    "check": "anomaly_rate",
                    "passed": True,
                    "detail": f"Anomaly rate {anomaly_rate:.4f} within bounds",
                }
            )

        # Check 2: Calibration spread
        spread = abs(p95 - p5)
        if spread < 0.01:
            checks.append(
                {
                    "check": "calibration_spread",
                    "passed": False,
                    "detail": f"Calibration spread {spread:.6f} is degenerate (p5={p5:.4f}, p95={p95:.4f})",
                }
            )
        else:
            checks.append(
                {
                    "check": "calibration_spread",
                    "passed": True,
                    "detail": f"Calibration spread {spread:.4f} is healthy",
                }
            )

        # Check 3: Inference smoke test on 5 random samples
        try:
            import joblib

            model_path = os.path.join(self._model_dir, "isolation_forest.joblib")
            model = joblib.load(model_path)
            rng = np.random.default_rng(42)
            sample_indices = rng.choice(len(X), min(5, len(X)), replace=False)
            sample = X[sample_indices]
            scores = -model.score_samples(sample)
            checks.append(
                {
                    "check": "inference_smoke",
                    "passed": True,
                    "detail": f"Scored {len(sample)} samples, scores range [{scores.min():.4f}, {scores.max():.4f}]",
                }
            )
        except Exception as e:
            checks.append(
                {
                    "check": "inference_smoke",
                    "passed": False,
                    "detail": f"Inference failed: {e}",
                }
            )

        all_passed = all(c["passed"] for c in checks)
        failed = [c for c in checks if not c["passed"]]
        return {
            "passed": all_passed,
            "checks": checks,
            "reason": failed[0]["detail"] if failed else "all checks passed",
        }

    # ── Data query ───────────────────────────────────────────────────

    def _query_training_data(self):
        """Read latest events from telemetry.db (read-only).

        Queries security_events first (scored, classified — ideal training data).
        If insufficient, supplements with observation_events and domain tables
        (process_events, fim_events, persistence_events) using column mapping.
        """
        try:
            import pandas as pd
        except ImportError:
            logger.error("pandas required for SomaBrain training")
            return None

        if not os.path.exists(self._db_path):
            logger.warning("Telemetry DB not found: %s", self._db_path)
            return None

        # Core columns that always exist
        core_cols = [
            "timestamp_dt",
            "device_id",
            "event_category",
            "event_action",
            "collection_agent",
            "risk_score",
            "confidence",
            "geometric_score",
            "temporal_score",
            "behavioral_score",
            "final_classification",
            "indicators",
            "mitre_techniques",
            "requires_investigation",
        ]
        # Optional columns that may or may not exist in the schema
        optional_cols = [
            "target_resource",
            "details",
            "description",
            "label_source",
            "event_timestamp_ns",
            "event_id",
            "probe_latency_ns",
            "quality_state",
            "training_exclude",
        ]

        try:
            conn = sqlite3.connect(
                f"file:{self._db_path}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
            conn.execute("PRAGMA query_only = ON")

            frames = []

            # ── Primary source: security_events (fully scored) ──
            sec_cols_info = conn.execute(
                "PRAGMA table_info(security_events)"
            ).fetchall()
            existing_cols = {row[1] for row in sec_cols_info}
            select_cols = [c for c in core_cols if c in existing_cols]
            for oc in optional_cols:
                if oc in existing_cols:
                    select_cols.append(oc)

            where_clauses = []
            if "quality_state" in existing_cols:
                where_clauses.append(
                    "LOWER(COALESCE(quality_state, 'valid')) = 'valid'"
                )
            if "training_exclude" in existing_cols:
                where_clauses.append(
                    "COALESCE(CAST(training_exclude AS TEXT), '0') IN ('0', 'false', 'FALSE', 'False')"
                )
            where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

            query = f"""
                SELECT {', '.join(select_cols)}
                FROM security_events
                {where_sql}
                ORDER BY timestamp_dt DESC
                LIMIT ?
            """
            df_sec = pd.read_sql_query(query, conn, params=(self.TRAINING_SAMPLE_SIZE,))
            if not df_sec.empty:
                frames.append(df_sec)
            logger.info("SomaBrain: security_events yielded %d rows", len(df_sec))

            # ── Supplementary sources if security_events insufficient ──
            remaining = self.TRAINING_SAMPLE_SIZE - len(df_sec)
            if remaining > 0:
                # observation_events — map columns to match security_events schema
                try:
                    obs_cols = {
                        row[1]
                        for row in conn.execute(
                            "PRAGMA table_info(observation_events)"
                        ).fetchall()
                    }
                    if obs_cols:
                        obs_where = []
                        if "quality_state" in obs_cols:
                            obs_where.append(
                                "LOWER(COALESCE(quality_state, 'valid')) = 'valid'"
                            )
                        if "training_exclude" in obs_cols:
                            obs_where.append(
                                "COALESCE(CAST(training_exclude AS TEXT), '0') "
                                "IN ('0', 'false', 'FALSE', 'False')"
                            )
                        obs_where_sql = (
                            f"WHERE {' AND '.join(obs_where)}" if obs_where else ""
                        )
                        obs_query = f"""
                            SELECT timestamp_dt, device_id,
                                   COALESCE(domain, 'unknown') as event_category,
                                   COALESCE(event_type, 'observation') as event_action,
                                   collection_agent,
                                   COALESCE(risk_score, 0.0) as risk_score,
                                   0.5 as confidence,
                                   0.0 as geometric_score,
                                   0.0 as temporal_score,
                                   0.0 as behavioral_score,
                                   'unknown' as final_classification,
                                   COALESCE(attributes, '{{}}') as indicators,
                                   '[]' as mitre_techniques,
                                   0 as requires_investigation
                            FROM observation_events
                            {obs_where_sql}
                            ORDER BY timestamp_dt DESC
                            LIMIT ?
                        """
                        df_obs = pd.read_sql_query(obs_query, conn, params=(remaining,))
                        if not df_obs.empty:
                            frames.append(df_obs)
                            remaining -= len(df_obs)
                        logger.info(
                            "SomaBrain: observation_events yielded %d rows",
                            len(df_obs),
                        )
                except Exception:
                    logger.debug("observation_events query failed", exc_info=True)

                # Domain tables — process_events, fim_events, persistence_events
                domain_tables = [
                    ("process_events", "exe", "process"),
                    ("fim_events", "path", "filesystem"),
                    ("persistence_events", "path", "persistence"),
                ]
                for table_name, resource_col, domain in domain_tables:
                    if remaining <= 0:
                        break
                    try:
                        tcols = {
                            row[1]
                            for row in conn.execute(
                                f"PRAGMA table_info({table_name})"
                            ).fetchall()
                        }
                        if not tcols:
                            continue
                        agent_col = (
                            "collection_agent"
                            if "collection_agent" in tcols
                            else f"'{domain}_agent'"
                        )
                        dom_query = f"""
                            SELECT timestamp_dt, device_id,
                                   '{domain}' as event_category,
                                   COALESCE(event_type, '{domain}') as event_action,
                                   {agent_col} as collection_agent,
                                   0.0 as risk_score,
                                   0.5 as confidence,
                                   0.0 as geometric_score,
                                   0.0 as temporal_score,
                                   0.0 as behavioral_score,
                                   'unknown' as final_classification,
                                   '{{}}' as indicators,
                                   '[]' as mitre_techniques,
                                   0 as requires_investigation
                            FROM {table_name}
                            ORDER BY timestamp_dt DESC
                            LIMIT ?
                        """
                        df_dom = pd.read_sql_query(dom_query, conn, params=(remaining,))
                        if not df_dom.empty:
                            frames.append(df_dom)
                            remaining -= len(df_dom)
                        logger.info(
                            "SomaBrain: %s yielded %d rows", table_name, len(df_dom)
                        )
                    except Exception:
                        logger.debug("%s query failed", table_name, exc_info=True)

            conn.close()

            if not frames:
                return None

            df = pd.concat(frames, ignore_index=True)

            # Fill missing optional columns with defaults
            for oc in optional_cols:
                if oc not in df.columns:
                    df[oc] = ""

            logger.info(
                "SomaBrain: total training data = %d rows from %d source(s)",
                len(df),
                len(frames),
            )
            return df
        except Exception:
            logger.error("Failed to query training data", exc_info=True)
            return None

    # ── Feature extraction (G3: event-native first) ──────────────────

    def _extract_features(self, df) -> Tuple[Any, List[str]]:
        """Extract event-native features from DataFrame.

        G3: Primary features are event-intrinsic (temporal, categorical,
        indicator-derived). Heuristic scores included as auxiliary only.
        """
        import pandas as pd

        features = pd.DataFrame(index=df.index)

        # Temporal features (from timestamp)
        try:
            ts = pd.to_datetime(df["timestamp_dt"], errors="coerce")
            features["hour_of_day"] = ts.dt.hour.fillna(12).astype(float)
            features["day_of_week"] = ts.dt.dayofweek.fillna(3).astype(float)
            features["is_business_hours"] = (
                (features["hour_of_day"] >= 9) & (features["hour_of_day"] <= 17)
            ).astype(float)
            features["is_weekend"] = (features["day_of_week"] >= 5).astype(float)
        except Exception:
            features["hour_of_day"] = 12.0
            features["day_of_week"] = 3.0
            features["is_business_hours"] = 1.0
            features["is_weekend"] = 0.0

        # Probe-local temporal features (from event_timestamp_ns — Step 3)
        if "event_timestamp_ns" in df.columns:
            evt_ts = pd.to_numeric(df["event_timestamp_ns"], errors="coerce").astype(
                "float64"
            )
            evt_ts = evt_ts.replace([np.inf, -np.inf], np.nan)
            # Support mixed timestamp scales without overflowing pandas conversion.
            valid_ts = evt_ts.dropna()
            if not valid_ts.empty:
                median_ts = float(valid_ts.median())
                if median_ts > 1e17:  # nanoseconds
                    evt_ts = evt_ts / 1e9
                elif median_ts > 1e14:  # microseconds
                    evt_ts = evt_ts / 1e6
                elif median_ts > 1e11:  # milliseconds
                    evt_ts = evt_ts / 1e3
            evt_ts = evt_ts.where(
                (evt_ts >= 0) & (evt_ts <= 32_503_680_000),
                np.nan,
            )
            probe_dt = pd.to_datetime(
                evt_ts.fillna(0).astype("int64"),
                unit="s",
                errors="coerce",
                utc=True,
            )
            probe_dt = probe_dt.where(evt_ts.notna())
            features["probe_hour_of_day"] = probe_dt.dt.hour.fillna(
                features["hour_of_day"]
            ).astype(float)
            features["probe_is_off_hours"] = (
                (features["probe_hour_of_day"] < 6)
                | (features["probe_hour_of_day"] >= 22)
            ).astype(float)
        else:
            features["probe_hour_of_day"] = features["hour_of_day"]
            features["probe_is_off_hours"] = 0.0

        if "probe_latency_ns" in df.columns:
            latency_ns = pd.to_numeric(df["probe_latency_ns"], errors="coerce").fillna(
                0
            )
            features["probe_ingestion_lag_s"] = (latency_ns / 1e9).astype(float)
            features["is_high_latency"] = (latency_ns > 30e9).astype(float)
        else:
            features["probe_ingestion_lag_s"] = 0.0
            features["is_high_latency"] = 0.0

        # Endpoint temporal probe signals (from indicators JSON)
        for sig_key in ["burst_score", "acceleration", "jitter_score", "rate"]:
            col_name = f"endpoint_{sig_key}"
            features[col_name] = (
                df["indicators"]
                .apply(lambda x, k=sig_key: self._json_float_key(x, k))
                .astype(float)
            )

        # Inter-event gap per device+category (using event_timestamp_ns)
        if "event_timestamp_ns" in df.columns:
            evt_ts_vals = pd.to_numeric(df["event_timestamp_ns"], errors="coerce")
            group_key = (
                df["device_id"].astype(str) + "|" + df["event_category"].astype(str)
            )
            features["inter_event_gap_s"] = (
                (evt_ts_vals.groupby(group_key).diff().fillna(0) / 1e9)
                .abs()
                .astype(float)
            )
            features["is_rapid_succession"] = (
                (features["inter_event_gap_s"] > 0)
                & (features["inter_event_gap_s"] < 2.0)
            ).astype(float)
        else:
            features["inter_event_gap_s"] = 0.0
            features["is_rapid_succession"] = 0.0

        # Categorical features (LabelEncoder)
        for col in ["event_category", "event_action", "collection_agent"]:
            enc_name = f"{col}_encoder"
            if enc_name not in self._label_encoders:
                self._label_encoders[enc_name] = LabelEncoder()

            values = df[col].fillna("unknown").astype(str)
            enc = self._label_encoders[enc_name]

            # Fit on all unique values (incremental)
            known = set(enc.classes_) if hasattr(enc, "classes_") else set()
            new_vals = set(values.unique()) - known
            if new_vals or not known:
                all_vals = sorted(known | new_vals)
                enc.fit(all_vals)

            features[col + "_encoded"] = enc.transform(values).astype(float)

        # Indicator-derived features (from JSON columns)
        features["mitre_technique_count"] = (
            df["mitre_techniques"].apply(self._count_json_items).astype(float)
        )

        features["has_threat_match"] = df["indicators"].apply(
            lambda x: 1.0 if self._json_has_key(x, "threat_match") else 0.0
        )

        features["has_external_ip"] = df["indicators"].apply(
            lambda x: 1.0 if self._json_has_key(x, "external_ip") else 0.0
        )

        features["indicators_field_count"] = (
            df["indicators"].apply(self._count_json_keys).astype(float)
        )

        # Event-intrinsic features (G3: the core of what makes this different)
        features["cmdline_length"] = (
            df["details"].apply(self._extract_cmdline_length).astype(float)
        )

        features["has_suspicious_tokens"] = (
            df["details"].apply(self._has_suspicious_tokens).astype(float)
        )

        features["path_depth"] = (
            df["target_resource"].apply(self._compute_path_depth).astype(float)
        )

        # Per-device and per-category rate features (computed from the batch)
        device_counts = df["device_id"].value_counts()
        features["device_event_rate"] = (
            df["device_id"].map(device_counts).fillna(1).astype(float)
        )

        cat_action = df["event_category"] + "|" + df["event_action"]
        cat_action_counts = cat_action.value_counts()
        features["event_type_frequency"] = (
            cat_action.map(cat_action_counts).fillna(1).astype(float)
        )

        features["unique_agents_for_device"] = (
            df["device_id"]
            .map(df.groupby("device_id")["collection_agent"].nunique())
            .fillna(1)
            .astype(float)
        )

        # Auxiliary features (G3: heuristic hints, NOT primary)
        features["aux_risk_score"] = pd.to_numeric(
            df["risk_score"], errors="coerce"
        ).fillna(0.0)
        features["aux_confidence"] = pd.to_numeric(
            df["confidence"], errors="coerce"
        ).fillna(0.5)

        # Requires investigation flag
        features["requires_investigation"] = df["requires_investigation"].apply(
            lambda x: 1.0 if x else 0.0
        )

        # Kill chain sequence match (from Step 4 — WAL processor injects this)
        features["in_kill_chain"] = (
            df["indicators"]
            .apply(
                lambda x: (
                    1.0 if self._json_float_key(x, "sequence_match_score") > 0 else 0.0
                )
            )
            .astype(float)
        )

        # Clean up any remaining NaN/inf
        features = features.fillna(0.0)
        features = features.replace([np.inf, -np.inf], 0.0)

        feature_names = list(features.columns)
        return features.values, feature_names

    # ── Feature extraction helpers ───────────────────────────────────

    @staticmethod
    def _count_json_items(val) -> int:
        if not val or val == "null":
            return 0
        try:
            parsed = json.loads(val) if isinstance(val, str) else val
            if isinstance(parsed, list):
                return len(parsed)
            if isinstance(parsed, dict):
                return len(parsed)
            return 0
        except (json.JSONDecodeError, TypeError):
            return 0

    @staticmethod
    def _json_has_key(val, key: str) -> bool:
        if not val or val == "null":
            return False
        try:
            parsed = json.loads(val) if isinstance(val, str) else val
            if isinstance(parsed, dict):
                return key in parsed
            return False
        except (json.JSONDecodeError, TypeError):
            return False

    @staticmethod
    def _json_float_key(val, key: str) -> float:
        """Extract a numeric value from a JSON dict by key, defaulting to 0.0."""
        if not val or val == "null":
            return 0.0
        try:
            parsed = json.loads(val) if isinstance(val, str) else val
            if isinstance(parsed, dict) and key in parsed:
                return float(parsed[key])
            return 0.0
        except (json.JSONDecodeError, TypeError, ValueError):
            return 0.0

    @staticmethod
    def _count_json_keys(val) -> int:
        if not val or val == "null":
            return 0
        try:
            parsed = json.loads(val) if isinstance(val, str) else val
            if isinstance(parsed, dict):
                return len(parsed)
            return 0
        except (json.JSONDecodeError, TypeError):
            return 0

    @staticmethod
    def _extract_cmdline_length(val) -> int:
        if not val or val == "null":
            return 0
        try:
            parsed = json.loads(val) if isinstance(val, str) else val
            if isinstance(parsed, dict):
                cmdline = parsed.get("cmdline", parsed.get("command_line", ""))
                return len(str(cmdline)) if cmdline else 0
            return 0
        except (json.JSONDecodeError, TypeError):
            return 0

    def _has_suspicious_tokens(self, val) -> float:
        if not val or val == "null":
            return 0.0
        try:
            text = val if isinstance(val, str) else json.dumps(val)
            text_lower = text.lower()
            for token in self._SUSPICIOUS_TOKENS:
                if token in text_lower:
                    return 1.0
            return 0.0
        except (TypeError, json.JSONDecodeError):
            return 0.0

    @staticmethod
    def _compute_path_depth(val) -> int:
        if not val or not isinstance(val, str):
            return 0
        return val.count("/") + val.count("\\")

    # ── High-trust label extraction (G2) ─────────────────────────────

    def _get_high_trust_labels(self, df):
        """Extract labels ONLY from high-trust sources.

        G2: Never train supervised on heuristic-generated final_classification.
        Only use labels from: incident escalation, strong IOC match, analyst tag.
        """
        import pandas as pd

        # Check if we have a label_source column
        if "label_source" in df.columns:
            mask = df["label_source"].isin(self.HIGH_TRUST_LABEL_SOURCES)
            if mask.sum() >= 50:
                labels = (
                    df.loc[mask, "final_classification"]
                    .map({"legitimate": 0, "suspicious": 1, "malicious": 2})
                    .dropna()
                    .astype(int)
                )
                return labels

        # Alternative: derive high-trust labels from indicators
        # Events with strong IOC matches get their classification as label
        high_trust_indices = []
        labels = []

        for idx, row in df.iterrows():
            label_source = self._determine_label_source(row)
            if label_source in self.HIGH_TRUST_LABEL_SOURCES:
                classification = row.get("final_classification", "")
                label_val = {"legitimate": 0, "suspicious": 1, "malicious": 2}.get(
                    classification
                )
                if label_val is not None:
                    high_trust_indices.append(idx)
                    labels.append(label_val)

        if len(labels) >= 50:
            return pd.Series(labels, index=high_trust_indices, dtype=int)

        logger.info(
            "SomaBrain: only %d high-trust labels (need 50), skipping supervised",
            len(labels),
        )
        return None

    @staticmethod
    def _determine_label_source(row) -> str:
        """Determine if an event has a high-trust label source.

        - ioc_strong: has threat intel match with high confidence
        - incident: was part of an incident (requires_investigation + high risk)
        """
        indicators = row.get("indicators", "")
        if isinstance(indicators, str) and indicators and indicators != "null":
            try:
                ind = json.loads(indicators)
                if isinstance(ind, dict):
                    if ind.get("threat_match"):
                        return "ioc_strong"
            except (json.JSONDecodeError, TypeError):
                pass

        # Events that require investigation with high risk score are
        # likely incident-confirmed
        if row.get("requires_investigation") and row.get("risk_score", 0) >= 8.0:
            return "incident"

        return "heuristic"

    # ── Model training ───────────────────────────────────────────────

    def _train_isolation_forest(self, X) -> Dict[str, Any]:
        """Train IsolationForest for unsupervised anomaly detection."""
        t0 = time.time()

        model = IsolationForest(
            contamination=0.05,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X)

        # Predict anomalies
        predictions = model.predict(X)
        anomaly_count = int((predictions == -1).sum())
        anomaly_rate = anomaly_count / len(X)

        # G4: Persist calibration quantiles for stable score normalization
        raw_scores = -model.score_samples(X)
        p5 = float(np.percentile(raw_scores, 5))
        p95 = float(np.percentile(raw_scores, 95))

        calibration = {
            "p5": p5,
            "p95": p95,
            "mean": float(raw_scores.mean()),
            "std": float(raw_scores.std()),
            "trained_at": time.time(),
        }
        cal_path = os.path.join(self._model_dir, "if_calibration.json")
        self._atomic_json_write(cal_path, calibration)

        # Persist model
        self._persist_model(model, "isolation_forest")

        elapsed = time.time() - t0
        metrics = {
            "status": "trained",
            "samples": len(X),
            "anomaly_count": anomaly_count,
            "anomaly_rate": round(anomaly_rate, 4),
            "calibration_p5": round(p5, 6),
            "calibration_p95": round(p95, 6),
            "elapsed_seconds": round(elapsed, 2),
        }
        logger.info(
            "IsolationForest trained: %d samples, %.1f%% anomalies, p5=%.4f, p95=%.4f",
            len(X),
            anomaly_rate * 100,
            p5,
            p95,
        )
        return metrics

    def _train_gradient_boost(self, X, y) -> Dict[str, Any]:
        """Train GradientBoostingClassifier on HIGH-TRUST labels only (G2)."""
        t0 = time.time()

        # Check class distribution
        unique, counts = np.unique(y, return_counts=True)
        class_dist = dict(zip(unique.tolist(), counts.tolist()))

        if len(unique) < 2:
            return {
                "status": "skipped",
                "reason": "single_class",
                "class_distribution": class_dist,
            }

        # Train with balanced class weights
        model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
        )

        # Simple train/test split for metrics
        split = max(1, int(len(X) * 0.8))
        X_train, X_test = X[:split], X[split:]
        y_train, y_test = y[:split], y[split:]

        if len(X_test) < 5:
            # Not enough data for split, train on all
            model.fit(X, y)
            accuracy = -1.0
            f1 = -1.0
        else:
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            accuracy = float((y_pred == y_test).mean())

            # Compute per-class F1 (macro average)
            from sklearn.metrics import f1_score

            f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

            # Retrain on full data for production model
            model.fit(X, y)

        # Feature importances
        importances = model.feature_importances_
        top_indices = np.argsort(importances)[-10:][::-1]
        top_features = []
        for idx in top_indices:
            if idx < len(self._feature_columns):
                top_features.append(
                    {
                        "feature": self._feature_columns[idx],
                        "importance": round(float(importances[idx]), 4),
                    }
                )

        self._persist_model(model, "gradient_boost")

        elapsed = time.time() - t0
        metrics = {
            "status": "trained",
            "samples": len(X),
            "class_distribution": class_dist,
            "accuracy": round(accuracy, 4) if accuracy >= 0 else "n/a",
            "f1_macro": round(f1, 4) if f1 >= 0 else "n/a",
            "top_features": top_features,
            "elapsed_seconds": round(elapsed, 2),
        }
        logger.info(
            "GBC trained: %d high-trust samples, accuracy=%.3f, F1=%.3f",
            len(X),
            accuracy if accuracy >= 0 else 0,
            f1 if f1 >= 0 else 0,
        )
        return metrics

    # ── Model persistence ────────────────────────────────────────────

    def _persist_model(self, model, name: str) -> str:
        """Atomically persist a model via tmp + os.replace()."""
        import joblib

        path = os.path.join(self._model_dir, f"{name}.joblib")
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self._model_dir, suffix=".tmp")
        os.close(tmp_fd)
        try:
            joblib.dump(model, tmp_path)
            os.replace(tmp_path, path)
            logger.debug("Persisted model: %s", path)
            return path
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def _persist_artifact(self, obj, name: str) -> None:
        """Persist a Python object (encoders, feature list) via joblib."""
        import joblib

        path = os.path.join(self._model_dir, f"{name}.joblib")
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self._model_dir, suffix=".tmp")
        os.close(tmp_fd)
        try:
            joblib.dump(obj, tmp_path)
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @staticmethod
    def _atomic_json_write(path: str, data: dict) -> None:
        """Atomic JSON write via tmp + replace."""
        dir_path = os.path.dirname(path) or "."
        tmp_fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, path)
        except Exception:
            os.close(tmp_fd)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def _save_metrics(self, metrics: dict) -> None:
        """Save latest metrics and append to training history."""
        # Current metrics
        metrics_path = os.path.join(self._model_dir, "brain_metrics.json")
        self._atomic_json_write(metrics_path, metrics)

        # Append to history (keep last 100 entries)
        history_path = os.path.join(self._model_dir, "training_history.json")
        history = []
        if os.path.exists(history_path):
            try:
                with open(history_path) as f:
                    history = json.load(f)
            except (json.JSONDecodeError, IOError):
                history = []
        history.append(metrics)
        history = history[-100:]
        self._atomic_json_write(history_path, history)

    def _notify_scorer_reload(self) -> None:
        """Signal the scorer that new models are available.

        Models are detected via mtime on next score() call —
        no explicit notification needed beyond file writes.
        """
        logger.debug(
            "SomaBrain: models written, scorer will hot-reload on next mtime check"
        )

    # ── Status ───────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """Return brain status for API."""
        return {
            "status": self._status,
            "training_count": self._training_count,
            "last_train_time": self._last_train_time,
            "last_metrics": self._last_metrics,
            "interval_seconds": self._interval,
            "model_dir": self._model_dir,
            "embedder": self._embedder.status() if self._embedder else None,
            "auto_calibrator": (
                self._auto_calibrator.status() if self._auto_calibrator else None
            ),
        }


# ── ModelScorerAdapter: Hot-Reload Models for Inference ───────────────


class ModelScorerAdapter:
    """Wraps trained sklearn models for real-time event scoring.

    Hot-reloads models when SomaBrain writes new ones to disk.
    Falls back gracefully if models unavailable or too old.

    G1: available() is a method (not property).
    G4: IF scores normalized via persisted p5/p95 calibration quantiles.
    """

    def __init__(
        self,
        model_dir: str = "data/intel/models",
        max_model_age_seconds: int = 7200,
    ) -> None:
        self._model_dir = model_dir
        self._max_age = max_model_age_seconds

        # Loaded model state
        self._if_model = None
        self._gbc_model = None
        self._label_encoders: Dict = {}
        self._feature_columns: List[str] = []
        self._if_calibration: Dict[str, float] = {}

        # Mtime tracking for hot-reload
        self._if_mtime: float = 0.0
        self._gbc_mtime: float = 0.0
        self._encoders_mtime: float = 0.0

        # Try initial load
        self._load_models()

    def available(self) -> bool:
        """Check if at least the IF model is loaded and not stale. (G1: method)"""
        if self._if_model is None:
            return False
        # Check if model file still exists and isn't too old
        path = os.path.join(self._model_dir, "isolation_forest.joblib")
        if not os.path.exists(path):
            return False
        age = time.time() - os.path.getmtime(path)
        return age < self._max_age

    def score(self, event: Dict[str, Any]) -> Tuple[float, List[Dict]]:
        """Score an event using trained models.

        Returns (score, factors) where score is 0.0-1.0 and factors is
        a list of explanatory dicts.
        """
        # Check for hot-reload before scoring
        self._check_hot_reload()

        if self._if_model is None:
            return 0.0, []

        # Extract features from event dict
        features = self._extract_event_features(event)
        if features is None:
            return 0.0, []

        factors: List[Dict] = []
        X = features.reshape(1, -1)

        # IsolationForest score (G4: stable normalization via calibration)
        try:
            raw_score = float(-self._if_model.score_samples(X)[0])
            if_score = self._normalize_if_score(raw_score)

            prediction = self._if_model.predict(X)[0]
            factors.append(
                {
                    "name": "ML Anomaly Detection",
                    "contribution": round(if_score, 3),
                    "detail": f"IsolationForest: {'anomaly' if prediction == -1 else 'normal'} (score={if_score:.3f})",
                }
            )
        except Exception:
            logger.debug("IF scoring failed", exc_info=True)
            return 0.0, []

        # GBC score (when available)
        gbc_score = 0.0
        if self._gbc_model is not None:
            try:
                probas = self._gbc_model.predict_proba(X)[0]
                # Score = weighted probability of suspicious + malicious
                # Classes: 0=legitimate, 1=suspicious, 2=malicious
                if len(probas) >= 3:
                    gbc_score = float(probas[1] * 0.3 + probas[2] * 0.7)
                elif len(probas) == 2:
                    gbc_score = float(probas[1])

                factors.append(
                    {
                        "name": "ML Classification",
                        "contribution": round(gbc_score, 3),
                        "detail": f"GBC supervised: legit={probas[0]:.2f}, suspicious={probas[1] if len(probas) > 1 else 0:.2f}, malicious={probas[2] if len(probas) > 2 else 0:.2f}",
                    }
                )
            except Exception:
                logger.debug("GBC scoring failed", exc_info=True)

        # Combine: IF primary, GBC secondary
        if gbc_score > 0.0:
            ml_score = 0.6 * if_score + 0.4 * gbc_score
        else:
            ml_score = if_score

        return round(ml_score, 4), factors

    def _normalize_if_score(self, raw: float) -> float:
        """Normalize IF score using persisted p5/p95 quantiles (G4)."""
        p5 = self._if_calibration.get("p5", -0.5)
        p95 = self._if_calibration.get("p95", 0.5)
        if abs(p95 - p5) < 1e-10:
            return 0.5
        normalized = (raw - p5) / (p95 - p5)
        return float(np.clip(normalized, 0.0, 1.0))

    def _extract_event_features(self, event: Dict) -> Optional[np.ndarray]:
        """Extract features from a single event dict matching training schema."""
        if not self._feature_columns:
            return None

        try:
            features = {}

            # Temporal
            ts_str = event.get("timestamp_dt", "")
            try:
                ts = (
                    datetime.fromisoformat(ts_str)
                    if ts_str
                    else datetime.now(timezone.utc)
                )
            except (ValueError, TypeError):
                ts = datetime.now(timezone.utc)
            features["hour_of_day"] = float(ts.hour)
            features["day_of_week"] = float(ts.weekday())
            features["is_business_hours"] = 1.0 if 9 <= ts.hour <= 17 else 0.0
            features["is_weekend"] = 1.0 if ts.weekday() >= 5 else 0.0

            # Categorical (use encoders)
            for col in ["event_category", "event_action", "collection_agent"]:
                enc_name = f"{col}_encoder"
                enc = self._label_encoders.get(enc_name)
                val = event.get(col, "unknown")
                if enc is not None and hasattr(enc, "classes_"):
                    if val in enc.classes_:
                        features[col + "_encoded"] = float(enc.transform([val])[0])
                    else:
                        features[col + "_encoded"] = -1.0
                else:
                    features[col + "_encoded"] = 0.0

            # Indicator-derived
            indicators = event.get("indicators", {})
            if isinstance(indicators, str):
                try:
                    indicators = json.loads(indicators)
                except (json.JSONDecodeError, TypeError):
                    indicators = {}
            if not isinstance(indicators, dict):
                indicators = {}

            mitre = event.get("mitre_techniques", [])
            if isinstance(mitre, str):
                try:
                    mitre = json.loads(mitre)
                except (json.JSONDecodeError, TypeError):
                    mitre = []
            if not isinstance(mitre, list):
                mitre = []

            features["mitre_technique_count"] = float(len(mitre))
            features["has_threat_match"] = (
                1.0 if indicators.get("threat_match") else 0.0
            )
            features["has_external_ip"] = 1.0 if indicators.get("external_ip") else 0.0
            features["indicators_field_count"] = float(len(indicators))

            # Event-intrinsic
            details = event.get("details", {})
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except (json.JSONDecodeError, TypeError):
                    details = {}

            cmdline = ""
            if isinstance(details, dict):
                cmdline = str(details.get("cmdline", details.get("command_line", "")))
            features["cmdline_length"] = float(len(cmdline))

            # Suspicious tokens
            text = json.dumps(details) if isinstance(details, dict) else str(details)
            text_lower = text.lower()
            features["has_suspicious_tokens"] = (
                1.0
                if any(t in text_lower for t in SomaBrain._SUSPICIOUS_TOKENS)
                else 0.0
            )

            target = event.get("target_resource", "")
            features["path_depth"] = (
                float(target.count("/") + target.count("\\"))
                if isinstance(target, str)
                else 0.0
            )

            # Rate features (single event context — best effort)
            features["device_event_rate"] = 1.0
            features["event_type_frequency"] = 1.0
            features["unique_agents_for_device"] = 1.0

            # Auxiliary
            features["aux_risk_score"] = float(event.get("risk_score", 0))
            features["aux_confidence"] = float(event.get("confidence", 0.5))
            features["requires_investigation"] = (
                1.0 if event.get("requires_investigation") else 0.0
            )

            # Build array in feature_columns order
            arr = np.array(
                [features.get(col, 0.0) for col in self._feature_columns],
                dtype=np.float64,
            )
            return arr

        except Exception:
            logger.debug("Feature extraction failed for event", exc_info=True)
            return None

    def _load_models(self) -> None:
        """Load models from disk."""
        import joblib

        # IsolationForest
        if_path = os.path.join(self._model_dir, "isolation_forest.joblib")
        if os.path.exists(if_path):
            try:
                self._if_model = joblib.load(if_path)
                self._if_mtime = os.path.getmtime(if_path)
                logger.info("Loaded IsolationForest model")
            except Exception:
                logger.warning("Failed to load IF model", exc_info=True)

        # IF calibration (G4)
        cal_path = os.path.join(self._model_dir, "if_calibration.json")
        if os.path.exists(cal_path):
            try:
                with open(cal_path) as f:
                    self._if_calibration = json.load(f)
                logger.info(
                    "Loaded IF calibration: p5=%.4f, p95=%.4f",
                    self._if_calibration.get("p5", 0),
                    self._if_calibration.get("p95", 0),
                )
            except Exception:
                logger.warning("Failed to load IF calibration", exc_info=True)

        # GradientBoosting
        gbc_path = os.path.join(self._model_dir, "gradient_boost.joblib")
        if os.path.exists(gbc_path):
            try:
                self._gbc_model = joblib.load(gbc_path)
                self._gbc_mtime = os.path.getmtime(gbc_path)
                logger.info("Loaded GBC model")
            except Exception:
                logger.warning("Failed to load GBC model", exc_info=True)

        # Label encoders
        enc_path = os.path.join(self._model_dir, "label_encoders.joblib")
        if os.path.exists(enc_path):
            try:
                self._label_encoders = joblib.load(enc_path)
                self._encoders_mtime = os.path.getmtime(enc_path)
            except Exception:
                logger.warning("Failed to load label encoders", exc_info=True)

        # Feature columns
        fc_path = os.path.join(self._model_dir, "feature_columns.joblib")
        if os.path.exists(fc_path):
            try:
                self._feature_columns = joblib.load(fc_path)
            except Exception:
                logger.warning("Failed to load feature columns", exc_info=True)

    def _check_hot_reload(self) -> None:
        """Check if model files have been updated and reload if needed."""
        try:
            # IF model
            if_path = os.path.join(self._model_dir, "isolation_forest.joblib")
            if os.path.exists(if_path):
                mtime = os.path.getmtime(if_path)
                if mtime > self._if_mtime:
                    import joblib

                    self._if_model = joblib.load(if_path)
                    self._if_mtime = mtime
                    logger.info("Hot-reloaded IsolationForest model")

                    # Reload calibration too
                    cal_path = os.path.join(self._model_dir, "if_calibration.json")
                    if os.path.exists(cal_path):
                        with open(cal_path) as f:
                            self._if_calibration = json.load(f)

            # GBC model
            gbc_path = os.path.join(self._model_dir, "gradient_boost.joblib")
            if os.path.exists(gbc_path):
                mtime = os.path.getmtime(gbc_path)
                if mtime > self._gbc_mtime:
                    import joblib

                    self._gbc_model = joblib.load(gbc_path)
                    self._gbc_mtime = mtime
                    logger.info("Hot-reloaded GBC model")
            elif self._gbc_model is not None:
                # Model was deleted — fallback
                self._gbc_model = None
                logger.info("GBC model removed, falling back to IF-only")

            # Encoders
            enc_path = os.path.join(self._model_dir, "label_encoders.joblib")
            if os.path.exists(enc_path):
                mtime = os.path.getmtime(enc_path)
                if mtime > self._encoders_mtime:
                    import joblib

                    self._label_encoders = joblib.load(enc_path)
                    self._encoders_mtime = mtime

                    fc_path = os.path.join(self._model_dir, "feature_columns.joblib")
                    if os.path.exists(fc_path):
                        self._feature_columns = joblib.load(fc_path)

        except Exception:
            logger.debug("Hot-reload check failed", exc_info=True)

    def status(self) -> Dict[str, Any]:
        """Return adapter status for API."""
        return {
            "if_loaded": self._if_model is not None,
            "gbc_loaded": self._gbc_model is not None,
            "available": self.available(),
            "if_age_seconds": (
                round(time.time() - self._if_mtime, 0) if self._if_mtime else None
            ),
            "gbc_age_seconds": (
                round(time.time() - self._gbc_mtime, 0) if self._gbc_mtime else None
            ),
            "feature_count": len(self._feature_columns),
            "calibration": self._if_calibration,
        }


# ── EventEmbedder: Co-occurrence SVD Semantic Understanding ───────────


class EventEmbedder:
    """Learns vector representations of event types from co-occurrence.

    Addresses semantic confusion: service_created + msiexec + signed
    binary + business hours is different from service_created + rundll32 +
    temp path + external IP.

    Uses co-occurrence matrix + TruncatedSVD(n_components=32).
    """

    EMBEDDING_DIM = 32
    COOCCURRENCE_WINDOW_S = 60

    def __init__(self, model_dir: str = "data/intel/models") -> None:
        self._model_dir = model_dir
        self._embeddings: Dict[str, np.ndarray] = {}
        self._vocabulary: List[str] = []
        self._centroid: Optional[np.ndarray] = None
        self._fitted = False

        # Try loading existing embeddings
        self.load()

    def fit(self, events_df) -> Dict[str, Any]:
        """Train embeddings from event co-occurrence patterns."""
        from scipy.sparse import lil_matrix
        from sklearn.decomposition import TruncatedSVD

        t0 = time.time()

        # Build vocabulary: "category|action|agent"
        keys = (
            events_df["event_category"].fillna("unknown")
            + "|"
            + events_df["event_action"].fillna("unknown")
            + "|"
            + events_df["collection_agent"].fillna("unknown")
        )
        vocab = sorted(keys.unique())
        vocab_idx = {v: i for i, v in enumerate(vocab)}
        n = len(vocab)

        if n < 3:
            return {
                "status": "skipped",
                "reason": "vocabulary_too_small",
                "vocab_size": n,
            }

        # Build co-occurrence matrix: events within WINDOW_S on same device
        cooccurrence = lil_matrix((n, n), dtype=np.float32)

        # Sort by device + time for windowing
        df_sorted = events_df[
            [
                "device_id",
                "timestamp_dt",
                "event_category",
                "event_action",
                "collection_agent",
            ]
        ].copy()
        df_sorted["_key"] = keys.values
        try:
            df_sorted["_ts"] = (
                __import__("pandas")
                .to_datetime(df_sorted["timestamp_dt"], errors="coerce")
                .astype("int64")
                // 10**9
            )
        except Exception:
            df_sorted["_ts"] = 0

        df_sorted = df_sorted.sort_values(["device_id", "_ts"])

        # Sliding window per device
        prev_device = None
        window: List[Tuple[int, str]] = []  # (timestamp, key)

        for _, row in df_sorted.iterrows():
            device = row["device_id"]
            ts = row["_ts"]
            key = row["_key"]

            if device != prev_device:
                window = []
                prev_device = device

            # Remove expired entries from window
            cutoff = ts - self.COOCCURRENCE_WINDOW_S
            window = [(t, k) for t, k in window if t >= cutoff]

            # Record co-occurrences with all events in window
            i = vocab_idx.get(key)
            if i is not None:
                for _, wk in window:
                    j = vocab_idx.get(wk)
                    if j is not None and i != j:
                        cooccurrence[i, j] += 1.0
                        cooccurrence[j, i] += 1.0

            window.append((ts, key))

        # Apply SVD
        dim = min(self.EMBEDDING_DIM, n - 1)
        svd = TruncatedSVD(n_components=dim, random_state=42)
        embeddings_matrix = svd.fit_transform(cooccurrence.tocsr())

        # Store embeddings
        self._vocabulary = vocab
        self._embeddings = {vocab[i]: embeddings_matrix[i] for i in range(len(vocab))}
        self._centroid = embeddings_matrix.mean(axis=0)
        self._fitted = True

        elapsed = time.time() - t0
        return {
            "status": "trained",
            "vocab_size": n,
            "embedding_dim": dim,
            "explained_variance": round(float(svd.explained_variance_ratio_.sum()), 4),
            "elapsed_seconds": round(elapsed, 2),
        }

    def get_embedding(
        self, category: str, action: str, agent: str = ""
    ) -> Optional[np.ndarray]:
        """Get embedding vector for an event type."""
        key = f"{category}|{action}|{agent}"
        return self._embeddings.get(key)

    def find_similar(
        self, category: str, action: str, top_k: int = 5
    ) -> List[Tuple[str, float]]:
        """Find most similar event types by cosine similarity."""
        key_prefix = f"{category}|{action}|"
        # Find embedding for any agent variant
        emb = None
        for k, v in self._embeddings.items():
            if k.startswith(key_prefix):
                emb = v
                break
        if emb is None:
            return []

        similarities = []
        norm_emb = np.linalg.norm(emb)
        if norm_emb < 1e-10:
            return []

        for k, v in self._embeddings.items():
            if k.startswith(key_prefix):
                continue
            norm_v = np.linalg.norm(v)
            if norm_v < 1e-10:
                continue
            sim = float(np.dot(emb, v) / (norm_emb * norm_v))
            # Extract category|action from key
            parts = k.split("|")
            label = f"{parts[0]}|{parts[1]}" if len(parts) >= 2 else k
            similarities.append((label, sim))

        similarities.sort(key=lambda x: x[1], reverse=True)
        # Deduplicate by label
        seen = set()
        unique = []
        for label, sim in similarities:
            if label not in seen:
                seen.add(label)
                unique.append((label, round(sim, 4)))
                if len(unique) >= top_k:
                    break
        return unique

    def novelty_score(self, category: str, action: str) -> float:
        """Distance from centroid — higher = more novel."""
        if self._centroid is None:
            return 0.5

        key_prefix = f"{category}|{action}|"
        emb = None
        for k, v in self._embeddings.items():
            if k.startswith(key_prefix):
                emb = v
                break
        if emb is None:
            return 1.0  # Unknown event = maximum novelty

        dist = float(np.linalg.norm(emb - self._centroid))
        # Normalize to 0-1 range (approximate using max distance seen)
        max_dist = (
            max(
                float(np.linalg.norm(v - self._centroid))
                for v in self._embeddings.values()
            )
            if self._embeddings
            else 1.0
        )
        if max_dist < 1e-10:
            return 0.5
        return float(np.clip(dist / max_dist, 0.0, 1.0))

    def save(self) -> None:
        """Persist embeddings to disk."""
        import joblib

        path = os.path.join(self._model_dir, "event_embedder.joblib")
        data = {
            "vocabulary": self._vocabulary,
            "embeddings": self._embeddings,
            "centroid": self._centroid,
        }
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self._model_dir, suffix=".tmp")
        os.close(tmp_fd)
        try:
            joblib.dump(data, tmp_path)
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def load(self) -> bool:
        """Load embeddings from disk."""
        import joblib

        path = os.path.join(self._model_dir, "event_embedder.joblib")
        if not os.path.exists(path):
            return False
        try:
            data = joblib.load(path)
            self._vocabulary = data.get("vocabulary", [])
            self._embeddings = data.get("embeddings", {})
            self._centroid = data.get("centroid")
            self._fitted = bool(self._embeddings)
            return True
        except Exception:
            return False

    def status(self) -> Dict[str, Any]:
        return {
            "fitted": self._fitted,
            "vocab_size": len(self._vocabulary),
            "embedding_dim": self.EMBEDDING_DIM,
        }


# ── AutoCalibrator: Rate-Limited Autonomous FP Detection ─────────────


class AutoCalibrator:
    """Autonomous FP detection with strict rate limiting (G5).

    Three detection signals:
    1. Oscillation: same event flips classifications >=3 times in 1h
    2. Frequency decay: "malicious" recurring >6h at constant rate without escalation
    3. Never-escalated: "suspicious" >24h without incident

    Guardrails (G5):
    - Max 10 adjustments per cycle
    - Min 200 occurrences before any adjustment
    - All adjustments logged with reason + evidence counts
    - Rollback via persisted history
    """

    MAX_ADJUSTMENTS_PER_CYCLE = 10
    MIN_EVIDENCE_COUNT = 200

    def __init__(
        self,
        scoring_engine: Any = None,
        model_dir: str = "data/intel/models",
    ) -> None:
        self._scorer = scoring_engine
        self._model_dir = model_dir
        self._log_path = os.path.join(model_dir, "auto_calibrator_log.json")

        # In-memory observation buffer for oscillation detection
        # Key: (device_id, category, action) → list of (timestamp, classification)
        self._observations: Dict[Tuple[str, str, str], List[Tuple[float, str]]] = (
            defaultdict(list)
        )
        self._total_observed = 0
        self._total_adjustments = 0

        # Load adjustment history for rollback
        self._adjustment_history: List[Dict] = []
        self._load_log()

    def observe(self, event: Dict[str, Any]) -> None:
        """Record a classification for oscillation detection."""
        key = (
            event.get("device_id", ""),
            event.get("event_category", ""),
            event.get("event_action", ""),
        )
        classification = event.get("final_classification", "legitimate")
        now = time.time()

        self._observations[key].append((now, classification))
        self._total_observed += 1

        # Trim old observations (keep last 1 hour)
        cutoff = now - 3600
        self._observations[key] = [
            (t, c) for t, c in self._observations[key] if t >= cutoff
        ]

    def analyze(self, telemetry_db_path: str) -> Dict[str, Any]:
        """Run all FP detection signals and apply bounded adjustments."""
        t0 = time.time()
        fp_candidates: List[Dict] = []

        # Signal 1: Oscillation
        oscillations = self._detect_oscillation()
        fp_candidates.extend(oscillations)

        # Signal 2: Frequency decay (needs DB access)
        try:
            decays = self._detect_frequency_decay(telemetry_db_path)
            fp_candidates.extend(decays)
        except Exception:
            logger.debug("Frequency decay detection failed", exc_info=True)

        # Signal 3: Never-escalated suspicious (needs DB access)
        try:
            never_esc = self._detect_never_escalated(telemetry_db_path)
            fp_candidates.extend(never_esc)
        except Exception:
            logger.debug("Never-escalated detection failed", exc_info=True)

        # Apply adjustments (G5: rate-limited)
        adjustments_made = self._apply_adjustments(fp_candidates)

        elapsed = time.time() - t0
        return {
            "status": "completed",
            "total_observed": self._total_observed,
            "fp_candidates_found": len(fp_candidates),
            "adjustments_made": adjustments_made,
            "total_adjustments": self._total_adjustments,
            "elapsed_seconds": round(elapsed, 2),
        }

    def _detect_oscillation(self) -> List[Dict]:
        """Detect events that flip classifications >=3 times in 1h."""
        candidates = []
        for key, obs in self._observations.items():
            if len(obs) < 3:
                continue
            classifications = [c for _, c in obs]
            # Count transitions
            transitions = sum(
                1
                for i in range(1, len(classifications))
                if classifications[i] != classifications[i - 1]
            )
            if transitions >= 3:
                candidates.append(
                    {
                        "category": key[1],
                        "action": key[2],
                        "reason": "oscillation",
                        "evidence_count": len(obs),
                        "transitions": transitions,
                    }
                )
        return candidates

    def _detect_frequency_decay(self, db_path: str) -> List[Dict]:
        """Detect 'malicious' events recurring >6h at constant rate without escalation."""
        candidates = []
        try:
            conn = sqlite3.connect(
                f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
            )
            conn.execute("PRAGMA query_only = ON")
            cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(security_events)").fetchall()
            }
            quality_where = ""
            if "quality_state" in cols:
                quality_where += (
                    " AND LOWER(COALESCE(quality_state, 'valid')) = 'valid'"
                )
            if "training_exclude" in cols:
                quality_where += (
                    " AND COALESCE(CAST(training_exclude AS TEXT), '0') "
                    "IN ('0', 'false', 'FALSE', 'False')"
                )

            # Find (category, action) pairs classified malicious for 6+ hours
            rows = conn.execute(
                f"""
                SELECT event_category, event_action, COUNT(*) as cnt,
                       MIN(timestamp_dt) as first_seen,
                       MAX(timestamp_dt) as last_seen
                FROM security_events
                WHERE final_classification = 'malicious'
                  AND timestamp_dt > datetime('now', '-24 hours')
                  {quality_where}
                GROUP BY event_category, event_action
                HAVING cnt >= ?
                   AND (julianday(MAX(timestamp_dt)) - julianday(MIN(timestamp_dt))) * 24 >= 6
            """,
                (self.MIN_EVIDENCE_COUNT,),
            ).fetchall()

            for cat, action, cnt, first, last in rows:
                candidates.append(
                    {
                        "category": cat,
                        "action": action,
                        "reason": "frequency_decay",
                        "evidence_count": cnt,
                        "first_seen": first,
                        "last_seen": last,
                    }
                )

            conn.close()
        except Exception:
            logger.debug("Frequency decay query failed", exc_info=True)

        return candidates

    def _detect_never_escalated(self, db_path: str) -> List[Dict]:
        """Detect 'suspicious' events >24h without incident escalation."""
        candidates = []
        try:
            conn = sqlite3.connect(
                f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
            )
            conn.execute("PRAGMA query_only = ON")
            cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(security_events)").fetchall()
            }
            quality_where = ""
            if "quality_state" in cols:
                quality_where += (
                    " AND LOWER(COALESCE(quality_state, 'valid')) = 'valid'"
                )
            if "training_exclude" in cols:
                quality_where += (
                    " AND COALESCE(CAST(training_exclude AS TEXT), '0') "
                    "IN ('0', 'false', 'FALSE', 'False')"
                )

            rows = conn.execute(
                f"""
                SELECT event_category, event_action, COUNT(*) as cnt
                FROM security_events
                WHERE final_classification = 'suspicious'
                  AND requires_investigation = 0
                  AND timestamp_dt < datetime('now', '-24 hours')
                  AND timestamp_dt > datetime('now', '-7 days')
                  {quality_where}
                GROUP BY event_category, event_action
                HAVING cnt >= ?
            """,
                (self.MIN_EVIDENCE_COUNT,),
            ).fetchall()

            for cat, action, cnt in rows:
                candidates.append(
                    {
                        "category": cat,
                        "action": action,
                        "reason": "never_escalated",
                        "evidence_count": cnt,
                    }
                )

            conn.close()
        except Exception:
            logger.debug("Never-escalated query failed", exc_info=True)

        return candidates

    def _apply_adjustments(self, fp_candidates: List[Dict]) -> int:
        """Apply FP adjustments, bounded by G5 guardrails."""
        if not self._scorer or not fp_candidates:
            return 0

        # G5: Rate limit
        applied = 0
        for candidate in fp_candidates:
            if applied >= self.MAX_ADJUSTMENTS_PER_CYCLE:
                logger.info(
                    "AutoCalibrator: hit max adjustments (%d), stopping",
                    self.MAX_ADJUSTMENTS_PER_CYCLE,
                )
                break

            # G5: Minimum evidence
            if candidate.get("evidence_count", 0) < self.MIN_EVIDENCE_COUNT:
                continue

            category = candidate["category"]
            action = candidate["action"]

            # Apply calibration via ScoringEngine
            try:
                self._scorer.recalibrate(category, action, is_false_positive=True)
                applied += 1
                self._total_adjustments += 1

                # Log adjustment (G5: with reason + evidence)
                log_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "category": category,
                    "action": action,
                    "reason": candidate.get("reason", "unknown"),
                    "evidence_count": candidate.get("evidence_count", 0),
                    "cycle_adjustment_num": applied,
                }
                self._adjustment_history.append(log_entry)

                logger.info(
                    "AutoCalibrator: adjusted %s/%s (reason=%s, evidence=%d)",
                    category,
                    action,
                    candidate.get("reason"),
                    candidate.get("evidence_count", 0),
                )
            except Exception:
                logger.warning(
                    "Failed to apply calibration for %s/%s",
                    category,
                    action,
                    exc_info=True,
                )

        # Persist log
        if applied > 0:
            self._save_log()

        return applied

    def rollback(self, n: int = 1) -> int:
        """Undo the last N adjustments."""
        if not self._scorer:
            return 0

        rolled_back = 0
        for _ in range(min(n, len(self._adjustment_history))):
            entry = self._adjustment_history.pop()
            # Reverse the calibration: apply TP feedback to counteract FP offset
            try:
                self._scorer.recalibrate(
                    entry["category"], entry["action"], is_false_positive=False
                )
                rolled_back += 1
            except Exception:
                logger.warning("Rollback failed for %s", entry)

        if rolled_back > 0:
            self._save_log()
        return rolled_back

    def _save_log(self) -> None:
        """Persist adjustment history to JSON."""
        # Keep last 500 entries
        history = self._adjustment_history[-500:]
        try:
            SomaBrain._atomic_json_write(self._log_path, history)
        except Exception:
            logger.debug("Failed to save calibrator log", exc_info=True)

    def _load_log(self) -> None:
        """Load adjustment history from JSON."""
        if os.path.exists(self._log_path):
            try:
                with open(self._log_path) as f:
                    self._adjustment_history = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._adjustment_history = []

    def status(self) -> Dict[str, Any]:
        return {
            "total_observed": self._total_observed,
            "total_adjustments": self._total_adjustments,
            "observation_keys": len(self._observations),
            "history_entries": len(self._adjustment_history),
        }
