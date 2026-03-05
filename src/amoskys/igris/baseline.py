"""
IGRIS Baseline Tracker

Learns normal system behavior via Exponential Moving Average.
Detects deviations using hybrid rules: statistical σ + hard thresholds.
Slow learner by design — IGRIS does not overreact.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

from .signals import IgrisSignal, SignalType

logger = logging.getLogger("igris.baseline")

# Resolve project root from this file's location (src/amoskys/igris/baseline.py)
_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
_DEFAULT_BASELINES_PATH = os.path.join(_PROJECT_ROOT, "data", "igris", "baselines.json")

# EMA smoothing factor: 0.1 = slow, stable learning
ALPHA = 0.1

# Warmup period: no signals during first N observations
WARMUP_CYCLES = 10

# ── Hard threshold rules ─────────────────────────────────────────
# Format: metric_pattern -> (warn_fn, crit_fn, signal_type, subsystem)
# Functions take (value, baseline_state) and return severity or None

HARD_RULES: dict[str, tuple] = {
    "fleet.offline": (
        lambda v, _: "medium" if v and v > 0 else None,
        lambda v, _: "critical" if v and v > 2 else None,
        SignalType.STABILITY_WARNING,
        "fleet",
    ),
    "fleet.agents_with_errors": (
        lambda v, _: "medium" if v and v > 0 else None,
        lambda v, _: "high" if v and v > 3 else None,
        SignalType.STABILITY_WARNING,
        "fleet",
    ),
    "transport.eventbus_alive": (
        None,
        lambda v, _: "critical" if v is False else None,
        SignalType.STABILITY_WARNING,
        "transport",
    ),
    "transport.wal_queue_depth": (
        lambda v, _: "medium" if v and v > 1000 else None,
        lambda v, _: "critical" if v and v > 5000 else None,
        SignalType.TRANSPORT_BACKPRESSURE,
        "transport",
    ),
    "transport.dead_letter_depth": (
        lambda v, _: "medium" if v and v > 100 else None,
        lambda v, _: "critical" if v and v > 500 else None,
        SignalType.INTEGRITY_WARNING,
        "transport",
    ),
    "ingestion.freshness_seconds": (
        lambda v, _: "medium" if v and v > 300 else None,
        lambda v, _: "high" if v and v > 600 else None,
        SignalType.STABILITY_WARNING,
        "ingestion",
    ),
    "amrdr.min_weight": (
        lambda v, _: "medium" if v is not None and v < 0.7 else None,
        lambda v, _: "high" if v is not None and v < 0.5 else None,
        SignalType.DRIFT_WARNING,
        "amrdr",
    ),
    "amrdr.quarantined_count": (
        lambda v, _: "high" if v and v > 0 else None,
        lambda v, _: "critical" if v and v > 1 else None,
        SignalType.DRIFT_WARNING,
        "amrdr",
    ),
    "amrdr.drifting_count": (
        lambda v, _: "medium" if v and v > 0 else None,
        lambda v, _: "high" if v and v > 2 else None,
        SignalType.DRIFT_WARNING,
        "amrdr",
    ),
    "soma.model_age_hours": (
        lambda v, _: "medium" if v is not None and v > 2 else None,
        lambda v, _: "high" if v is not None and v > 4 else None,
        SignalType.MODEL_STALENESS,
        "soma",
    ),
    "soma.last_train_age_hours": (
        lambda v, _: "medium" if v is not None and v > 1 else None,
        lambda v, _: "high" if v is not None and v > 2 else None,
        SignalType.MODEL_STALENESS,
        "soma",
    ),
    "enrichment.available_count": (
        lambda v, _: "medium" if v is not None and v < 4 else None,
        lambda v, _: "high" if v is not None and v < 2 else None,
        SignalType.SUPERVISION_DEFICIT,
        "enrichment",
    ),
    # ── Integrity rules (IGRIS Auditor) ──
    "integrity.dead_letter_last_hour": (
        lambda v, _: "medium" if v and v > 0 else None,
        lambda v, _: "high" if v and v > 10 else None,
        SignalType.INTEGRITY_WARNING,
        "integrity",
    ),
    "integrity.schema_complete": (
        None,
        lambda v, _: "high" if v is False else None,
        SignalType.INTEGRITY_WARNING,
        "integrity",
    ),
}

# ── Statistical rules ────────────────────────────────────────────
# Metrics that use σ-based deviation detection
# Format: metric_pattern -> (warn_sigma, crit_sigma, direction, signal_type, subsystem)
# direction: "high" = only alert on increases, "both" = alert on either direction

SIGMA_RULES: dict[str, tuple] = {
    "transport.wal_queue_depth": (
        2.5,
        3.5,
        "high",
        SignalType.TRANSPORT_BACKPRESSURE,
        "transport",
    ),
    "transport.dead_letter_depth": (
        2.0,
        3.0,
        "high",
        SignalType.INTEGRITY_WARNING,
        "transport",
    ),
    "ingestion.events_last_hour": (
        2.5,
        3.5,
        "both",
        SignalType.STABILITY_WARNING,
        "ingestion",
    ),
    "ingestion.events_last_5min": (
        2.5,
        3.5,
        "both",
        SignalType.STABILITY_WARNING,
        "ingestion",
    ),
    "intelligence.incidents_1h": (
        3.0,
        4.0,
        "high",
        SignalType.STABILITY_WARNING,
        "intelligence",
    ),
}

# Message templates
MESSAGES = {
    SignalType.STABILITY_WARNING: "{metric} at {value} (baseline {baseline}) — system stability concern",
    SignalType.DRIFT_WARNING: "{metric} at {value} (baseline {baseline}) — agent reliability drift",
    SignalType.INTEGRITY_WARNING: "{metric} at {value} (baseline {baseline}) — data integrity concern",
    SignalType.SUPERVISION_DEFICIT: "{metric} at {value} (baseline {baseline}) — supervision gap",
    SignalType.MODEL_STALENESS: "{metric} at {value} (baseline {baseline}) — model freshness concern",
    SignalType.TRANSPORT_BACKPRESSURE: "{metric} at {value} (baseline {baseline}) — transport pressure",
}


class BaselineTracker:
    """EMA-based baseline learning with hybrid deviation detection."""

    def __init__(self, data_dir: str | None = None):
        self._baselines: dict[str, dict] = {}
        self._baselines_path = (
            os.path.join(data_dir, "baselines.json")
            if data_dir
            else _DEFAULT_BASELINES_PATH
        )

    def evaluate(self, metrics: dict[str, Any]) -> list[IgrisSignal]:
        """Evaluate all metrics against baselines. Return signals for deviations."""
        signals = []

        for metric_name, value in metrics.items():
            # Skip non-numeric and nested dict metrics
            if value is None:
                continue
            if isinstance(value, dict):
                continue
            if isinstance(value, bool):
                # Handle boolean metrics via hard rules only
                self._check_hard_rules(metric_name, value, signals)
                continue
            if not isinstance(value, (int, float)):
                continue

            # Update EMA baseline
            state = self._update_ema(metric_name, float(value))

            # Check hard threshold rules
            self._check_hard_rules(metric_name, value, signals)

            # Check statistical deviation rules (only after warmup)
            if state["sample_count"] >= WARMUP_CYCLES:
                self._check_sigma_rules(metric_name, float(value), state, signals)

        return signals

    def _update_ema(self, metric_name: str, value: float) -> dict:
        """Update EMA for a metric. Returns the baseline state."""
        if metric_name not in self._baselines:
            self._baselines[metric_name] = {
                "ema": value,
                "ema_dev": 0.0,
                "min_seen": value,
                "max_seen": value,
                "sample_count": 0,
            }

        state = self._baselines[metric_name]
        state["sample_count"] += 1

        if state["sample_count"] <= 1:
            state["ema"] = value
            state["ema_dev"] = 0.0
        else:
            deviation = abs(value - state["ema"])
            state["ema"] = ALPHA * value + (1 - ALPHA) * state["ema"]
            state["ema_dev"] = ALPHA * deviation + (1 - ALPHA) * state["ema_dev"]

        state["min_seen"] = min(state["min_seen"], value)
        state["max_seen"] = max(state["max_seen"], value)

        return state

    def _check_hard_rules(self, metric_name: str, value: Any, signals: list) -> None:
        """Check hard threshold rules for a metric."""
        rule = HARD_RULES.get(metric_name)
        if not rule:
            return

        warn_fn, crit_fn, signal_type, subsystem = rule
        state = self._baselines.get(metric_name, {})
        ema = state.get("ema", 0)

        # Check critical first
        if crit_fn:
            severity = crit_fn(value, state)
            if severity:
                signals.append(
                    IgrisSignal(
                        signal_type=signal_type,
                        severity=severity,
                        metric_name=metric_name,
                        baseline_value=round(ema, 2) if isinstance(ema, float) else 0,
                        current_value=(
                            float(value) if isinstance(value, (int, float)) else 0
                        ),
                        deviation_sigma=0,
                        confidence=0.95,
                        subsystem=subsystem,
                        message=MESSAGES[signal_type].format(
                            metric=metric_name,
                            value=value,
                            baseline=round(ema, 2) if isinstance(ema, float) else 0,
                        ),
                    )
                )
                return  # Don't also emit warning

        if warn_fn:
            severity = warn_fn(value, state)
            if severity:
                signals.append(
                    IgrisSignal(
                        signal_type=signal_type,
                        severity=severity,
                        metric_name=metric_name,
                        baseline_value=round(ema, 2) if isinstance(ema, float) else 0,
                        current_value=(
                            float(value) if isinstance(value, (int, float)) else 0
                        ),
                        deviation_sigma=0,
                        confidence=0.85,
                        subsystem=subsystem,
                        message=MESSAGES[signal_type].format(
                            metric=metric_name,
                            value=value,
                            baseline=round(ema, 2) if isinstance(ema, float) else 0,
                        ),
                    )
                )

    def _check_sigma_rules(
        self, metric_name: str, value: float, state: dict, signals: list
    ) -> None:
        """Check statistical σ-deviation rules for a metric."""
        rule = SIGMA_RULES.get(metric_name)
        if not rule:
            return

        warn_sigma, crit_sigma, direction, signal_type, subsystem = rule
        ema = state["ema"]
        ema_dev = state["ema_dev"]

        if ema_dev < 1e-6:
            return  # Not enough variance to detect deviations

        sigma = abs(value - ema) / ema_dev

        # Direction check
        if direction == "high" and value <= ema:
            return
        # "both" alerts on either direction

        severity = None
        if sigma >= crit_sigma:
            severity = "high"
        elif sigma >= warn_sigma:
            severity = "medium"

        if severity:
            signals.append(
                IgrisSignal(
                    signal_type=signal_type,
                    severity=severity,
                    metric_name=metric_name,
                    baseline_value=round(ema, 2),
                    current_value=round(value, 2),
                    deviation_sigma=round(sigma, 2),
                    confidence=min(0.99, 0.7 + sigma * 0.05),
                    subsystem=subsystem,
                    message=f"{metric_name} at {round(value, 1)} — {round(sigma, 1)}σ from baseline {round(ema, 1)}",
                    evidence=[
                        {
                            "ema": round(ema, 2),
                            "ema_dev": round(ema_dev, 2),
                            "sigma": round(sigma, 2),
                            "samples": state["sample_count"],
                        }
                    ],
                )
            )

    def get_baselines(self) -> dict[str, dict]:
        """Return all current baselines for inspection."""
        result = {}
        for name, state in self._baselines.items():
            result[name] = {
                "ema": round(state["ema"], 3),
                "ema_dev": round(state["ema_dev"], 3),
                "min_seen": (
                    round(state["min_seen"], 3)
                    if isinstance(state["min_seen"], float)
                    else state["min_seen"]
                ),
                "max_seen": (
                    round(state["max_seen"], 3)
                    if isinstance(state["max_seen"], float)
                    else state["max_seen"]
                ),
                "sample_count": state["sample_count"],
            }
        return result

    def reset(self) -> None:
        """Clear all baselines. IGRIS re-enters warmup."""
        self._baselines.clear()

    def save(self, path: str | None = None) -> None:
        """Persist baselines to disk."""
        path = path or self._baselines_path
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump(self._baselines, f, indent=2, default=str)
        except OSError as e:
            logger.debug("Failed to save baselines: %s", e)

    def load(self, path: str | None = None) -> None:
        """Load baselines from disk."""
        path = path or self._baselines_path
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                self._baselines = loaded
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Failed to load baselines: %s", e)
