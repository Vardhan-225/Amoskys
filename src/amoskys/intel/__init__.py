"""
Intelligence and Correlation Layer

Transforms raw telemetry events from multiple agents into actionable
security intelligence through correlation and fusion.

Components:
- FusionEngine: Correlation orchestrator
- Incident: Attack chain representation
- DeviceRiskSnapshot: Security posture scoring
- Correlation Rules: Hand-written detection logic

Usage:
    from amoskys.intel import FusionEngine

    engine = FusionEngine(db_path="data/intel/fusion.db")
    engine.run_once()  # Single evaluation pass
    # or
    engine.run()  # Continuous evaluation loop
"""

from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.ingest import TelemetryIngestor
from amoskys.intel.models import (
    DeviceRiskSnapshot,
    Incident,
    TelemetryEventView,
    RiskLevel,
    Severity,
    MitreTactic,
)
from amoskys.intel.rules import evaluate_rules, ALL_RULES

__all__ = [
    "FusionEngine",
    "TelemetryIngestor",
    "DeviceRiskSnapshot",
    "Incident",
    "TelemetryEventView",
    "RiskLevel",
    "Severity",
    "MitreTactic",
    "evaluate_rules",
    "ALL_RULES",
]
