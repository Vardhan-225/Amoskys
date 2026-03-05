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

from amoskys.intel.explanation import AgentExplainer, EventExplainer, IncidentExplainer
from amoskys.intel.fusion_engine import FusionEngine
from amoskys.intel.ingest import TelemetryIngestor
from amoskys.intel.models import (
    DeviceRiskSnapshot,
    Incident,
    MitreTactic,
    RiskLevel,
    Severity,
    TelemetryEventView,
    ThreatLevel,
)
from amoskys.intel.rules import ALL_RULES, evaluate_rules
from amoskys.intel.scoring import ScoringEngine
from amoskys.intel.soma_brain import (
    AutoCalibrator,
    EventEmbedder,
    ModelScorerAdapter,
    SomaBrain,
)

__all__ = [
    "FusionEngine",
    "TelemetryIngestor",
    "ScoringEngine",
    "SomaBrain",
    "ModelScorerAdapter",
    "EventEmbedder",
    "AutoCalibrator",
    "EventExplainer",
    "IncidentExplainer",
    "AgentExplainer",
    "DeviceRiskSnapshot",
    "Incident",
    "TelemetryEventView",
    "RiskLevel",
    "Severity",
    "MitreTactic",
    "ThreatLevel",
    "evaluate_rules",
    "ALL_RULES",
]
