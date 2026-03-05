"""AMOSKYS Red-Team Contract Framework.

Every probe in AMOSKYS ships with a mandatory red-team contract:
  1. probe_spec.yaml — machine-readable manifest
  2. Unit tests      — all logic paths, thresholds, FP cases
  3. Red-team harness — 3 positive attacks + 3 evasions + 2 benign per probe
  4. Evidence story  — structured artifact for each scenario run

CLI usage:
  amoskys-redteam run credential_dump --report
  amoskys-redteam list
  amoskys-redteam show credential_dump
"""

from amoskys.redteam.harness import (
    AdversarialCase,
    CaseResult,
    RedTeamHarness,
    Scenario,
    ScenarioResult,
)
from amoskys.redteam.report_builder import AttackStory, IncidentEvidence, ReportBuilder

__all__ = [
    "AdversarialCase",
    "AttackStory",
    "CaseResult",
    "IncidentEvidence",
    "RedTeamHarness",
    "ReportBuilder",
    "Scenario",
    "ScenarioResult",
]
