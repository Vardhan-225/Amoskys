"""AMOSKYS Red-Team Scenarios registry.

Each module in this package defines one or more Scenario objects.
The CLI discovers scenarios via SCENARIO_REGISTRY.

To add a new scenario:
  1. Create scenarios/<probe_id>.py
  2. Define a Scenario object
  3. Register it: SCENARIO_REGISTRY["<name>"] = <scenario>
"""

from __future__ import annotations

from typing import Dict

from amoskys.redteam.harness import Scenario

SCENARIO_REGISTRY: Dict[str, Scenario] = {}


def register(scenario: Scenario) -> Scenario:
    """Register a scenario in the global registry."""
    SCENARIO_REGISTRY[scenario.name] = scenario
    return scenario


def _load_all() -> None:
    """Eagerly import all scenario modules to populate the registry."""
    from amoskys.redteam.scenarios import credential_dump  # noqa: F401
    from amoskys.redteam.scenarios import kernel_audit_probes  # noqa: F401
    from amoskys.redteam.scenarios import auth_probes  # noqa: F401
    from amoskys.redteam.scenarios import proc_probes  # noqa: F401
    from amoskys.redteam.scenarios import attacker_touched_the_box  # noqa: F401


__all__ = ["SCENARIO_REGISTRY", "register"]
