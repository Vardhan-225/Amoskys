"""AMOSKYS Detection-as-Code Framework.

Provides Sigma and YARA rule evaluation against AMOSKYS telemetry events.
Rules are stored in `detection/rules/sigma/` and `detection/rules/yara/`
organized by MITRE ATT&CK tactic.

Components:
    SigmaEngine    — Evaluate Sigma YAML rules against TelemetryEvents
    YARAEngine     — YARA rule scanning for file/memory detection
    DetectionLifecycle — Rule lifecycle: create → test → deploy → tune → retire
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from amoskys.detection.sigma_engine import SigmaEngine  # noqa: F401
from amoskys.detection.yara_engine import YARA_AVAILABLE, YARAEngine  # noqa: F401

logger = logging.getLogger(__name__)

_YARA_RULES_DIR = Path(__file__).parent / "rules" / "yara"

_yara_engine: Optional[YARAEngine] = None
_yara_engine_built = False


def get_yara_engine() -> Optional[YARAEngine]:
    """Return the process-wide YARAEngine, building it on first access.

    Returns None only if construction itself failed; a missing yara-python
    still yields a live engine in metadata-only mode.
    """
    global _yara_engine, _yara_engine_built
    if not _yara_engine_built:
        _yara_engine_built = True
        _yara_engine = _build_yara_engine()
    return _yara_engine


def _build_yara_engine() -> Optional[YARAEngine]:
    """Construct the YARA engine and load rules/, mirroring the SigmaEngine
    init in analyzer_main. Never raises — the analyzer must survive a broken
    or absent YARA install."""
    try:
        engine = YARAEngine()
        engine.load_rules(str(_YARA_RULES_DIR))
        if engine.can_scan:
            logger.info(
                "YARAEngine initialized — %d rules loaded, %d techniques covered",
                engine.rule_count,
                len(engine.get_coverage().technique_to_rules),
            )
        else:
            # Not fatal, but it must be loud: without yara-python every
            # scan_file()/scan_data() call returns [] silently, so the 8
            # macos_threats rules are metadata only. Measured on this host:
            # `import yara` → ModuleNotFoundError, can_scan False.
            logger.warning(
                "YARAEngine in metadata-only mode (%d rules, scanning disabled)"
                " — %s",
                engine.rule_count,
                (
                    "yara-python not installed"
                    if not YARA_AVAILABLE
                    else "rule compilation failed"
                ),
            )
        return engine
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("YARAEngine not available: %s", e)
        return None


# Build at package import. Before this the class was never instantiated
# anywhere in the tree (grep: only its own module and this file), so the YARA
# rules were never parsed and never compiled — 8 rules of dead detection.
# Importing amoskys.detection.sigma_engine (as analyzer_main does) runs this.
get_yara_engine()

__all__ = ["SigmaEngine", "YARAEngine", "get_yara_engine"]
