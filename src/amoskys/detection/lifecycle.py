"""AMOSKYS Detection Rule Lifecycle — manage rules from creation to retirement.

Lifecycle stages:
    experimental → test → stable → deprecated → retired

Each rule tracks:
    - Creation date and author
    - Test results (true positives, false positives)
    - Deployment status
    - Performance metrics (fire count, FP rate, last match)
    - Tuning history

Usage:
    lifecycle = DetectionLifecycle(sigma_engine, yara_engine)
    result = lifecycle.validate_rule("path/to/rule.yml")
    metrics = lifecycle.get_metrics("amoskys-auth-001")
    report = lifecycle.coverage_report()
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yara  # noqa: F401

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of validating a detection rule."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    rule_id: str = ""
    rule_type: str = ""  # "sigma" | "yara"


@dataclass
class TestResult:
    """Result of testing a rule against fixtures."""

    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    total_fixtures: int = 0
    passed: bool = False
    details: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        """Precision: TP / (TP + FP)."""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall: TP / (TP + FN)."""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0


@dataclass
class RuleMetrics:
    """Runtime metrics for a deployed detection rule."""

    rule_id: str
    fire_count: int = 0
    false_positive_count: int = 0
    last_match_ns: int = 0
    fp_rate: float = 0.0
    status: str = "experimental"
    deployed_since_ns: int = 0

    @property
    def fp_percentage(self) -> float:
        """False positive rate as percentage."""
        if self.fire_count == 0:
            return 0.0
        return (self.false_positive_count / self.fire_count) * 100


@dataclass
class CoverageReport:
    """Combined MITRE ATT&CK coverage from all detection sources."""

    # Per-source coverage
    sigma_techniques: Dict[str, List[str]] = field(default_factory=dict)
    yara_techniques: Dict[str, List[str]] = field(default_factory=dict)
    probe_techniques: Dict[str, List[str]] = field(default_factory=dict)

    # Combined
    all_techniques: Dict[str, List[str]] = field(default_factory=dict)
    all_tactics: Dict[str, List[str]] = field(default_factory=dict)

    # Summary
    total_techniques_covered: int = 0
    total_sigma_rules: int = 0
    total_yara_rules: int = 0
    total_probes: int = 0

    # Gaps
    uncovered_techniques: List[str] = field(default_factory=list)


class DetectionLifecycle:
    """Manage detection rule lifecycle: validate → test → deploy → tune → retire.

    Integrates with SigmaEngine and YARAEngine to provide unified rule
    management and coverage reporting.
    """

    # All MITRE ATT&CK Enterprise techniques we aim to cover
    # (top-level, not sub-techniques — those are covered implicitly)
    TARGET_TECHNIQUES = [
        # Initial Access
        "T1190",
        "T1195",
        "T1566",
        # Execution
        "T1059",
        "T1106",
        "T1204",
        # Persistence
        "T1053",
        "T1136",
        "T1543",
        "T1547",
        # Privilege Escalation
        "T1548",
        "T1055",
        "T1068",
        # Defense Evasion
        "T1027",
        "T1036",
        "T1070",
        "T1140",
        "T1218",
        "T1562",
        # Credential Access
        "T1003",
        "T1110",
        "T1555",
        "T1557",
        # Discovery
        "T1016",
        "T1018",
        "T1046",
        "T1057",
        "T1082",
        "T1083",
        "T1087",
        # Lateral Movement
        "T1021",
        "T1072",
        "T1570",
        # Collection
        "T1005",
        "T1074",
        "T1113",
        # Command & Control
        "T1071",
        "T1090",
        "T1095",
        "T1105",
        "T1568",
        "T1571",
        "T1572",
        # Exfiltration
        "T1041",
        "T1048",
        "T1567",
        # Impact
        "T1485",
        "T1486",
        "T1496",
        "T1499",
    ]

    def __init__(
        self,
        sigma_engine: Optional[Any] = None,
        yara_engine: Optional[Any] = None,
    ) -> None:
        self._sigma = sigma_engine
        self._yara = yara_engine
        self._rule_metrics: Dict[str, RuleMetrics] = {}
        self._fp_reports: Dict[str, List[Dict[str, Any]]] = {}

    def validate_rule(self, rule_path: str) -> ValidationResult:
        """Validate a detection rule file.

        Checks:
            - File exists and is readable
            - Valid YAML/YARA syntax
            - Required fields present (id, title, detection)
            - MITRE tags are valid
            - Confidence is in [0, 1]
        """
        path = Path(rule_path)
        result = ValidationResult(is_valid=True, rule_type="unknown")

        if not path.is_file():
            result.is_valid = False
            result.errors.append(f"File not found: {rule_path}")
            return result

        suffix = path.suffix.lower()

        if suffix in (".yml", ".yaml"):
            return self._validate_sigma_rule(path)
        elif suffix in (".yar", ".yara"):
            return self._validate_yara_rule(path)
        else:
            result.is_valid = False
            result.errors.append(f"Unknown rule type: {suffix}")
            return result

    def test_rule(self, rule_path: str, fixtures: List[Dict[str, Any]]) -> TestResult:
        """Test a rule against test fixtures.

        Each fixture should have:
            - "event": Dict — the event to evaluate
            - "should_match": bool — whether the rule should fire
            - "description": str — test case description
        """
        path = Path(rule_path)
        rule_id = path.stem

        result = TestResult(
            rule_id=rule_id,
            total_fixtures=len(fixtures),
        )

        if not self._sigma:
            result.details.append("Sigma engine not configured")
            return result

        # Load the rule temporarily
        rule = None
        if path.suffix in (".yml", ".yaml"):
            rule = self._sigma.load_rule_from_string(path.read_text(), str(path))

        if not rule:
            result.details.append(f"Failed to load rule from {rule_path}")
            return result

        for fixture in fixtures:
            event = fixture.get("event", {})
            should_match = fixture.get("should_match", True)
            desc = fixture.get("description", "unnamed")

            matches = self._sigma.evaluate(event)
            did_match = any(m.rule_id == rule.id for m in matches)

            if should_match and did_match:
                result.true_positives += 1
            elif should_match and not did_match:
                result.false_negatives += 1
                result.details.append(f"MISS: {desc}")
            elif not should_match and did_match:
                result.false_positives += 1
                result.details.append(f"FP: {desc}")
            else:
                result.true_negatives += 1

        result.passed = result.false_positives == 0 and result.false_negatives == 0

        # Clean up temporary rule
        self._sigma.remove_rule(rule.id)

        return result

    def get_metrics(self, rule_id: str) -> RuleMetrics:
        """Get runtime metrics for a deployed rule."""
        if rule_id in self._rule_metrics:
            return self._rule_metrics[rule_id]

        # Try to get from engines
        metrics = RuleMetrics(rule_id=rule_id)

        if self._sigma:
            sigma_metrics = self._sigma.get_rule_metrics(rule_id)
            if sigma_metrics.get("exists"):
                metrics.fire_count = sigma_metrics.get("match_count", 0)
                metrics.last_match_ns = sigma_metrics.get("last_match_ns", 0)

        if self._yara:
            yara_metrics = self._yara.get_rule_metrics(rule_id)
            if yara_metrics.get("exists"):
                metrics.fire_count += yara_metrics.get("match_count", 0)
                metrics.last_match_ns = max(
                    metrics.last_match_ns,
                    yara_metrics.get("last_match_ns", 0),
                )

        # Apply FP data
        fp_count = len(self._fp_reports.get(rule_id, []))
        metrics.false_positive_count = fp_count
        if metrics.fire_count > 0:
            metrics.fp_rate = fp_count / metrics.fire_count

        return metrics

    def report_false_positive(self, rule_id: str, details: Dict[str, Any]) -> None:
        """Report a false positive for analyst feedback loop."""
        self._fp_reports.setdefault(rule_id, []).append(
            {
                "timestamp_ns": int(time.time() * 1e9),
                **details,
            }
        )
        logger.info("FP reported for rule %s: %s", rule_id, details.get("reason", ""))

    def coverage_report(self) -> CoverageReport:
        """Generate combined MITRE ATT&CK coverage report."""
        report = CoverageReport()

        # Sigma coverage
        if self._sigma:
            sigma_cov = self._sigma.get_coverage()
            report.sigma_techniques = sigma_cov.technique_to_rules
            report.total_sigma_rules = sigma_cov.total_rules

        # YARA coverage
        if self._yara:
            yara_cov = self._yara.get_coverage()
            report.yara_techniques = yara_cov.technique_to_rules
            report.total_yara_rules = yara_cov.total_rules

        # Combine all sources
        all_techs: Dict[str, List[str]] = {}

        for tech, rules in report.sigma_techniques.items():
            all_techs.setdefault(tech, []).extend(f"sigma:{r}" for r in rules)

        for tech, rules in report.yara_techniques.items():
            all_techs.setdefault(tech, []).extend(f"yara:{r}" for r in rules)

        for tech, rules in report.probe_techniques.items():
            all_techs.setdefault(tech, []).extend(f"probe:{r}" for r in rules)

        report.all_techniques = all_techs
        report.total_techniques_covered = len(all_techs)

        # Identify gaps
        covered = set()
        for tech in all_techs:
            # Match both exact and parent technique
            covered.add(tech)
            if "." in tech:
                covered.add(tech.split(".")[0])

        report.uncovered_techniques = [
            t for t in self.TARGET_TECHNIQUES if t not in covered
        ]

        return report

    # ── Internal Validation ──────────────────────────────────────────────

    def _validate_sigma_rule(self, path: Path) -> ValidationResult:
        """Validate a Sigma YAML rule."""
        result = ValidationResult(is_valid=True, rule_type="sigma")

        try:
            import yaml

            with open(path) as f:
                data = yaml.safe_load(f)
        except ImportError:
            result.is_valid = False
            result.errors.append("PyYAML not installed")
            return result
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"YAML parse error: {e}")
            return result

        if not isinstance(data, dict):
            result.is_valid = False
            result.errors.append("Root element must be a mapping")
            return result

        # Required fields
        for field_name in ("id", "title", "detection"):
            if field_name not in data:
                result.is_valid = False
                result.errors.append(f"Missing required field: {field_name}")

        result.rule_id = data.get("id", "")

        # Detection must have condition
        detection = data.get("detection", {})
        if isinstance(detection, dict) and "condition" not in detection:
            result.warnings.append("Detection block missing 'condition'")

        # Validate MITRE tags
        tags = data.get("tags", [])
        for tag in tags:
            if str(tag).startswith("attack.") and not (
                str(tag).startswith("attack.t")
                or str(tag).startswith("attack.initial")
                or str(tag).startswith("attack.execution")
                or str(tag).startswith("attack.persistence")
                or str(tag).startswith("attack.privilege")
                or str(tag).startswith("attack.defense")
                or str(tag).startswith("attack.credential")
                or str(tag).startswith("attack.discovery")
                or str(tag).startswith("attack.lateral")
                or str(tag).startswith("attack.collection")
                or str(tag).startswith("attack.command")
                or str(tag).startswith("attack.exfiltration")
                or str(tag).startswith("attack.impact")
                or str(tag).startswith("attack.resource")
                or str(tag).startswith("attack.reconnaissance")
            ):
                result.warnings.append(f"Unknown MITRE tag: {tag}")

        # Validate confidence
        confidence = data.get("confidence")
        if confidence is not None:
            try:
                c = float(confidence)
                if not 0 <= c <= 1:
                    result.warnings.append(f"Confidence {c} outside [0, 1]")
            except (ValueError, TypeError):
                result.warnings.append(f"Invalid confidence value: {confidence}")

        # Validate level
        valid_levels = {"informational", "low", "medium", "high", "critical"}
        level = data.get("level", "medium")
        if level not in valid_levels:
            result.warnings.append(f"Unknown level: {level}")

        return result

    def _validate_yara_rule(self, path: Path) -> ValidationResult:
        """Validate a YARA rule file."""
        result = ValidationResult(is_valid=True, rule_type="yara")

        try:
            content = path.read_text()
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Cannot read file: {e}")
            return result

        # Basic structure check
        if "rule " not in content:
            result.is_valid = False
            result.errors.append("No 'rule' keyword found")

        if "condition:" not in content:
            result.is_valid = False
            result.errors.append("No 'condition:' block found")

        # Try to compile if yara-python available
        if YARA_AVAILABLE:
            try:
                yara.compile(source=content)
            except Exception as e:
                result.is_valid = False
                result.errors.append(f"YARA compilation error: {e}")

        return result
