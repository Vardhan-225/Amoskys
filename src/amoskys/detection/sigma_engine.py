"""AMOSKYS Sigma Rule Engine — evaluate Sigma YAML rules against telemetry events.

The Sigma format is an open standard for describing log-based detections.
AMOSKYS extends it with:
    - Direct mapping to TelemetryEvent fields
    - Probe integration (rules reference which probes produce matching events)
    - Confidence scoring from rule metadata
    - MITRE ATT&CK coverage reporting

Rule format (YAML):
    title: SSH Brute Force Detection
    id: amoskys-auth-001
    status: stable
    level: high
    description: Detects 5+ SSH login failures from the same source IP
    author: AMOSKYS
    references:
        - https://attack.mitre.org/techniques/T1110/001/
    tags:
        - attack.credential_access
        - attack.t1110.001
    logsource:
        category: authentication
        product: amoskys
    detection:
        selection:
            event_type: ssh_login_failure
        condition: selection | count(source_ip) >= 5
        timeframe: 5m
    fields:
        - source_ip
        - username
        - pid
    falsepositives:
        - Automated SSH key rotation systems
        - CI/CD pipelines with misconfigured credentials
    confidence: 0.85

Usage:
    engine = SigmaEngine()
    loaded = engine.load_rules("src/amoskys/detection/rules/sigma/")
    matches = engine.evaluate(telemetry_event)
    coverage = engine.get_coverage()
"""

from __future__ import annotations

import fnmatch
import logging
import operator
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.warning("PyYAML not installed — Sigma engine will not function")


# ── Data Models ──────────────────────────────────────────────────────────────


@dataclass
class SigmaRule:
    """Parsed Sigma detection rule."""

    id: str
    title: str
    description: str = ""
    status: str = "experimental"  # experimental | test | stable | deprecated
    level: str = "medium"  # informational | low | medium | high | critical
    author: str = ""
    references: List[str] = field(default_factory=list)

    # MITRE ATT&CK tags
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)

    # Log source
    logsource_category: str = ""
    logsource_product: str = "amoskys"

    # Detection logic
    detection: Dict[str, Any] = field(default_factory=dict)
    condition: str = ""
    timeframe: str = ""

    # Output fields
    output_fields: List[str] = field(default_factory=list)

    # Metadata
    falsepositives: List[str] = field(default_factory=list)
    confidence: float = 0.7
    file_path: str = ""

    # Compiled detection (internal)
    _matchers: List[Callable] = field(default_factory=list, repr=False)


@dataclass
class SigmaMatch:
    """Result of a Sigma rule matching against an event."""

    rule_id: str
    rule_title: str
    level: str
    confidence: float
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    matched_fields: Dict[str, Any]
    timestamp_ns: int
    event_type: str


@dataclass
class RuleCoverage:
    """MITRE coverage report for loaded rules."""

    technique_to_rules: Dict[str, List[str]]  # T1234 → [rule_id, ...]
    tactic_to_rules: Dict[str, List[str]]  # credential_access → [rule_id, ...]
    total_rules: int
    total_techniques: int
    total_tactics: int


# ── Sigma Engine ─────────────────────────────────────────────────────────────


class SigmaEngine:
    """Evaluate Sigma YAML rules against AMOSKYS telemetry events.

    The engine loads rules from YAML files, compiles detection logic into
    callable matchers, and evaluates incoming events against all loaded rules.
    """

    # Default rules directory relative to this file
    _DEFAULT_RULES_DIR = str(Path(__file__).parent / "rules" / "sigma")

    def __init__(
        self, rules_dir: Optional[str] = None, *, auto_load: bool = True
    ) -> None:
        self._rules: Dict[str, SigmaRule] = {}  # rule_id → SigmaRule
        self._rules_by_category: Dict[str, List[SigmaRule]] = {}
        self._match_count: Dict[str, int] = {}  # rule_id → match count
        self._last_match: Dict[str, int] = {}  # rule_id → last match timestamp_ns

        # Aggregation state for timeframe-based conditions
        self._agg_buffers: Dict[str, List[Dict[str, Any]]] = {}

        if auto_load:
            load_path = rules_dir or self._DEFAULT_RULES_DIR
            if Path(load_path).is_dir():
                self.load_rules(load_path)

    @property
    def rule_count(self) -> int:
        """Number of loaded rules."""
        return len(self._rules)

    def load_rules(self, rules_dir: str) -> int:
        """Load all .yml/.yaml Sigma rules from directory (recursive).

        Args:
            rules_dir: Path to directory containing Sigma YAML rules.

        Returns:
            Number of rules successfully loaded.
        """
        if not YAML_AVAILABLE:
            logger.error("PyYAML not installed — cannot load Sigma rules")
            return 0

        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            logger.error("Rules directory not found: %s", rules_dir)
            return 0

        loaded = 0
        errors = 0

        for yaml_file in sorted(rules_path.rglob("*.y*ml")):
            if yaml_file.suffix not in (".yml", ".yaml"):
                continue
            try:
                rule = self._parse_rule(yaml_file)
                if rule:
                    self._rules[rule.id] = rule
                    category = rule.logsource_category or "uncategorized"
                    self._rules_by_category.setdefault(category, []).append(rule)
                    self._match_count[rule.id] = 0
                    loaded += 1
            except Exception as e:
                logger.warning("Failed to parse %s: %s", yaml_file.name, e)
                errors += 1

        logger.info(
            "Sigma engine: loaded %d rules (%d errors) from %s",
            loaded,
            errors,
            rules_dir,
        )
        return loaded

    def load_rule_from_string(
        self, yaml_content: str, source: str = "<string>"
    ) -> Optional[SigmaRule]:
        """Load a single rule from a YAML string.

        Useful for testing and dynamic rule injection.
        """
        if not YAML_AVAILABLE:
            return None
        try:
            data = yaml.safe_load(yaml_content)
            if not data or not isinstance(data, dict):
                return None
            rule = self._build_rule(data, source)
            if rule:
                self._rules[rule.id] = rule
                category = rule.logsource_category or "uncategorized"
                self._rules_by_category.setdefault(category, []).append(rule)
                self._match_count[rule.id] = 0
            return rule
        except Exception as e:
            logger.warning("Failed to parse rule from string: %s", e)
            return None

    def evaluate(self, event: Any) -> List[SigmaMatch]:
        """Evaluate an event against all loaded rules.

        Args:
            event: A TelemetryEvent (or dict-like object with event_type,
                   data, severity, etc.)

        Returns:
            List of SigmaMatch for rules that matched.
        """
        matches: List[SigmaMatch] = []

        # Normalize event to dict
        event_dict = self._event_to_dict(event)
        if not event_dict:
            return matches

        event_type = event_dict.get("event_type", "")
        category = event_dict.get("category", "")

        # Check against all rules (category filtering for performance)
        candidate_rules = list(self._rules.values())

        for rule in candidate_rules:
            if self._rule_matches(rule, event_dict):
                match = SigmaMatch(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    confidence=rule.confidence,
                    mitre_techniques=rule.mitre_techniques,
                    mitre_tactics=rule.mitre_tactics,
                    matched_fields={
                        f: event_dict.get(f, event_dict.get("data", {}).get(f))
                        for f in rule.output_fields
                        if event_dict.get(f) is not None
                        or (
                            isinstance(event_dict.get("data"), dict)
                            and f in event_dict["data"]
                        )
                    },
                    timestamp_ns=event_dict.get("timestamp_ns", int(time.time() * 1e9)),
                    event_type=event_type,
                )
                matches.append(match)

                self._match_count[rule.id] = self._match_count.get(rule.id, 0) + 1
                self._last_match[rule.id] = match.timestamp_ns

        return matches

    def get_coverage(self) -> RuleCoverage:
        """Generate MITRE ATT&CK coverage report from loaded rules.

        Returns:
            RuleCoverage with technique→rules and tactic→rules mappings.
        """
        technique_to_rules: Dict[str, List[str]] = {}
        tactic_to_rules: Dict[str, List[str]] = {}

        for rule in self._rules.values():
            for tech in rule.mitre_techniques:
                technique_to_rules.setdefault(tech, []).append(rule.id)
            for tactic in rule.mitre_tactics:
                tactic_to_rules.setdefault(tactic, []).append(rule.id)

        return RuleCoverage(
            technique_to_rules=technique_to_rules,
            tactic_to_rules=tactic_to_rules,
            total_rules=len(self._rules),
            total_techniques=len(technique_to_rules),
            total_tactics=len(tactic_to_rules),
        )

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    def get_rule_metrics(self, rule_id: str) -> Dict[str, Any]:
        """Get match metrics for a specific rule."""
        return {
            "rule_id": rule_id,
            "match_count": self._match_count.get(rule_id, 0),
            "last_match_ns": self._last_match.get(rule_id, 0),
            "exists": rule_id in self._rules,
        }

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the engine."""
        if rule_id not in self._rules:
            return False
        rule = self._rules.pop(rule_id)
        category = rule.logsource_category or "uncategorized"
        if category in self._rules_by_category:
            self._rules_by_category[category] = [
                r for r in self._rules_by_category[category] if r.id != rule_id
            ]
        self._match_count.pop(rule_id, None)
        self._last_match.pop(rule_id, None)
        return True

    # ── Internal: Rule Parsing ───────────────────────────────────────────

    def _parse_rule(self, path: Path) -> Optional[SigmaRule]:
        """Parse a Sigma YAML file into a SigmaRule."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return None

        return self._build_rule(data, str(path))

    def _build_rule(self, data: Dict[str, Any], source: str) -> Optional[SigmaRule]:
        """Build a SigmaRule from parsed YAML data."""
        rule_id = data.get("id", "")
        title = data.get("title", "")

        if not rule_id or not title:
            logger.debug("Skipping rule without id/title in %s", source)
            return None

        # Parse MITRE tags
        tags = data.get("tags", [])
        mitre_techniques = []
        mitre_tactics = []
        for tag in tags:
            tag_str = str(tag).lower()
            if tag_str.startswith("attack.t"):
                # Extract technique ID: attack.t1059.001 → T1059.001
                tech = tag_str.replace("attack.", "").upper()
                mitre_techniques.append(tech)
            elif tag_str.startswith("attack."):
                tactic = tag_str.replace("attack.", "")
                mitre_tactics.append(tactic)

        # Parse logsource
        logsource = data.get("logsource", {})

        # Parse detection
        detection = data.get("detection", {})
        condition = (
            detection.pop("condition", "") if isinstance(detection, dict) else ""
        )
        timeframe = (
            detection.pop("timeframe", "") if isinstance(detection, dict) else ""
        )

        rule = SigmaRule(
            id=rule_id,
            title=title,
            description=data.get("description", ""),
            status=data.get("status", "experimental"),
            level=data.get("level", "medium"),
            author=data.get("author", ""),
            references=data.get("references", []),
            tags=tags,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            logsource_category=logsource.get("category", ""),
            logsource_product=logsource.get("product", "amoskys"),
            detection=detection,
            condition=str(condition),
            timeframe=str(timeframe) if timeframe else "",
            output_fields=data.get("fields", []),
            falsepositives=data.get("falsepositives", []),
            confidence=float(data.get("confidence", 0.7)),
            file_path=source,
        )

        # Compile detection matchers
        rule._matchers = self._compile_detection(detection, condition)

        return rule

    def _compile_detection(
        self, detection: Dict[str, Any], condition: str
    ) -> List[Callable]:
        """Compile detection selection/filter into callable matchers.

        Supports:
            - Simple field matching (selection: {field: value})
            - Wildcard matching (field: "*.exe")
            - List matching (field: [val1, val2])
            - Negation via "not" in condition
            - count() aggregation in condition
        """
        matchers: List[Callable] = []

        if not detection:
            return matchers

        for name, criteria in detection.items():
            if not isinstance(criteria, dict):
                continue
            matchers.append(self._build_field_matcher(name, criteria))

        return matchers

    def _build_field_matcher(
        self, name: str, criteria: Dict[str, Any]
    ) -> Callable[[Dict[str, Any]], bool]:
        """Build a field matcher function from detection criteria."""

        def matcher(event: Dict[str, Any]) -> bool:
            for field_name, expected in criteria.items():
                actual = event.get(field_name)
                # Also check nested data dict
                if actual is None and isinstance(event.get("data"), dict):
                    actual = event["data"].get(field_name)

                if actual is None:
                    return False

                if not _value_matches(actual, expected):
                    return False
            return True

        return matcher

    # ── Internal: Rule Evaluation ────────────────────────────────────────

    def _rule_matches(self, rule: SigmaRule, event_dict: Dict[str, Any]) -> bool:
        """Check if an event matches a rule's detection logic."""
        if not rule._matchers:
            return False

        condition = rule.condition.lower().strip()

        # Handle "not" conditions
        negate = False
        if condition.startswith("not "):
            negate = True
            condition = condition[4:].strip()

        # Handle "selection and filter" / "selection or filter"
        if " and " in condition:
            parts = condition.split(" and ")
            result = all(
                self._match_named(rule, name.strip(), event_dict)
                for name in parts
                if not name.strip().startswith("count")
            )
        elif " or " in condition:
            parts = condition.split(" or ")
            result = any(
                self._match_named(rule, name.strip(), event_dict) for name in parts
            )
        elif "|" in condition and "count" in condition:
            # e.g., "selection | count(source_ip) >= 5"
            # For single-event evaluation, we check the selection part
            sel_name = condition.split("|")[0].strip()
            result = self._match_named(rule, sel_name, event_dict)
        else:
            # Simple: "selection"
            result = any(m(event_dict) for m in rule._matchers)

        return not result if negate else result

    def _match_named(
        self, rule: SigmaRule, name: str, event_dict: Dict[str, Any]
    ) -> bool:
        """Match a named detection section against an event."""
        criteria = rule.detection.get(name)
        if criteria is None:
            # Try matching any compiled matcher
            return any(m(event_dict) for m in rule._matchers)
        if isinstance(criteria, dict):
            matcher = self._build_field_matcher(name, criteria)
            return matcher(event_dict)
        return False

    @staticmethod
    def _event_to_dict(event: Any) -> Optional[Dict[str, Any]]:
        """Normalize event to a flat dictionary for matching."""
        if isinstance(event, dict):
            return event

        # Handle TelemetryEvent dataclass
        result: Dict[str, Any] = {}
        for attr in (
            "event_type",
            "severity",
            "probe_name",
            "confidence",
            "timestamp_ns",
            "tags",
            "mitre_techniques",
            "mitre_tactics",
            "correlation_id",
        ):
            val = getattr(event, attr, None)
            if val is not None:
                if hasattr(val, "value"):  # Enum
                    result[attr] = val.value
                else:
                    result[attr] = val

        data = getattr(event, "data", None)
        if isinstance(data, dict):
            result["data"] = data
            # Flatten data keys for direct field matching
            for k, v in data.items():
                if k not in result:
                    result[k] = v

        return result if result else None


# ── Value Matching Helpers ───────────────────────────────────────────────────


def _value_matches(actual: Any, expected: Any) -> bool:
    """Check if actual value matches expected (with wildcards and lists)."""
    if isinstance(expected, list):
        return any(_value_matches(actual, e) for e in expected)

    if isinstance(expected, str):
        actual_str = str(actual).lower()
        expected_lower = expected.lower()

        # Wildcard matching
        if "*" in expected_lower or "?" in expected_lower:
            return fnmatch.fnmatch(actual_str, expected_lower)

        # Regex matching (Sigma |re modifier not standard, but useful)
        if expected_lower.startswith("/") and expected_lower.endswith("/"):
            pattern = expected_lower[1:-1]
            try:
                return bool(re.search(pattern, actual_str, re.IGNORECASE))
            except re.error:
                return False

        # Exact match (case-insensitive for strings)
        return actual_str == expected_lower

    # Numeric/boolean comparison
    return actual == expected
