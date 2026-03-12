"""Unit tests for amoskys.detection.sigma_engine — Sigma rule loading and validation.

Covers:
  - Auto-loading 56 rules from the default rules directory
  - Opt-out via auto_load=False
  - Graceful handling of nonexistent rules directory
  - Required field validation across all loaded rules
  - Category distribution across logsource types
  - Presence of specific new rule IDs (Shield / infostealer wave)
"""

import pytest

from amoskys.detection.sigma_engine import SigmaEngine


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture()
def engine() -> SigmaEngine:
    """SigmaEngine with default auto-loaded rules."""
    return SigmaEngine()


# ============================================================================
# Rule loading
# ============================================================================


class TestSigmaEngineLoading:

    def test_auto_loads_56_rules(self, engine: SigmaEngine) -> None:
        """Default init auto-loads all 56 Sigma rules from the built-in directory."""
        assert engine.rule_count == 56

    def test_auto_load_false_starts_empty(self) -> None:
        """SigmaEngine(auto_load=False) should start with zero rules."""
        eng = SigmaEngine(auto_load=False)
        assert eng.rule_count == 0

    def test_nonexistent_rules_dir_loads_zero(self) -> None:
        """Pointing at a nonexistent directory should load 0 rules gracefully."""
        eng = SigmaEngine(rules_dir="/tmp/amoskys_no_such_dir_12345")
        assert eng.rule_count == 0


# ============================================================================
# Rule quality — required fields
# ============================================================================


class TestSigmaRuleFields:

    def test_all_rules_have_required_fields(self, engine: SigmaEngine) -> None:
        """Every loaded rule must have id, title, level, and detection."""
        for rule_id in list(engine._rules):
            rule = engine.get_rule(rule_id)
            assert rule is not None, f"Rule {rule_id} disappeared"
            assert rule.id, f"Rule missing id: {rule.file_path}"
            assert rule.title, f"Rule {rule.id} missing title"
            assert rule.level in (
                "informational",
                "low",
                "medium",
                "high",
                "critical",
            ), f"Rule {rule.id} has invalid level: {rule.level}"
            assert isinstance(
                rule.detection, dict
            ), f"Rule {rule.id} has non-dict detection"


# ============================================================================
# Category distribution
# ============================================================================


class TestSigmaRuleCategories:

    EXPECTED_CATEGORIES = {
        "process_creation",
        "network_connection",
        "file_event",
        "authentication",
        "dns",
        "database",
        "network",
        "webserver",
        "application",
        "web_application",
        "file_access",
    }

    def test_rules_span_expected_categories(self, engine: SigmaEngine) -> None:
        """Loaded rules should cover all expected logsource categories."""
        actual_categories = set(engine._rules_by_category.keys())
        for cat in self.EXPECTED_CATEGORIES:
            assert cat in actual_categories, (
                f"Category '{cat}' missing from loaded rules. "
                f"Present: {sorted(actual_categories)}"
            )


# ============================================================================
# Specific new rules (Shield / infostealer wave)
# ============================================================================


class TestSpecificRulesExist:

    @pytest.mark.parametrize(
        "rule_id, expected_title_fragment",
        [
            ("amoskys-cred-010", "Infostealer Credential Store Access"),
            ("amoskys-cred-011", "Fake Password Dialog"),
            ("amoskys-cred-012", "Cryptocurrency Wallet"),
            ("amoskys-cred-013", "Session Cookie"),
            ("amoskys-de-010", "Quarantine"),
            ("amoskys-exec-010", "ClickFix"),
        ],
    )
    def test_rule_exists_and_title_matches(
        self,
        engine: SigmaEngine,
        rule_id: str,
        expected_title_fragment: str,
    ) -> None:
        """New Shield/infostealer rules must be present with correct titles."""
        rule = engine.get_rule(rule_id)
        assert rule is not None, f"Rule {rule_id} not found in loaded rules"
        assert expected_title_fragment in rule.title, (
            f"Rule {rule_id} title mismatch: "
            f"expected fragment '{expected_title_fragment}' in '{rule.title}'"
        )
