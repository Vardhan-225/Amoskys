"""
AMOSKYS Agent Entrypoint Tests

Verifies that all agents can be imported and have proper main() functions.
These tests are critical for ensuring consistent deployment behavior.

Run with: pytest tests/agents/test_entrypoints.py -v
"""

import importlib

import pytest


class TestAgentModuleImports:
    """Test that all agent modules can be imported without errors."""

    @pytest.mark.smoke
    def test_proc_agent_import(self):
        """Proc agent module imports successfully."""
        mod = importlib.import_module("amoskys.agents.shared.process")
        assert hasattr(mod, "ProcAgent")

    @pytest.mark.smoke
    def test_auth_agent_import(self):
        """Auth agent module imports successfully."""
        mod = importlib.import_module("amoskys.agents.shared.auth")
        assert hasattr(mod, "AuthGuardAgent")

    @pytest.mark.smoke
    def test_dns_agent_import(self):
        """DNS agent module imports successfully."""
        mod = importlib.import_module("amoskys.agents.shared.dns")
        assert hasattr(mod, "DNSAgent")

    def test_fim_agent_import(self):
        """FIM agent module imports successfully."""
        mod = importlib.import_module("amoskys.agents.shared.filesystem")
        assert hasattr(mod, "FIMAgent")

    def test_persistence_agent_import(self):
        """Persistence agent module imports successfully."""
        mod = importlib.import_module("amoskys.agents.shared.persistence")
        assert hasattr(mod, "PersistenceGuard")

    def test_kernel_audit_agent_import(self):
        """Kernel audit agent module imports successfully."""
        mod = importlib.import_module("amoskys.agents.os.linux.kernel_audit")
        assert hasattr(mod, "KernelAuditAgent")

    def test_peripheral_agent_import(self):
        """Peripheral agent module imports successfully."""
        mod = importlib.import_module("amoskys.agents.shared.peripheral")
        assert hasattr(mod, "PeripheralAgent")


class TestAgentMainFunctions:
    """Test that all agent __main__ modules have main() functions."""

    @pytest.mark.smoke
    def test_proc_agent_has_main(self):
        """Proc agent __main__ has main() function."""
        mod = importlib.import_module("amoskys.agents.shared.process.__main__")
        assert hasattr(mod, "main")
        assert callable(mod.main)

    @pytest.mark.smoke
    def test_auth_agent_has_main(self):
        """Auth agent __main__ has main() function."""
        mod = importlib.import_module("amoskys.agents.shared.auth.__main__")
        assert hasattr(mod, "main")
        assert callable(mod.main)

    @pytest.mark.smoke
    def test_dns_agent_has_main(self):
        """DNS agent __main__ has main() function."""
        mod = importlib.import_module("amoskys.agents.shared.dns.__main__")
        assert hasattr(mod, "main")
        assert callable(mod.main)

    def test_persistence_agent_has_main(self):
        """Persistence agent __main__ has main() function."""
        mod = importlib.import_module("amoskys.agents.shared.persistence.__main__")
        assert hasattr(mod, "main")
        assert callable(mod.main)

    def test_kernel_audit_agent_has_main(self):
        """Kernel audit agent __main__ has main() function."""
        mod = importlib.import_module("amoskys.agents.os.linux.kernel_audit.__main__")
        assert hasattr(mod, "main")
        assert callable(mod.main)

    def test_peripheral_agent_has_main(self):
        """Peripheral agent __main__ has main() function."""
        mod = importlib.import_module("amoskys.agents.shared.peripheral.__main__")
        assert hasattr(mod, "main")
        assert callable(mod.main)

    def test_snmp_agent_has_main(self):
        """SNMP agent __main__ has main() function."""
        mod = importlib.import_module("amoskys.agents.shared.snmp.__main__")
        assert hasattr(mod, "main")
        assert callable(mod.main)

    def test_flow_publisher_has_main(self):
        """EventBus flow publisher has main() function."""
        mod = importlib.import_module("amoskys.eventbus.flow_publisher")
        assert hasattr(mod, "main")
        assert callable(mod.main)


class TestCLIFramework:
    """Test the shared CLI framework functions."""

    def test_cli_module_imports(self):
        """CLI module imports successfully."""
        from amoskys.agents.common.cli import (
            agent_main,
            build_agent_parser,
            configure_logging,
            run_agent,
            write_heartbeat,
        )

        assert callable(build_agent_parser)
        assert callable(run_agent)
        assert callable(agent_main)
        assert callable(configure_logging)
        assert callable(write_heartbeat)

    def test_build_agent_parser_default_args(self):
        """Parser has all standard arguments."""
        from amoskys.agents.common.cli import build_agent_parser

        parser = build_agent_parser("test_agent", "Test agent for unit tests")

        # Parse with defaults
        args = parser.parse_args([])

        assert args.config == "config/amoskys.yaml"
        assert args.interval == 30
        assert args.once is False
        assert args.log_level == "INFO"
        assert args.no_heartbeat is False

    def test_build_agent_parser_custom_args(self):
        """Parser accepts custom arguments."""
        from amoskys.agents.common.cli import build_agent_parser

        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--interval", "60", "--once", "--log-level", "DEBUG"])

        assert args.interval == 60
        assert args.once is True
        assert args.log_level == "DEBUG"

    def test_build_agent_parser_with_custom_callback(self):
        """Parser accepts custom argument callback."""
        from amoskys.agents.common.cli import build_agent_parser

        def add_custom(parser):
            parser.add_argument("--custom-option", type=str, default="default")

        parser = build_agent_parser("test_agent", add_custom_args=add_custom)
        args = parser.parse_args(["--custom-option", "custom_value"])

        assert args.custom_option == "custom_value"


class TestAgentRegistry:
    """Test the agent registry in agents/__init__.py."""

    def test_agent_registry_exists(self):
        """Agent registry is defined and non-empty."""
        from amoskys.agents import AGENT_REGISTRY

        assert isinstance(AGENT_REGISTRY, dict)
        assert len(AGENT_REGISTRY) > 0

    def test_all_registry_entries_have_required_fields(self):
        """All registry entries have required metadata."""
        from amoskys.agents import AGENT_REGISTRY

        required_fields = {"name", "description", "platforms"}

        for agent_id, meta in AGENT_REGISTRY.items():
            for field in required_fields:
                assert field in meta, f"Agent '{agent_id}' missing '{field}'"

    def test_get_available_agents(self):
        """get_available_agents returns agents for current platform."""
        from amoskys.agents import get_available_agents

        agents = get_available_agents()
        assert isinstance(agents, dict)
        # Should have at least some agents available
        assert len(agents) > 0
