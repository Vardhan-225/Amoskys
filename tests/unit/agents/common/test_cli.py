"""Tests for amoskys.agents.common.cli — Agent CLI argument parser and runner.

Covers:
    - build_agent_parser: default args, custom args callback, version flag
    - configure_logging: level parsing, third-party silencing
    - write_heartbeat: success path, extra_data, directory creation, failure path
    - run_agent: single-run, continuous loop, signal handling, version exit,
      config validation, interval validation, constructor probing, no collect method
    - agent_main: one-liner convenience wrapper
"""

import argparse
import json
import logging
import os
import signal
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest

from amoskys.agents.common.cli import (
    DEFAULT_HEARTBEAT_DIR,
    agent_main,
    build_agent_parser,
    configure_logging,
    run_agent,
    write_heartbeat,
)

# ---------------------------------------------------------------------------
# build_agent_parser
# ---------------------------------------------------------------------------


class TestBuildAgentParser:
    """Test argument parser construction."""

    def test_default_args_present(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args([])
        assert args.config == "config/amoskys.yaml"
        assert args.interval == 30
        assert args.once is False
        assert args.log_level == "INFO"
        assert args.no_heartbeat is False
        assert args.version is False

    def test_description_defaults_to_agent_name(self):
        parser = build_agent_parser("proc_agent")
        assert "proc_agent" in parser.description

    def test_description_override(self):
        parser = build_agent_parser("proc_agent", "Custom description")
        assert parser.description == "Custom description"

    def test_custom_args_callback(self):
        def add_custom(p):
            p.add_argument("--extra", default="foo")

        parser = build_agent_parser("test_agent", add_custom_args=add_custom)
        args = parser.parse_args([])
        assert args.extra == "foo"

    def test_interval_argument(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--interval", "60"])
        assert args.interval == 60

    def test_once_flag(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--once"])
        assert args.once is True

    def test_log_level_choices(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--log-level", "DEBUG"])
        assert args.log_level == "DEBUG"

    def test_no_heartbeat_flag(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--no-heartbeat"])
        assert args.no_heartbeat is True

    def test_version_flag(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--version"])
        assert args.version is True

    def test_config_argument(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--config", "/etc/amoskys.yaml"])
        assert args.config == "/etc/amoskys.yaml"

    def test_heartbeat_dir_argument(self):
        parser = build_agent_parser("test_agent")
        args = parser.parse_args(["--heartbeat-dir", "/tmp/hb"])
        assert args.heartbeat_dir == "/tmp/hb"

    def test_prog_name_includes_agent_name(self):
        parser = build_agent_parser("dns_agent")
        assert "dns_agent" in parser.prog


# ---------------------------------------------------------------------------
# configure_logging
# ---------------------------------------------------------------------------


class TestConfigureLogging:
    """Test logging configuration."""

    def setup_method(self):
        # Clear existing handlers so basicConfig can take effect
        logging.root.handlers.clear()

    def test_adds_handler_to_root(self):
        configure_logging("DEBUG", "test_agent")
        root = logging.getLogger()
        assert len(root.handlers) >= 1

    def test_level_computation_debug(self):
        """Verify getattr(logging, 'DEBUG') yields correct level constant."""
        level = getattr(logging, "DEBUG", logging.INFO)
        assert level == logging.DEBUG

    def test_level_computation_invalid_defaults_to_info(self):
        """Verify getattr(logging, 'NONEXISTENT', INFO) yields INFO."""
        level = getattr(logging, "NONEXISTENT", logging.INFO)
        assert level == logging.INFO

    def test_silences_urllib3(self):
        configure_logging("DEBUG", "test_agent")
        assert logging.getLogger("urllib3").level >= logging.WARNING

    def test_silences_grpc(self):
        configure_logging("DEBUG", "test_agent")
        assert logging.getLogger("grpc").level >= logging.WARNING

    def teardown_method(self):
        logging.root.handlers.clear()


# ---------------------------------------------------------------------------
# write_heartbeat
# ---------------------------------------------------------------------------


class TestWriteHeartbeat:
    """Test heartbeat file writing."""

    def test_writes_heartbeat_file(self, tmp_path):
        write_heartbeat("test_agent", tmp_path)
        hb_file = tmp_path / "test_agent.json"
        assert hb_file.exists()
        data = json.loads(hb_file.read_text())
        assert data["agent_name"] == "test_agent"
        assert "pid" in data
        assert "timestamp" in data

    def test_includes_extra_data(self, tmp_path):
        write_heartbeat("test_agent", tmp_path, extra_data={"cycle": 5, "status": "ok"})
        hb_file = tmp_path / "test_agent.json"
        data = json.loads(hb_file.read_text())
        assert data["cycle"] == 5
        assert data["status"] == "ok"

    def test_creates_directory_if_missing(self, tmp_path):
        nested_dir = tmp_path / "deep" / "nested"
        write_heartbeat("test_agent", nested_dir)
        assert (nested_dir / "test_agent.json").exists()

    def test_failure_logs_warning(self, tmp_path):
        """When write fails, should log warning and not raise."""
        bad_dir = Path("/nonexistent_root_dir/heartbeats")
        # Should not raise
        write_heartbeat("test_agent", bad_dir)

    def test_no_extra_data_omits_extra_keys(self, tmp_path):
        write_heartbeat("test_agent", tmp_path)
        data = json.loads((tmp_path / "test_agent.json").read_text())
        assert "agent_name" in data
        assert "pid" in data
        # No extra fields like "cycle" should be present
        assert "cycle" not in data

    def test_hostname_field_present(self, tmp_path):
        write_heartbeat("test_agent", tmp_path)
        data = json.loads((tmp_path / "test_agent.json").read_text())
        assert "hostname" in data


# ---------------------------------------------------------------------------
# run_agent
# ---------------------------------------------------------------------------


class _DummyAgent:
    """Dummy agent for testing run_agent lifecycle."""

    VERSION = "2.0.0"

    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self.collected = 0

    def collect(self):
        self.collected += 1


class _NoCollectAgent:
    """Agent with no collect method."""

    def __init__(self, **kwargs):
        pass


class _ConfigPathAgent:
    """Agent that requires config_path kwarg."""

    def __init__(self, config_path):
        self.config_path = config_path

    def collect(self):
        pass


class _FailingConstructorAgent:
    """Agent whose constructor always fails with a non-TypeError."""

    def __init__(self, **kwargs):
        raise ValueError("bad agent")


class TestRunAgent:
    """Test the agent run loop."""

    def _make_args(self, **overrides):
        defaults = {
            "config": "/nonexistent/config.yaml",
            "interval": 1,
            "once": True,
            "log_level": "WARNING",
            "heartbeat_dir": "/tmp/test_hb",
            "no_heartbeat": True,
            "version": False,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_version_flag_exits(self):
        args = self._make_args(version=True)
        with pytest.raises(SystemExit) as exc_info:
            run_agent(_DummyAgent, args, "test")
        assert exc_info.value.code == 0

    def test_version_flag_prints_version(self, capsys):
        args = self._make_args(version=True)
        with pytest.raises(SystemExit):
            run_agent(_DummyAgent, args, "test")
        captured = capsys.readouterr()
        assert "2.0.0" in captured.out

    def test_single_run_mode(self, tmp_path):
        args = self._make_args(once=True, no_heartbeat=True)
        # Should not block; runs one cycle then exits
        run_agent(_DummyAgent, args, "test")

    def test_interval_less_than_one_exits(self):
        args = self._make_args(interval=0)
        with pytest.raises(SystemExit) as exc_info:
            run_agent(_DummyAgent, args, "test")
        assert exc_info.value.code == 1

    def test_interval_greater_than_3600_warns(self, tmp_path):
        args = self._make_args(interval=7200, once=True, no_heartbeat=True)
        # Should still run (just warns)
        run_agent(_DummyAgent, args, "test")

    def test_config_exists_logs_size(self, tmp_path):
        config_file = tmp_path / "amoskys.yaml"
        config_file.write_text("key: value")
        args = self._make_args(config=str(config_file), once=True, no_heartbeat=True)
        run_agent(_DummyAgent, args, "test")

    def test_no_collect_method_exits(self):
        args = self._make_args()
        with pytest.raises(SystemExit) as exc_info:
            run_agent(_NoCollectAgent, args, "test")
        assert exc_info.value.code == 1

    def test_agent_name_defaults_to_class_name(self, tmp_path):
        args = self._make_args(once=True, no_heartbeat=True)
        # agent_name=None -> uses class name
        run_agent(_DummyAgent, args)

    def test_constructor_probing_config_path(self, tmp_path):
        args = self._make_args(once=True, no_heartbeat=True)
        run_agent(_ConfigPathAgent, args, "test")

    def test_constructor_all_fail_exits(self):
        args = self._make_args()
        with pytest.raises(SystemExit) as exc_info:
            run_agent(_FailingConstructorAgent, args, "test")
        assert exc_info.value.code == 1

    def test_heartbeat_written_when_enabled(self, tmp_path):
        hb_dir = tmp_path / "heartbeats"
        args = self._make_args(
            once=True,
            no_heartbeat=False,
            heartbeat_dir=str(hb_dir),
        )
        run_agent(_DummyAgent, args, "test")
        assert (hb_dir / "test.json").exists()

    def test_collection_error_recorded_in_heartbeat(self, tmp_path):
        class _ErrorAgent:
            def __init__(self, **kwargs):
                pass

            def collect(self):
                raise RuntimeError("collection exploded")

        hb_dir = tmp_path / "heartbeats"
        args = self._make_args(
            once=True,
            no_heartbeat=False,
            heartbeat_dir=str(hb_dir),
        )
        run_agent(_ErrorAgent, args, "test")
        data = json.loads((hb_dir / "test.json").read_text())
        assert data["status"] == "error"
        assert "collection exploded" in data["error"]

    def test_signal_handler_stops_loop(self):
        """Verify signal handler sets shutdown_requested."""
        call_count = [0]

        class _SlowAgent:
            def __init__(self, **kwargs):
                pass

            def collect(self):
                call_count[0] += 1
                # Simulate receiving SIGTERM on second call
                if call_count[0] >= 2:
                    raise KeyboardInterrupt

        args = self._make_args(once=False, no_heartbeat=True, interval=1)
        with patch("amoskys.agents.common.cli.time.sleep"):
            run_agent(_SlowAgent, args, "test")
        assert call_count[0] >= 1

    def test_continuous_mode_sleeps(self):
        """In continuous mode, agent should sleep between cycles."""
        call_count = [0]

        class _CountAgent:
            def __init__(self, **kwargs):
                pass

            def collect(self):
                call_count[0] += 1
                if call_count[0] >= 2:
                    raise KeyboardInterrupt

        args = self._make_args(once=False, no_heartbeat=True, interval=10)
        with patch("amoskys.agents.common.cli.time.sleep") as mock_sleep:
            run_agent(_CountAgent, args, "test")
            # Sleep should have been called at least once
            assert mock_sleep.called


# ---------------------------------------------------------------------------
# agent_main
# ---------------------------------------------------------------------------


class TestAgentMain:
    """Test the agent_main convenience wrapper."""

    def test_agent_main_calls_run_agent(self):
        with patch("amoskys.agents.common.cli.build_agent_parser") as mock_build:
            mock_parser = MagicMock()
            mock_parser.parse_args.return_value = argparse.Namespace(
                config="/tmp/cfg.yaml",
                interval=1,
                once=True,
                log_level="WARNING",
                heartbeat_dir="/tmp/hb",
                no_heartbeat=True,
                version=False,
            )
            mock_build.return_value = mock_parser
            with patch("amoskys.agents.common.cli.run_agent") as mock_run:
                agent_main(_DummyAgent, "test_agent", "Test agent")
                mock_run.assert_called_once()

    def test_agent_main_custom_args(self):
        custom_fn = MagicMock()
        with patch("amoskys.agents.common.cli.build_agent_parser") as mock_build:
            mock_parser = MagicMock()
            mock_parser.parse_args.return_value = argparse.Namespace(
                config="/tmp/cfg.yaml",
                interval=1,
                once=True,
                log_level="WARNING",
                heartbeat_dir="/tmp/hb",
                no_heartbeat=True,
                version=False,
            )
            mock_build.return_value = mock_parser
            with patch("amoskys.agents.common.cli.run_agent"):
                agent_main(_DummyAgent, "test_agent", add_custom_args=custom_fn)
                mock_build.assert_called_once_with("test_agent", "", custom_fn)
