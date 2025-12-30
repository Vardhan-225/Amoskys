"""
AMOSKYS Agent CLI Framework

Provides a standardized command-line interface for all AMOSKYS agents.
Every agent gets consistent CLI arguments and run behavior.

Usage:
    In your agent module:

    from amoskys.agents.common.cli import build_agent_parser, run_agent

    def main() -> None:
        parser = build_agent_parser("proc_agent", "Process monitoring agent")
        args = parser.parse_args()
        run_agent(ProcAgent, args)

    if __name__ == "__main__":
        main()
"""

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Type

logger = logging.getLogger(__name__)

# Default heartbeat directory
DEFAULT_HEARTBEAT_DIR = Path(
    os.getenv("AMOSKYS_HEARTBEATS", "/opt/amoskys/data/heartbeats")
)


def build_agent_parser(
    agent_name: str,
    description: str = "",
    add_custom_args: Optional[Callable[[argparse.ArgumentParser], None]] = None,
) -> argparse.ArgumentParser:
    """Build standardized argument parser for an AMOSKYS agent.

    All agents get these standard arguments:
        --config: Path to configuration file
        --interval: Collection interval in seconds
        --once: Run single collection cycle then exit
        --log-level: Logging verbosity
        --heartbeat-dir: Directory for heartbeat files
        --no-heartbeat: Disable heartbeat writing

    Args:
        agent_name: Agent identifier (e.g., "proc_agent")
        description: Agent description for help text
        add_custom_args: Optional callback to add agent-specific arguments

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog=f"python -m amoskys.agents.{agent_name}",
        description=description or f"AMOSKYS {agent_name} security agent",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Standard arguments for all agents
    parser.add_argument(
        "--config",
        type=str,
        default="config/amoskys.yaml",
        help="Path to configuration file",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Collection interval in seconds",
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run single collection cycle then exit",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity level",
    )

    parser.add_argument(
        "--heartbeat-dir",
        type=str,
        default=str(DEFAULT_HEARTBEAT_DIR),
        help="Directory for heartbeat status files",
    )

    parser.add_argument(
        "--no-heartbeat",
        action="store_true",
        help="Disable heartbeat file writing",
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show agent version and exit",
    )

    # Allow agent-specific arguments
    if add_custom_args:
        add_custom_args(parser)

    return parser


def configure_logging(log_level: str, agent_name: str) -> None:
    """Configure logging for an agent.

    Args:
        log_level: Logging level string (DEBUG, INFO, etc.)
        agent_name: Agent name for log prefix
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure root logger with consistent format
    logging.basicConfig(
        level=level,
        format=f"%(asctime)s [{agent_name}] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("grpc").setLevel(logging.WARNING)


def write_heartbeat(
    agent_name: str,
    heartbeat_dir: Path,
    extra_data: Optional[dict] = None,
) -> None:
    """Write heartbeat file for agent status tracking.

    Heartbeat files are JSON with:
        - agent_name: Agent identifier
        - pid: Process ID
        - timestamp: ISO format UTC timestamp
        - Any extra_data provided

    Args:
        agent_name: Agent identifier
        heartbeat_dir: Directory to write heartbeat file
        extra_data: Optional additional data to include
    """
    import json

    try:
        heartbeat_dir.mkdir(parents=True, exist_ok=True)
        heartbeat_path = heartbeat_dir / f"{agent_name}.json"

        payload = {
            "agent_name": agent_name,
            "pid": os.getpid(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
        }

        if extra_data:
            payload.update(extra_data)

        heartbeat_path.write_text(json.dumps(payload, indent=2))
        logger.debug("Heartbeat written: %s", heartbeat_path)

    except Exception as e:
        logger.warning("Failed to write heartbeat: %s", e)


def run_agent(
    agent_class: Type[Any],
    args: argparse.Namespace,
    agent_name: Optional[str] = None,
) -> None:
    """Run an agent with standardized lifecycle management.

    Handles:
        - Logging configuration
        - Signal handling (graceful shutdown)
        - Heartbeat writing
        - Run loop with interval
        - Single-run mode (--once)

    Args:
        agent_class: Agent class to instantiate
        args: Parsed command-line arguments
        agent_name: Optional override for agent name (defaults to class name)
    """
    name = agent_name or agent_class.__name__

    # Configure logging
    configure_logging(args.log_level, name)

    # Version check
    if getattr(args, "version", False):
        version = getattr(agent_class, "VERSION", "1.0.0")
        print(f"{name} version {version}")
        sys.exit(0)

    logger.info("=" * 60)
    logger.info("AMOSKYS %s starting", name)
    logger.info("=" * 60)
    logger.info("  Config: %s", args.config)
    logger.info("  Interval: %ds", args.interval)
    logger.info("  Log level: %s", args.log_level)
    logger.info("  Mode: %s", "single-run" if args.once else "continuous")

    # Instantiate agent
    try:
        # Try to pass config path if agent accepts it
        try:
            agent = agent_class(config_path=args.config)
        except TypeError:
            # Fall back to no-arg constructor
            agent = agent_class()
    except Exception as e:
        logger.error("Failed to instantiate agent: %s", e)
        sys.exit(1)

    # Heartbeat setup
    heartbeat_dir = Path(args.heartbeat_dir)
    write_heartbeat_enabled = not getattr(args, "no_heartbeat", False)

    # Graceful shutdown handling
    shutdown_requested = False

    def handle_signal(signum: int, frame: Any) -> None:
        nonlocal shutdown_requested
        logger.info("Received signal %d, shutting down gracefully...", signum)
        shutdown_requested = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Get collection method
    collect_method = getattr(agent, "collect", None) or getattr(agent, "run_once", None)
    if not collect_method:
        logger.error("Agent has no collect() or run_once() method")
        sys.exit(1)

    # Run loop
    cycle = 0
    try:
        while not shutdown_requested:
            cycle += 1
            start_time = time.time()

            logger.info("-" * 40)
            logger.info("Collection cycle #%d - %s", cycle, datetime.now().isoformat())

            try:
                collect_method()
                duration_ms = (time.time() - start_time) * 1000
                logger.info("Cycle complete in %.1fms", duration_ms)

                # Write heartbeat after successful collection
                if write_heartbeat_enabled:
                    write_heartbeat(
                        name,
                        heartbeat_dir,
                        extra_data={
                            "cycle": cycle,
                            "duration_ms": round(duration_ms, 1),
                            "status": "healthy",
                        },
                    )

            except Exception as e:
                logger.exception("Collection error: %s", e)
                if write_heartbeat_enabled:
                    write_heartbeat(
                        name,
                        heartbeat_dir,
                        extra_data={
                            "cycle": cycle,
                            "status": "error",
                            "error": str(e),
                        },
                    )

            # Single-run mode
            if args.once:
                logger.info("Single-run mode, exiting")
                break

            # Sleep until next interval
            elapsed = time.time() - start_time
            sleep_time = max(0, args.interval - elapsed)
            if sleep_time > 0 and not shutdown_requested:
                logger.debug("Sleeping %.1fs until next cycle", sleep_time)
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt, shutting down")

    logger.info("=" * 60)
    logger.info("AMOSKYS %s stopped after %d cycles", name, cycle)
    logger.info("=" * 60)


# Convenience function for simple agents
def agent_main(
    agent_class: Type[Any],
    agent_name: str,
    description: str = "",
    add_custom_args: Optional[Callable[[argparse.ArgumentParser], None]] = None,
) -> None:
    """One-liner main() for simple agents.

    Usage in agent module:
        from amoskys.agents.common.cli import agent_main
        from .my_agent import MyAgent

        def main():
            agent_main(MyAgent, "my_agent", "My security agent")

        if __name__ == "__main__":
            main()
    """
    parser = build_agent_parser(agent_name, description, add_custom_args)
    args = parser.parse_args()
    run_agent(agent_class, args, agent_name)
