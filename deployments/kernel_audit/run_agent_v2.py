#!/usr/bin/env python3
"""CLI entry point for KernelAudit Agent v2.

Usage:
    python run_agent_v2.py [OPTIONS]

    # Or install as system command:
    sudo cp run_agent_v2.py /usr/local/bin/amoskys-kernel-audit-agent
    sudo chmod +x /usr/local/bin/amoskys-kernel-audit-agent
    amoskys-kernel-audit-agent [OPTIONS]

Examples:
    # Basic usage with defaults
    python run_agent_v2.py --device-id=host-001

    # Custom configuration
    python run_agent_v2.py \
        --device-id=prod-web-01 \
        --audit-log=/var/log/audit/audit.log \
        --queue-path=/var/lib/amoskys/queues/kernel_audit \
        --collection-interval=10 \
        --metrics-interval=60

    # With HTTP metrics endpoint
    python run_agent_v2.py \
        --device-id=host-001 \
        --metrics-http-port=9100
"""

import argparse
import logging
import os
import signal
import sys
from typing import Optional

# Add parent directory to Python path to find amoskys module
# Try multiple possible locations (local dev, server deployment, pip install)
_script_dir = os.path.dirname(os.path.abspath(__file__))
_possible_paths = [
    os.path.join(_script_dir, "../../src"),  # Local dev: deployments/kernel_audit/../../src
    os.path.expanduser("~/amoskys-src"),      # Server: ~/amoskys-src/amoskys/
    os.path.join(os.path.expanduser("~"), "amoskys", "src"),  # Server alt
]

for path in _possible_paths:
    if os.path.isdir(path):
        sys.path.insert(0, path)

from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.kernel_audit.kernel_audit_agent_v2 import KernelAuditAgentV2

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AMOSKYS KernelAudit Guard v2 - Syscall-Plane Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Required arguments
    parser.add_argument(
        "--device-id",
        type=str,
        default=os.environ.get("AMOSKYS_DEVICE_ID", os.uname().nodename),
        help="Unique device identifier (default: hostname)",
    )

    # Data source configuration
    parser.add_argument(
        "--audit-log",
        type=str,
        default="/var/log/audit/audit.log",
        help="Path to audit log file (default: /var/log/audit/audit.log)",
    )

    # Queue configuration
    parser.add_argument(
        "--queue-path",
        type=str,
        default="/var/lib/amoskys/queues/kernel_audit",
        help="Path to local queue directory (default: /var/lib/amoskys/queues/kernel_audit)",
    )

    # Collection timing
    parser.add_argument(
        "--collection-interval",
        type=float,
        default=5.0,
        help="Seconds between collection cycles (default: 5.0)",
    )

    parser.add_argument(
        "--metrics-interval",
        type=float,
        default=60.0,
        help="Seconds between metrics emissions (default: 60.0)",
    )

    # Observability
    parser.add_argument(
        "--metrics-http-port",
        type=int,
        default=None,
        help="Enable HTTP metrics endpoint on this port (e.g., 9100)",
    )

    # Logging
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=os.environ.get("AMOSKYS_LOG_LEVEL", "INFO"),
        help="Logging level (default: INFO)",
    )

    # Testing mode
    parser.add_argument(
        "--stub-collector",
        action="store_true",
        help="Use stub collector for testing (no real audit log)",
    )

    return parser.parse_args()


def validate_environment(args: argparse.Namespace) -> bool:
    """Validate runtime environment and permissions.

    Args:
        args: Parsed command-line arguments

    Returns:
        True if environment is valid, False otherwise
    """
    # Check if audit log exists (unless stub mode)
    if not args.stub_collector:
        if not os.path.exists(args.audit_log):
            logger.error(f"Audit log not found: {args.audit_log}")
            logger.error("Ensure auditd is running: systemctl status auditd")
            return False

        # Check read permissions
        if not os.access(args.audit_log, os.R_OK):
            logger.error(f"Cannot read audit log: {args.audit_log}")
            logger.error("Grant read permissions:")
            logger.error(f"  sudo setfacl -m u:{os.getenv('USER')}:r {args.audit_log}")
            return False

    # Check queue directory
    queue_dir = os.path.dirname(args.queue_path)
    if not os.path.exists(queue_dir):
        logger.warning(f"Queue directory does not exist: {queue_dir}")
        logger.info(f"Creating directory: {queue_dir}")
        try:
            os.makedirs(queue_dir, mode=0o755, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create queue directory: {e}")
            return False

    # Check write permissions
    if not os.access(queue_dir, os.W_OK):
        logger.error(f"Cannot write to queue directory: {queue_dir}")
        logger.error(f"  sudo chown {os.getenv('USER')} {queue_dir}")
        return False

    return True


def main() -> int:
    """Main entry point.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    args = parse_args()

    # Configure logging
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    logger.info("=" * 70)
    logger.info("AMOSKYS KernelAudit Guard v2")
    logger.info("=" * 70)
    logger.info(f"Device ID: {args.device_id}")
    logger.info(f"Audit Log: {args.audit_log}")
    logger.info(f"Queue Path: {args.queue_path}")
    logger.info(f"Collection Interval: {args.collection_interval}s")
    logger.info(f"Metrics Interval: {args.metrics_interval}s")
    logger.info(f"Log Level: {args.log_level}")
    logger.info("=" * 70)

    # Validate environment
    if not validate_environment(args):
        logger.error("Environment validation failed. Exiting.")
        return 1

    # Create queue adapter
    try:
        # queue_path is a directory - append the database filename
        queue_db_path = os.path.join(args.queue_path, "kernel_audit_queue.db")
        queue_adapter = LocalQueueAdapter(
            queue_path=queue_db_path,
            agent_name="kernel_audit_v2",
            device_id=args.device_id,
        )
        logger.info(f"Initialized queue adapter at {queue_db_path}")
    except Exception as e:
        logger.error(f"Failed to initialize queue adapter: {e}")
        return 1

    # Create agent
    try:
        # Use stub collector if requested (for testing)
        collector = None
        if args.stub_collector:
            from amoskys.agents.kernel_audit.collector import (
                StubKernelAuditCollector,
            )

            collector = StubKernelAuditCollector()
            logger.warning("Using STUB collector - no real audit events")

        agent = KernelAuditAgentV2(
            device_id=args.device_id,
            agent_name="kernel_audit_v2",
            collection_interval=args.collection_interval,
            audit_log_path=args.audit_log,
            collector=collector,
            queue_adapter=queue_adapter,
            metrics_interval=args.metrics_interval,
        )

        logger.info("Agent initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize agent: {e}", exc_info=True)
        return 1

    # Start HTTP metrics endpoint if requested
    if args.metrics_http_port:
        try:
            agent.start_metrics_http_server(
                host="127.0.0.1", port=args.metrics_http_port
            )
            logger.info(f"Metrics HTTP endpoint: http://127.0.0.1:{args.metrics_http_port}/metrics")
        except Exception as e:
            logger.warning(f"Failed to start metrics HTTP server: {e}")

    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        agent.is_running = False

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Run agent
    try:
        logger.info("Starting agent main loop...")
        agent.run()
        logger.info("Agent stopped gracefully")
        return 0

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0

    except Exception as e:
        logger.error(f"Agent crashed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
