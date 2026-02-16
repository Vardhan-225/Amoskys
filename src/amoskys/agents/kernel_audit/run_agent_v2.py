#!/usr/bin/env python3
"""Launcher for KernelAuditAgentV2 — Mac Lab & Production.

Usage:
    python -m amoskys.agents.kernel_audit.run_agent_v2 \
        --device-id mac-akash \
        --queue-path .amoskys_lab/queues/kernel_audit \
        --collection-interval 30 \
        --log-level INFO
"""

import argparse
import logging
import os
import sys
from pathlib import Path

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AMOSKYS KernelAudit Agent v2 Launcher",
    )
    parser.add_argument("--device-id", default=os.getenv("AMOSKYS_DEVICE_ID", "host-001"))
    parser.add_argument("--queue-path", default=None, help="Directory for SQLite queue DB")
    parser.add_argument("--collection-interval", type=float, default=30.0)
    parser.add_argument("--metrics-interval", type=float, default=60.0)
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("--audit-log-path", default="/var/log/audit/audit.log",
                        help="Path to audit log (Linux auditd)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [kernel_audit_v2] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("grpc").setLevel(logging.WARNING)

    # Wire up queue adapter if path provided
    queue_adapter = None
    if args.queue_path:
        from amoskys.agents.common.queue_adapter import LocalQueueAdapter
        queue_dir = Path(args.queue_path)
        queue_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(queue_dir / "kernel_audit_queue.db")
        queue_adapter = LocalQueueAdapter(
            queue_path=db_path,
            agent_name="kernel_audit_v2",
            device_id=args.device_id,
        )
        logging.getLogger(__name__).info("Queue adapter: %s", db_path)

    from amoskys.agents.kernel_audit.kernel_audit_agent_v2 import KernelAuditAgentV2

    agent = KernelAuditAgentV2(
        device_id=args.device_id,
        collection_interval=args.collection_interval,
        metrics_interval=args.metrics_interval,
        queue_adapter=queue_adapter,
        audit_log_path=args.audit_log_path,
    )

    logging.getLogger(__name__).info(
        "KernelAuditAgentV2 starting — device=%s interval=%.0fs",
        args.device_id, args.collection_interval,
    )
    # Use run() not run_forever() — V2 agents use queue_adapter, not EventBus
    agent.run()


if __name__ == "__main__":
    main()
