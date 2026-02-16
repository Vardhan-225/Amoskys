#!/usr/bin/env python3
"""Queue drain utility - prevents disk overflow by archiving old events.

This script:
1. Reads oldest events from agent queue databases
2. Archives them to compressed files
3. Deletes processed rows to reclaim space
4. Optionally vacuums the database

Usage:
    python drain_queue.py --agent protocol_collectors --batch 5000
    python drain_queue.py --agent kernel_audit --vacuum
    python drain_queue.py --all --batch 2000

Can be run via cron:
    */30 * * * * /home/ubuntu/amoskys-venv/bin/python /home/ubuntu/amoskys-src/scripts/drain_queue.py --all
"""

import argparse
import gzip
import logging
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration
QUEUE_BASE = Path("/var/lib/amoskys/queues")
DRAIN_BASE = Path("/var/lib/amoskys/drained")

AGENT_CONFIGS = {
    "kernel_audit": {
        "db_name": "kernel_audit_queue.db",
        "queue_path": QUEUE_BASE / "kernel_audit",
        "drain_path": DRAIN_BASE / "kernel_audit",
    },
    "protocol_collectors": {
        "db_name": "protocol_collectors_queue.db",
        "queue_path": QUEUE_BASE / "protocol_collectors",
        "drain_path": DRAIN_BASE / "protocol_collectors",
    },
    "device_discovery": {
        "db_name": "device_discovery_queue.db",
        "queue_path": QUEUE_BASE / "device_discovery",
        "drain_path": DRAIN_BASE / "device_discovery",
    },
}


def drain_agent_queue(
    agent_name: str,
    batch_size: int = 1000,
    vacuum: bool = False,
    dry_run: bool = False,
) -> dict:
    """Drain events from an agent's queue.
    
    Args:
        agent_name: Name of agent (kernel_audit, protocol_collectors, etc.)
        batch_size: Number of rows to process per batch
        vacuum: Whether to VACUUM after draining
        dry_run: If True, don't actually delete rows
        
    Returns:
        Dict with drain statistics
    """
    if agent_name not in AGENT_CONFIGS:
        logger.error(f"Unknown agent: {agent_name}")
        return {"error": f"Unknown agent: {agent_name}"}
    
    config = AGENT_CONFIGS[agent_name]
    db_path = config["queue_path"] / config["db_name"]
    drain_path = config["drain_path"]
    
    if not db_path.exists():
        logger.warning(f"Queue DB not found: {db_path}")
        return {"error": f"DB not found: {db_path}"}
    
    # Ensure drain directory exists
    drain_path.mkdir(parents=True, exist_ok=True)
    
    stats = {
        "agent": agent_name,
        "rows_drained": 0,
        "bytes_archived": 0,
        "batches": 0,
        "output_file": None,
        "vacuum": vacuum,
        "dry_run": dry_run,
    }
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Check current count
        cursor.execute("SELECT COUNT(*) FROM queue")
        initial_count = cursor.fetchone()[0]
        logger.info(f"[{agent_name}] Starting drain: {initial_count} events in queue")
        
        if initial_count == 0:
            logger.info(f"[{agent_name}] Queue empty, nothing to drain")
            conn.close()
            return stats
        
        # Create output file
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_file = drain_path / f"batch_{ts}.log.gz"
        stats["output_file"] = str(out_file)
        
        total_drained = 0
        
        with gzip.open(out_file, "wt", encoding="utf-8") as f:
            # Write header
            f.write(f"# AMOSKYS Queue Drain - {agent_name}\n")
            f.write(f"# Timestamp: {ts}\n")
            f.write(f"# Format: id|ts_ns|idem|len|hex_prefix\n")
            f.write("#\n")
            
            while True:
                cursor.execute(
                    "SELECT id, ts_ns, idem, bytes FROM queue ORDER BY id ASC LIMIT ?",
                    (batch_size,)
                )
                rows = cursor.fetchall()
                
                if not rows:
                    break
                
                max_id = 0
                for row_id, ts_ns, idem, data in rows:
                    # Write: id | timestamp | idempotency key | length | first 100 bytes hex
                    hex_prefix = data[:100].hex() if data else ""
                    f.write(f"{row_id}|{ts_ns}|{idem}|{len(data) if data else 0}|{hex_prefix}\n")
                    max_id = max(max_id, row_id)
                    stats["bytes_archived"] += len(data) if data else 0
                
                if not dry_run:
                    cursor.execute("DELETE FROM queue WHERE id <= ?", (max_id,))
                    conn.commit()
                
                total_drained += len(rows)
                stats["batches"] += 1
                
                if len(rows) < batch_size:
                    break  # Last batch
        
        stats["rows_drained"] = total_drained
        logger.info(f"[{agent_name}] Drained {total_drained} events to {out_file}")
        
        # Vacuum if requested
        if vacuum and not dry_run and total_drained > 0:
            logger.info(f"[{agent_name}] Running VACUUM...")
            cursor.execute("VACUUM")
            conn.commit()
            logger.info(f"[{agent_name}] VACUUM complete")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"[{agent_name}] Drain failed: {e}")
        stats["error"] = str(e)
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Drain AMOSKYS agent queues to prevent disk overflow"
    )
    parser.add_argument(
        "--agent",
        choices=list(AGENT_CONFIGS.keys()),
        help="Agent queue to drain"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Drain all agent queues"
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=1000,
        help="Batch size for processing (default: 1000)"
    )
    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run VACUUM after draining to reclaim disk space"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't actually delete rows, just archive"
    )
    
    args = parser.parse_args()
    
    if not args.agent and not args.all:
        parser.error("Must specify --agent or --all")
    
    agents = list(AGENT_CONFIGS.keys()) if args.all else [args.agent]
    
    results = []
    for agent in agents:
        if not (AGENT_CONFIGS[agent]["queue_path"] / AGENT_CONFIGS[agent]["db_name"]).exists():
            logger.info(f"[{agent}] Skipping - queue not found")
            continue
            
        result = drain_agent_queue(
            agent_name=agent,
            batch_size=args.batch,
            vacuum=args.vacuum,
            dry_run=args.dry_run,
        )
        results.append(result)
    
    # Summary
    print("\n" + "=" * 60)
    print("DRAIN SUMMARY")
    print("=" * 60)
    for r in results:
        if "error" in r:
            print(f"  {r.get('agent', 'unknown')}: ERROR - {r['error']}")
        else:
            print(f"  {r['agent']}: {r['rows_drained']} events drained")
            if r.get("output_file"):
                print(f"    → {r['output_file']}")


if __name__ == "__main__":
    main()
