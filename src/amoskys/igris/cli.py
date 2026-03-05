"""IGRIS CLI — standalone supervisory daemon and query interface.

Usage:
    amoskys-igris --daemon              # Run as foreground daemon
    amoskys-igris --status              # Query IGRIS status
    amoskys-igris --metrics             # Dump latest metrics
    amoskys-igris --signals             # Show active signals
    amoskys-igris --coherence           # Organism coherence check
    amoskys-igris --reset               # Reset baselines (re-enter warmup)
"""

from __future__ import annotations

import argparse
import json as jsonlib
import logging
import signal
import sys
import time


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IGRIS — Autonomous Supervisory Intelligence Layer",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--daemon", action="store_true", help="Run as foreground daemon")
    mode.add_argument("--status", action="store_true", help="Query IGRIS status")
    mode.add_argument("--metrics", action="store_true", help="Dump latest metrics")
    mode.add_argument("--signals", action="store_true", help="Show active signals")
    mode.add_argument(
        "--coherence", action="store_true", help="Organism coherence check"
    )
    mode.add_argument(
        "--reset", action="store_true", help="Reset baselines (re-enter warmup)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Observation interval in seconds (default: 60)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.daemon:
        from amoskys.igris import start_igris

        igris = start_igris(interval=args.interval)
        print(f"IGRIS daemon running (interval={args.interval}s). Ctrl+C to stop.")
        try:
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            igris.stop()
            print("IGRIS stopped.")
        return

    # Query modes — get singleton without starting daemon
    from amoskys.igris import get_igris

    igris = get_igris()

    if args.status:
        data = igris.get_status()
    elif args.metrics:
        data = igris.get_metrics()
    elif args.signals:
        data = igris.get_signals(limit=50)
    elif args.coherence:
        data = igris.get_coherence()
    elif args.reset:
        data = igris.reset_baselines()
    else:
        parser.print_help()
        return

    if args.json:
        print(jsonlib.dumps(data, indent=2, default=str))
    else:
        import pprint

        pprint.pprint(data)


if __name__ == "__main__":
    main()
