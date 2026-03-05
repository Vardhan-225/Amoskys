"""SOMA Brain CLI — query status, trigger training, inspect models.

Usage:
    amoskys-soma --status               # Show brain status
    amoskys-soma --train                # Trigger single training cycle
    amoskys-soma --daemon               # Run as foreground trainer daemon
    amoskys-soma --model-status         # Model scorer availability
"""

from __future__ import annotations

import argparse
import json as jsonlib
import logging
import signal
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOMA Brain — Autonomous Self-Training Intelligence Engine",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--status", action="store_true", help="Show brain status")
    mode.add_argument(
        "--train", action="store_true", help="Trigger single training cycle"
    )
    mode.add_argument(
        "--daemon", action="store_true", help="Run as foreground trainer daemon"
    )
    mode.add_argument(
        "--model-status", action="store_true", help="Model scorer availability"
    )
    parser.add_argument(
        "--db", default="data/telemetry.db", help="Telemetry database path"
    )
    parser.add_argument(
        "--model-dir", default="data/intel/models", help="Model artifact directory"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=1800,
        help="Training interval in seconds (default: 1800)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.model_status:
        from amoskys.intel.soma_brain import ModelScorerAdapter

        adapter = ModelScorerAdapter(model_dir=args.model_dir)
        data = {"available": adapter.available(), "model_dir": args.model_dir}
        _output(data, args.json)
        return

    from amoskys.intel.soma_brain import SomaBrain

    brain = SomaBrain(
        telemetry_db_path=args.db,
        model_dir=args.model_dir,
        training_interval_seconds=args.interval,
    )

    if args.status:
        _output(brain.status(), args.json)
    elif args.train:
        print("Starting single training cycle...")
        metrics = brain.train_once()
        _output(metrics, args.json)
    elif args.daemon:
        import time

        brain.start()
        print(f"SOMA daemon running (interval={args.interval}s). Ctrl+C to stop.")
        try:
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            brain.stop()
            print("SOMA stopped.")
    else:
        parser.print_help()


def _output(data: object, as_json: bool) -> None:
    if as_json:
        print(jsonlib.dumps(data, indent=2, default=str))
    else:
        import pprint

        pprint.pprint(data)


if __name__ == "__main__":
    main()
