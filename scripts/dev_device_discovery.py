#!/usr/bin/env python3
"""Run DeviceDiscoveryV2 in dev mode on your local Mac.

This script:
- Sets AMOSKYS_ENV=dev (uses local queues, DEBUG logs)
- Runs the same run_agent_v2.py used in production
- No sudo required, safe for development

Usage:
    python3 scripts/dev_device_discovery.py
"""

import os
import subprocess
import sys
from pathlib import Path

# Repo root
ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "deployments" / "device_discovery"

# Local queue path for dev
LOCAL_QUEUES = ROOT / ".local_queues" / "device_discovery"
LOCAL_QUEUES.mkdir(parents=True, exist_ok=True)


def main():
    """Run DeviceDiscovery agent in dev mode."""
    env = os.environ.copy()
    env["AMOSKYS_ENV"] = "dev"
    env["PYTHONPATH"] = str(ROOT / "src")

    cmd = [
        sys.executable,
        str(AGENT_DIR / "run_agent_v2.py"),
        "--device-id",
        "dev-mac",
        "--queue-path",
        str(LOCAL_QUEUES),
        "--collection-interval",
        "30",  # Discovery is slower
        "--metrics-interval",
        "30",
        "--log-level",
        "DEBUG",
    ]

    print(f"Running: {' '.join(cmd)}")
    print(f"Queue: {LOCAL_QUEUES}")
    print(f"Press Ctrl+C to stop")
    print("-" * 70)

    try:
        subprocess.call(cmd, env=env)
    except KeyboardInterrupt:
        print("\n\nStopped by user")
        return 0


if __name__ == "__main__":
    sys.exit(main())
