"""Backward-compatibility shim — use run_agent.py instead."""

from amoskys.agents.device_discovery.run_agent import *  # noqa: F401,F403
from amoskys.agents.device_discovery.run_agent import main

if __name__ == "__main__":
    main()
