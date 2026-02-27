#!/usr/bin/env python3
"""Deprecated: use ``python -m amoskys.agents.device_discovery`` instead."""

import warnings

warnings.warn(
    "run_agent.py is deprecated. Use: python -m amoskys.agents.device_discovery",
    DeprecationWarning,
    stacklevel=2,
)

from amoskys.agents.device_discovery.__main__ import main  # noqa: E402

if __name__ == "__main__":
    main()
