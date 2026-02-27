#!/usr/bin/env python3
"""Deprecated: use ``python -m amoskys.agents.kernel_audit`` instead."""

import warnings

warnings.warn(
    "run_agent_v2.py is deprecated. Use: python -m amoskys.agents.kernel_audit",
    DeprecationWarning,
    stacklevel=2,
)

from amoskys.agents.kernel_audit.__main__ import main  # noqa: E402

if __name__ == "__main__":
    main()
