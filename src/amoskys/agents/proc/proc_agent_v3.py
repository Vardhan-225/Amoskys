"""Backward-compatibility shim — use proc_agent.py instead.

Deprecated in v0.9.0-beta.1 (B5.1). Will be removed in v1.0.
"""

from amoskys.agents.proc.proc_agent import *  # noqa: F401,F403
from amoskys.agents.proc.proc_agent import ProcAgent

ProcAgentV3 = ProcAgent
