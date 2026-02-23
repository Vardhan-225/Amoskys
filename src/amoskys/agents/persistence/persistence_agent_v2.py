"""Backward-compatibility shim — use persistence_agent.py instead.

Deprecated in v0.9.0-beta.1 (B5.1). Will be removed in v1.0.
"""

from amoskys.agents.persistence.persistence_agent import *  # noqa: F401,F403
from amoskys.agents.persistence.persistence_agent import PersistenceGuard

PersistenceGuardV2 = PersistenceGuard
