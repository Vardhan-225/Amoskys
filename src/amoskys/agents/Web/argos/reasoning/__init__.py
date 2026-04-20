"""Argos reasoning layer — decision playbooks that live alongside the
tools, so an MCP agent (e.g. Claude) can look up "what should I do
next, given what I know?" before acting.

Design goal
───────────
Tools are primitives. Playbooks are the reasoning. We keep them
separate so:

  1. Claude (or any reasoning agent) can introspect `playbook.as_dict()`
     to see available moves, their preconditions, and their mandates.
  2. A human operator can review playbooks without reading all the
     tool code.
  3. Playbooks stay VCS-first — every change is a diff, auditable.
"""

from amoskys.agents.Web.argos.reasoning.playbook import (
    EngagementState,
    Playbook,
    PlaybookMove,
    default_playbook,
)

__all__ = [
    "EngagementState",
    "Playbook",
    "PlaybookMove",
    "default_playbook",
]
