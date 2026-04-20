"""Argos attack-chain reasoner.

Single-bug reports are what commodity scanners produce. Real
attackers chain. LFI alone is low-severity; LFI + wp-config reveal
+ DB over the public internet = root on the database. SSRF alone
is medium; SSRF + IMDSv1 + IAM role = AWS account takeover.

This module takes a bag of individual findings (from Argos AST
scanner, evasion probes, zeroday hunter, fingerprint profile,
origin bypass results) and tries to compose them into end-to-end
exploit paths with severity >> the max of any single link.

Rules are hand-coded (not learned) so each chain has an auditable
justification an operator can verify before exploitation.
"""

from amoskys.agents.Web.argos.chain.reasoner import (
    ChainFinding,
    ChainReport,
    ExploitChain,
    ChainReasoner,
    reason_chains,
)

__all__ = [
    "ChainFinding", "ChainReport", "ExploitChain",
    "ChainReasoner", "reason_chains",
]
