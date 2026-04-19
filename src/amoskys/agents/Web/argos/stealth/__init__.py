"""Argos stealth — primitives for looking like an unremarkable visitor.

Customer pentests test the blue team's ability to notice an attacker.
If Argos bursts 1,000 rps from a single IP with the User-Agent
"python-requests/2.28", we're testing nothing. The primitives here are
what every active Argos tool must route through:

  - RateLimiter: token-bucket + adaptive backoff on block signals
  - Identity: realistic UA pool, consistent per-session per-target
  - (future) TorSession: route through SOCKS5 for high-stealth runs

These are NOT detection-evasion tools in the malicious sense — they're
how we produce traffic shaped like a real threat actor so defenders can
tune their rules against it. All tools that use these primitives must
also write audit-log entries so the operator can defend every request
made on a customer's behalf.
"""

from amoskys.agents.Web.argos.stealth.rate_limiter import (
    AdaptiveRateLimiter,
    BlockedTargetError,
    RateLimiterConfig,
)
from amoskys.agents.Web.argos.stealth.identity import (
    IdentityPool,
    Session,
)

__all__ = [
    "AdaptiveRateLimiter",
    "BlockedTargetError",
    "IdentityPool",
    "RateLimiterConfig",
    "Session",
]
