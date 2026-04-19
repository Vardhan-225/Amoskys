"""Adaptive rate limiter + block detector.

Token-bucket limiter with one twist: it listens to the outcome of each
request and adjusts itself. When a target returns 429 / 403 / 503, the
effective rate is halved and a backoff is scheduled. After N consecutive
blocks, the target is marked hostile and further requests raise
BlockedTargetError — we stop, audit it, and tell the operator.

Why this matters for customer pentests:
    - Bursts trigger WAFs; WAFs block the source IP for 10-60 minutes.
    - Once blocked, we either switch source or wait.
    - A quiet, steady 1-2 rps stream looks like a curious visitor,
      not a scanner. That's what the customer's blue team should
      have to *earn* catching — not a flashing siren.

Usage:

    rl = AdaptiveRateLimiter("lab.amoskys.com")
    for target_url in urls_to_probe:
        rl.wait()                       # blocks until a token is free
        try:
            resp = requests.get(target_url, ...)
            rl.observe(resp.status_code)   # feeds outcome back
        except Exception as e:
            rl.observe_error(e)
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("amoskys.argos.stealth")


# ── Public API ─────────────────────────────────────────────────────


class BlockedTargetError(RuntimeError):
    """Raised when a target has repeatedly signaled block/deny.

    Callers should treat this as a hard stop for that target. Do NOT
    retry with the same source identity. The operator can re-enable
    after investigating (usually needing a new source IP).
    """


@dataclass
class RateLimiterConfig:
    """Tuning knobs. Defaults are deliberately conservative."""

    initial_rps: float = 1.0           # 1 request per second default
    min_rps: float = 0.1               # floor when adaptive halving kicks in
    max_rps: float = 5.0               # hard ceiling even if target is quiet
    jitter_ratio: float = 0.3          # ±30% jitter on wait interval
    block_threshold: int = 3           # consecutive blocks → BlockedTargetError
    backoff_base_s: float = 30.0       # first backoff on a single block
    backoff_max_s: float = 900.0       # 15-minute cap
    halve_on_block_codes: frozenset = field(
        default_factory=lambda: frozenset({429, 403, 503})
    )
    respect_retry_after: bool = True    # honor Retry-After header if present


# ── Implementation ─────────────────────────────────────────────────


class AdaptiveRateLimiter:
    """Per-target adaptive rate limiter.

    Thread-safe. One instance per (customer, target) pair.
    """

    def __init__(
        self,
        target: str,
        config: Optional[RateLimiterConfig] = None,
        now_fn=time.monotonic,
        sleep_fn=time.sleep,
    ) -> None:
        self.target = target
        self.config = config or RateLimiterConfig()
        self._now = now_fn
        self._sleep = sleep_fn
        self._lock = threading.Lock()

        self._current_rps = self.config.initial_rps
        self._consecutive_blocks = 0
        self._blocked = False
        self._next_allowed_at = 0.0
        self._total_requests = 0
        self._total_blocks = 0

    # ── Wait gate ─────────────────────────────────────────────────

    def wait(self) -> None:
        """Block until the next token is available.

        Raises BlockedTargetError if the target has been marked hostile.
        """
        if self._blocked:
            raise BlockedTargetError(
                f"target {self.target!r} marked blocked after "
                f"{self._total_blocks} block signals; not making further requests"
            )

        with self._lock:
            now = self._now()
            delay = max(0.0, self._next_allowed_at - now)

        if delay > 0:
            jittered = _jitter(delay, self.config.jitter_ratio)
            self._sleep(jittered)

        with self._lock:
            interval = 1.0 / max(self._current_rps, 0.01)
            self._next_allowed_at = self._now() + interval
            self._total_requests += 1

    # ── Outcome feedback ──────────────────────────────────────────

    def observe(
        self,
        status_code: int,
        retry_after_s: Optional[float] = None,
    ) -> None:
        """Feed a response outcome. Adjusts rate + backoff accordingly."""
        with self._lock:
            if status_code in self.config.halve_on_block_codes:
                self._register_block(retry_after_s)
                return
            # Successful request — reset the block counter, slowly
            # recover rate if previously reduced.
            if 200 <= status_code < 400:
                self._consecutive_blocks = 0
                if self._current_rps < self.config.initial_rps:
                    # Recover by 10% per success, up to initial_rps.
                    self._current_rps = min(
                        self.config.initial_rps,
                        self._current_rps * 1.1,
                    )

    def observe_error(self, error: BaseException) -> None:
        """Treat network errors as a mild penalty (halve rate, no block)."""
        with self._lock:
            self._current_rps = max(
                self.config.min_rps,
                self._current_rps * 0.5,
            )
        logger.debug(
            "rate_limiter: %s saw error %s, rps now %.2f",
            self.target, type(error).__name__, self._current_rps,
        )

    # ── Inspection ────────────────────────────────────────────────

    @property
    def current_rps(self) -> float:
        return self._current_rps

    @property
    def blocked(self) -> bool:
        return self._blocked

    def stats(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "current_rps": self._current_rps,
            "total_requests": self._total_requests,
            "total_blocks": self._total_blocks,
            "consecutive_blocks": self._consecutive_blocks,
            "blocked": self._blocked,
        }

    def reset(self) -> None:
        """Clear block state — use after operator intervention or source rotation."""
        with self._lock:
            self._current_rps = self.config.initial_rps
            self._consecutive_blocks = 0
            self._blocked = False
            self._next_allowed_at = 0.0

    # ── Internal ──────────────────────────────────────────────────

    def _register_block(self, retry_after_s: Optional[float]) -> None:
        self._consecutive_blocks += 1
        self._total_blocks += 1

        # Halve the rate, floor at min_rps.
        self._current_rps = max(
            self.config.min_rps,
            self._current_rps * 0.5,
        )

        # Compute backoff delay.
        if retry_after_s is not None and self.config.respect_retry_after:
            backoff = min(retry_after_s, self.config.backoff_max_s)
        else:
            # Exponential on consecutive blocks, capped.
            backoff = min(
                self.config.backoff_base_s * (2 ** (self._consecutive_blocks - 1)),
                self.config.backoff_max_s,
            )

        self._next_allowed_at = self._now() + backoff

        logger.warning(
            "rate_limiter: %s block #%d (total %d), rps→%.2f, backoff %.1fs",
            self.target,
            self._consecutive_blocks,
            self._total_blocks,
            self._current_rps,
            backoff,
        )

        if self._consecutive_blocks >= self.config.block_threshold:
            self._blocked = True
            logger.error(
                "rate_limiter: %s marked BLOCKED after %d consecutive blocks",
                self.target, self._consecutive_blocks,
            )


# ── Helpers ────────────────────────────────────────────────────────


def _jitter(value: float, ratio: float) -> float:
    """Apply ±ratio jitter to a value. Non-negative result guaranteed."""
    if ratio <= 0:
        return max(0.0, value)
    lo = value * (1.0 - ratio)
    hi = value * (1.0 + ratio)
    return max(0.0, random.uniform(lo, hi))
