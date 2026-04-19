"""Identity rotation — session-consistent, target-specific browser personas.

The rule: one "Session" per (customer, target), held for the duration
of the engagement. Within a session, the User-Agent, Accept-Language,
and other headers are stable — real browsers don't swap UA every
request. Across sessions we rotate.

The identity pool is a small, curated list of realistic current-version
browser fingerprints. Not randomly generated: generated UAs drift out of
sync with the rest of the TLS/HTTP fingerprint and become themselves a
signal. The pool is meant to be reviewed + refreshed quarterly.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── Pool ───────────────────────────────────────────────────────────
#
# Each entry is a self-consistent browser fingerprint. The UA string
# matches the `sec-ch-ua` branding where applicable, and Accept/
# Accept-Language are what that browser would send on a first visit.
#
# When refreshing this pool, keep sec-ch-ua accurate — curious blue
# teams cross-check UA vs sec-ch-ua, and mismatches are a signal.

_POOL: List[Dict[str, str]] = [
    {
        # Chrome 131 on macOS 14
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "accept_language": "en-US,en;q=0.9",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_mobile": "?0",
    },
    {
        # Chrome 131 on Windows 11
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "accept_language": "en-US,en;q=0.9",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0",
    },
    {
        # Safari 18 on macOS 14
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/18.1 Safari/605.1.15"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "*/*;q=0.8"
        ),
        "accept_language": "en-US,en;q=0.9",
    },
    {
        # Firefox 132 on Ubuntu
        "user_agent": (
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) "
            "Gecko/20100101 Firefox/132.0"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "accept_language": "en-US,en;q=0.5",
    },
    {
        # Edge 131 on Windows 11
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "accept_language": "en-US,en;q=0.9",
        "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0",
    },
]


# ── Session ────────────────────────────────────────────────────────


@dataclass
class Session:
    """One consistent browser persona for the life of an engagement.

    Sessions are deterministically derived from a seed (usually
    customer_id + target) so if the process restarts, the same
    customer/target pair gets the same persona — which means the
    blue team sees continuity, not a fresh persona per request.
    """

    session_id: str
    persona: Dict[str, str]
    seed: str

    def headers(self, referer: Optional[str] = None) -> Dict[str, str]:
        """Return the request headers for this session."""
        hdrs = {
            "User-Agent": self.persona["user_agent"],
            "Accept": self.persona["accept"],
            "Accept-Language": self.persona["accept_language"],
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none" if referer is None else "same-origin",
            "Sec-Fetch-User": "?1",
        }
        if "sec_ch_ua" in self.persona:
            hdrs["sec-ch-ua"] = self.persona["sec_ch_ua"]
            hdrs["sec-ch-ua-platform"] = self.persona["sec_ch_ua_platform"]
            hdrs["sec-ch-ua-mobile"] = self.persona["sec_ch_ua_mobile"]
        if referer:
            hdrs["Referer"] = referer
        return hdrs


# ── Pool manager ───────────────────────────────────────────────────


class IdentityPool:
    """Deterministic persona selector keyed by (customer, target)."""

    def __init__(self, pool: Optional[List[Dict[str, str]]] = None) -> None:
        self._pool = list(pool or _POOL)
        if not self._pool:
            raise ValueError("identity pool cannot be empty")

    def session_for(self, customer_id: str, target: str) -> Session:
        """Return the persona assigned to (customer, target).

        Same inputs → same persona, across process restarts. Different
        targets for the same customer get different personas, so a
        cross-target observer can't correlate our traffic by UA alone.
        """
        seed = f"{customer_id}::{target}"
        idx = _hash_to_index(seed, len(self._pool))
        return Session(
            session_id=_short_sid(seed),
            persona=self._pool[idx],
            seed=seed,
        )

    def random_session(self) -> Session:
        """Ad-hoc session for non-customer contexts (e.g. corpus fetch)."""
        persona = random.choice(self._pool)
        return Session(
            session_id=_short_sid(f"random::{random.random()}"),
            persona=persona,
            seed="random",
        )

    @property
    def size(self) -> int:
        return len(self._pool)


def _hash_to_index(seed: str, modulus: int) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % modulus


def _short_sid(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
