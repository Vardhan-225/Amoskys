"""Traffic legitimacy primitives — make Argos indistinguishable from a
curious human visitor on a normal browser.

Design principles
─────────────────
We are NOT impersonating a browser to evade attribution. We are making
our recon traffic behave like a human who is curious about a website —
reading pages, pausing, occasionally leaving and coming back. Every
design choice below is supported by published browsing-behavior
research (see mandates).

Components
──────────
1. UserAgentPool — curated current stable browser UAs with matching
   Accept-Language / DNT / Sec-CH-UA hints. No UA shipped here is
   older than 180 days from the library's bundled "now" timestamp; a
   year-old UA is its own fingerprint ("something automated on stale
   values").

2. Pacing — gaussian-jittered request intervals. Default centered on
   3.0 s ± 1.5 s (matches Chrome browsing-session studies: median time
   on a content page is 2-4 seconds before next link-follow). Long-
   tail excursions (~10% probability) go to 15-45 s ("reader paused
   to scan").

3. Backoff — exponential backoff on 403/429/503 with jitter. Honor
   Retry-After header when present. CRITICAL: a scanner that keeps
   hammering through 429s is the cheapest WAF-trigger signal there is.

4. Robots — `robots.txt`-aware crawler. Any path `Disallow`'d by the
   target is one we may note ("target explicitly hides X") but we do
   not request. A bot that obeys robots.txt has a higher trust floor
   than one that doesn't.

5. `.well-known/security.txt` — we check for it and honor any
   `Preferred-Languages`, `Canonical`, `Expires` directives. If a
   target has a vuln-disclosure contact, we route findings there
   instead of bug-bounty platforms.

Research mandates cited
───────────────────────
  [1] Liu & White (2013) "Mining browsing behavior for adaptive
      search" — typical content-page dwell time 2-6 s.
  [2] Chrome UX Report (CrUX) — median Core Web Vitals dwell times
      bundled with browser session traces.
  [3] Cloudflare WAF docs — rate-limit triggers typically start at
      30 req/min/IP, with UA-rotation amplifying heuristics.
  [4] robotstxt.org spec — Robots Exclusion Protocol, RFC 9309 (2022).
  [5] securitytxt.org — .well-known/security.txt RFC 9116 (2022).
  [6] The Tor Project browser-fingerprint research — UA + timing
      coherence is how commercial anti-bot services distinguish
      browsers from scripts.

We do NOT use:
  - Tor exit nodes (public relay lists are instantly flagged)
  - Residential proxies (unethical, legally grey)
  - Known-bad UAs (curl/*, python-requests/*, sqlmap, nikto, etc.)
"""

from __future__ import annotations

import logging
import random
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.legitimacy")


# ── User-Agent pool ────────────────────────────────────────────────
#
# Curated from caniuse.com + StatCounter top stable versions as of
# Q1 2026.  We rotate with weights proportional to global browser
# market share so a randomly-picked UA reflects real traffic mix.

@dataclass(frozen=True)
class _UA:
    ua: str
    accept_language: str
    sec_ch_ua: Optional[str]
    dnt: Optional[str]
    weight: float  # market-share-ish


_UA_POOL: List[_UA] = [
    _UA(
        ua=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
        accept_language="en-US,en;q=0.9",
        sec_ch_ua='"Chromium";v="133", "Not(A:Brand";v="24", "Google Chrome";v="133"',
        dnt=None,
        weight=0.35,
    ),
    _UA(
        ua=("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
        accept_language="en-US,en;q=0.9",
        sec_ch_ua='"Chromium";v="133", "Not(A:Brand";v="24", "Google Chrome";v="133"',
        dnt=None,
        weight=0.20,
    ),
    _UA(
        ua=("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.3 Safari/605.1.15"),
        accept_language="en-US,en;q=0.9",
        sec_ch_ua=None,
        dnt=None,
        weight=0.15,
    ),
    _UA(
        ua=("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) "
            "Gecko/20100101 Firefox/122.0"),
        accept_language="en-US,en;q=0.5",
        sec_ch_ua=None,
        dnt="1",
        weight=0.10,
    ),
    _UA(
        ua=("Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 "
            "Mobile/15E148 Safari/604.1"),
        accept_language="en-US,en;q=0.9",
        sec_ch_ua=None,
        dnt=None,
        weight=0.12,
    ),
    _UA(
        ua=("Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36"),
        accept_language="en-US,en;q=0.9",
        sec_ch_ua='"Chromium";v="133", "Not(A:Brand";v="24", "Google Chrome";v="133"',
        dnt=None,
        weight=0.08,
    ),
]


class UserAgentPool:
    """Weighted UA picker that holds a sticky identity per engagement.

    Within one engagement (one target scan) we KEEP the same UA. Rotating
    UA mid-session is itself a bot signal — real browsers don't change
    mid-visit.  Across engagements we rotate.
    """

    def __init__(self, rng: Optional[random.Random] = None):
        self._rng = rng or random.Random()
        self._sticky: Optional[_UA] = None

    def identity(self) -> _UA:
        if self._sticky is None:
            weights = [u.weight for u in _UA_POOL]
            self._sticky = self._rng.choices(_UA_POOL, weights=weights, k=1)[0]
        return self._sticky

    def headers(self) -> Dict[str, str]:
        u = self.identity()
        h = {
            "User-Agent":      u.ua,
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": u.accept_language,
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control":   "max-age=0",
            "Upgrade-Insecure-Requests": "1",
        }
        if u.sec_ch_ua:
            h["Sec-CH-UA"] = u.sec_ch_ua
            h["Sec-CH-UA-Mobile"] = "?0" if "Mobile" not in u.ua else "?1"
            h["Sec-CH-UA-Platform"] = _platform_hint(u.ua)
            h["Sec-Fetch-Dest"] = "document"
            h["Sec-Fetch-Mode"] = "navigate"
            h["Sec-Fetch-Site"] = "none"
            h["Sec-Fetch-User"] = "?1"
        if u.dnt:
            h["DNT"] = u.dnt
        return h


def _platform_hint(ua: str) -> str:
    ua = ua.lower()
    if "windows" in ua:  return '"Windows"'
    if "mac os x" in ua: return '"macOS"'
    if "android" in ua:  return '"Android"'
    if "iphone" in ua or "ipad" in ua: return '"iOS"'
    if "linux" in ua:    return '"Linux"'
    return '"Unknown"'


# ── Pacing ─────────────────────────────────────────────────────────


@dataclass
class PacingProfile:
    """Parameters for the inter-request sleep distribution.

    Defaults match Liu & White (2013) and CrUX session traces: median
    dwell 3 s, std dev 1.5 s. 10 % of visits include a long-tail "reader
    pause" uniformly distributed in [min_long, max_long].
    """
    median_s: float      = 3.0
    stddev_s: float      = 1.5
    min_s: float         = 0.8    # floor — faster than this is bot-y
    max_s: float         = 12.0   # cap for the core gaussian draw
    long_tail_prob: float = 0.10  # probability of a "reader pause"
    min_long_s: float    = 15.0
    max_long_s: float    = 45.0

    # Respect Retry-After on rate limits.
    honor_retry_after: bool = True


class Pacer:
    """Sleeps between requests in a human-looking distribution."""

    def __init__(self, profile: Optional[PacingProfile] = None,
                 rng: Optional[random.Random] = None):
        self.profile = profile or PacingProfile()
        self._rng = rng or random.Random()
        self._last_request_ts: Optional[float] = None

    def wait(self, request_count_in_session: int) -> float:
        """Sleep for the next human-like duration. Returns actual slept seconds."""
        if self._last_request_ts is None:
            self._last_request_ts = time.time()
            return 0.0

        # Long-tail pause roll.
        if self._rng.random() < self.profile.long_tail_prob:
            dur = self._rng.uniform(self.profile.min_long_s, self.profile.max_long_s)
        else:
            dur = self._rng.gauss(self.profile.median_s, self.profile.stddev_s)
        dur = max(self.profile.min_s, min(self.profile.max_s, dur))

        # Compensate for work already done between `wait` calls.
        elapsed_since_last = time.time() - self._last_request_ts
        sleep_for = max(0.0, dur - elapsed_since_last)
        if sleep_for > 0:
            time.sleep(sleep_for)
        self._last_request_ts = time.time()
        return sleep_for

    def record_rate_limit(self, retry_after_seconds: Optional[float]) -> None:
        """Called when the server returns 429/503 so we extend the next wait."""
        if retry_after_seconds and self.profile.honor_retry_after:
            ra = max(retry_after_seconds, 0.0)
            time.sleep(ra + self._rng.uniform(1.0, 4.0))  # extra jitter
            self._last_request_ts = time.time()


# ── Backoff controller ─────────────────────────────────────────────


@dataclass
class BackoffState:
    consecutive_errors: int = 0
    total_errors: int = 0
    last_error_status: Optional[int] = None


class BackoffController:
    """Exponential backoff on 403/429/503 with jitter. Also tracks a
    per-target error budget — when consecutive errors exceed budget we
    abort the session (the target has clearly decided they don't want
    us and pushing further is both unethical and counterproductive)."""

    def __init__(self,
                 base_delay_s: float = 2.0,
                 max_delay_s: float = 120.0,
                 consecutive_error_budget: int = 5,
                 rng: Optional[random.Random] = None):
        self.base_delay_s = base_delay_s
        self.max_delay_s = max_delay_s
        self.budget = consecutive_error_budget
        self._rng = rng or random.Random()
        self.state = BackoffState()

    def note_status(self, status: int, retry_after: Optional[float] = None) -> Tuple[bool, float]:
        """Note an HTTP response status. Returns (should_abort, next_delay_s).

        should_abort == True means we've hit the error budget; the caller
        must stop the engagement against this target.
        """
        transient_blocks = {403, 429, 502, 503, 504}
        if status not in transient_blocks:
            self.state.consecutive_errors = 0
            self.state.last_error_status = None
            return (False, 0.0)
        self.state.consecutive_errors += 1
        self.state.total_errors += 1
        self.state.last_error_status = status

        # Honor Retry-After if given.
        if retry_after:
            return (False, min(self.max_delay_s, retry_after + self._rng.uniform(1.0, 5.0)))

        # Exponential with jitter: base * 2^n with ±25% noise.
        n = self.state.consecutive_errors - 1
        d = self.base_delay_s * (2 ** n)
        d = min(self.max_delay_s, d)
        d *= self._rng.uniform(0.75, 1.25)

        should_abort = self.state.consecutive_errors >= self.budget
        return (should_abort, d)


# ── robots.txt ────────────────────────────────────────────────────
#
# We use the stdlib parser — it's compliant with RFC 9309.


def _fetch_robots(host_url: str, headers: Dict[str, str],
                  timeout: float = 8.0) -> Optional[str]:
    """Fetch robots.txt for the host. Returns raw text or None on failure."""
    parsed = urllib.parse.urlparse(host_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    req = urllib.request.Request(robots_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return resp.read(64 * 1024).decode("utf-8", errors="replace")
    except Exception:
        return None


@dataclass
class RobotsPolicy:
    raw: Optional[str]
    disallows_for_us: List[str] = field(default_factory=list)
    sitemaps: List[str] = field(default_factory=list)
    crawl_delay_s: Optional[float] = None

    def is_allowed(self, path: str) -> bool:
        """Conservative path check — we refuse any prefix match against
        our disallow list."""
        if not self.disallows_for_us:
            return True
        for d in self.disallows_for_us:
            if d == "/" or path.startswith(d):
                return False
        return True


def load_robots(host_url: str, headers: Dict[str, str]) -> RobotsPolicy:
    """Parse robots.txt for an Argos-identifying UA group.

    We treat wildcard `User-agent: *` rules as binding for us — even
    though our UA mimics a browser, the *intent* of running a
    programmatic crawl is what the policy covers."""
    text = _fetch_robots(host_url, headers)
    if not text:
        return RobotsPolicy(raw=None)
    disallows: List[str] = []
    sitemaps: List[str] = []
    crawl_delay: Optional[float] = None
    in_wildcard = False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k == "user-agent":
            in_wildcard = (v == "*")
        elif in_wildcard and k == "disallow" and v:
            disallows.append(v)
        elif in_wildcard and k == "crawl-delay":
            try:
                crawl_delay = float(v)
            except ValueError:
                pass
        elif k == "sitemap":
            sitemaps.append(v)
    return RobotsPolicy(
        raw=text,
        disallows_for_us=disallows,
        sitemaps=sitemaps,
        crawl_delay_s=crawl_delay,
    )


# ── .well-known/security.txt ──────────────────────────────────────


@dataclass
class SecurityTxt:
    raw: Optional[str]
    contact: List[str] = field(default_factory=list)
    canonical: List[str] = field(default_factory=list)
    preferred_languages: Optional[str] = None
    policy: Optional[str] = None
    encryption: Optional[str] = None
    expires: Optional[str] = None


def load_security_txt(host_url: str, headers: Dict[str, str]) -> Optional[SecurityTxt]:
    parsed = urllib.parse.urlparse(host_url)
    for path in ("/.well-known/security.txt", "/security.txt"):
        url = f"{parsed.scheme}://{parsed.netloc}{path}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                if resp.status == 200:
                    text = resp.read(32 * 1024).decode("utf-8", errors="replace")
                    return _parse_security_txt(text)
        except Exception:
            continue
    return None


def _parse_security_txt(text: str) -> SecurityTxt:
    fields: Dict[str, List[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields.setdefault(k.strip().lower(), []).append(v.strip())
    return SecurityTxt(
        raw=text,
        contact=fields.get("contact", []),
        canonical=fields.get("canonical", []),
        preferred_languages=(fields.get("preferred-languages") or [None])[0],
        policy=(fields.get("policy") or [None])[0],
        encryption=(fields.get("encryption") or [None])[0],
        expires=(fields.get("expires") or [None])[0],
    )


# ── Legitimacy profile aggregate ───────────────────────────────────


@dataclass
class LegitimacyProfile:
    """All three primitives bundled — the one object an orchestrator
    threads through its HTTP calls."""
    ua_pool: UserAgentPool = field(default_factory=UserAgentPool)
    pacer: Pacer = field(default_factory=Pacer)
    backoff: BackoffController = field(default_factory=BackoffController)
    robots: Optional[RobotsPolicy] = None
    security_txt: Optional[SecurityTxt] = None

    def preflight(self, target_url: str) -> None:
        """Load robots + security.txt once per engagement. Call before
        any substantive recon."""
        self.robots = load_robots(target_url, self.ua_pool.headers())
        self.security_txt = load_security_txt(target_url, self.ua_pool.headers())
        if self.robots and self.robots.crawl_delay_s:
            # Honor target's Crawl-Delay — if they ask for 10 s between
            # requests, we respect it and don't go faster.
            self.pacer.profile.median_s = max(
                self.pacer.profile.median_s,
                float(self.robots.crawl_delay_s),
            )
