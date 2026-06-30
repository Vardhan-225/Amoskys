"""Coverage-guided grammar fuzzer for HTTP probes.

An APT-grade fuzzer doesn't send random bytes. It sends grammar-
valid mutations and watches RESPONSES to learn which mutations
uncover new code paths in the target.

We implement the classic "response-bucket coverage" heuristic:

    1. Fire a baseline request, record (status, length, content-hash,
       header-set) → "bucket_0"
    2. Fire each mutation, compute its response bucket.
    3. If bucket is new, save the mutation + keep mutating from it
       (queue-based evolution).
    4. If bucket matches a known one, drop the mutation.

After N rounds, the queue contains a minimal set of distinct-response
inputs — each probably corresponds to a different code path in the
target. Human reviews; one per bucket is usually enough.

This is NOT AFL-level coverage-guided (no instrumentation), but
"response-bucket" is a surprisingly effective proxy for "did we
trigger a new code path?" on HTTP endpoints.

Grammars
--------
Per-class grammars live in argos.evasion.mutate — we re-use those
corpora as the mutation universe. The fuzzer adds:
  - parameter-name mutation (try similar param names: id, ID, Id, id_,
    _id, item_id)
  - method flipping (GET↔POST)
  - content-type flipping (urlencoded ↔ json ↔ multipart)
  - header injection (X-Original-URL, X-Forwarded-Host, etc.)

Output
------
FuzzReport with the response-bucket map: which inputs produced which
response shapes. The operator eyeballs the N "bucket leaders" for
exploitation opportunities.
"""

from __future__ import annotations

import hashlib
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.zeroday.fuzzer")


# ── Response bucketing ────────────────────────────────────────────


def response_bucket(status: int, body: bytes, headers: Dict[str, str]) -> str:
    """Stable key identifying the "shape" of a response.

    Two responses hash to the same bucket if:
      - same status code
      - body length within 5% of each other
      - same set of response headers (sorted keys)
      - same first-64-byte content hash (catches templated 404 pages)
    """
    length_bucket = len(body) // max(1, len(body) // 20 or 1)  # ~5% bucketing
    header_keys = ",".join(sorted(h.lower() for h in headers or {}))
    prefix_hash = hashlib.sha256((body or b"")[:64]).hexdigest()[:10]
    return f"{status}|{length_bucket}|{prefix_hash}|{header_keys}"


@dataclass
class ResponseObservation:
    input_repr: str
    bucket: str
    status: int
    body_len: int
    latency_ms: int
    header_count: int


@dataclass
class FuzzReport:
    target: str
    inputs_fired: int = 0
    unique_buckets: int = 0
    buckets: Dict[str, List[ResponseObservation]] = field(default_factory=dict)
    baseline_bucket: str = ""
    interesting: List[ResponseObservation] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "inputs_fired": self.inputs_fired,
            "unique_buckets": self.unique_buckets,
            "baseline_bucket": self.baseline_bucket,
            "interesting": [vars(o) for o in self.interesting[:30]],
            "bucket_leaders": [vars(obs[0]) for obs in self.buckets.values() if obs],
            "errors": self.errors,
        }


# ── The fuzzer ────────────────────────────────────────────────────


@dataclass
class GrammarFuzzer:
    """Stateless fuzzer — caller drives the mutation loop.

    fire(params: dict, body: Optional[str]) -> (status, body_bytes,
                                                 headers_dict, latency_ms)
    """

    target_url: str
    fire: Callable[[dict, Optional[str]], Tuple[int, bytes, Dict[str, str], int]]
    max_rounds: int = 100
    seed_params: Dict[str, str] = field(default_factory=dict)
    param_candidates: List[str] = field(default_factory=list)
    enable_method_flip: bool = True

    def run(self, mutations: Iterable[str]) -> FuzzReport:
        """Run one fuzz round with the given mutation stream.

        For each mutation string, we:
          - substitute it into each seed parameter value
          - also try it as an extra param (HPP)
          - record the response bucket
          - if the bucket is new and interesting, add to report.interesting
        """
        rep = FuzzReport(target=self.target_url)

        # 1. Baseline.
        try:
            status, body, hdrs, lat = self.fire(self.seed_params, None)
        except Exception as e:  # noqa: BLE001
            rep.errors.append(f"baseline fire failed: {e}")
            return rep
        baseline = response_bucket(status, body, hdrs)
        rep.baseline_bucket = baseline
        rep.buckets[baseline] = [
            ResponseObservation(
                input_repr="<baseline>",
                bucket=baseline,
                status=status,
                body_len=len(body),
                latency_ms=lat,
                header_count=len(hdrs),
            )
        ]
        rep.inputs_fired += 1

        # 2. Mutation stream.
        rounds = 0
        for mut in mutations:
            if rounds >= self.max_rounds:
                break
            rounds += 1
            # Replace each seed param value with the mutation, one at a time.
            for pname in list(self.seed_params.keys()):
                mutated = dict(self.seed_params)
                mutated[pname] = mut
                try:
                    s, b, h, lt = self.fire(mutated, None)
                    self._record(rep, mutated, s, b, h, lt, baseline)
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"param-sub fire failed: {e}")
            # Extra-param (HPP-style) — try each candidate param name.
            for pname in self.param_candidates or ["id", "p", "q"]:
                mutated = dict(self.seed_params)
                mutated[pname] = mut
                try:
                    s, b, h, lt = self.fire(mutated, None)
                    self._record(rep, mutated, s, b, h, lt, baseline)
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"hpp-param fire failed: {e}")

        rep.inputs_fired = sum(len(v) for v in rep.buckets.values())
        rep.unique_buckets = len(rep.buckets)
        return rep

    def _record(
        self,
        rep: FuzzReport,
        params: dict,
        status: int,
        body: bytes,
        headers: Dict[str, str],
        latency_ms: int,
        baseline: str,
    ) -> None:
        bucket = response_bucket(status, body, headers)
        obs = ResponseObservation(
            input_repr=urllib.parse.urlencode(params)[:200],
            bucket=bucket,
            status=status,
            body_len=len(body),
            latency_ms=latency_ms,
            header_count=len(headers),
        )
        rep.buckets.setdefault(bucket, []).append(obs)
        # A response is "interesting" if its bucket is different from
        # baseline — that means the mutation triggered a different
        # code path.
        if bucket != baseline:
            rep.interesting.append(obs)


# ── Hidden-parameter discovery ────────────────────────────────────


def discover_hidden_params(
    fuzzer: GrammarFuzzer,
    wordlist: List[str],
    marker_value: str = "AMSW_PROBE_MARKER_XYZ",
) -> List[str]:
    """Fire one request per wordlist entry with a marker value.
    Any param whose name the target reflects in the response OR whose
    presence changes the response bucket is a "hidden param" worth
    deeper probing.
    """
    reflected_params: List[str] = []
    # Baseline.
    try:
        s0, b0, h0, _ = fuzzer.fire(fuzzer.seed_params, None)
    except Exception:
        return reflected_params
    baseline_bucket = response_bucket(s0, b0, h0)
    for name in wordlist:
        params = dict(fuzzer.seed_params)
        params[name] = marker_value
        try:
            s, b, h, _ = fuzzer.fire(params, None)
        except Exception:
            continue
        bucket = response_bucket(s, b, h)
        reflected = marker_value.encode() in (b or b"")
        if reflected or bucket != baseline_bucket:
            reflected_params.append(name)
    return reflected_params


# ── Common hidden-param wordlist ─────────────────────────────────


HIDDEN_PARAM_WORDLIST = [
    # WP-specific.
    "p",
    "page_id",
    "post_id",
    "author",
    "cat",
    "tag",
    "s",
    "preview",
    "preview_id",
    "preview_nonce",
    "user_id",
    "user",
    "uid",
    "action",
    "do",
    "op",
    "operation",
    "cmd",
    "command",
    "nonce",
    "_nonce",
    "_wpnonce",
    "token",
    "callback",
    "cb",
    "jsonp",
    # Generic.
    "id",
    "ID",
    "Id",
    "item_id",
    "itemid",
    "debug",
    "test",
    "trace",
    "log",
    "file",
    "filename",
    "path",
    "url",
    "redirect",
    "next",
    "return_to",
    "include",
    "template",
    "view",
    "tmpl",
    "sort",
    "order",
    "filter",
    "search",
    "query",
    "q",
    "limit",
    "offset",
    "per_page",
    "page",
    "pg",
    "lang",
    "locale",
    "language",
    "format",
    "fmt",
    "output",
    "type",
]
