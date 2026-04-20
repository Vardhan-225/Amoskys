"""Investigate / Timeline / Graph view models.

ONE source of truth, ONE filter language, FOUR perspectives:
  - /web/investigate  → search + table + histogram + facets
  - /web/timeline     → vis-timeline lanes (one per sensor family)
  - /web/graph        → vis-network entity graph (site ↔ IPs ↔ families)
  - /web/event/<id>   → single-event drill-in with chain context

The whole module reads `events.jsonl` directly via `aegis_live.LOG_PATH`,
walks the file once per page render, applies the user's filter, then hands
off to one of the four shape-builders below. There's intentionally no
caching at this layer — Aegis logs are small (<10MB at the lab today),
and "always fresh" beats "needs invalidation" for security telemetry.

Filter language (Lucene-lite):
    severity:critical                   single value
    severity:critical,high              comma-OR within one key
    family:auth                         sensor-family (second segment of event_type)
    ip:1.2.3.4                          source IP from request.ip
    event_type:rest.poi                 substring match on event_type
    since:5m                            relative time window: 5m, 1h, 6h, 24h, 7d
    free text                           substring match on event_type

Multiple key:val pairs are AND-ed. Free text is AND-ed with everything.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .aegis_live import LOG_PATH, AEGIS_SENSOR_FAMILIES
from . import event_semantics as _ev_sem


# ─────────────────────────────────────────────────────────────────────
# Filter
# ─────────────────────────────────────────────────────────────────────

_RELATIVE_UNITS = {"m": 60, "h": 3600, "d": 86400, "s": 1}


@dataclass
class Filter:
    """Parsed query. All sets empty = no constraint on that key."""
    severities:    Set[str] = field(default_factory=set)
    families:      Set[str] = field(default_factory=set)
    ips:           Set[str] = field(default_factory=set)
    event_types:   Set[str] = field(default_factory=set)  # substring matches
    since_ms:      Optional[int] = None                   # epoch ms; older events filtered out
    free_text:     str = ""                               # substring match against event_type

    @property
    def is_empty(self) -> bool:
        return (
            not self.severities and not self.families and not self.ips
            and not self.event_types and self.since_ms is None and not self.free_text
        )

    def to_chips(self) -> List[Dict[str, str]]:
        """For the search-bar UI: render each constraint as a removable chip."""
        chips = []
        for s in sorted(self.severities):
            chips.append({"key": "severity", "value": s, "color": _sev_color(s)})
        for f in sorted(self.families):
            chips.append({"key": "family", "value": f, "color": "#00d9ff"})
        for ip in sorted(self.ips):
            chips.append({"key": "ip", "value": ip, "color": "#ffaa00"})
        for et in sorted(self.event_types):
            chips.append({"key": "event_type", "value": et, "color": "#a78bfa"})
        if self.since_ms is not None:
            secs_ago = (int(time.time() * 1000) - self.since_ms) // 1000
            chips.append({"key": "since", "value": _fmt_secs(secs_ago) + " ago", "color": "#6b7280"})
        if self.free_text:
            chips.append({"key": "text", "value": self.free_text, "color": "#6b7280"})
        return chips

    def to_query_string(self) -> str:
        """Round-trip the filter to its canonical query syntax (for URL state)."""
        parts: List[str] = []
        if self.severities:
            parts.append("severity:" + ",".join(sorted(self.severities)))
        if self.families:
            parts.append("family:" + ",".join(sorted(self.families)))
        if self.ips:
            parts.append("ip:" + ",".join(sorted(self.ips)))
        if self.event_types:
            parts.append("event_type:" + ",".join(sorted(self.event_types)))
        if self.since_ms is not None:
            secs_ago = max(1, (int(time.time() * 1000) - self.since_ms) // 1000)
            parts.append("since:" + _fmt_secs(secs_ago))
        if self.free_text:
            parts.append(self.free_text)
        return " ".join(parts)


_TOKEN_RE = re.compile(r"""("[^"]+"|\S+)""")


def parse_query(q: str, *, default_window: Optional[str] = None) -> Filter:
    """Parse a Lucene-lite query string into a `Filter`.

    Unknown keys are treated as free text. Robust to malformed input
    (returns empty filter rather than raising)."""
    flt = Filter()
    if not q:
        if default_window:
            flt.since_ms = _resolve_window_ms(default_window)
        return flt

    free_bits: List[str] = []
    for tok in _TOKEN_RE.findall(q):
        # Strip surrounding quotes if present
        if tok.startswith('"') and tok.endswith('"'):
            tok = tok[1:-1]

        if ":" not in tok:
            free_bits.append(tok)
            continue

        key, _, val = tok.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        values = [v.strip() for v in val.split(",") if v.strip()]

        if key in ("severity", "sev"):
            flt.severities.update(v.lower() for v in values)
        elif key in ("family", "fam"):
            # Accept both raw family ("auth") and dotted ("aegis.auth")
            for v in values:
                if v.startswith("aegis."):
                    flt.families.add(v.split(".", 1)[1])
                else:
                    flt.families.add(v.lower())
        elif key == "ip":
            flt.ips.update(values)
        elif key in ("event_type", "type"):
            flt.event_types.update(values)
        elif key in ("since", "last"):
            ms = _resolve_window_ms(values[0])
            if ms is not None:
                flt.since_ms = ms
        else:
            # Unknown key — treat the whole token as free text
            free_bits.append(tok)

    if free_bits:
        flt.free_text = " ".join(free_bits).strip()
    return flt


def _resolve_window_ms(spec: str) -> Optional[int]:
    """'5m' → epoch_ms 5 minutes ago. None on parse failure."""
    if not spec:
        return None
    m = re.fullmatch(r"(\d+)([smhd])", spec.strip().lower())
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2)
    secs = n * _RELATIVE_UNITS[unit]
    return int(time.time() * 1000) - secs * 1000


def _fmt_secs(secs: int) -> str:
    if secs < 60: return f"{secs}s"
    if secs < 3600: return f"{secs // 60}m"
    if secs < 86400: return f"{secs // 3600}h"
    return f"{secs // 86400}d"


def _sev_color(sev: str) -> str:
    return {
        "critical": "#dc2626",
        "high":     "#ff3366",
        "warn":     "#ffaa00",
        "info":     "#00d9ff",
    }.get(sev, "#6b7280")


# ─────────────────────────────────────────────────────────────────────
# Source — read events.jsonl directly, no in-memory cache
# ─────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────
# Parsed-events cache.
#
# The investigate / timeline / graph / event-detail pages all read the
# same JSONL log. Pre-redesign, every page render re-opened and
# re-parsed the full 93MB log — on the lab EC2 a single /web/investigate
# hit took 15-45s, which hit the worker timeout on wider time windows.
#
# This is a band-aid around the real fix (SQLite-indexed event store,
# follow-up). The cache:
#   * Keys on the log file's mtime — so on first render after new events
#     land, we do the full re-read exactly once per writer-flush cycle.
#   * Retains the full parsed list in memory for the process lifetime
#     of the cache entry. Memory cost is bounded by log size; dominant
#     consumer is the event attrs dict.
#   * Thread-safe via a short-lived lock around the rebuild, so only one
#     worker thread actually pays the parse cost when the log changes.
# ─────────────────────────────────────────────────────────────────────

_PARSED_CACHE:        Optional[List[Dict[str, Any]]] = None
_PARSED_CACHE_OFFSET: int  = 0
_PARSED_CACHE_INODE:  Optional[int] = None
_PARSED_CACHE_LOCK    = threading.Lock()


def _read_from(log_path: str, start_offset: int) -> Tuple[List[Dict[str, Any]], int]:
    """Read and parse new JSONL lines from ``start_offset`` to EOF.

    Returns (events, final_offset). Malformed lines are skipped silently;
    a trailing partial line (not yet terminated by \\n) is left for the
    next read to avoid parsing a half-written record.
    """
    out: List[Dict[str, Any]] = []
    with open(log_path, "rb") as f:
        f.seek(start_offset)
        buf = b""
        while True:
            chunk = f.read(1 * 1024 * 1024)  # 1 MB
            if not chunk:
                break
            buf += chunk
            lines = buf.split(b"\n")
            buf = lines.pop()   # keep trailing partial line
            for raw in lines:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        # We successfully consumed everything up to the partial line.
        final_offset = f.tell() - len(buf)
    return out, final_offset


def _ensure_parsed_cache(log_path: str) -> List[Dict[str, Any]]:
    """Return the parsed event list, doing only incremental work.

    Algorithm:
        * First call — read the whole file once (≈40s on a 93 MB log
          on t3.micro, one-time).
        * Subsequent calls — seek to the last offset, read only the
          delta, append to the cache. This is the key property that
          makes investigate survive under continuous Aegis writes.
        * Rotation / truncation — detected via inode change or shrunk
          size; fall back to a full re-read.

    The append uses a copy-on-write swap so concurrent iterators see a
    consistent list: we build `new_cache = old + delta` and only then
    swap the module-level reference. Old readers continue iterating
    the old reference; new readers see the new one.
    """
    global _PARSED_CACHE, _PARSED_CACHE_OFFSET, _PARSED_CACHE_INODE

    if not os.path.exists(log_path):
        return []
    try:
        st = os.stat(log_path)
    except OSError:
        return []

    # Fast path without the lock: cache exists AND we've already read past
    # the current EOF. Not perfect consistency (a write could arrive mid
    # check) but a good-enough optimistic skip for the 95% case where
    # nothing new needs to be ingested right this instant.
    if (
        _PARSED_CACHE is not None
        and _PARSED_CACHE_INODE == st.st_ino
        and _PARSED_CACHE_OFFSET >= st.st_size
    ):
        return _PARSED_CACHE

    with _PARSED_CACHE_LOCK:
        # Re-stat under lock to avoid acting on a stale decision; file could
        # have grown while we waited for the lock.
        try:
            st = os.stat(log_path)
        except OSError:
            return _PARSED_CACHE or []

        # Rotation or truncation → wipe and re-read from the top.
        if (
            _PARSED_CACHE is None
            or _PARSED_CACHE_INODE != st.st_ino
            or st.st_size < _PARSED_CACHE_OFFSET
        ):
            events, final_offset = _read_from(log_path, 0)
            _PARSED_CACHE = events
            _PARSED_CACHE_OFFSET = final_offset
            _PARSED_CACHE_INODE = st.st_ino
            return _PARSED_CACHE

        # Incremental: just read the delta.
        if st.st_size > _PARSED_CACHE_OFFSET:
            new_events, final_offset = _read_from(log_path, _PARSED_CACHE_OFFSET)
            if new_events:
                # Copy-on-write swap so concurrent readers of the old ref
                # don't see torn state.
                _PARSED_CACHE = _PARSED_CACHE + new_events
            _PARSED_CACHE_OFFSET = final_offset

        return _PARSED_CACHE


def iter_all_events(*, log_path: str = LOG_PATH) -> Iterable[Dict[str, Any]]:
    """Yield every event in the JSONL log, oldest-first.

    Served from an incremental-append cache so we don't re-parse 93 MB
    of JSON on every page render. The first render after process start
    pays a one-time parse cost; subsequent renders only read the bytes
    added since the last call.
    """
    return iter(_ensure_parsed_cache(log_path))


def _family_of(event_type: str) -> str:
    parts = (event_type or "").split(".")
    return parts[1] if len(parts) >= 2 else "?"


# ─────────────────────────────────────────────────────────────────────
# The filter engine — applied to the raw event stream
# ─────────────────────────────────────────────────────────────────────

def matches(ev: Dict[str, Any], f: Filter) -> bool:
    """Test one event against a filter. Hot path — keep cheap."""
    if f.severities and ev.get("severity") not in f.severities:
        return False
    if f.families:
        if _family_of(ev.get("event_type", "")) not in f.families:
            return False
    if f.ips:
        ip = (ev.get("request") or {}).get("ip")
        if ip not in f.ips:
            return False
    if f.event_types:
        et = ev.get("event_type", "") or ""
        if not any(needle in et for needle in f.event_types):
            return False
    if f.since_ms is not None:
        ts_ns = ev.get("event_timestamp_ns") or 0
        if ts_ns // 1_000_000 < f.since_ms:
            return False
    if f.free_text:
        et = ev.get("event_type", "") or ""
        if f.free_text.lower() not in et.lower():
            return False
    return True


def collect(filter_: Filter, *, cap: int = 5000) -> List[Dict[str, Any]]:
    """Walk the JSONL once, return matching events up to `cap`."""
    out: List[Dict[str, Any]] = []
    for ev in iter_all_events():
        if matches(ev, filter_):
            out.append(ev)
            if len(out) >= cap:
                # Once we exceed the cap, keep walking — but the cap is a
                # signal to the UI ("> 5000 results, refine your query").
                pass
    return out


# ─────────────────────────────────────────────────────────────────────
# Shape builder #1 — investigation page (rich result + facets)
# ─────────────────────────────────────────────────────────────────────

@dataclass
class InvestigateResult:
    total:       int
    capped:      bool
    rows:        List[Dict[str, Any]]      # newest-first event view-models
    histogram:   List[Dict[str, Any]]      # bucketed for the strip chart
    facets:      Dict[str, List[Dict[str, Any]]]   # field → top values w/ counts
    severities:  Dict[str, int]            # for the colored summary tiles
    families:    Dict[str, int]
    chain_ok:    int
    chain_breaks: int


_BUILD_CACHE: Dict[Tuple[str, int, int], Tuple[int, "InvestigateResult"]] = {}
_BUILD_CACHE_TTL_SEC = 15.0
_BUILD_CACHE_MAX = 100
_BUILD_CACHE_LOCK = threading.Lock()


def _filter_cache_key(f: "Filter", page_size: int, hist_bins: int) -> Tuple[str, int, int]:
    """Stable hashable identity for a filter — used as build-cache key."""
    parts = [
        "sev:" + ",".join(sorted(f.severities)),
        "fam:" + ",".join(sorted(f.families)),
        "ip:"  + ",".join(sorted(f.ips)),
        "et:"  + ",".join(sorted(f.event_types)),
        "since:" + str(f.since_ms or ""),
        "q:"   + f.free_text,
    ]
    return ("|".join(parts), page_size, hist_bins)


def build_investigate(filter_: Filter, *, page_size: int = 200, hist_bins: int = 60) -> InvestigateResult:
    """Apply `filter_` and return everything the /web/investigate page needs.

    Result is memoised for 15 s keyed on the filter; repeat hits with the
    same query (e.g. from the auto-refresh JSON endpoint, or a user
    hitting back/forward) skip the O(N) facet+histogram rebuild. The TTL
    is short on purpose — investigation is a post-hoc view, a few seconds
    of staleness is fine, anything older feels wrong.
    """
    now_s = int(time.time())
    cache_key = _filter_cache_key(filter_, page_size, hist_bins)
    cached = _BUILD_CACHE.get(cache_key)
    if cached is not None and (now_s - cached[0]) < _BUILD_CACHE_TTL_SEC:
        return cached[1]

    matches_all = collect(filter_, cap=20_000)
    capped = len(matches_all) >= 20_000

    rows: List[Dict[str, Any]] = []
    severities: Counter[str] = Counter()
    families:   Counter[str] = Counter()
    ip_counts:  Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    chain_ok = 0
    chain_breaks = 0

    # Walk again for chain integrity (need adjacent prev_sig comparison)
    prev_sig: Optional[str] = None
    for ev in iter_all_events():
        # Walk in order so chain check is right; only "match" rows go in `rows`
        if prev_sig is None:
            chain_ok_inc = (ev.get("prev_sig") in (None, ""))
        else:
            chain_ok_inc = (ev.get("prev_sig") == prev_sig)
        if chain_ok_inc:
            chain_ok += 1
        else:
            chain_breaks += 1
        prev_sig = ev.get("sig")

        if not matches(ev, filter_):
            continue

        sev = ev.get("severity", "info")
        fam = _family_of(ev.get("event_type", ""))
        severities[sev] += 1
        families[fam] += 1
        ip = (ev.get("request") or {}).get("ip")
        if ip and ip not in ("127.0.0.1", "::1"):
            ip_counts[ip] += 1
        type_counts[ev.get("event_type", "?")] += 1

        rows.append(_event_view(ev))

    # Newest-first for display
    rows.sort(key=lambda r: r.get("ts_ms", 0), reverse=True)
    visible = rows[:page_size]

    histogram = build_histogram(matches_all, bins=hist_bins)

    facets = {
        "severity":   _facet(severities, formatter=lambda k: k),
        "family":     _facet(families,   formatter=lambda k: k),
        "ip":         _facet(ip_counts,  formatter=lambda k: k, top=12),
        "event_type": _facet(type_counts, formatter=lambda k: k, top=12),
    }

    result = InvestigateResult(
        total=len(matches_all),
        capped=capped,
        rows=visible,
        histogram=histogram,
        facets=facets,
        severities=dict(severities),
        families=dict(families),
        chain_ok=chain_ok,
        chain_breaks=chain_breaks,
    )

    # Memoise under a short TTL. See module-level _BUILD_CACHE docstring.
    with _BUILD_CACHE_LOCK:
        _BUILD_CACHE[cache_key] = (now_s, result)
        # LRU-ish prune: oldest timestamp evicted first.
        if len(_BUILD_CACHE) > _BUILD_CACHE_MAX:
            oldest_key = min(_BUILD_CACHE.items(), key=lambda kv: kv[1][0])[0]
            _BUILD_CACHE.pop(oldest_key, None)

    return result


def _event_view(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Compact view-model used by templates + JSON endpoints.

    Enriched with the event_semantics layer so the investigate table can
    show "Failed admin login" instead of `aegis.auth.login_failed`,
    along with a concern level, category, verdict icon, and optional
    operator action hint. The raw event_type is kept too so power users
    can still see exactly what hook fired.
    """
    req = ev.get("request") or {}
    ts_ns = ev.get("event_timestamp_ns") or 0
    sig = ev.get("sig") or ""
    et = ev.get("event_type", "")
    meaning = _ev_sem.meaning_for(et)
    return {
        "event_id":   ev.get("event_id"),
        "event_type": et,
        "family":     _family_of(et),
        "severity":   ev.get("severity", "info"),
        "ts_ns":      ts_ns,
        "ts_ms":      ts_ns // 1_000_000 if ts_ns else 0,
        "site_id":    ev.get("site_id"),
        "schema":     ev.get("schema_version", "?"),
        "request": {
            "method": req.get("method"),
            "uri":    req.get("uri"),
            "ip":     req.get("ip"),
            "ua":     (req.get("ua") or "")[:120],
        },
        "attributes": ev.get("attributes") or {},
        "sig":        sig,
        "sig_short":  sig[:10] if sig else "",
        "prev_sig":   ev.get("prev_sig"),
        # ── Natural-English layer ──
        "phrase":     meaning.phrase,
        "detail":     meaning.detail,
        "concern":    meaning.concern,
        "category":   meaning.category,
        "verdict":    meaning.verdict,
        "action":     meaning.action,
        "audience":   meaning.audience,
    }


def _facet(counter: Counter, *, formatter, top: int = 8) -> List[Dict[str, Any]]:
    items = counter.most_common(top)
    if not items:
        return []
    max_n = items[0][1] or 1
    return [
        {
            "value": formatter(k),
            "count": n,
            "pct":   round(100 * n / max_n, 1),
        }
        for k, n in items
    ]


# ─────────────────────────────────────────────────────────────────────
# Shape builder #2 — histogram (events over time, bucketed)
# ─────────────────────────────────────────────────────────────────────

def build_histogram(events: List[Dict[str, Any]], *, bins: int = 60) -> List[Dict[str, Any]]:
    """Bucket events by time. Window is [first_event, last_event] of the matched set,
    or the user's `since:` window if specified (handled implicitly via the events list)."""
    if not events:
        return []
    timestamps = [int(e.get("event_timestamp_ns") or 0) // 1_000_000 for e in events]
    timestamps = [t for t in timestamps if t > 0]
    if not timestamps:
        return []
    t_min = min(timestamps)
    t_max = max(timestamps)
    if t_max == t_min:
        # Single-instant edge case; centre a single bucket around it.
        t_min -= 1000
        t_max += 1000
    bin_ms = max(1, (t_max - t_min) // bins)
    buckets: Dict[int, Dict[str, int]] = defaultdict(lambda: {"info": 0, "warn": 0, "high": 0, "critical": 0})
    for ev in events:
        ts = int(ev.get("event_timestamp_ns") or 0) // 1_000_000
        if ts <= 0:
            continue
        idx = min(bins - 1, (ts - t_min) // bin_ms)
        sev = ev.get("severity", "info")
        if sev not in buckets[idx]:
            buckets[idx][sev] = 0
        buckets[idx][sev] += 1

    out = []
    for i in range(bins):
        b = buckets.get(i, {"info": 0, "warn": 0, "high": 0, "critical": 0})
        out.append({
            "ts_ms":   t_min + i * bin_ms,
            "info":     b.get("info", 0),
            "warn":     b.get("warn", 0),
            "high":     b.get("high", 0),
            "critical": b.get("critical", 0),
            "total":    sum(b.values()),
        })
    return out


# ─────────────────────────────────────────────────────────────────────
# Shape builder #3 — vis-timeline data (groups + items)
# ─────────────────────────────────────────────────────────────────────

def build_timeline(events: List[Dict[str, Any]], *, max_items: int = 1500) -> Dict[str, Any]:
    """vis-timeline format: { groups: [...], items: [...] }.

    Groups are sensor families (one lane each). Items are events colored
    by severity. Capped to `max_items` newest to keep the DOM lean."""
    # Newest-first, then truncate
    events = sorted(events, key=lambda e: int(e.get("event_timestamp_ns") or 0), reverse=True)
    if len(events) > max_items:
        events = events[:max_items]

    # Stable group ordering: catalog order, with families that have events first
    fam_in_use = {_family_of(e.get("event_type", "")) for e in events}
    catalog_order = [f.split(".", 1)[1] for f in AEGIS_SENSOR_FAMILIES.keys()]
    groups_ordered = [f for f in catalog_order if f in fam_in_use]
    # Add any family present that wasn't in the catalog (defensive)
    for f in sorted(fam_in_use):
        if f not in groups_ordered:
            groups_ordered.append(f)

    groups = [
        {"id": f, "content": f, "title": AEGIS_SENSOR_FAMILIES.get(f"aegis.{f}", "")}
        for f in groups_ordered
    ]

    items = []
    for ev in events:
        ts_ns = int(ev.get("event_timestamp_ns") or 0)
        if not ts_ns:
            continue
        sev = ev.get("severity", "info")
        et = ev.get("event_type", "?")
        fam = _family_of(et)
        ip = (ev.get("request") or {}).get("ip") or ""
        items.append({
            "id":      ev.get("event_id") or f"{ts_ns}",
            "group":   fam,
            "start":   ts_ns // 1_000_000,
            "type":    "point",
            "title":   f"{et} · {sev}{(' · ' + ip) if ip else ''}",
            "className": f"vis-sev-{sev}",
            "severity": sev,
            "event_id": ev.get("event_id"),
        })
    return {"groups": groups, "items": items, "truncated": len(items) >= max_items}


# ─────────────────────────────────────────────────────────────────────
# Shape builder #4 — vis-network entity graph (nodes + edges)
# ─────────────────────────────────────────────────────────────────────

def build_graph(events: List[Dict[str, Any]], *, top_ips: int = 30) -> Dict[str, Any]:
    """Three-tier graph: site (centre) ← family nodes ← top external IPs.

    Edge weight = co-occurrence count. Edge colour = worst severity seen
    on that pairing.
    """
    site_id = next((e.get("site_id") for e in events if e.get("site_id")), "site")
    site_url = next((e.get("site_url") for e in events if e.get("site_url")), site_id)

    ip_counts: Counter[str] = Counter()
    fam_counts: Counter[str] = Counter()
    ip_fam_count: Counter[Tuple[str, str]] = Counter()
    fam_severity: Dict[str, str] = {}
    ip_severity: Dict[str, str] = {}

    sev_rank = {"critical": 4, "high": 3, "warn": 2, "info": 1}

    for ev in events:
        ip = (ev.get("request") or {}).get("ip") or ""
        if ip in ("127.0.0.1", "::1", ""):
            ip = ""
        fam = _family_of(ev.get("event_type", ""))
        sev = ev.get("severity", "info")
        fam_counts[fam] += 1
        if sev_rank.get(sev, 0) > sev_rank.get(fam_severity.get(fam, "info"), 0):
            fam_severity[fam] = sev
        if ip:
            ip_counts[ip] += 1
            ip_fam_count[(ip, fam)] += 1
            if sev_rank.get(sev, 0) > sev_rank.get(ip_severity.get(ip, "info"), 0):
                ip_severity[ip] = sev

    keep_ips = {ip for ip, _ in ip_counts.most_common(top_ips)}

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # 1. Site node (centre)
    nodes.append({
        "id":      f"site::{site_id}",
        "label":   site_url or site_id,
        "group":   "site",
        "shape":   "diamond",
        "color":   {"background": "#00d9ff", "border": "#00b8d4"},
        "size":    32,
        "font":    {"color": "#00d9ff", "size": 14, "face": "Inter"},
        "title":   f"Customer site (events: {len(events)})",
    })

    # 2. Family nodes — connect each to site
    for fam, n in fam_counts.most_common():
        col = _sev_color(fam_severity.get(fam, "info"))
        nodes.append({
            "id":     f"fam::{fam}",
            "label":  fam,
            "group":  "family",
            "shape":  "dot",
            "color":  {"background": col, "border": col},
            "size":   max(8, min(24, 6 + (n ** 0.5))),
            "font":   {"color": "#fff", "size": 11, "face": "JetBrains Mono"},
            "title":  f"{AEGIS_SENSOR_FAMILIES.get(f'aegis.{fam}', '')} — {n} events",
        })
        edges.append({
            "from":   f"fam::{fam}",
            "to":     f"site::{site_id}",
            "value":  n,
            "color":  {"color": col, "opacity": 0.4},
            "title":  f"{n} events",
        })

    # 3. IP nodes — connect each to its dominant family/families
    for ip in keep_ips:
        sev = ip_severity.get(ip, "info")
        col = _sev_color(sev)
        nodes.append({
            "id":     f"ip::{ip}",
            "label":  ip,
            "group":  "ip",
            "shape":  "dot",
            "color":  {"background": col, "border": col},
            "size":   max(6, min(18, 4 + (ip_counts[ip] ** 0.4))),
            "font":   {"color": col, "size": 10, "face": "JetBrains Mono"},
            "title":  f"{ip} — {ip_counts[ip]} events, worst severity {sev}",
        })

    for (ip, fam), n in ip_fam_count.items():
        if ip not in keep_ips:
            continue
        col = _sev_color(ip_severity.get(ip, "info"))
        edges.append({
            "from":   f"ip::{ip}",
            "to":     f"fam::{fam}",
            "value":  n,
            "color":  {"color": col, "opacity": 0.6},
            "title":  f"{n} events",
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "site_id": site_id,
        "site_url": site_url,
        "ip_total": sum(ip_counts.values()),
        "ip_unique": len(ip_counts),
    }


# ─────────────────────────────────────────────────────────────────────
# Shape builder #5 — single-event drill-in
# ─────────────────────────────────────────────────────────────────────

def find_event(event_id: str) -> Optional[Dict[str, Any]]:
    """Linear scan of the JSONL — fine at this scale, eliminates an index."""
    for ev in iter_all_events():
        if ev.get("event_id") == event_id:
            return ev
    return None


def find_event_with_neighbors(event_id: str) -> Tuple[Optional[Dict[str, Any]],
                                                     Optional[Dict[str, Any]],
                                                     Optional[Dict[str, Any]]]:
    """Return (prev, target, next) for the chain context view."""
    target = None
    prev = None
    next_ = None
    last_seen: Optional[Dict[str, Any]] = None
    found = False
    for ev in iter_all_events():
        if found:
            next_ = ev
            break
        if ev.get("event_id") == event_id:
            target = ev
            prev = last_seen
            found = True
            continue
        last_seen = ev
    return prev, target, next_


def verify_sig(ev: Dict[str, Any]) -> Tuple[bool, str]:
    """Re-compute the sig server-side; return (ok, recomputed_sig)."""
    import hashlib
    body = {k: v for k, v in ev.items() if k != "sig"}
    canonical = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return (expected == ev.get("sig", "")), expected
