"""Aegis live-event reader — the real feed from the WordPress plugin.

This is what makes the Command Center a *command center* instead of a
mock dashboard. It reads the actual events.jsonl that the Aegis plugin
writes to, computes summary stats, verifies chain integrity, and gives
the operator everything the plugin is watching in real time.

Deployed at /opt/amoskys-web/src/app/web_product/aegis_live.py — pulled
from this canonical file in the repo under
deploy/web/command-center/aegis_live.py.

Zero coupling to the WP plugin beyond the file path — if you change
Aegis's log location or format, this file updates, nothing else.

Architecture (2026-04 rewrite):
    Previously `snapshot()` re-opened and re-parsed the entire JSONL log
    on every request. This became untenable at ~100 MB / 140k events
    where it blew past gunicorn's worker timeout (→ 504 storms).

    Now:
      * A background daemon thread (``_IngestLoop``) seeks from the last
        byte offset it read, parses only the delta, and updates the
        in-process state in place. Bounded CPU and memory, O(Δ lines)
        per tick instead of O(N).
      * The first iteration after startup does the catch-up scan
        (~10 s one-time for a 100 MB file on t3.micro). Subsequent ticks
        typically process zero-to-dozens of lines.
      * File rotation / truncation is detected via inode + size and
        triggers a safe re-scan from offset 0.
      * ``snapshot()`` reads the shared state under a short-lived lock,
        builds a lightweight view, and caches it for ``_CACHE_TTL_SEC``
        so bursts of polling clients (dashboard auto-refresh, globe
        pings, etc.) converge to a single read.
      * Public surface (LiveSnapshot, AegisTail.snapshot, AEGIS_SENSOR_
        FAMILIES) is unchanged — this is a transparent upgrade.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Where the Aegis plugin writes its JSONL log. Override with env var.
DEFAULT_LOG_PATH = "/var/www/html/wp-content/uploads/amoskys-aegis/events.jsonl"
LOG_PATH = os.environ.get("AMOSKYS_AEGIS_LOG", DEFAULT_LOG_PATH)

# How many tail events we keep in-memory for quick display.
TAIL_WINDOW = 200

# Per-severity tail (how many recent events to keep grouped by severity).
TAIL_BY_SEVERITY = 50

# TTL for the cached snapshot. Two seconds means a dashboard auto-refreshing
# at 1 Hz converges to ~0.5 cache-miss per second at worst, which is fine.
_CACHE_TTL_SEC = 2.0

# How long the background ingester sleeps between iterations.
# During initial catch-up we don't sleep at all — we just keep reading
# until we hit EOF once. Steady-state poll = 1s.
_IDLE_POLL_SEC = 1.0

# Active-defense and supply-chain windows (seconds from now).
_BLOCK_WINDOW_SEC = 600          # 10 min, matches plugin BLOCK_DURATION_SEC
_DRIFT_WINDOW_SEC = 24 * 3600    # 24 h

# For building the request ring-buffer's view-model (truncation budgets).
_URI_DISPLAY_LEN = 80
_UA_DISPLAY_LEN  = 60
_UA_COUNT_LEN    = 80
_SIG_DISPLAY_LEN = 16

# Threshold below which we do the first-scan synchronously inline. At or
# above it we let the background thread do the scan so the caller doesn't
# hang. 10 MB is about 15k events which parses in well under a second on
# the EC2 t3.micro.
_INLINE_FIRSTSCAN_BYTES = 10 * 1024 * 1024


@dataclass
class LiveSnapshot:
    """Everything the Command Center needs for one render.

    This is an immutable-by-convention view-model — the dashboard renders
    directly from it and AegisTail never hands the same instance twice
    to a caller (the caches hold references, but callers get read-only
    dicts/lists and should treat them as snapshot-at-a-moment).
    """

    total_events: int
    last_event_ns: Optional[int]
    read_at_ns: int
    event_types: Dict[str, int]
    severities: Dict[str, int]
    sensors: Dict[str, int]
    external_ips: Dict[str, int]
    user_agents: Dict[str, int]
    chain_ok: int
    chain_breaks: int
    chain_first_sig: Optional[str]
    chain_last_sig: Optional[str]
    recent: List[Dict[str, Any]] = field(default_factory=list)
    by_severity_recent: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    # v0.4 — active defense + supply chain
    active_blocks: List[Dict[str, Any]] = field(default_factory=list)
    blocks_started_count: int = 0
    blocks_enforced_count: int = 0
    supply_chain_drift: List[Dict[str, Any]] = field(default_factory=list)
    supply_chain_last_cycle: Optional[Dict[str, Any]] = None
    # Ingest-pipeline health (new, useful for ops / debug but cheap to carry).
    ingest_caught_up: bool = False      # True once first full scan completed
    ingest_last_offset: int = 0         # byte offset we've read up to
    ingest_file_bytes: int = 0          # current size on disk
    ingest_lag_bytes: int = 0           # max(0, file_bytes - last_offset)


# ─────────────────────────────────────────────────────────────────────
# Internal state carried between ticks of the background ingester.
# Owned by AegisTail; never leaks out. Mutations happen under _lock.
# ─────────────────────────────────────────────────────────────────────


class _IngestState:
    __slots__ = (
        "event_types", "severities", "sensors",
        "external_ips", "user_agents",
        "ring", "recent_by_sev",
        "chain_ok", "chain_breaks",
        "first_sig", "last_sig", "prev_sig",
        "total", "last_event_ns",
        "active_blocks_by_ip",
        "blocks_started_events",
        "blocks_enforced_events",
        "drift_events",
        "last_supply_cycle",
        "last_offset", "last_inode", "last_size",
        "caught_up",
        "errors",
    )

    def __init__(self) -> None:
        self.event_types: Counter = Counter()
        self.severities: Counter = Counter()
        self.sensors: Counter = Counter()
        self.external_ips: Counter = Counter()
        self.user_agents: Counter = Counter()
        self.ring: deque = deque(maxlen=TAIL_WINDOW)
        self.recent_by_sev: Dict[str, deque] = {}

        self.chain_ok: int = 0
        self.chain_breaks: int = 0
        self.first_sig: Optional[str] = None
        self.last_sig: Optional[str] = None
        self.prev_sig: Optional[str] = None

        self.total: int = 0
        self.last_event_ns: Optional[int] = None

        # Active-defense state.
        #
        # We store (ts_sec, ip, block_data) tuples in deques so we can
        # efficiently prune elements older than BLOCK_WINDOW on each snapshot.
        # ``active_blocks_by_ip`` is the materialized "currently blocked"
        # table — rebuilt from the deque during pruning.
        self.active_blocks_by_ip: Dict[str, Dict[str, Any]] = {}
        self.blocks_started_events: deque = deque()
        self.blocks_enforced_events: deque = deque()

        # Supply-chain drift: dedup by (slug, drift_type) keeping the most
        # recent. Pruned by DRIFT_WINDOW.
        self.drift_events: deque = deque()
        self.last_supply_cycle: Optional[Dict[str, Any]] = None

        # Tail state.
        self.last_offset: int = 0
        self.last_inode: Optional[int] = None
        self.last_size: int = 0
        self.caught_up: bool = False

        # Bounded list of recent parsing/ingest errors for ops visibility.
        self.errors: deque = deque(maxlen=20)


# ─────────────────────────────────────────────────────────────────────
# Event → state update. This is the hot path; keep it tight.
# ─────────────────────────────────────────────────────────────────────


def _process_event(state: _IngestState, e: Dict[str, Any], now_sec: float) -> None:
    state.total += 1
    et = e.get("event_type") or "unknown"
    sev = e.get("severity") or "unknown"
    state.event_types[et] += 1
    state.severities[sev] += 1

    # Sensor family = first two segments of event_type.
    parts = et.split(".")
    if len(parts) >= 2:
        state.sensors[f"{parts[0]}.{parts[1]}"] += 1

    req = e.get("request") or {}
    ip = req.get("ip") or ""
    ua = req.get("ua") or ""
    if ip and ip not in ("127.0.0.1", "::1", "localhost"):
        state.external_ips[ip] += 1
    if ua:
        state.user_agents[ua[:_UA_COUNT_LEN]] += 1

    # Chain integrity — preserved as-is from the legacy implementation.
    submitted_prev = e.get("prev_sig")
    if submitted_prev == state.prev_sig or (
        not submitted_prev and not state.prev_sig
    ):
        state.chain_ok += 1
    else:
        state.chain_breaks += 1
    this_sig = e.get("sig")
    state.prev_sig = this_sig
    state.last_sig = this_sig
    if state.first_sig is None:
        state.first_sig = this_sig

    event_ns = e.get("event_timestamp_ns")
    if event_ns:
        state.last_event_ns = event_ns

    # Active-defense + supply-chain rollups.
    attrs = e.get("attributes") or {}
    event_sec = (event_ns or 0) / 1e9

    if et == "aegis.block.started":
        ip_ = attrs.get("ip") or ""
        if ip_:
            block_data = {
                "ip": ip_,
                "rule": attrs.get("rule"),
                "strikes": attrs.get("strikes"),
                "blocked_since": int(event_sec),
                "ttl_sec": attrs.get("ttl_sec", _BLOCK_WINDOW_SEC),
            }
            state.blocks_started_events.append((event_sec, ip_, block_data))
            state.active_blocks_by_ip[ip_] = block_data
    elif et == "aegis.block.enforced":
        state.blocks_enforced_events.append((event_sec, attrs.get("ip") or ""))
    elif et == "aegis.supply_chain.drift":
        state.drift_events.append((event_sec, {
            "slug": attrs.get("slug"),
            "drift_type": attrs.get("drift_type"),
            "reason": attrs.get("reason"),
            "remote_ver": attrs.get("remote_ver"),
            "author": attrs.get("author"),
            "ts_sec": int(event_sec),
        }))
    elif et == "aegis.supply_chain.cycle":
        state.last_supply_cycle = {
            "installed": attrs.get("installed"),
            "checked": attrs.get("checked"),
            "drift_count": attrs.get("drift_count"),
            "ts_sec": int(event_sec),
        }

    # Compact view-model for the display ring-buffer.
    view = {
        "event_type": et,
        "severity": sev,
        "ts_ns": event_ns,
        "site_id": e.get("site_id"),
        "sig_short": (this_sig or "")[:10],
        "request": {
            "method": req.get("method"),
            "uri": (req.get("uri") or "")[:_URI_DISPLAY_LEN],
            "ip": ip,
            "ua": ua[:_UA_DISPLAY_LEN],
        },
        "attributes": attrs,
    }
    state.ring.append(view)

    # Per-severity ring is useful for the "critical tail" widget without
    # making callers filter client-side.
    sev_deque = state.recent_by_sev.get(sev)
    if sev_deque is None:
        sev_deque = deque(maxlen=TAIL_BY_SEVERITY)
        state.recent_by_sev[sev] = sev_deque
    sev_deque.append(view)


def _prune_time_windowed(state: _IngestState, now_sec: float) -> None:
    """Drop active-defense and drift entries that have aged out of their
    respective windows. O(k) where k = entries that aged out this tick."""

    # blocks.started — when aged out, also remove from active_blocks_by_ip
    # if that IP's latest block_data matches.
    while state.blocks_started_events:
        ev_sec, ip_, block_data = state.blocks_started_events[0]
        if now_sec - ev_sec >= _BLOCK_WINDOW_SEC:
            state.blocks_started_events.popleft()
            # Only expire the IP entry if it still references this block.
            # (A newer block on the same IP would have replaced it.)
            if state.active_blocks_by_ip.get(ip_) is block_data:
                state.active_blocks_by_ip.pop(ip_, None)
        else:
            break

    while state.blocks_enforced_events:
        ev_sec, _ip = state.blocks_enforced_events[0]
        if now_sec - ev_sec >= _BLOCK_WINDOW_SEC:
            state.blocks_enforced_events.popleft()
        else:
            break

    while state.drift_events:
        ev_sec, _d = state.drift_events[0]
        if now_sec - ev_sec >= _DRIFT_WINDOW_SEC:
            state.drift_events.popleft()
        else:
            break


# ─────────────────────────────────────────────────────────────────────
# AegisTail — public class.
# ─────────────────────────────────────────────────────────────────────


class AegisTail:
    """Incremental JSONL tailer with TTL-cached snapshot.

    Thread-safe. Safe to instantiate as a module-level singleton. The
    ingester starts lazily on first ``snapshot()`` call — this matters
    for gunicorn sync-worker processes where post-fork state is per
    worker, and we don't want every gunicorn worker to spawn a thread at
    import time if the dashboard is never opened.
    """

    def __init__(
        self,
        log_path: str = LOG_PATH,
        window: int = TAIL_WINDOW,
        cache_ttl_sec: float = _CACHE_TTL_SEC,
    ) -> None:
        self.log_path = log_path
        self.window = window
        self._cache_ttl_sec = cache_ttl_sec

        self._lock = threading.Lock()
        self._state = _IngestState()
        self._state.ring = deque(maxlen=window)

        self._cached: Optional[LiveSnapshot] = None
        self._cached_at: float = 0.0

        self._ingester_started: bool = False
        self._ingester_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ───────────── Public API ─────────────

    def snapshot(self, severity_filter: Optional[str] = None) -> LiveSnapshot:
        """Return a LiveSnapshot. Non-blocking on the request path."""
        self._ensure_ingester()

        # TTL cache short-circuit — only for the unfiltered snapshot.
        now = time.time()
        if (
            severity_filter is None
            and self._cached is not None
            and (now - self._cached_at) < self._cache_ttl_sec
        ):
            return self._cached

        snap = self._build_snapshot(severity_filter=severity_filter)
        if severity_filter is None:
            self._cached = snap
            self._cached_at = now
        return snap

    def stop(self) -> None:
        """Signal the ingester to stop (for clean shutdown / tests)."""
        self._stop_event.set()

    # ───────────── Ingester lifecycle ─────────────

    def _ensure_ingester(self) -> None:
        if self._ingester_started:
            return
        with self._lock:
            if self._ingester_started:
                return
            self._ingester_started = True

            # For small logs, do an inline first scan so the first dashboard
            # render after process start already has populated stats. For
            # large logs, let the background thread do the catch-up.
            try:
                size = os.path.getsize(self.log_path) if os.path.exists(self.log_path) else 0
            except OSError:
                size = 0

            if 0 < size <= _INLINE_FIRSTSCAN_BYTES:
                try:
                    self._ingest_once()
                except Exception as exc:  # noqa: BLE001
                    self._state.errors.append(f"inline-firstscan: {type(exc).__name__}: {exc}")

            t = threading.Thread(
                target=self._ingest_loop,
                name="aegis-ingest",
                daemon=True,
            )
            self._ingester_thread = t
            t.start()

    def _ingest_loop(self) -> None:
        """Background daemon: catch up, then steady-state poll forever."""
        while not self._stop_event.is_set():
            try:
                did_work = self._ingest_once()
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._state.errors.append(
                        f"ingest: {type(exc).__name__}: {exc}"
                    )
                did_work = False

            # If we read new lines, loop again immediately (catch-up mode).
            # When idle, sleep. This keeps the thread's footprint zero
            # when the log is quiet.
            if not did_work:
                self._stop_event.wait(timeout=_IDLE_POLL_SEC)

    def _ingest_once(self) -> bool:
        """One scan: read from last offset to EOF. Returns True if we
        processed at least one line, False if the log was empty/unchanged."""

        if not os.path.exists(self.log_path):
            return False

        try:
            st = os.stat(self.log_path)
        except OSError:
            return False

        with self._lock:
            # Detect rotation / truncation.
            if self._state.last_inode is not None and st.st_ino != self._state.last_inode:
                self._reset_tail_position_locked()
            elif st.st_size < self._state.last_offset:
                self._reset_tail_position_locked()

            self._state.last_inode = st.st_ino
            self._state.last_size = st.st_size

            if st.st_size == self._state.last_offset:
                # Nothing new.
                self._state.caught_up = True
                return False

            offset_at_entry = self._state.last_offset

        # Read outside the lock so other threads can still snapshot() on
        # cached state while we're doing I/O. We'll apply the delta under
        # the lock in one shot.
        processed: List[Dict[str, Any]] = []
        errors_local: List[str] = []
        final_offset = offset_at_entry

        try:
            with open(self.log_path, "rb") as f:
                f.seek(offset_at_entry)
                # Read in chunks to bound memory, reassemble lines.
                buf = b""
                while True:
                    chunk = f.read(1 * 1024 * 1024)  # 1 MB per read
                    if not chunk:
                        break
                    buf += chunk
                    lines = buf.split(b"\n")
                    buf = lines.pop()  # last element is partial or empty
                    for raw in lines:
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            processed.append(json.loads(raw))
                        except json.JSONDecodeError:
                            errors_local.append("json-decode")
                    # Budget: if we've already got a big batch, flush mid-stream
                    # so the dashboard can see progress during catch-up of a
                    # 100 MB log.
                    if len(processed) >= 5000:
                        final_offset = f.tell() - len(buf)
                        self._apply_batch_locked(processed, errors_local, final_offset)
                        processed.clear()
                        errors_local.clear()
                # End-of-file reached. If there's a leftover partial line
                # it's probably a half-written record — leave it for the
                # next tick (don't advance past it).
                final_offset = f.tell() - len(buf)
        except OSError as exc:
            errors_local.append(f"read: {type(exc).__name__}: {exc}")
            final_offset = offset_at_entry

        if processed or errors_local:
            self._apply_batch_locked(processed, errors_local, final_offset)
            return True

        # No data processed, but offset may have advanced past whitespace.
        with self._lock:
            self._state.last_offset = final_offset
        return False

    def _reset_tail_position_locked(self) -> None:
        """Called when we detect rotation/truncation. Clears counters so
        they re-accumulate from the new file state."""
        self._state.last_offset = 0
        self._state.last_inode = None
        # Reset cumulative state. Time-windowed structures will repopulate
        # naturally from re-read events.
        self._state.event_types.clear()
        self._state.severities.clear()
        self._state.sensors.clear()
        self._state.external_ips.clear()
        self._state.user_agents.clear()
        self._state.ring.clear()
        self._state.recent_by_sev.clear()
        self._state.chain_ok = 0
        self._state.chain_breaks = 0
        self._state.first_sig = None
        self._state.last_sig = None
        self._state.prev_sig = None
        self._state.total = 0
        self._state.last_event_ns = None
        self._state.active_blocks_by_ip.clear()
        self._state.blocks_started_events.clear()
        self._state.blocks_enforced_events.clear()
        self._state.drift_events.clear()
        self._state.last_supply_cycle = None
        self._state.caught_up = False

    def _apply_batch_locked(
        self,
        events: List[Dict[str, Any]],
        errors: List[str],
        new_offset: int,
    ) -> None:
        """Apply a batch of parsed events to state atomically under the lock.

        Keeping the batch size reasonable (≤ 5000) bounds lock hold time to
        a few ms even during the initial catch-up, so concurrent snapshot()
        calls still return quickly.
        """
        if not events and not errors:
            with self._lock:
                self._state.last_offset = new_offset
            return

        now_sec = time.time()
        with self._lock:
            state = self._state
            for e in events:
                try:
                    _process_event(state, e, now_sec)
                except Exception as exc:  # noqa: BLE001
                    state.errors.append(f"process: {type(exc).__name__}: {exc}")
            for err in errors:
                state.errors.append(err)
            state.last_offset = new_offset
            # Invalidate cache so the next snapshot() call rebuilds from
            # fresh state rather than serving pre-batch data.
            self._cached = None

    # ───────────── Snapshot building ─────────────

    def _build_snapshot(self, severity_filter: Optional[str]) -> LiveSnapshot:
        now_sec = time.time()
        now_ns = int(now_sec * 1e9)

        with self._lock:
            state = self._state

            # Prune time-windowed structures lazily here (we're already
            # under the lock, and this is cheap — O(k) where k is the number
            # of items that just aged out).
            _prune_time_windowed(state, now_sec)

            # Build lightweight copies so the caller gets an immutable view.
            event_types = dict(state.event_types.most_common())
            severities = dict(state.severities.most_common())
            sensors = dict(state.sensors.most_common())
            external_ips = dict(state.external_ips.most_common(10))
            user_agents = dict(state.user_agents.most_common(8))

            if severity_filter is None:
                recent_list = list(reversed(state.ring))
            else:
                # Build from the per-severity ring — much cheaper than
                # scanning the full ring when caller asked for e.g. "error".
                filtered = state.recent_by_sev.get(severity_filter, ())
                recent_list = list(reversed(filtered))[: self.window]

            by_sev_recent: Dict[str, List[Dict[str, Any]]] = {}
            for sev, dq in state.recent_by_sev.items():
                by_sev_recent[sev] = list(reversed(dq))

            active_blocks_list = sorted(
                state.active_blocks_by_ip.values(),
                key=lambda b: b.get("blocked_since") or 0,
                reverse=True,
            )

            drift_list = [d for (_ts, d) in list(state.drift_events)]
            drift_list = list(reversed(drift_list))[:10]

            errors_list = list(state.errors)

            file_bytes = state.last_size
            last_offset = state.last_offset

            return LiveSnapshot(
                total_events=state.total,
                last_event_ns=state.last_event_ns,
                read_at_ns=now_ns,
                event_types=event_types,
                severities=severities,
                sensors=sensors,
                external_ips=external_ips,
                user_agents=user_agents,
                chain_ok=state.chain_ok,
                chain_breaks=state.chain_breaks,
                chain_first_sig=(state.first_sig or "")[:_SIG_DISPLAY_LEN] if state.first_sig else None,
                chain_last_sig=(state.last_sig or "")[:_SIG_DISPLAY_LEN] if state.last_sig else None,
                recent=recent_list,
                by_severity_recent=by_sev_recent,
                errors=errors_list,
                active_blocks=active_blocks_list,
                blocks_started_count=len(state.blocks_started_events),
                blocks_enforced_count=len(state.blocks_enforced_events),
                supply_chain_drift=drift_list,
                supply_chain_last_cycle=state.last_supply_cycle,
                ingest_caught_up=state.caught_up,
                ingest_last_offset=last_offset,
                ingest_file_bytes=file_bytes,
                ingest_lag_bytes=max(0, file_bytes - last_offset),
            )


# The canonical sensor-family taxonomy (must match Aegis plugin)
AEGIS_SENSOR_FAMILIES = {
    "aegis.auth":        "Authentication — login/role/password activity",
    "aegis.rest":        "REST API — route registration + POI canary",
    "aegis.plugin":      "Plugin lifecycle — install/update/activate/delete",
    "aegis.theme":       "Theme — switch/update",
    "aegis.fim":         "File integrity — wp-config.php tampering",
    "aegis.outbound":    "Outbound HTTP — calls with Ethereum-RPC detection",
    "aegis.http":        "HTTP request — every inbound request",
    "aegis.admin":       "Admin — page views and privileged actions",
    "aegis.options":     "Options — WP option adds/updates",
    "aegis.cron":        "Cron — scheduled task execution",
    "aegis.mail":        "Mail — wp_mail success + failure",
    "aegis.post":        "Post — create/update/status/delete",
    "aegis.comment":     "Comment — insert",
    "aegis.media":       "Media — upload/delete with MIME flagging",
    "aegis.db":          "Database — per-request query summary",
    "aegis.lifecycle":   "Plugin lifecycle — own activation/deactivation",
    # v0.4 additions
    "aegis.block":       "Active defense — IP burst blocking + 403 enforcement",
    "aegis.supply_chain":"Supply chain — daily plugin author/update drift check",
    "aegis.browser":     "Browser beacon — admin-page client-side events",
    # v0.5+ query + nonce
    "aegis.query":       "Database — slow/anomalous query per request",
    "aegis.nonce":       "Nonces — CSRF token generation + verification",
    "aegis.request":     "Request pipeline — point-of-ingestion sensors",
    "aegis.redirect":    "Redirects — admin-forced / login-forced navigation",
    "aegis.capability":  "Capability — denied map_meta_cap filter hits",
    "aegis.404":         "404 — observed missing-resource probes",
}
