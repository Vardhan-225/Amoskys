"""Aegis live-event reader — the real feed from the WordPress plugin.

This is what makes the Command Center a *command center* instead of a
mock dashboard. It reads the actual events.jsonl that the Aegis plugin
writes to, computes summary stats, verifies chain integrity, and gives
the operator everything the plugin is watching in real time.

Deployed at /opt/amoskys-web/src/app/web_product/aegis_live.py — pulled
from this canonical file in the repo under docs/web/deployment/.

Zero coupling to the WP plugin beyond the file path — if you change
Aegis's log location or format, this file updates, nothing else.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional


# Where the Aegis plugin writes its JSONL log. Override with env var.
DEFAULT_LOG_PATH = "/var/www/html/wp-content/uploads/amoskys-aegis/events.jsonl"
LOG_PATH = os.environ.get("AMOSKYS_AEGIS_LOG", DEFAULT_LOG_PATH)

# How many tail events we keep in-memory for quick display
TAIL_WINDOW = 200


@dataclass
class LiveSnapshot:
    """Everything the Command Center needs for one render."""
    total_events: int
    last_event_ns: Optional[int]
    read_at_ns: int
    event_types: Dict[str, int]  # event_type -> count
    severities: Dict[str, int]   # severity -> count
    sensors: Dict[str, int]      # inferred sensor family -> count
    external_ips: Dict[str, int] # source IP -> count (excludes localhost)
    user_agents: Dict[str, int]  # user-agent -> count
    chain_ok: int
    chain_breaks: int
    chain_first_sig: Optional[str]
    chain_last_sig: Optional[str]
    recent: List[Dict[str, Any]] = field(default_factory=list)
    by_severity_recent: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class AegisTail:
    """In-memory ring buffer of recent events + cumulative stats.

    The file is re-read in full each snapshot call — that's acceptable
    for the current log volume (<10 MB typical). For scale, switch to
    incremental tailing via seek/inotify.
    """

    def __init__(self, log_path: str = LOG_PATH, window: int = TAIL_WINDOW) -> None:
        self.log_path = log_path
        self.window = window
        self._lock = Lock()

    def snapshot(self, severity_filter: Optional[str] = None) -> LiveSnapshot:
        """Build a fresh summary + tail, applying an optional severity filter."""
        now_ns = int(time.time() * 1e9)
        errors: List[str] = []

        if not os.path.exists(self.log_path):
            return LiveSnapshot(
                total_events=0, last_event_ns=None, read_at_ns=now_ns,
                event_types={}, severities={}, sensors={},
                external_ips={}, user_agents={},
                chain_ok=0, chain_breaks=0,
                chain_first_sig=None, chain_last_sig=None,
                recent=[], errors=[f"log not found at {self.log_path}"],
            )

        event_types: Counter[str] = Counter()
        severities: Counter[str] = Counter()
        sensors: Counter[str] = Counter()
        external_ips: Counter[str] = Counter()
        user_agents: Counter[str] = Counter()
        ring: deque = deque(maxlen=self.window)
        recent_by_sev: Dict[str, List[Dict[str, Any]]] = {}

        prev_sig = None
        chain_ok = 0
        chain_breaks = 0
        total = 0
        first_sig: Optional[str] = None
        last_sig: Optional[str] = None
        last_event_ns: Optional[int] = None

        with self._lock:
            try:
                with open(self.log_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            e = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        total += 1
                        et = e.get("event_type", "unknown")
                        sev = e.get("severity", "unknown")
                        event_types[et] += 1
                        severities[sev] += 1

                        # Sensor family = first two segments of event_type
                        parts = et.split(".")
                        if len(parts) >= 2:
                            sensors[f"{parts[0]}.{parts[1]}"] += 1

                        req = e.get("request") or {}
                        ip = req.get("ip") or ""
                        ua = req.get("ua") or ""
                        if ip and ip not in ("127.0.0.1", "::1", "localhost"):
                            external_ips[ip] += 1
                        if ua:
                            # Truncate UA for display
                            ua_short = ua[:80]
                            user_agents[ua_short] += 1

                        # Chain integrity
                        submitted_prev = e.get("prev_sig")
                        if submitted_prev == prev_sig or (
                            not submitted_prev and not prev_sig
                        ):
                            chain_ok += 1
                        else:
                            chain_breaks += 1
                        prev_sig = e.get("sig")
                        last_sig = prev_sig
                        if first_sig is None:
                            first_sig = prev_sig

                        last_event_ns = e.get("event_timestamp_ns") or last_event_ns

                        if severity_filter and sev != severity_filter:
                            continue

                        # Build a compact view-model for display
                        view = {
                            "event_type": et,
                            "severity": sev,
                            "ts_ns": e.get("event_timestamp_ns"),
                            "site_id": e.get("site_id"),
                            "sig_short": (e.get("sig") or "")[:10],
                            "request": {
                                "method": req.get("method"),
                                "uri": (req.get("uri") or "")[:80],
                                "ip": ip,
                                "ua": ua[:60],
                            },
                            "attributes": e.get("attributes") or {},
                        }
                        ring.append(view)
                        recent_by_sev.setdefault(sev, []).append(view)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")

        # Keep at most 20 per severity for UI
        for k in list(recent_by_sev.keys()):
            recent_by_sev[k] = list(reversed(recent_by_sev[k]))[:20]

        return LiveSnapshot(
            total_events=total,
            last_event_ns=last_event_ns,
            read_at_ns=now_ns,
            event_types=dict(event_types.most_common()),
            severities=dict(severities.most_common()),
            sensors=dict(sensors.most_common()),
            external_ips=dict(external_ips.most_common(10)),
            user_agents=dict(user_agents.most_common(8)),
            chain_ok=chain_ok,
            chain_breaks=chain_breaks,
            chain_first_sig=(first_sig or "")[:16] if first_sig else None,
            chain_last_sig=(last_sig or "")[:16] if last_sig else None,
            recent=list(reversed(ring)),
            by_severity_recent=recent_by_sev,
            errors=errors,
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
}
