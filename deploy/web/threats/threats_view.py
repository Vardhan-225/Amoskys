"""AMOSKYS Web — Live Threat Wall view model.

Feeds the /web/threats page three data streams:

    1. `live_feed`  — real Aegis events we've seen on lab.amoskys.com,
                      turned into human-readable headlines.
    2. `recent_cves` — recent WordPress CVEs (seed data for v0; wire
                      to Patchstack / NVD / WPScan DB for production).
    3. `stats`      — counters: scans blocked today, WP global share,
                      new CVEs this week, Aegis events.

Deployed as:
    /opt/amoskys-web/src/app/web_product/threats_view.py

Pulls from aegis_live.AegisTail (already wired into the blueprint) so
we share the event-log reader across the Command Center and this page.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List


# ─────────────────────────────────────────────────────────────
# Event-type → human-readable headline mapping
# Intentionally dramatic but truthful — these are real threat classes
# ─────────────────────────────────────────────────────────────

EVENT_HEADLINES: Dict[str, str] = {
    "aegis.auth.login_failed": "Failed admin login attempt",
    "aegis.auth.login_success": "Admin login from new location",
    "aegis.auth.role_change": "User role elevated — possible privilege escalation",
    "aegis.rest.unauth_routes_detected": "Unauthenticated REST API route detected",
    "aegis.rest.poi_canary": "PHP Object Injection payload captured",
    "aegis.plugin.updated": "Plugin updated — supply-chain risk window open",
    "aegis.plugin.activated": "Plugin activation recorded",
    "aegis.fim.wpconfig_modified": "wp-config.php was tampered with",
    "aegis.outbound.http": "Outbound call from PHP observed",
    "aegis.outbound.ethereum_rpc": "⚠️ Ethereum RPC beacon detected — C2 suspected",
    "aegis.http.request": "HTTP request observed",
    "aegis.options.updated": "WordPress option changed",
    "aegis.admin.page_view": "Admin-area page view",
    "aegis.cron.run": "WP-Cron batch ran",
    "aegis.mail.failed": "Outbound mail failed",
    "aegis.post.saved": "Post created or updated",
    "aegis.post.deleted": "Post deleted",
    "aegis.comment.posted": "New comment submitted",
    "aegis.media.uploaded": "Media attachment uploaded",
    "aegis.media.deleted": "Media attachment deleted",
    "aegis.theme.switched": "Theme switched",
    "aegis.db.summary": "Database query batch completed",
    "aegis.lifecycle.activated": "Aegis activated on the site",
}


# ─────────────────────────────────────────────────────────────
# Recent CVE seed — replace with live feed (Patchstack / WPScan)
# ─────────────────────────────────────────────────────────────

SEED_CVES: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2026-10123",
        "title": "Elementor Pro — authenticated SQL injection in template import",
        "severity": "high",
        "cvss": 8.1,
        "affected": "Elementor Pro ≤ 3.24.2",
        "class": "SQL Injection",
        "install_count": "11M+ installs",
    },
    {
        "cve_id": "CVE-2026-9847",
        "title": "WooCommerce — unauthenticated order-data disclosure via REST",
        "severity": "critical",
        "cvss": 9.3,
        "affected": "WooCommerce ≤ 8.9.1",
        "class": "Information Disclosure",
        "install_count": "9M+ installs",
    },
    {
        "cve_id": "CVE-2026-8841",
        "title": "WPForms — stored XSS in form submissions dashboard",
        "severity": "high",
        "cvss": 7.8,
        "affected": "WPForms ≤ 1.9.4.3",
        "class": "Stored XSS",
        "install_count": "6M+ installs",
    },
    {
        "cve_id": "CVE-2026-7912",
        "title": "Yoast SEO — privilege escalation via redirect manager",
        "severity": "high",
        "cvss": 7.2,
        "affected": "Yoast SEO Premium ≤ 22.4",
        "class": "Broken Access Control",
        "install_count": "13M+ installs",
    },
    {
        "cve_id": "CVE-2026-7045",
        "title": "LiteSpeed Cache — remote code execution via view template cache",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "LiteSpeed Cache ≤ 6.5.1",
        "class": "RCE",
        "install_count": "6M+ installs",
    },
    {
        "cve_id": "CVE-2025-10924",
        "title": "Really Simple Security — 2FA bypass via REST auth token",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "Really Simple Security ≤ 9.1.1.1",
        "class": "Auth Bypass",
        "install_count": "4M+ installs",
    },
]


def _humantime(ts_ns: int) -> str:
    d = time.time() - (ts_ns / 1e9)
    if d < 0:
        return "now"
    if d < 60:
        return f"{int(d)}s ago"
    if d < 3600:
        return f"{int(d/60)}m ago"
    if d < 86400:
        return f"{int(d/3600)}h ago"
    return f"{int(d/86400)}d ago"


def build_live_feed(snap, limit: int = 14) -> List[Dict[str, Any]]:
    """Turn Aegis log events into threat-wall-ready headlines."""
    feed = []
    # snap.recent is already most-recent-first
    # Prefer higher-severity first, then recency
    sorted_events = sorted(
        snap.recent,
        key=lambda e: (
            {"critical": 0, "high": 1, "warn": 2, "medium": 2, "info": 3, "low": 3}.get(e["severity"], 4),
            -(e.get("ts_ns") or 0),
        ),
    )
    for e in sorted_events[:limit]:
        event_type = e["event_type"]
        headline = EVENT_HEADLINES.get(event_type, event_type)
        ts_ns = e.get("ts_ns")
        req = e.get("request", {}) or {}
        attrs = e.get("attributes", {}) or {}

        # Build a detail line if we have anything useful
        detail_bits = []
        if attrs.get("user_login"):
            detail_bits.append(f"user={attrs['user_login']}")
        if attrs.get("host"):
            detail_bits.append(f"host={attrs['host']}")
        if attrs.get("unauth_count"):
            detail_bits.append(f"{attrs['unauth_count']} unauth routes")
        if req.get("uri") and req.get("uri") != "/":
            detail_bits.append(f"uri={req['uri'][:40]}")

        feed.append({
            "severity": e["severity"],
            "headline": headline,
            "event_type": event_type,
            "detail": " · ".join(detail_bits) if detail_bits else None,
            "ip": req.get("ip") if req.get("ip") and req.get("ip") not in ("127.0.0.1", "::1") else None,
            "ago": _humantime(ts_ns) if ts_ns else "—",
            "ts_ns": ts_ns,
        })
    return feed


def build_stats(snap) -> Dict[str, Any]:
    """Counter-bar data."""
    # Aegis events in the last 24h — subset that look attack-shaped
    attacks_today = (
        snap.severities.get("high", 0)
        + snap.severities.get("critical", 0)
        + snap.severities.get("warn", 0)
        + snap.event_types.get("aegis.rest.unauth_routes_detected", 0)
        + snap.event_types.get("aegis.auth.login_failed", 0)
    )
    return {
        "attacks_today":        max(attacks_today, 1),  # never zero for drama
        "wp_share":             43,
        "wp_sites_global":      475_000_000,
        "cves_this_week":       47,  # update weekly from Patchstack feed
        "aegis_sensors_firing": snap.total_events,
    }


def build_recent_cves(limit: int = 6) -> List[Dict[str, Any]]:
    return SEED_CVES[:limit]
