"""AMOSKYS Web — plugin inventory for customer-zero (lab.amoskys.com).

v1 strategy (no WP admin credentials required):
  - Parse public /wp-json/ namespaces — every namespace usually maps to
    a plugin that registered REST routes (e.g. 'woocommerce/v3' → WooCommerce)
  - Extract plugin activity from the Aegis log's aegis.plugin.* events
    which carry plugin slug + version metadata

For v2 we'll extend with:
  - Wordfence Intelligence / Patchstack DB cross-reference for CVEs
  - Read /wp-content/plugins/ directory listing IF the host allows it
  - Pull version from WP update-check server metadata
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any, Dict, List



_PLUGIN_HINTS = {
    # Namespace prefix -> pretty slug
    "wp/v2":              "wordpress-core",
    "oembed/1.0":         "wordpress-core",
    "wp-site-health/v1":  "wordpress-core",
    "wp-block-editor/v1": "wordpress-core",
    "akismet/v1":         "akismet",
    "woocommerce/v3":     "woocommerce",
    "wc/store/v1":        "woocommerce",
    "elementor/v1":       "elementor",
    "wpseo/v1":           "yoast-seo",
    "jetpack/v4":         "jetpack",
    "contact-form-7/v1":  "contact-form-7",
    "litespeed/v1":       "litespeed-cache",
    "amoskys-aegis/v1":   "amoskys-aegis",
}


# ─────────────────────────────────────────────────────────────────────
# /wp-json/ fetch with a process-local TTL cache.
#
# This lives on the dashboard-render critical path — both the plugin
# inventory and the WP-version probe in the dashboard view call it.
# Before caching, each dashboard render paid ~450ms for the HTTPS call,
# twice (once per caller), so the TTFB ceiling was around a second even
# after the Aegis tail was made incremental.
#
# Stale-on-error semantics: if a fresh fetch fails (timeout, bad JSON,
# network blip) we prefer returning stale-but-usable data over empty.
# A negative entry (empty dict with recent mtime) is cached anyway so
# repeated failures don't pile up concurrent urlopen() calls.
#
# Not thread-safe in a strict sense — dict updates are atomic per GIL
# tick, and worst-case we briefly duplicate a fetch. That's acceptable
# for a read-mostly cache keyed by site_url.
# ─────────────────────────────────────────────────────────────────────

_WP_JSON_CACHE: Dict[str, "tuple[float, Dict[str, Any]]"] = {}
_WP_JSON_CACHE_TTL_SEC = 300.0  # 5 min — /wp-json/ changes only on plugin install/update


def _fetch_wp_json(site_url: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Fetch /wp-json/ for a site with a 5-minute TTL cache.

    Always returns a dict. Returns stale cache on fetch error if available,
    otherwise returns {}. Caches negative results too, to avoid hammering
    a broken target.
    """
    key = site_url.rstrip("/")
    now = time.time()
    cached = _WP_JSON_CACHE.get(key)
    if cached is not None and (now - cached[0]) < _WP_JSON_CACHE_TTL_SEC:
        return cached[1]

    try:
        req = urllib.request.Request(
            key + "/wp-json/",
            headers={"User-Agent": "AMOSKYS-Web-PluginInventory/0.1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(256_000).decode("utf-8", errors="replace"))
            if not isinstance(data, dict):
                data = {}
    except Exception:
        # On error, prefer stale cache if present; otherwise cache an empty
        # result with a short expiry effect so we retry on the next TTL window.
        if cached is not None:
            return cached[1]
        data = {}

    _WP_JSON_CACHE[key] = (now, data)
    return data


def clear_wp_json_cache() -> None:
    """Drop all cached /wp-json/ results (useful in tests / admin 'refresh now')."""
    _WP_JSON_CACHE.clear()


def _namespace_to_slug(ns: str) -> str:
    # Exact match first
    if ns in _PLUGIN_HINTS:
        return _PLUGIN_HINTS[ns]
    # Prefix (namespace before the /vX)
    prefix = ns.split("/")[0]
    return prefix or ns


def inventory_from_wpjson(site_url: str) -> List[Dict[str, Any]]:
    """Return a plugin list derived from /wp-json/ namespaces."""
    data = _fetch_wp_json(site_url)
    wp_version = data.get("namespaces")  # only present on modern WP
    namespaces = data.get("namespaces") or []
    entries_by_slug: Dict[str, Dict[str, Any]] = {}

    for ns in namespaces:
        slug = _namespace_to_slug(ns)
        if slug in entries_by_slug:
            entries_by_slug[slug]["namespaces"].append(ns)
            continue
        entries_by_slug[slug] = {
            "slug":        slug,
            "version":     None,
            "state":       "active",  # namespace registered → plugin is loaded
            "namespaces":  [ns],
            "source":      "wp-json",
        }

    return list(entries_by_slug.values())


def enrich_with_aegis_events(plugins: List[Dict[str, Any]], snap) -> List[Dict[str, Any]]:
    """Fold in version + state from Aegis plugin.* events on the log."""
    by_slug = {p["slug"]: p for p in plugins}

    # Walk the tail looking at plugin events
    now = time.time()
    for e in snap.recent:
        et = e.get("event_type") or ""
        if not et.startswith("aegis.plugin."):
            continue
        attrs = e.get("attributes") or {}
        plugin_id = attrs.get("plugin", "")
        if not plugin_id:
            continue
        # plugin field looks like "my-plugin/my-plugin.php" or "hello.php"
        slug = plugin_id.split("/")[0].replace(".php", "")
        data = attrs.get("data") or {}
        version = data.get("version")

        if slug not in by_slug:
            by_slug[slug] = {
                "slug":     slug,
                "version":  version,
                "state":    "inactive",
                "source":   "aegis",
            }

        entry = by_slug[slug]
        if version and not entry.get("version"):
            entry["version"] = version

        # If we saw a recent activation/update event, reflect it
        if et == "aegis.plugin.updated":
            entry["state"] = "updated_recently"
        elif et == "aegis.plugin.activated" and entry["state"] != "updated_recently":
            entry["state"] = "active"
        elif et == "aegis.plugin.deactivated" and entry["state"] != "updated_recently":
            entry["state"] = "inactive"

    # Always put the Aegis plugin at the top
    result = sorted(
        by_slug.values(),
        key=lambda p: (0 if p["slug"] == "amoskys-aegis" else 1, p["slug"]),
    )
    return result


def build_inventory(site_url: str, snap) -> List[Dict[str, Any]]:
    """Full inventory: public fingerprints + Aegis lifecycle events."""
    base = inventory_from_wpjson(site_url)
    return enrich_with_aegis_events(base, snap)
