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

from amoskys.agents.Web.ingest import __version__  # noqa: F401  (already imported elsewhere)


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


def _fetch_wp_json(site_url: str, timeout: float = 6.0) -> Dict[str, Any]:
    try:
        req = urllib.request.Request(
            site_url.rstrip("/") + "/wp-json/",
            headers={"User-Agent": "AMOSKYS-Web-PluginInventory/0.1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(256_000).decode("utf-8", errors="replace"))
    except Exception:
        return {}


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
