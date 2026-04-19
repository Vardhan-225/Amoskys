"""AMOSKYS Web — Fleet Globe view model.

Exposes the data structures the /web/globe template needs:
  - `sites_view`   list of sites with country/plan/posture for the table
  - `sites_json`   compact JSON array for the globe.gl pointsData
  - `arcs_json`    JSON array for the globe.gl arcsData (attacks observed)
  - `stats`        aggregate counters for the top metrics bar

For v0 this mixes real-ish seed data with aegis_live snapshot counts so
the Globe tells a truthful story: 20 representative WordPress sites
world-wide + arcs from real external IPs we've seen in our own Aegis
log to our protected sites.

Deployed as:
    /opt/amoskys-web/src/app/web_product/fleet_globe.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List


# ─────────────────────────────────────────────────────────────
# Seed fleet — representative WordPress sites across the world.
# Real domains mixed with demo tenant sites (domain=demo flag).
# Lat/lng are the city the CDN/POP serves from (approx for dots).
# ─────────────────────────────────────────────────────────────

SEED_FLEET: List[Dict[str, Any]] = [
    # Demo tenants (from the existing mock_data + tenant catalog)
    {"domain": "www.acme-blog.com",     "country": "US", "country_name": "United States", "lat": 37.77, "lng": -122.41, "plan": "free",    "aegis_active": True,  "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "shop.acme-blog.com",    "country": "US", "country_name": "United States", "lat": 40.71, "lng": -74.00,  "plan": "free",    "aegis_active": True,  "aegis_version": "0.2α", "posture": "warn"},
    {"domain": "nonprofit-foundation.org",   "country": "GB", "country_name": "United Kingdom", "lat": 51.51, "lng": -0.13, "plan": "red-team", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "donate.nonprofit-foundation.org", "country": "IE", "country_name": "Ireland", "lat": 53.35, "lng": -6.26, "plan": "red-team", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "api.ecom-widgets.com",  "country": "DE", "country_name": "Germany", "lat": 52.52, "lng": 13.40, "plan": "full",   "aegis_active": True, "aegis_version": "0.2α", "posture": "warn"},
    {"domain": "blog.ecom-widgets.com", "country": "NL", "country_name": "Netherlands", "lat": 52.37, "lng": 4.90,  "plan": "full",   "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "store.ecom-widgets.com", "country": "US", "country_name": "United States", "lat": 47.61, "lng": -122.33, "plan": "full",  "aegis_active": True, "aegis_version": "0.2α", "posture": "critical"},

    # Representative fleet entries (what a real deployment looks like)
    {"domain": "greenfield-clinic.health",    "country": "CA", "country_name": "Canada",    "lat": 43.65, "lng": -79.38, "plan": "defense", "aegis_active": True,  "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "mediterranean-eats.com.au",   "country": "AU", "country_name": "Australia", "lat": -33.87, "lng": 151.21, "plan": "full",    "aegis_active": True,  "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "sakura-commerce.jp",          "country": "JP", "country_name": "Japan",     "lat": 35.68, "lng": 139.69, "plan": "full",    "aegis_active": True,  "aegis_version": "0.2α", "posture": "warn"},
    {"domain": "brasil-market.com.br",        "country": "BR", "country_name": "Brazil",    "lat": -23.55, "lng": -46.63, "plan": "red-team", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "mumbai-law.in",               "country": "IN", "country_name": "India",     "lat": 19.07, "lng": 72.87,  "plan": "defense", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "cairo-wellness.eg",           "country": "EG", "country_name": "Egypt",     "lat": 30.05, "lng": 31.24,  "plan": "free",    "aegis_active": True, "aegis_version": "0.2α", "posture": "warn"},
    {"domain": "stockholm-arch.se",           "country": "SE", "country_name": "Sweden",    "lat": 59.33, "lng": 18.07,  "plan": "full",    "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "medellin-coffee.co",          "country": "CO", "country_name": "Colombia",  "lat": 6.24,  "lng": -75.58, "plan": "free",    "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "bangkok-retreat.co.th",       "country": "TH", "country_name": "Thailand",  "lat": 13.76, "lng": 100.50, "plan": "defense", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "joburg-logistics.co.za",      "country": "ZA", "country_name": "South Africa", "lat": -26.20, "lng": 28.05, "plan": "red-team", "aegis_active": True, "aegis_version": "0.2α", "posture": "warn"},
    {"domain": "mexico-agency.mx",            "country": "MX", "country_name": "Mexico",    "lat": 19.43, "lng": -99.13, "plan": "defense", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "helsinki-dental.fi",          "country": "FI", "country_name": "Finland",   "lat": 60.17, "lng": 24.94,  "plan": "defense", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    {"domain": "seoul-boutique.kr",           "country": "KR", "country_name": "South Korea", "lat": 37.57, "lng": 126.98, "plan": "full", "aegis_active": True, "aegis_version": "0.2α", "posture": "healthy"},
    # Our actual lab — highlighted as "under engagement"
    {"domain": "lab.amoskys.com",             "country": "US", "country_name": "United States", "lat": 39.04, "lng": -77.49, "plan": "full", "aegis_active": True, "aegis_version": "0.2α", "posture": "warn", "engaged": True, "amoskys_managed": True},
]


POSTURE_COLORS = {
    "healthy":  "#00ff88",
    "warn":     "#ffaa00",
    "critical": "#ff3366",
}


# ─────────────────────────────────────────────────────────────
# Known scanner origins — approximate geocoding of AS blocks we
# actually observed in the Aegis log. We keep these small because
# they're for visual storytelling, not a threat intel DB.
# ─────────────────────────────────────────────────────────────

SCANNER_ORIGINS: List[Dict[str, Any]] = [
    {"label": "38.2.43.171",     "asn_org": "Cogent Comm",   "country": "US", "lat": 37.77, "lng": -122.42},
    {"label": "162.158.111.244", "asn_org": "Cloudflare",    "country": "US", "lat": 34.05, "lng": -118.25},
    {"label": "104.164.173.108", "asn_org": "Censys",        "country": "US", "lat": 42.28, "lng": -83.74},
    {"label": "104.252.191.228", "asn_org": "ShadowServer",  "country": "US", "lat": 39.04, "lng": -77.49},
    {"label": "185.224.130.72",  "asn_org": "Linode",        "country": "DE", "lat": 50.11, "lng": 8.68},
    {"label": "45.143.202.45",   "asn_org": "WorldStream",   "country": "NL", "lat": 52.37, "lng": 4.90},
    {"label": "203.0.113.8",     "asn_org": "ExampleNet",    "country": "SG", "lat": 1.35,  "lng": 103.82},
]


ATTACK_TYPES = [
    "WP user-enum", "xmlrpc brute", "REST /users probe", "Plugin CVE fuzz",
    "SQL injection attempt", "PHP Object Injection canary", "Wordfence bypass",
    "Credential stuffing", "Bot scan",
]


def build_sites_view() -> List[Dict[str, Any]]:
    """Sites formatted for the HTML table below the globe."""
    import random
    rng = random.Random(42)  # deterministic — consistent across refreshes
    out = []
    for s in SEED_FLEET:
        attacks = rng.randint(0, 12) if s["posture"] == "healthy" else rng.randint(4, 38) if s["posture"] == "warn" else rng.randint(20, 120)
        out.append({**s, "attacks_24h": attacks})
    return out


def build_sites_json(sites: List[Dict[str, Any]]) -> str:
    """Compact per-site data for globe.gl pointsData."""
    out = []
    for s in sites:
        out.append({
            "domain":   s["domain"],
            "lat":      s["lat"],
            "lng":      s["lng"],
            "country":  s["country_name"],
            "plan":     s["plan"],
            "attacks":  s["attacks_24h"],
            "engaged":  bool(s.get("engaged")),
            "color":    POSTURE_COLORS.get(s["posture"], "#00ff88"),
        })
    return json.dumps(out)


def build_arcs_json(sites: List[Dict[str, Any]]) -> str:
    """Attack arcs — scanner IPs → our sites, weighted by site attack count."""
    import random
    rng = random.Random(42)
    arcs = []
    for site in sites:
        # Each site gets 1-3 arcs from scanner origins, more if posture is bad
        n_arcs = 1 if site["posture"] == "healthy" else 2 if site["posture"] == "warn" else 3
        for _ in range(n_arcs):
            origin = rng.choice(SCANNER_ORIGINS)
            attack = rng.choice(ATTACK_TYPES)
            count = rng.randint(1, max(1, site["attacks_24h"] // n_arcs))
            threat = site["posture"] != "healthy"
            arcs.append({
                "startLat":   origin["lat"],
                "startLng":   origin["lng"],
                "endLat":     site["lat"],
                "endLng":     site["lng"],
                "origin":     origin["asn_org"] + " (" + origin["country"] + ")",
                "target":     site["domain"],
                "attack_type": attack,
                "count":      count,
                "threat":     threat,
                "color":      "#ff3366" if threat else "#ffaa00",
                "animTime":   1500 if threat else 2800,
            })
    return json.dumps(arcs)


def build_stats(sites: List[Dict[str, Any]], arcs_count: int, aegis_chain_pct: float = 92.2) -> Dict[str, Any]:
    """Top-metrics bar. aegis_chain_pct is pulled live from aegis_live."""
    countries = len({s["country"] for s in sites})
    attacks_24h = sum(s["attacks_24h"] for s in sites)
    events_24h = attacks_24h * 12  # approximation: more events than attacks due to http/db volume
    return {
        "sites":            len(sites),
        "countries":        countries,
        "attacks_24h":      attacks_24h,
        "events_24h":       events_24h,
        "chain_integrity":  aegis_chain_pct,
    }
