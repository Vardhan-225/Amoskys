"""AMOSKYS Web — User-Agent crawler/bot classifier.

Takes the raw user_agent string from each Aegis HTTP event and
classifies the caller into one of a small set of intent buckets.
That classification is what the Command Center, the customer
dashboard, and the forthcoming bot-traffic widget all display.

Categories:
    search        Legit search-engine crawlers (Google, Bing, Yandex)
    seo           SEO/marketing crawlers (Ahrefs, Semrush, Moz)
    security      Internet security researchers (Censys, Shadowserver, Shodan)
    scanner       Active vulnerability scanners (nuclei, WPScan, zgrab, nmap)
    ai            AI training + retrieval crawlers (GPTBot, ClaudeBot, PerplexityBot)
    bot_other     Unclassified non-human UAs (curl, python-requests, Go-http-client)
    human         Browser UAs (Chrome, Firefox, Safari, Edge)
    unknown       Empty or unmatched

Deployed to:
    /opt/amoskys-web/src/app/web_product/crawler_classifier.py
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


# ─────────────────────────────────────────────────────────────
# Pattern table — order matters; more specific first.
# Each entry: (regex, category, pretty_name)
# ─────────────────────────────────────────────────────────────

PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # Search engines
    (re.compile(r"Googlebot", re.I),           "search",   "Googlebot"),
    (re.compile(r"Bingbot", re.I),             "search",   "Bingbot"),
    (re.compile(r"DuckDuckBot", re.I),         "search",   "DuckDuckBot"),
    (re.compile(r"YandexBot", re.I),           "search",   "YandexBot"),
    (re.compile(r"Baiduspider", re.I),         "search",   "Baiduspider"),
    (re.compile(r"Applebot", re.I),            "search",   "Applebot"),

    # SEO / marketing
    (re.compile(r"AhrefsBot", re.I),           "seo",      "AhrefsBot"),
    (re.compile(r"SemrushBot", re.I),          "seo",      "SemrushBot"),
    (re.compile(r"MJ12bot", re.I),             "seo",      "MJ12bot"),
    (re.compile(r"DotBot", re.I),              "seo",      "DotBot"),
    (re.compile(r"ScreamingFrogSEOSpider", re.I), "seo",   "Screaming Frog"),
    (re.compile(r"moz\.com", re.I),            "seo",      "Moz"),

    # Security-research telescopes (mostly benign)
    (re.compile(r"Censys", re.I),              "security", "Censys"),
    (re.compile(r"Shadowserver", re.I),        "security", "Shadowserver"),
    (re.compile(r"Shodan", re.I),              "security", "Shodan"),
    (re.compile(r"zgrab", re.I),               "security", "zgrab (ZMap)"),
    (re.compile(r"masscan", re.I),             "security", "masscan"),
    (re.compile(r"InternetMeasurement", re.I), "security", "internet-measurement.com"),
    (re.compile(r"Expanse", re.I),             "security", "Palo Alto Expanse"),

    # Active vuln scanners — these are adversarial even if legal
    (re.compile(r"Nuclei", re.I),              "scanner",  "nuclei (ProjectDiscovery)"),
    (re.compile(r"WPScan", re.I),              "scanner",  "WPScan"),
    (re.compile(r"nmap", re.I),                "scanner",  "nmap"),
    (re.compile(r"sqlmap", re.I),              "scanner",  "sqlmap"),
    (re.compile(r"dalfox", re.I),              "scanner",  "dalfox"),
    (re.compile(r"Acunetix", re.I),            "scanner",  "Acunetix"),
    (re.compile(r"Qualys", re.I),              "scanner",  "Qualys"),
    (re.compile(r"Nessus", re.I),              "scanner",  "Nessus"),
    (re.compile(r"OpenVAS", re.I),             "scanner",  "OpenVAS"),
    (re.compile(r"Detectify", re.I),           "scanner",  "Detectify"),

    # AI training/retrieval crawlers
    (re.compile(r"GPTBot", re.I),              "ai",       "GPTBot (OpenAI)"),
    (re.compile(r"ClaudeBot", re.I),           "ai",       "ClaudeBot (Anthropic)"),
    (re.compile(r"PerplexityBot", re.I),       "ai",       "PerplexityBot"),
    (re.compile(r"CCBot", re.I),               "ai",       "CCBot (Common Crawl)"),
    (re.compile(r"anthropic-ai", re.I),        "ai",       "Anthropic UA"),
    (re.compile(r"OAI-SearchBot", re.I),       "ai",       "OAI-SearchBot"),

    # Generic bots / libraries
    (re.compile(r"WP CLI", re.I),              "bot_other", "WP-CLI (internal)"),
    (re.compile(r"curl/", re.I),               "bot_other", "curl"),
    (re.compile(r"wget/", re.I),               "bot_other", "wget"),
    (re.compile(r"python-requests", re.I),     "bot_other", "python-requests"),
    (re.compile(r"python-urllib", re.I),       "bot_other", "python-urllib"),
    (re.compile(r"Go-http-client", re.I),      "bot_other", "Go http"),
    (re.compile(r"libwww-perl", re.I),         "bot_other", "libwww-perl"),
    (re.compile(r"Java/", re.I),               "bot_other", "Java"),
    (re.compile(r"PostmanRuntime", re.I),      "bot_other", "Postman"),

    # Browsers (heuristic — last resort, must include engine strings)
    (re.compile(r"Chrome/", re.I),             "human",    "Chrome"),
    (re.compile(r"Firefox/", re.I),            "human",    "Firefox"),
    (re.compile(r"Safari/", re.I),             "human",    "Safari"),
    (re.compile(r"Edg/", re.I),                "human",    "Edge"),
]


# ─────────────────────────────────────────────────────────────
# Intent posture — informs UI coloring + sort order
# ─────────────────────────────────────────────────────────────

INTENT_POSTURE = {
    "search":    ("info",  "Legit search-engine crawler."),
    "seo":       ("info",  "SEO / marketing bot. Consider blocking if volume bothers you."),
    "security":  ("info",  "Internet security telescope. Usually harmless."),
    "ai":        ("warn",  "AI training / retrieval. Some sites opt out via robots.txt."),
    "bot_other": ("warn",  "Unclassified non-human caller. Investigate."),
    "scanner":   ("high",  "Active vulnerability scanner — someone is probing your site."),
    "human":     ("info",  "Human browser session."),
    "unknown":   ("warn",  "Empty or unrecognized UA. Probably a crude scanner."),
}


def classify(ua: str) -> Dict[str, str]:
    """Return {category, pretty_name, severity, note} for a UA string."""
    ua = (ua or "").strip()
    if not ua:
        sev, note = INTENT_POSTURE["unknown"]
        return {"category": "unknown", "pretty_name": "(empty UA)", "severity": sev, "note": note}

    for rx, category, pretty in PATTERNS:
        if rx.search(ua):
            sev, note = INTENT_POSTURE[category]
            return {"category": category, "pretty_name": pretty, "severity": sev, "note": note}

    # Any bot-looking UA without a known signature
    if "bot" in ua.lower() or "crawler" in ua.lower() or "spider" in ua.lower():
        sev, note = INTENT_POSTURE["bot_other"]
        return {"category": "bot_other", "pretty_name": "Unknown bot", "severity": sev, "note": note}

    sev, note = INTENT_POSTURE["unknown"]
    return {"category": "unknown", "pretty_name": ua[:60], "severity": sev, "note": note}


def summarize(aegis_snap) -> Dict[str, any]:
    """Build a view-model from an AegisTail snapshot.

    Returns:
      {
        "by_category": [{category, count, severity, pretty_names: [...]}, ...],
        "top_bots":    [{pretty_name, category, count, sample_ip}, ...],
        "totals":      {human, bot, scanner, unknown}
      }
    """
    from collections import Counter
    per_pretty: Counter = Counter()
    per_category: Counter = Counter()
    pretty_samples: Dict[str, Dict[str, any]] = {}

    for ua, n in aegis_snap.user_agents.items():
        c = classify(ua)
        per_category[c["category"]] += n
        key = c["pretty_name"]
        per_pretty[key] += n
        if key not in pretty_samples:
            pretty_samples[key] = {
                "pretty_name": key,
                "category":    c["category"],
                "severity":    c["severity"],
                "note":        c["note"],
                "count":       0,
                "sample_ua":   ua[:100],
            }
        pretty_samples[key]["count"] = per_pretty[key]

    # Totals
    totals = {
        "human":   per_category.get("human", 0),
        "search":  per_category.get("search", 0),
        "seo":     per_category.get("seo", 0),
        "security": per_category.get("security", 0),
        "ai":      per_category.get("ai", 0),
        "scanner": per_category.get("scanner", 0),
        "bot_other": per_category.get("bot_other", 0),
        "unknown": per_category.get("unknown", 0),
    }

    # By category view
    by_category = []
    for cat, count in per_category.most_common():
        sev, _ = INTENT_POSTURE.get(cat, ("info", ""))
        members = [ps for ps in pretty_samples.values() if ps["category"] == cat]
        by_category.append({
            "category": cat,
            "count":    count,
            "severity": sev,
            "members":  sorted(members, key=lambda m: -m["count"])[:6],
        })

    top_bots = sorted(pretty_samples.values(), key=lambda m: -m["count"])[:12]

    return {
        "by_category": by_category,
        "top_bots":    top_bots,
        "totals":      totals,
    }
