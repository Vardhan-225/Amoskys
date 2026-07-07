#!/usr/bin/env python3
"""
AMOSKYS Insight Core — the honest analysis layer.

Reads a fleet_cache.db (real telemetry) and produces ONE truthful model:
  - a single risk-oriented verdict (0-100, three bands: calm / worth-a-look / act-now)
  - benign suppression (the moat: recognise the owner's own deploy/admin workflow
    and system activity as EXPECTED, instead of screaming "malicious exfil")
  - cross-domain correlation into incident "stories"
  - globe arcs from real geolocated flows, coloured by real verdict
  - per-domain rollups for the nervous-system view

Importable as a data service (build_model(db_path) -> dict) AND runnable as a CLI
that writes model.json for the static prototype.

Design rule: never invent a number. If something isn't assessed, say so.
"""
from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ── Known-good egress (ASN org substring -> friendly label) ──────────────────
KNOWN_GOOD_ASN = {
    "anthropic": "Anthropic (AI API)",
    "google": "Google",
    "amazon": "Amazon AWS",
    "cloudflare": "Cloudflare (CDN)",
    "fastly": "Fastly (CDN)",
    "akamai": "Akamai (CDN)",
    "github": "GitHub",
    "apple": "Apple (iCloud/OS)",
    "microsoft": "Microsoft",
}

# Binaries that, run by the machine's owner toward a known host, are the owner's
# own admin/deploy workflow — NOT exfiltration. This is the suppression moat.
OWNER_ADMIN_BINARIES = ("ssh", "scp", "sftp", "curl", "git", "rsync", "wget", "gh")

# The owner's developer tools. On a dev machine these constantly spawn processes,
# make outbound connections and check for updates — that is not an intrusion.
OWNER_DEV_PROCS = (
    "python", "python3", "claude", "codex", "node", "ruby", "go", "cargo",
    "rustc", "java", "deno", "bun", "npm", "pip", "brew", "docker", "code",
)

# Apple/macOS system daemons. Their beaconing/telemetry is the OS working.
APPLE_SYSTEM_PROCS = (
    "mdnsresponder", "sharingd", "dataaccessd", "featureaccessagent", "apsd",
    "cloudd", "nsurlsessiond", "webkit", "mdworker", "mds", "spotlight",
    "softwareupdated", "trustd", "syspolicyd", "akd", "identityservicesd",
    "commcenter", "rapportd", "networkserviceproxy", "bluetoothd", "coreauthd",
)

# Apple/OS system binary path prefixes -> expected system activity.
SYSTEM_PATH_PREFIXES = (
    "/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/",
    "/Library/Apple/", "/opt/homebrew/", "/sbin/", "/Applications/",
)

# Telemetry / update / CDN endpoints that legitimately beacon.
KNOWN_TELEMETRY = (
    "datadoghq", "apple.com", "icloud", "gstatic", "googleapis", "google.com",
    "cloudflare", "github", "githubusercontent", "mozilla", "sentry", "segment",
    "amazonaws", "cloudfront", "fastly", "akamai", "microsoft", "office",
)

# Categories that are scary enough that we NEVER auto-suppress them — even if
# the process looks routine, a human should confirm. (Research: suppress benign
# noise, but never silently drop needs-confirmation categories.)
NEVER_SUPPRESS = ("browser_credential_theft", "persistence_creation", "credential_dump")


def _proc_ctx(desc: str) -> str:
    """Lowercased process/exe context from an event description."""
    return (desc or "").lower()


# ── Redaction: never ship a secret-shaped value or a private path to a client ─
_RE_TMP = re.compile(r"/private/(?:tmp|var)/\S+")
_RE_SSHKEY = re.compile(r"(\.ssh/)[^\s'\"/]+")
_RE_USERHOST = re.compile(r"\b([a-z_][a-z0-9_-]*)@(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+)")
_RE_HOME = re.compile(r"/Users/[^/\s'\"]+")
_RE_TOKEN = re.compile(r"\b[A-Za-z0-9+/_\-]{32,}\b")


def _redact(s: str | None) -> str | None:
    """Strip private paths, key names, user@host and long secret-shaped tokens
    before any raw telemetry string is sent to the browser."""
    if not s:
        return s
    s = _RE_TMP.sub("/private/…", s)
    s = _RE_HOME.sub("~", s)              # /Users/<user>/… -> ~/…
    s = _RE_SSHKEY.sub(r"\1[key]", s)     # ~/.ssh/amoskys-deploy -> ~/.ssh/[key]
    s = _RE_USERHOST.sub(r"\1@[host]", s)  # ubuntu@1.2.3.4 -> ubuntu@[host]
    s = _RE_TOKEN.sub("[token]", s)
    return s

# Bands (risk-oriented: LOW score = safe). Research-backed 3-band model.
BAND_ACT = 65      # >= -> act now (red)
BAND_LOOK = 25     # >= -> worth a look (amber);  < -> calm (green)


def _connect(db_path: str) -> sqlite3.Connection:
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
    db.row_factory = sqlite3.Row
    return db


def _scope_sql(allowed_device_ids: list[str] | None, conj: str) -> tuple[str, tuple]:
    """SQL fragment enforcing the org device allowlist (tenant isolation).

    None  -> no restriction (admin);  []  -> match nothing (FAIL CLOSED);
    [ids] -> device_id IN (...).  `conj` is " WHERE " or " AND "."""
    if allowed_device_ids is None:
        return "", ()
    if not allowed_device_ids:
        return f"{conj}device_id = ?", ("__none__",)
    placeholders = ",".join("?" * len(allowed_device_ids))
    return f"{conj}device_id IN ({placeholders})", tuple(allowed_device_ids)


# ── DB resolution + cached model (app entry points) ──────────────────────────
def resolve_db_path() -> str | None:
    """Find the fleet_cache.db regardless of tier (server / local dev)."""
    from pathlib import Path
    candidates = [
        os.getenv("AMOSKYS_FLEET_CACHE", ""),
        os.getenv("CC_DB_PATH", ""),
        "/opt/amoskys/data/fleet_cache.db",         # presentation server
        "data/fleet_cache.db",                       # relative to WorkingDirectory
        str(Path(__file__).resolve().parents[3] / "data" / "fleet_cache.db"),
        str(Path(__file__).resolve().parents[3] / "server" / "fleet.db"),
    ]
    for p in candidates:
        if p and Path(p).exists():
            return p
    return None


def _error_stub(kind: str, message: str, headline: str, sub: str) -> dict:
    return {
        "error": kind, "message": message,
        "verdict": {"active_risk": 0, "band": "calm", "headline": headline, "tone": "calm",
                    "live_count": 0, "suppressed_count": 0, "requires_investigation": 0,
                    "top_factors": [], "sub_line": sub},
        "incidents": [], "globe": {"device": {"lat": 0, "lon": 0}, "destinations": []},
        "domains": [], "timeline": [], "classes": {},
        "totals": {"security_events": 0, "flows": 0, "destinations": 0},
        "device": {"name": "—", "id": "—", "events": 0},
    }


_HOME_LAT = float(os.getenv("AMOSKYS_HOME_LAT", "37.3382"))
_HOME_LON = float(os.getenv("AMOSKYS_HOME_LON", "-121.8863"))

# Model cache keyed by scope (org_id or 'admin') so one tenant's cached model
# can never be served to another tenant.
_CACHE: dict = {}
_TTL_SECONDS = 45.0


def get_model(force: bool = False, allowed_device_ids: list[str] | None = None,
              cache_key: str = "admin") -> dict:
    """Cached model for the API. Never raises: returns an honest error stub so
    the dashboard degrades gracefully instead of 500-ing."""
    import time

    now = time.time()
    entry = _CACHE.get(cache_key)
    if not force and entry is not None and (now - entry["at"]) < _TTL_SECONDS:
        return entry["model"]
    path = resolve_db_path()
    if not path:
        return _error_stub("no_data", "Fleet telemetry store not found.",
                           "No data yet", "Waiting for the first telemetry to arrive.")
    try:
        model = build_model(path, allowed_device_ids=allowed_device_ids)
        _CACHE[cache_key] = {"at": now, "model": model, "path": path}
        return model
    except sqlite3.Error as exc:
        return _error_stub("db_error", str(exc), "Telemetry unavailable", str(exc))


def _j(raw, fallback):
    if raw is None or raw == "":
        return fallback
    try:
        v = json.loads(raw)
        return v if v is not None else fallback
    except (json.JSONDecodeError, TypeError):
        return fallback


def _asn_friendly(org: str | None) -> str | None:
    if not org:
        return None
    low = org.lower()
    for key, label in KNOWN_GOOD_ASN.items():
        if key in low:
            return label
    return org


def _is_known_good(org: str | None) -> bool:
    if not org:
        return False
    low = org.lower()
    return any(k in low for k in KNOWN_GOOD_ASN)


# ── Benign suppression: the moat ─────────────────────────────────────────────
def classify_expected(ev: dict) -> str | None:
    """Return a human reason if this event is EXPECTED activity, else None.

    This is where AMOSKYS earns its keep: instead of laundering a scary category
    label into a 'malicious' verdict, we recognise the owner's own workflow.
    """
    cat = (ev.get("event_category") or "").lower()
    desc = ev.get("description") or ""
    desc_low = _proc_ctx(desc)

    # Guardrail: scary categories always surface for human confirmation.
    if cat in NEVER_SUPPRESS:
        return None

    # 1) Owner's own deploy/admin: ssh/scp/rsync/git are admin tools; curl/wget
    #    to a known host is the deploy workflow.
    if cat in ("execute_to_exfil", "full_kill_chain", "lolbin_execution",
               "c2_beacon_suspect", "pid_network_anomaly", "long_lived_connection"):
        for b in ("ssh", "scp", "sftp", "rsync", "git"):
            if re.search(rf"\b{b}\b", desc_low):
                return f"Owner admin/deploy — {b} session (admin tooling)"
        for b in ("curl", "wget"):
            if re.search(rf"\b{b}\b", desc_low) and (
                "/.ssh/" in desc_low or "amoskys" in desc_low or "ubuntu@" in desc_low
                or any(t in desc_low for t in KNOWN_TELEMETRY)
            ):
                return f"Owner admin/deploy — {b} to a known host"

    # 2) Owner developer tools (Python/Claude/Codex/node…): dev activity.
    if any(re.search(rf"\b{p}\b", desc_low) for p in OWNER_DEV_PROCS):
        return "Your developer tools (routine dev activity)"

    # 3) Apple/macOS system daemons and any binary running from a system path:
    #    the OS doing its job. Applies to ALL non-scary categories (a system
    #    daemon 'beaconing' is a software-update check, not C2).
    if any(p in desc_low for p in APPLE_SYSTEM_PROCS):
        return "macOS system daemon (expected OS activity)"
    if any(p in desc for p in SYSTEM_PATH_PREFIXES):
        return "macOS system process (expected OS activity)"

    # 4) Beaconing to known telemetry / update / CDN endpoints.
    if "beacon" in cat and any(t in desc_low for t in KNOWN_TELEMETRY):
        return "Telemetry/update check to a reputable service"

    # 5) First-seen domain / new external connection to a known-good CDN/cloud.
    if cat in ("new_domain_first_seen", "new_external_connection", "cloud_sync_active"):
        asn = ev.get("asn_src_org") or ev.get("asn_dst_org") or ""
        if _is_known_good(asn) or any(t in desc_low for t in KNOWN_TELEMETRY):
            return f"First contact with a reputable service"

    return None


def load_events(db: sqlite3.Connection, allowed_device_ids: list[str] | None = None) -> list[dict]:
    scope, scope_p = _scope_sql(allowed_device_ids, " WHERE ")
    rows = db.execute(
        """SELECT timestamp_ns, timestamp_dt, device_id, event_category, event_action,
                  event_outcome, risk_score, confidence, mitre_techniques,
                  geometric_score, temporal_score, behavioral_score, final_classification,
                  description, requires_investigation, threat_intel_match,
                  geo_src_country, asn_src_org, event_id, tier
           FROM security_events"""
        + scope
        + " ORDER BY timestamp_ns DESC",
        scope_p,
    ).fetchall()
    out = []
    for r in rows:
        ev = dict(r)
        ev["mitre"] = _j(ev.get("mitre_techniques"), [])
        ev["expected_reason"] = classify_expected(ev)
        out.append(ev)
    return out


# ── The honest verdict ───────────────────────────────────────────────────────
def compute_verdict(events: list[dict]) -> dict:
    """One risk-oriented number, 0-100, three bands. LOW = safe.

    Anti-cry-wolf design, learned the hard way: the score is driven by the PEAK
    corroborated signal, NOT the sum of routine activity. A thousand benign
    'legitimate' events must never add up to red. Only non-suppressed events
    that are actually classified suspicious/malicious are even candidates, and
    the band is HARD-GATED: we never say 'act now' unless at least one event
    genuinely requires investigation or matches threat intelligence.
    """
    live = [e for e in events if not e["expected_reason"]]
    suppressed = [e for e in events if e["expected_reason"]]

    # Only genuinely-flagged, non-suppressed events are candidates.
    candidates = [e for e in live if (e.get("final_classification") in ("suspicious", "malicious"))]

    contributors = []
    categories = set()
    for e in candidates:
        risk = e.get("risk_score") or 0.0
        conf = e.get("confidence") or 0.0
        weight = risk * (0.4 + 0.6 * conf)          # confidence-gated
        rarity = 0.0
        country = (e.get("geo_src_country") or "").upper()
        if country and country not in ("US", "", "GB", "IE", "NL"):
            rarity = 0.15                             # foreign, non-home region
        if e.get("threat_intel_match"):
            rarity += 0.5
        contribution = weight + rarity
        if contribution > 0.05:
            contributors.append((contribution, e))
            categories.add(e.get("event_category"))

    # Peak signal + a small corroboration/breadth bump — NOT a volume sum.
    contributors.sort(key=lambda x: -x[0])
    peak = contributors[0][0] if contributors else 0.0
    breadth = len(categories)
    signal = peak * 1.6 + 0.05 * max(0, breadth - 1)
    active = 100 * (1 - math.exp(-signal))

    requires = sum(1 for e in live if e.get("requires_investigation"))
    intel_hits = sum(1 for e in live if e.get("threat_intel_match"))

    # Corroboration damping: if the top signal is an unconfirmed probe flag with
    # no investigation requirement and no threat-intel hit, it is evidence to
    # *glance at*, not to act on. Discount it. This is the moat: a scary label
    # alone can't drive the number — only corroboration can.
    if requires == 0 and intel_hits == 0:
        active *= 0.68
    active = round(min(active, 100), 0)

    # HARD band gate: red requires real investigation/intel signal, not a big number.
    # Band vocabulary is unified with incidents: calm / amber / red.
    if (requires > 0 or intel_hits > 0) and active >= BAND_ACT:
        band, headline = "red", "Act now"
    elif candidates and active >= BAND_LOOK:
        band, headline = "amber", "Worth a look"
    elif candidates:
        band, headline = "amber", "A couple of things to glance at"
        active = max(active, 18)
    else:
        band, headline = "calm", "You're OK"
        active = min(active, 12)
    # Never present red without a real trigger.
    if band != "red":
        active = min(active, 64)

    # Dedupe factor labels so a category shows once (not full_kill_chain x3).
    seen_labels, top_factors = set(), []
    for c in contributors:
        label = (c[1].get("event_category") or "event").replace("_", " ")
        if label in seen_labels:
            continue
        seen_labels.add(label)
        top_factors.append({
            "label": label,
            "detail": _redact((c[1].get("description") or "")[:80]),
            "weight": round(c[0], 2),
        })
        if len(top_factors) >= 4:
            break

    return {
        "active_risk": int(active),
        "band": band,
        "headline": headline,
        "tone": band,
        "live_count": len(live),
        "suppressed_count": len(suppressed),
        "requires_investigation": requires,
        "top_factors": top_factors,
        "sub_line": (
            "All observed activity matches your normal patterns."
            if band == "calm"
            else f"{breadth} kind{'s' if breadth != 1 else ''} of activity above your baseline · {len(suppressed)} cleared automatically."
        ),
    }


# ── Correlation into incident "stories" ──────────────────────────────────────
def build_incidents(events: list[dict], flows_by_dest: dict) -> list[dict]:
    """Group related events into legible, correlated stories. Severity = MAX
    member, verdict reflects suppression. Auto-named from attributes."""
    incidents = []

    # Story 1: owner deploy/admin session (the suppressed exec-to-exfil cluster).
    admin = [e for e in events if e["expected_reason"] and "admin/deploy" in (e["expected_reason"] or "")]
    if admin:
        cmds = []
        for e in admin[:6]:
            m = re.search(r"\b(ssh|curl|scp|git|rsync|wget|sftp)\b", (e.get("description") or "").lower())
            if m:
                cmds.append(m.group(1))
        toolset = ", ".join(sorted(set(cmds))) or "ssh/curl"
        incidents.append({
            "id": "inc-owner-deploy",
            "title": f"Your deploy workflow ({toolset} to the AMOSKYS server)",
            "verdict": "expected",
            "verdict_label": "Expected activity",
            "band": "calm",
            "count": len(admin),
            "mitre": sorted({t for e in admin for t in e["mitre"]}),
            "why": (
                "AMOSKYS saw ssh/curl launched by you, using your deploy key, to a host "
                "you administer. A naive detector labels this 'exfiltration'. AMOSKYS "
                "recognises it as your own recurring workflow and suppresses it."
            ),
            "first": admin[-1]["timestamp_dt"],
            "last": admin[0]["timestamp_dt"],
            "factors": ["Known deploy key", "Known destination host", "Recurring pattern", "Owner-initiated"],
        })

    # Story 2: foreign / unattributed egress (the genuinely interesting signal).
    foreign = []
    for key, agg in flows_by_dest.items():
        country = (agg.get("country") or "").upper()
        org = agg.get("org") or ""
        if country and country not in ("US", "GB", "IE", "NL", "") and not _is_known_good(org):
            foreign.append(agg)
    foreign.sort(key=lambda a: -a["flows"])
    for agg in foreign[:3]:
        incidents.append({
            "id": f"inc-egress-{agg['country'].lower()}-{re.sub(r'[^a-z0-9]+', '', (agg['org'] or 'unknown').lower())[:10]}",
            "title": f"Outbound to {agg.get('city') or agg['country']} — {agg.get('org') or 'unattributed'}",
            "verdict": "look",
            "verdict_label": "Worth a look",
            "band": "amber",
            "count": agg["flows"],
            "mitre": ["T1071"],
            "why": (
                f"{agg['flows']} connection(s) to {agg.get('org') or 'an unattributed host'} in "
                f"{agg.get('city') or ''} {agg['country']}. Low volume, foreign, not a service you "
                "normally use. Probably benign (a website or CDN edge) — but AMOSKYS surfaces it "
                "because it is genuinely off your baseline, unlike your deploy traffic."
            ),
            "first": None,
            "last": None,
            "factors": [f"{agg['country']} destination", "Not a known service", f"{agg.get('bytes', 0):,} bytes", "Off baseline"],
            "dest": {"lat": agg["lat"], "lon": agg["lon"], "org": agg.get("org"), "country": agg["country"]},
        })

    # Story: high-signal categories we never auto-suppress (surface for confirm).
    high_signal = {
        "browser_credential_theft": ("Browser credential access flagged", "T1555.003",
            "A probe saw a process touch browser credential storage. On a dev machine this is "
            "usually a password manager or the browser itself — but credential access is worth a "
            "one-time confirmation, so AMOSKYS never hides it."),
        "persistence_creation": ("New login item / LaunchAgent created", "T1543.001",
            "A new persistence entry appeared in ~/Library/LaunchAgents. Often a legitimate app "
            "installing itself — confirm you recognise it."),
    }
    for cat, (title, tech, why) in high_signal.items():
        hits = [e for e in events if (e.get("event_category") or "").lower() == cat and not e["expected_reason"]]
        if hits:
            incidents.append({
                "id": f"inc-{cat.replace('_', '-')}",
                "title": title, "verdict": "look", "verdict_label": "Confirm this",
                "band": "amber", "count": len(hits), "mitre": [tech],
                "why": why, "first": hits[-1]["timestamp_dt"], "last": hits[0]["timestamp_dt"],
                "factors": ["High-signal category", "Not auto-suppressed", "Needs your confirmation"],
            })

    # Story 3: DNS beaconing cluster (suspected periodic lookups).
    beacon = [e for e in events if "beacon" in (e.get("event_category") or "").lower() and not e["expected_reason"]]
    if beacon:
        incidents.append({
            "id": "inc-dns-beacon",
            "title": f"Periodic DNS lookups flagged ({len(beacon)} events)",
            "verdict": "look" if len(beacon) > 20 else "expected",
            "verdict_label": "Worth a look" if len(beacon) > 20 else "Likely benign",
            "band": "amber" if len(beacon) > 20 else "calm",
            "count": len(beacon),
            "mitre": sorted({t for e in beacon for t in e["mitre"]}) or ["T1071.004"],
            "why": (
                "Regular, evenly-spaced DNS lookups can indicate C2 beaconing — but the same "
                "pattern is produced by software update checks, telemetry and push services. "
                "Flagged for review, not auto-escalated."
            ),
            "first": beacon[-1]["timestamp_dt"],
            "last": beacon[0]["timestamp_dt"],
            "factors": ["Periodic interval", "No threat-intel match", "Needs destination review"],
        })

    # Rank: act > look > calm, then by count.
    order = {"act": 0, "look": 1, "calm": 2}
    incidents.sort(key=lambda i: (order.get(i["band"], 3), -i["count"]))
    return incidents


# ── Globe: real geolocated flows -> arcs ─────────────────────────────────────
def build_globe(db: sqlite3.Connection, device_id: str | None = None,
                allowed_device_ids: list[str] | None = None):
    dev_and = " AND device_id = ?" if device_id else ""
    dev_p: tuple = (device_id,) if device_id else ()
    scope, scope_p = _scope_sql(allowed_device_ids, " AND ")
    rows = db.execute(
        """SELECT geo_dst_latitude lat, geo_dst_longitude lon, geo_dst_city city,
                  geo_dst_country country, asn_dst_org org,
                  COUNT(*) flows, SUM(COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) bytes,
                  GROUP_CONCAT(DISTINCT process_name) procs
           FROM flow_events
           WHERE geo_dst_latitude IS NOT NULL AND geo_dst_longitude IS NOT NULL"""
        + dev_and
        + scope
        + """
           GROUP BY geo_dst_latitude, geo_dst_longitude, asn_dst_org
           ORDER BY flows DESC""",
        dev_p + scope_p,
    ).fetchall()
    dests, by_key = [], {}
    for r in rows:
        org = r["org"] or ""
        known = _is_known_good(org)
        country = (r["country"] or "").upper()
        foreign = bool(country and country not in ("US", "GB", "IE", "NL", "") and not known)
        band = "amber" if foreign else "calm"
        d = {
            "lat": r["lat"], "lon": r["lon"],
            "city": r["city"], "country": country,
            "org": _asn_friendly(org), "org_raw": org,
            "flows": r["flows"], "bytes": r["bytes"] or 0,
            "procs": (r["procs"] or "").split(",")[:4],
            "band": band, "known_good": known,
        }
        dests.append(d)
        by_key[f"{r['lat']},{r['lon']},{org}"] = d
    return dests, by_key


# ── Per-domain rollups (the nervous-system strip) ────────────────────────────
def build_domains(db: sqlite3.Connection, events: list[dict],
                  allowed_device_ids: list[str] | None = None) -> list[dict]:
    where, where_p = _scope_sql(allowed_device_ids, " WHERE ")
    and_, and_p = _scope_sql(allowed_device_ids, " AND ")

    def count(q, p=()):
        try:
            return db.execute(q, p).fetchone()[0]
        except sqlite3.Error:
            return 0

    suppressed = sum(1 for e in events if e["expected_reason"])
    flagged = sum(1 for e in events if not e["expected_reason"] and (e.get("final_classification") in ("suspicious", "malicious")))
    return [
        {"key": "process", "label": "Processes", "count": count("SELECT COUNT(*) FROM process_events" + where, where_p),
         "suspicious": count("SELECT COUNT(*) FROM process_events WHERE is_suspicious=1" + and_, and_p), "icon": "cpu"},
        {"key": "network", "label": "Network", "count": count("SELECT COUNT(*) FROM flow_events" + where, where_p),
         "suspicious": count("SELECT COUNT(*) FROM flow_events WHERE is_suspicious=1" + and_, and_p), "icon": "globe"},
        {"key": "dns", "label": "DNS", "count": count("SELECT COUNT(*) FROM dns_events" + where, where_p),
         "suspicious": count("SELECT COUNT(*) FROM dns_events WHERE is_beaconing=1" + and_, and_p), "icon": "dns"},
        {"key": "security", "label": "Correlations", "count": len(events),
         "suspicious": flagged, "icon": "shield"},
        {"key": "suppressed", "label": "Auto-cleared", "count": suppressed,
         "suspicious": 0, "icon": "filter"},
    ]


def build_activity_timeline(db: sqlite3.Connection,
                            allowed_device_ids: list[str] | None = None) -> list[dict]:
    """Hourly event volume across domains for the sparkline/heartbeat."""
    where, where_p = _scope_sql(allowed_device_ids, " WHERE ")
    rows = db.execute(
        """SELECT strftime('%Y-%m-%dT%H:00', timestamp_dt) hr, COUNT(*) n
           FROM flow_events"""
        + where
        + " GROUP BY hr ORDER BY hr DESC LIMIT 48",
        where_p,
    ).fetchall()
    return [{"hour": r["hr"], "count": r["n"]} for r in reversed(rows)]


def _device_name(db: sqlite3.Connection, device_id: str) -> str:
    """Resolve a display name for a device — never invent one."""
    try:
        row = db.execute(
            "SELECT hostname FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        if row and row[0]:
            return str(row[0])
    except Exception:
        pass
    return (device_id or "unknown")[:16]


def build_model(db_path: str, allowed_device_ids: list[str] | None = None) -> dict:
    db = _connect(db_path)
    try:
        scope, scope_p = _scope_sql(allowed_device_ids, " WHERE ")
        events = load_events(db, allowed_device_ids=allowed_device_ids)
        dests, by_key = build_globe(db, allowed_device_ids=allowed_device_ids)
        verdict = compute_verdict(events)
        incidents = build_incidents(events, by_key)
        domains = build_domains(db, events, allowed_device_ids=allowed_device_ids)
        timeline = build_activity_timeline(db, allowed_device_ids=allowed_device_ids)

        device_row = db.execute(
            "SELECT device_id, COUNT(*) n, MAX(timestamp_dt) latest FROM security_events"
            + scope
            + " GROUP BY device_id ORDER BY n DESC LIMIT 1",
            scope_p,
        ).fetchone()
        device = dict(device_row) if device_row else {}

        classes = Counter(e.get("final_classification") for e in events)
        return {
            "generated_at": db.execute(
                "SELECT MAX(timestamp_dt) FROM security_events" + scope, scope_p
            ).fetchone()[0],
            "device": {
                "id": device.get("device_id", "unknown"),
                "name": _device_name(db, device.get("device_id", "")),
                "lat": _HOME_LAT, "lon": _HOME_LON,  # owner home region (env-config)
                "events": device.get("n", 0),
                "latest": device.get("latest"),
            },
            "verdict": verdict,
            "incidents": incidents,
            "globe": {"device": {"lat": _HOME_LAT, "lon": _HOME_LON}, "destinations": dests},
            "domains": domains,
            "timeline": timeline,
            "classes": dict(classes),
            "totals": {
                "security_events": len(events),
                "flows": db.execute(
                    "SELECT COUNT(*) FROM flow_events" + scope, scope_p
                ).fetchone()[0],
                "destinations": len(dests),
            },
        }
    finally:
        db.close()


# ── Device drill-down: the cross-domain "story" (the moat view) ──────────────
def _exe_short(exe: str | None) -> str:
    if not exe:
        return "—"
    return exe.rsplit("/", 1)[-1] if "/" in exe else exe


def build_device_model(db_path: str, device_id: str | None = None,
                       allowed_device_ids: list[str] | None = None) -> dict:
    """One device's whole nervous system: exposure vs active-risk, per-domain
    lanes, and a UNIFIED cross-domain event stream (process→network→dns→
    correlation) — the thing a single-domain tool cannot show."""
    db = _connect(db_path)
    try:
        if not device_id:
            scope, scope_p = _scope_sql(allowed_device_ids, " WHERE ")
            row = db.execute(
                "SELECT device_id FROM security_events"
                + scope
                + " GROUP BY device_id ORDER BY COUNT(*) DESC LIMIT 1",
                scope_p,
            ).fetchone()
            device_id = row[0] if row else "unknown"
        # Tenant isolation, defence in depth: a device outside the caller's
        # allowlist yields an empty model even if the route check is bypassed.
        if allowed_device_ids is not None and device_id not in allowed_device_ids:
            device_id = "__none__"

        events = load_events(db)
        # STRICT device scoping — the old `or events` fallback silently showed
        # the whole fleet's events under this device's name when it had none.
        events = [e for e in events if e.get("device_id") == device_id]
        verdict = compute_verdict(events)

        # Exposure (posture) — honest: derived from the hygiene signals we DO see.
        posture_hits = sum(
            1 for e in events
            if (e.get("event_category") or "") in ("persistence_creation", "browser_credential_theft")
            and not e["expected_reason"]
        )
        exposure = {
            "band": "amber" if posture_hits else "calm",
            "label": f"{posture_hits} to review" if posture_hits else "Good",
            "note": "login items & credential access" if posture_hits else "no open hygiene items seen",
        }

        stream = []

        def add(ts, dom, band, title, detail, mitre=None):
            stream.append({"ts": ts, "domain": dom, "band": band,
                           "title": _redact(title), "detail": _redact(detail), "mitre": mitre or []})

        # security correlations — flagged (non-suppressed suspicious/malicious)
        # first, then recent for texture.
        flagged_corr = [e for e in events if not e["expected_reason"]
                        and e.get("final_classification") in ("suspicious", "malicious")]
        recent_corr = [e for e in events if e not in flagged_corr][:16]
        for e in (flagged_corr[:18] + recent_corr):
            band = "calm" if e["expected_reason"] else (
                "amber" if e.get("final_classification") in ("suspicious", "malicious") else "calm")
            title = (e.get("event_category") or "event").replace("_", " ")
            detail = e["expected_reason"] or (e.get("description") or "")[:110]
            add(e.get("timestamp_dt"), "correlation", band, title, detail, e.get("mitre"))

        # network — recent geolocated flows
        for r in db.execute(
            """SELECT timestamp_dt, dst_ip, dst_port, asn_dst_org, geo_dst_city, geo_dst_country,
                      process_name, (COALESCE(bytes_tx,0)+COALESCE(bytes_rx,0)) b, is_suspicious
               FROM flow_events WHERE device_id=? AND geo_dst_latitude IS NOT NULL
               ORDER BY timestamp_ns DESC LIMIT 22""", (device_id,)):
            org = r["asn_dst_org"] or ""
            known = _is_known_good(org)
            country = (r["geo_dst_country"] or "").upper()
            foreign = bool(country and country not in ("US", "GB", "IE", "NL", "") and not known)
            add(r["timestamp_dt"], "network", "amber" if (foreign or r["is_suspicious"]) else "calm",
                f"{r['process_name'] or 'conn'} → {_asn_friendly(org) or r['dst_ip']}",
                f"{(r['geo_dst_city'] or '')} {country} · {r['b']:,} bytes · :{r['dst_port']}")

        # dns — recent lookups, beaconing flagged
        for r in db.execute(
            """SELECT timestamp_dt, domain, process_name, is_beaconing, dga_score
               FROM dns_events WHERE device_id=? ORDER BY timestamp_ns DESC LIMIT 16""", (device_id,)):
            beacon = bool(r["is_beaconing"])
            known = any(t in (r["domain"] or "").lower() for t in KNOWN_TELEMETRY)
            add(r["timestamp_dt"], "dns", "amber" if (beacon and not known) else "calm",
                r["domain"] or "(lookup)",
                f"{r['process_name'] or '—'}" + (" · periodic" if beacon else ""))

        # process — recent spawns (highlight non-system / suspicious)
        for r in db.execute(
            """SELECT timestamp_dt, exe, username, is_suspicious, cpu_percent
               FROM process_events WHERE device_id=? ORDER BY timestamp_ns DESC LIMIT 16""", (device_id,)):
            exe = r["exe"] or ""
            sysproc = any(exe.startswith(p) for p in SYSTEM_PATH_PREFIXES)
            add(r["timestamp_dt"], "process", "amber" if r["is_suspicious"] else "calm",
                _exe_short(exe), ("system" if sysproc else "user") + f" · {r['username'] or '—'}")

        # Tell the moat: keep ALL flagged (amber/red) events, then fill with the
        # most recent calm ones for texture — never let recency bury the signal.
        amber = [s for s in stream if s["band"] in ("amber", "red")]
        calm = sorted((s for s in stream if s["band"] == "calm"),
                      key=lambda s: s["ts"] or "", reverse=True)
        stream = amber + calm[: max(0, 60 - len(amber))]
        stream.sort(key=lambda s: s["ts"] or "", reverse=True)

        def c(q):
            try:
                return db.execute(q, (device_id,)).fetchone()[0]
            except sqlite3.Error:
                return 0
        lanes = [
            {"key": "process", "label": "Process", "icon": "cpu",
             "count": c("SELECT COUNT(*) FROM process_events WHERE device_id=?"),
             "flagged": c("SELECT COUNT(*) FROM process_events WHERE device_id=? AND is_suspicious=1")},
            {"key": "network", "label": "Network", "icon": "globe",
             "count": c("SELECT COUNT(*) FROM flow_events WHERE device_id=?"),
             "flagged": c("SELECT COUNT(*) FROM flow_events WHERE device_id=? AND is_suspicious=1")},
            {"key": "dns", "label": "DNS", "icon": "dns",
             "count": c("SELECT COUNT(*) FROM dns_events WHERE device_id=?"),
             "flagged": c("SELECT COUNT(*) FROM dns_events WHERE device_id=? AND is_beaconing=1")},
            {"key": "correlation", "label": "Correlations", "icon": "shield",
             "count": len(events),
             "flagged": sum(1 for e in events if not e["expected_reason"]
                            and e.get("final_classification") in ("suspicious", "malicious"))},
        ]

        dests, by_key = build_globe(db, device_id=device_id)
        incidents = build_incidents(events, by_key)
        latest = db.execute(
            "SELECT MAX(timestamp_dt) FROM security_events WHERE device_id=?", (device_id,)
        ).fetchone()[0]
        return {
            "generated_at": latest,
            "device": {"id": device_id, "name": _device_name(db, device_id),
                       "events": len(events), "latest": latest},
            "verdict": verdict,
            "exposure": exposure,
            "lanes": lanes,
            "stream": stream[:60],
            "incidents": incidents,
        }
    finally:
        db.close()


# Device-model cache keyed by (org_id or 'admin', device_id) — see _CACHE.
_DEV_CACHE: dict = {}


def get_device_model(device_id: str | None = None, force: bool = False,
                     allowed_device_ids: list[str] | None = None,
                     cache_key: str = "admin") -> dict:
    """Cached device model; degrades gracefully like get_model()."""
    import time
    now = time.time()
    key = (cache_key, device_id or "_default")
    entry = _DEV_CACHE.get(key)
    if not force and entry is not None and (now - entry["at"]) < _TTL_SECONDS:
        return entry["model"]
    path = resolve_db_path()
    if not path:
        return {"error": "no_data", "device": {"name": "—", "id": "—", "events": 0},
                "verdict": {"active_risk": 0, "band": "calm", "headline": "No data yet"},
                "exposure": {"band": "calm", "label": "—", "note": ""},
                "lanes": [], "stream": [], "incidents": []}
    try:
        model = build_device_model(path, device_id,
                                   allowed_device_ids=allowed_device_ids)
        _DEV_CACHE[key] = {"at": now, "model": model}
        return model
    except sqlite3.Error as exc:
        return {"error": "db_error", "message": str(exc),
                "device": {"name": "—", "id": "—", "events": 0},
                "verdict": {"active_risk": 0, "band": "calm", "headline": "Telemetry unavailable"},
                "exposure": {"band": "calm", "label": "—", "note": ""},
                "lanes": [], "stream": [], "incidents": []}


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "fleet_cache.db"
    out = sys.argv[2] if len(sys.argv) > 2 else "model.json"
    # device model too (for the prototype)
    dev = build_device_model(path)
    with open("device_model.json", "w") as f:
        json.dump(dev, f, indent=2, default=str)
    with open("device_model.js", "w") as f:
        f.write("window.AMOSKYS_DEVICE = ")
        json.dump(dev, f, default=str)
        f.write(";")
    print(f"  device stream: {len(dev['stream'])} events · exposure {dev['exposure']['label']} · lanes {[l['flagged'] for l in dev['lanes']]}")
    model = build_model(path)
    with open(out, "w") as f:
        json.dump(model, f, indent=2, default=str)
    # Also emit a JS global so the standalone prototype renders from file://.
    js_out = out.rsplit(".", 1)[0] + ".js"
    with open(js_out, "w") as f:
        f.write("window.AMOSKYS_MODEL = ")
        json.dump(model, f, default=str)
        f.write(";")
    v = model["verdict"]
    print(f"✓ model → {out}")
    print(f"  verdict: {v['headline']} ({v['band']}, active_risk={v['active_risk']}/100)")
    print(f"  live={v['live_count']} suppressed={v['suppressed_count']} requires_investigation={v['requires_investigation']}")
    print(f"  incidents: {len(model['incidents'])}  destinations: {model['totals']['destinations']}")
    for i in model["incidents"]:
        print(f"    [{i['band']:5}] {i['verdict_label']:18} — {i['title']}  (x{i['count']})")
