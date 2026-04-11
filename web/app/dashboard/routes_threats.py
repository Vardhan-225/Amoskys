"""Threat-related API routes for the AMOSKYS Dashboard.

Extracted from __init__.py — contains the live threats feed and unified
event stream endpoints.
"""

import time
from datetime import datetime, timezone

from flask import jsonify, request

from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login
from . import dashboard_bp
from .route_helpers import (
    _normalize_agent_id,
    _parse_indicators,
    _parse_mitre,
    _query_table_dns,
    _query_table_fim,
    _query_table_flow,
    _query_table_persistence,
    _query_table_process,
    _query_table_security,
    _risk_to_severity,
)


# Real-time Data Endpoints
@dashboard_bp.route("/api/live/threats")
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def live_threats():
    """Real-time threat feed from TelemetryStore."""
    from .telemetry_bridge import get_telemetry_store

    now = datetime.now(timezone.utc)
    store = get_telemetry_store()

    if store is None:
        return jsonify(
            {
                "status": "success",
                "threats": [],
                "count": 0,
                "timestamp": now.isoformat(),
            }
        )

    try:
        hours = min(int(request.args.get("hours", 24)), 8760)
    except (ValueError, TypeError):
        hours = 24

    # Pagination params
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(max(10, int(request.args.get("per_page", 50))), 200)
    except (ValueError, TypeError):
        per_page = 50
    offset = (page - 1) * per_page

    # DB-level aggregate counts across ALL domain tables
    counts = store.get_unified_event_counts(hours=hours)
    clustering = store.get_security_event_clustering(hours=hours)
    # Fast threat-only count (events with risk > threshold)
    _threat_min = 0.1

    # Unified query — filter to actual detections (risk > 0.1) for threat feed
    min_risk = 0.1
    try:
        min_risk = float(request.args.get("min_risk", 0.1))
    except (ValueError, TypeError):
        pass
    # Tier filter: default to "attack" (real threats only).
    # Pass tier="" or tier=all to see everything including observations.
    tier = request.args.get("tier", "attack")
    if tier == "all":
        tier = ""
    rows = store.get_unified_threat_events(
        limit=per_page, hours=hours, offset=offset, min_risk=min_risk, tier=tier
    )
    data_stale = False
    if not rows and page == 1:
        rows = store.get_unified_threat_events(
            limit=50, hours=8760, min_risk=0.0, tier=tier
        )
        data_stale = bool(rows)
    recent_events = []
    for row in rows:
        # Extract source_ip from indicators JSON if available
        indicators = _parse_indicators(row.get("indicators"))

        source_ip = ""
        if isinstance(indicators, dict):
            source_ip = indicators.get("source_ip") or indicators.get("src_ip") or ""
            # Extract first remote IP from public_connections if present
            if not indicators.get("dst_ip") and not indicators.get("remote_ip"):
                conns = indicators.get("public_connections")
                if isinstance(conns, list) and conns:
                    first_remote = conns[0].get("remote_ip", "")
                    if first_remote:
                        indicators["remote_ip"] = first_remote
                        if len(conns) > 1:
                            indicators["remote_ip_count"] = len(conns)

        # Parse MITRE techniques
        mitre = _parse_mitre(row.get("mitre_techniques"))

        # Resolve agent name with normalization
        agent_raw = ""
        if isinstance(indicators, dict):
            agent_raw = indicators.get("agent", "")
        agent_raw = agent_raw or row.get("collection_agent") or ""
        agent_name = _normalize_agent_id(agent_raw)
        device_id = row.get("device_id", "")
        confidence = round(row.get("confidence", 0) or 0, 3)
        risk_score = round(row.get("risk_score", 0) or 0, 3)
        source_table = row.get("source", "security")

        recent_events.append(
            {
                "id": row.get("id"),
                "source": source_table,
                "type": row.get("type") or row.get("event_category", "unknown"),
                "severity": _risk_to_severity(risk_score),
                "risk_score": risk_score,
                "confidence": confidence,
                "source_ip": source_ip,
                "description": row.get("description", ""),
                "timestamp": row.get("timestamp_dt", ""),
                "agent_name": agent_name,
                "device_id": device_id,
                "agent_id": agent_name or device_id,
                "classification": row.get("final_classification", ""),
                "mitre_techniques": mitre,
                "requires_investigation": bool(
                    row.get("requires_investigation", False)
                ),
                "event_action": row.get("event_action", ""),
                "indicators": indicators,
            }
        )

    # Deduplicate: same (source_table, id) pair means exact DB duplicate
    seen_pks: set = set()
    deduped: list = []
    for e in recent_events:
        pk = f"{e.get('source', '')}:{e.get('id', '')}"
        if pk not in seen_pks:
            seen_pks.add(pk)
            deduped.append(e)
    recent_events = deduped

    # Count events requiring investigation
    investigating_count = sum(1 for e in recent_events if e["requires_investigation"])

    # Determine when the most recent event occurred
    last_event_time = recent_events[0]["timestamp"] if recent_events else None

    # Aggregate stats: false-positive rate, avg confidence
    legit_count = sum(1 for e in recent_events if e["classification"] == "legitimate")
    fp_rate = round(legit_count / len(recent_events), 3) if recent_events else 0
    confidences = [e["confidence"] for e in recent_events if e["confidence"] > 0]
    avg_confidence = round(sum(confidences) / len(confidences), 3) if confidences else 0

    db_total = counts.get("total", 0)
    threat_total = store.get_threat_count(hours=hours, min_risk=min_risk, tier=tier)
    total_pages = max(1, -(-threat_total // per_page))  # ceil division

    return jsonify(
        {
            "status": "success",
            "threats": recent_events,
            "count": len(recent_events),
            "db_total": db_total,
            "threat_total": threat_total,
            "by_source": counts.get("by_source", {}),
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "db_by_classification": counts.get("by_classification", {}),
            "db_by_severity": clustering.get("by_severity", {}),
            "investigating_count": investigating_count,
            "fp_rate": fp_rate,
            "avg_confidence": avg_confidence,
            "data_stale": data_stale,
            "last_event_time": last_event_time,
            "timestamp": now.isoformat(),
        }
    )


@dashboard_bp.route("/api/live/unified-events")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def unified_events():
    """Truly unified event stream across ALL domain tables.

    Queries security_events, process_events, flow_events, dns_events,
    persistence_events, and fim_events — merges into a single sorted stream.

    Query params:
        hours: Time window (default 24)
        limit: Max results (default 100)
        offset: Skip N results (default 0)
        agent: Filter by agent name
        severity: Filter by severity (critical, high, medium, low)
        search: Text search on event_category and description
        hour: Filter by specific hour (ISO format)
        domain: Filter by event domain (process, flow, dns, fim, persistence,
                security, audit, peripheral, observation)
    """
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"events": [], "total": 0})

    try:
        hours = min(int(request.args.get("hours", 24)), 8760)
    except (ValueError, TypeError):
        hours = 24
    try:
        limit = min(max(1, int(request.args.get("limit", 100))), 500)
    except (ValueError, TypeError):
        limit = 100
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except (ValueError, TypeError):
        offset = 0

    agent_filter = request.args.get("agent", "")
    severity_filter = request.args.get("severity", "")
    search_filter = request.args.get("search", "")
    hour_filter = request.args.get("hour", "")
    domain_filter = request.args.get("domain", "")
    cutoff_ns = int((time.time() - hours * 3600) * 1e9)

    # Severity filter ranges
    sev_lo, sev_hi = 0.0, 1.01
    if severity_filter:
        sev_ranges = {
            "critical": (0.75, 1.01),
            "high": (0.50, 0.75),
            "medium": (0.25, 0.50),
            "low": (0.0, 0.25),
        }
        if severity_filter.lower() in sev_ranges:
            sev_lo, sev_hi = sev_ranges[severity_filter.lower()]

    # Hour filter
    hour_start_ns, hour_end_ns = None, None
    if hour_filter:
        try:
            hour_dt = datetime.fromisoformat(hour_filter.replace("Z", "+00:00"))
            hour_start_ns = int(hour_dt.timestamp() * 1e9)
            hour_end_ns = hour_start_ns + int(3600 * 1e9)
        except ValueError:
            pass

    # Normalize agent filter
    norm_agent = _normalize_agent_id(agent_filter) if agent_filter else ""

    # Domain filter → set of source_table names to include
    # Maps domain pill values to the source_table names used by _query_table_* functions
    _domain_to_tables = {
        "process": {"process"},
        "flow": {"flow"},
        "dns": {"dns"},
        "fim": {"fim"},
        "persistence": {"persistence"},
        "security": {"security"},
        "audit": {"security"},
        "peripheral": {"security"},
        "observation": {"security"},
    }
    domain_tables = _domain_to_tables.get(domain_filter) if domain_filter else None

    def _include_table(table_name):
        """Check if a table should be queried given domain filter."""
        if domain_tables is None:
            return True
        return table_name in domain_tables

    try:
        all_events = []

        with store._lock:
            # ── 1. security_events ──
            if _include_table("security"):
                all_events.extend(
                    _query_table_security(
                        store,
                        cutoff_ns,
                        norm_agent,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 2. process_events ──
            if (not norm_agent or norm_agent == "proc") and _include_table("process"):
                all_events.extend(
                    _query_table_process(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 3. flow_events ──
            if (not norm_agent or norm_agent == "flow") and _include_table("flow"):
                all_events.extend(
                    _query_table_flow(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 4. dns_events ──
            if (not norm_agent or norm_agent == "dns") and _include_table("dns"):
                all_events.extend(
                    _query_table_dns(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 5. persistence_events ──
            if (not norm_agent or norm_agent == "persistence") and _include_table(
                "persistence"
            ):
                all_events.extend(
                    _query_table_persistence(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

            # ── 6. fim_events ──
            if (not norm_agent or norm_agent == "fim") and _include_table("fim"):
                all_events.extend(
                    _query_table_fim(
                        store,
                        cutoff_ns,
                        sev_lo,
                        sev_hi,
                        search_filter,
                        hour_start_ns,
                        hour_end_ns,
                    )
                )

        # Post-filter for domain types that share the security_events table
        if domain_filter in ("audit", "peripheral", "observation"):
            _domain_agent_prefixes = {
                "audit": ("auth", "audit"),
                "peripheral": ("peripheral", "periph", "usb"),
                "observation": (
                    "obs",
                    "infostealer",
                    "quarantine",
                    "provenance",
                    "network_sentinel",
                ),
            }
            prefixes = _domain_agent_prefixes[domain_filter]
            all_events = [
                ev
                for ev in all_events
                if any(
                    (ev.get("agent") or "").lower().startswith(p)
                    or (ev.get("event_category") or "").lower().startswith(p)
                    for p in prefixes
                )
            ]

        # Sort all events by timestamp descending, paginate
        all_events.sort(key=lambda e: e.get("_sort_ts", 0), reverse=True)
        total = len(all_events)
        page = all_events[offset : offset + limit]

        # Strip internal sort key
        for ev in page:
            ev.pop("_sort_ts", None)

        return jsonify({"events": page, "total": total})
    except Exception as e:
        return jsonify({"events": [], "total": 0, "error": str(e)})
