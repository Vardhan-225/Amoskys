"""Agent management, pipeline control, incident CRUD, correlation, and deep overview routes.

Extracted from dashboard/__init__.py to reduce file size.
All routes are registered on ``dashboard_bp`` which is imported from the
parent package.
"""

from __future__ import annotations

import importlib
import time
from datetime import datetime, timezone

from flask import jsonify, request

from ..api.rate_limiter import require_rate_limit
from ..middleware import require_login
from . import dashboard_bp
from .route_helpers import (
    _get_local_ip,
    _get_store,
    _normalize_agent_id,
    _parse_indicators,
    _parse_mitre,
)

# ── Shared constants ─────────────────────────────────────────────

_MSG_DB_UNAVAILABLE = "Database unavailable"


# ── Agent Control Endpoints ──────────────────────────────────────


@dashboard_bp.route("/api/agents/status", methods=["GET"])
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def agents_detailed_status():
    """Get detailed status of all agents with health checks"""
    from .agent_control import get_all_agents_status_detailed

    try:
        status_data = get_all_agents_status_detailed()
        return jsonify(
            {
                "status": "success",
                "data": status_data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/status", methods=["GET"])
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def agent_status(agent_id):
    """Get detailed status of a specific agent"""
    from .agent_control import get_agent_status

    try:
        status = get_agent_status(agent_id)
        return jsonify(
            {
                "status": "success",
                "data": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/start", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def start_agent(agent_id):
    """Start a stopped agent"""
    from .agent_control import start_agent as start_agent_fn

    try:
        result = start_agent_fn(agent_id)
        status_code = (
            200 if result.get("status") in ("started", "already_running") else 400
        )
        return jsonify(result), status_code
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "agent_id": agent_id,
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/stop", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def stop_agent(agent_id):
    """Stop a running agent"""
    from .agent_control import stop_agent as stop_agent_fn

    try:
        result = stop_agent_fn(agent_id)
        status_code = (
            200
            if result.get("status") in ("stopped", "force_killed", "not_running")
            else 400
        )
        return jsonify(result), status_code
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "agent_id": agent_id,
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/health", methods=["GET"])
@require_login
@require_rate_limit(max_requests=100, window_seconds=60)
def agent_health_check(agent_id):
    """Perform health check on a specific agent"""
    from .agent_control import health_check_agent

    try:
        health = health_check_agent(agent_id)
        status_code = 200 if health.get("healthy") else 400
        return (
            jsonify(
                {
                    "status": "success",
                    "data": health,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            status_code,
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/<agent_id>/logs", methods=["GET"])
@require_login
@require_rate_limit(max_requests=50, window_seconds=60)
def agent_logs(agent_id):
    """Get startup logs for an agent"""
    from .agent_control import get_startup_logs

    lines = request.args.get("lines", default=50, type=int)

    try:
        logs = get_startup_logs(agent_id, lines=min(lines, 500))
        return jsonify(
            {
                "status": "success",
                "data": logs,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/agents/restart-all", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def restart_all_agents():
    """Restart all agents (with proper shutdown and restart)"""
    from .agent_control import start_agent as start_agent_fn
    from .agent_control import stop_agent as stop_agent_fn
    from .agent_discovery import AGENT_CATALOG

    try:
        results = {
            "total": len(AGENT_CATALOG),
            "stopped": 0,
            "started": 0,
            "failed": 0,
            "agents": {},
        }

        # First, stop all running agents
        for agent_id in AGENT_CATALOG:
            stop_result = stop_agent_fn(agent_id)
            if stop_result.get("status") in ("stopped", "force_killed", "not_running"):
                results["stopped"] += 1
            results["agents"][agent_id] = {"stopped": stop_result.get("status")}

        # Wait a moment between shutdown and startup
        time.sleep(2)

        # Then, start all agents (infrastructure first, then security)
        import platform as _plat

        current = _plat.system().lower()
        infra_first = sorted(
            AGENT_CATALOG.items(),
            key=lambda x: (0 if x[1].get("critical") else 1),
        )
        for agent_id, config in infra_first:
            if current not in config.get("platform", []):
                continue
            start_result = start_agent_fn(agent_id)
            if start_result.get("status") in ("started", "already_running"):
                results["started"] += 1
            else:
                results["failed"] += 1
            results["agents"].setdefault(agent_id, {})
            results["agents"][agent_id]["started"] = start_result.get("status")

        return jsonify(
            {
                "status": "success",
                "data": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


# ── Pipeline Start API ────────────────────────────────────────────


@dashboard_bp.route("/api/pipeline/start", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def start_entire_pipeline():
    """Start the entire AMOSKYS pipeline in dependency order.

    Order: EventBus -> WAL Processor -> All security agents.
    Each infrastructure component waits for confirmation before proceeding.
    """
    from .agent_control import start_agent as start_agent_fn
    from .agent_discovery import AGENT_CATALOG

    try:
        results = {
            "phase": [],
            "started": 0,
            "failed": 0,
            "skipped": 0,
            "agents": {},
        }

        # Phase 1: Infrastructure (EventBus, WAL Processor) — order matters
        infra_ids = ["eventbus", "wal_processor"]
        for agent_id in infra_ids:
            if agent_id not in AGENT_CATALOG:
                continue
            r = start_agent_fn(agent_id)
            status = r.get("status")
            results["agents"][agent_id] = r
            if status in ("started", "already_running"):
                results["started"] += 1
            else:
                results["failed"] += 1
        results["phase"].append({"name": "infrastructure", "agents": infra_ids})

        # Brief pause for infra to initialize
        time.sleep(2)

        # Phase 2: All security agents
        security_ids = [aid for aid in AGENT_CATALOG if aid not in infra_ids]
        for agent_id in security_ids:
            cfg = AGENT_CATALOG[agent_id]
            # Skip agents not for this platform
            import platform as _plat

            current = _plat.system().lower()
            if current not in cfg.get("platform", []):
                results["skipped"] += 1
                continue
            r = start_agent_fn(agent_id)
            status = r.get("status")
            results["agents"][agent_id] = r
            if status in ("started", "already_running"):
                results["started"] += 1
            else:
                results["failed"] += 1
        results["phase"].append({"name": "security_agents", "agents": security_ids})

        return jsonify(
            {
                "status": "success",
                "message": (
                    f"Pipeline started: {results['started']} running, "
                    f"{results['failed']} failed, {results['skipped']} skipped"
                ),
                "data": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


@dashboard_bp.route("/api/pipeline/stop", methods=["POST"])
@require_login
@require_rate_limit(max_requests=5, window_seconds=60)
def stop_entire_pipeline():
    """Stop the entire AMOSKYS pipeline in reverse dependency order."""
    from .agent_control import stop_agent as stop_agent_fn
    from .agent_discovery import AGENT_CATALOG

    try:
        results = {"stopped": 0, "failed": 0, "agents": {}}

        # Phase 1: Stop security agents first
        infra_ids = {"eventbus", "wal_processor"}
        for agent_id in AGENT_CATALOG:
            if agent_id in infra_ids:
                continue
            r = stop_agent_fn(agent_id)
            results["agents"][agent_id] = r
            if r.get("status") in ("stopped", "force_killed", "not_running"):
                results["stopped"] += 1

        time.sleep(1)

        # Phase 2: Stop infrastructure (reverse order)
        for agent_id in reversed(list(infra_ids)):
            r = stop_agent_fn(agent_id)
            results["agents"][agent_id] = r
            if r.get("status") in ("stopped", "force_killed", "not_running"):
                results["stopped"] += 1

        return jsonify(
            {
                "status": "success",
                "message": f"Pipeline stopped: {results['stopped']} components",
                "data": results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
        )


# ── New Feature APIs ──────────────────────────────────────────────


@dashboard_bp.route("/api/mitre/coverage")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def mitre_coverage_data():
    """MITRE ATT&CK technique coverage: declared (from probes) + detected (from events)."""
    import platform as _platform

    from .capabilities import get_declared_mitre_coverage
    from .telemetry_bridge import get_telemetry_store

    target = "darwin" if _platform.system() == "Darwin" else "linux"
    declared = get_declared_mitre_coverage(target)

    store = get_telemetry_store()
    detected = {}
    if store:
        try:
            detected = store.get_mitre_coverage()
        except Exception:
            pass

    return jsonify(
        {
            "status": "success",
            "declared": declared,
            "detected": detected,
            "by_tactic": declared.get("by_tactic", {}),
            "coverage": detected,  # backward compat
            "total_techniques": declared.get("technique_count", 0),
            "total_detected": len(detected),
            "total_hits": sum(v.get("count", 0) for v in detected.values()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/hunt/search")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def hunt_search():
    """Log search / threat hunting endpoint."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify(
            {"status": "success", "results": [], "total_count": 0, "has_more": False}
        )

    query = request.args.get("q", "")
    ALLOWED_TABLES = {
        "security_events",
        "process_events",
        "flow_events",
        "dns_events",
        "fim_events",
        "audit_events",
        "persistence_events",
        "peripheral_events",
        "observation_events",
    }
    table = request.args.get("table", "security_events")
    if table not in ALLOWED_TABLES:
        return jsonify({"status": "error", "message": "Invalid table name"}), 400
    hours = request.args.get("hours", 24, type=int)
    limit = min(request.args.get("limit", 50, type=int), 200)
    offset = request.args.get("offset", 0, type=int)
    min_risk = request.args.get("min_risk", type=float)
    category = request.args.get("category")

    data = store.search_events(
        query=query,
        table=table,
        hours=hours,
        limit=limit,
        offset=offset,
        min_risk=min_risk,
        category=category,
    )
    data["status"] = "success"
    data["timestamp"] = datetime.now(timezone.utc).isoformat()
    return jsonify(data)


# ── Incident CRUD ─────────────────────────────────────────────────


@dashboard_bp.route("/api/incidents", methods=["GET"])
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def list_incidents():
    """List security incidents with optional pagination and status filter."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify(
            {
                "status": "success",
                "incidents": [],
                "count": 0,
                "total": 0,
                "page": 1,
                "per_page": 20,
                "total_pages": 0,
                "status_counts": {},
                "severity_counts": {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    status_filter = request.args.get("status") or None
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(max(1, int(request.args.get("per_page", 20))), 100)
    except (ValueError, TypeError):
        per_page = 20

    total = store.get_incidents_count(status=status_filter)
    total_pages = max(1, (total + per_page - 1) // per_page) if total else 1
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    incidents = store.get_incidents(status=status_filter, limit=per_page, offset=offset)
    status_counts = store.get_incidents_status_counts()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    severity_counts.update(store.get_incidents_severity_counts() or {})

    return jsonify(
        {
            "status": "success",
            "incidents": incidents,
            "count": len(incidents),
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/incidents", methods=["POST"])
@require_login
@require_rate_limit(max_requests=20, window_seconds=60)
def create_incident():
    """Create a new security incident."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500

    data = request.get_json(silent=True) or {}
    incident_id = store.create_incident(data)
    if incident_id:
        return jsonify({"status": "success", "incident_id": incident_id}), 201
    return jsonify({"status": "error", "message": "Failed to create"}), 500


@dashboard_bp.route("/api/incidents/<int:incident_id>", methods=["GET"])
@require_login
def get_incident_route(incident_id):
    """Get a single incident."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": "DB unavailable"}), 500

    incident = store.get_incident(incident_id)
    if incident:
        return jsonify({"status": "success", "incident": incident})
    return jsonify({"status": "error", "message": "Not found"}), 404


@dashboard_bp.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def update_incident_route(incident_id):
    """Update an incident."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "error", "message": "DB unavailable"}), 500

    data = request.get_json(silent=True) or {}
    ok = store.update_incident(incident_id, data)
    if ok:
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Update failed"}), 500


# ── Network Topology ──────────────────────────────────────────────


@dashboard_bp.route("/api/network/topology")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def network_topology_data():
    """Network topology from device_telemetry and flow_events."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    if store is None:
        return jsonify({"status": "success", "nodes": [], "edges": []})

    nodes = []
    edges = []
    try:
        # Devices — deduplicate via GROUP BY instead of fetching all rows
        cursor = store.db.execute(
            "SELECT device_id, MAX(ip_address), MAX(device_type), MAX(manufacturer) "
            "FROM device_telemetry GROUP BY device_id LIMIT 200"
        )
        seen_ids = set()
        for row in cursor.fetchall():
            did = row[0]
            if did not in seen_ids:
                seen_ids.add(did)
                nodes.append(
                    {
                        "id": did,
                        "label": did,
                        "ip": row[1] or "",
                        "type": row[2] or "host",
                        "manufacturer": row[3] or "",
                    }
                )
        # Flow edges — limit to recent 24h and top 200 connections
        flow_cutoff = int((time.time() - 24 * 3600) * 1e9)
        cursor = store.db.execute(
            "SELECT src_ip, dst_ip, protocol, SUM(bytes_tx), COUNT(*) "
            "FROM flow_events WHERE timestamp_ns > ? "
            "GROUP BY src_ip, dst_ip, protocol "
            "ORDER BY COUNT(*) DESC LIMIT 200",
            (flow_cutoff,),
        )
        for row in cursor.fetchall():
            if row[0] and row[1]:
                edges.append(
                    {
                        "source": row[0],
                        "target": row[1],
                        "protocol": row[2] or "TCP",
                        "bytes": row[3] or 0,
                        "count": row[4],
                    }
                )
        # Security device IDs — use index, limit to 200
        cursor = store.db.execute(
            "SELECT DISTINCT device_id FROM security_events LIMIT 200"
        )
        for row in cursor.fetchall():
            did = row[0]
            if did and did not in seen_ids:
                seen_ids.add(did)
                nodes.append(
                    {
                        "id": did,
                        "label": did,
                        "ip": "",
                        "type": "endpoint",
                        "manufacturer": "",
                    }
                )
    except Exception:
        pass

    return jsonify(
        {
            "status": "success",
            "nodes": nodes,
            "edges": edges,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ── Event Correlation ─────────────────────────────────────────────


@dashboard_bp.route("/api/correlate")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def correlate_events():
    """Correlate events around a seed event for timeline replay and evidence chain."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    event_id = request.args.get("event_id", type=int)
    window_minutes = request.args.get("window_minutes", 30, type=int)
    max_results = request.args.get("max_results", 100, type=int)

    if store is None:
        return jsonify({"status": "error", "message": _MSG_DB_UNAVAILABLE}), 500

    if not event_id:
        return jsonify({"status": "error", "message": "event_id required"}), 400

    source_table = request.args.get("source", "security")

    # Table-specific queries for seed event lookup
    _SEED_QUERIES = {
        "security": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "event_category, event_action, risk_score, confidence, description, "
            "mitre_techniques, final_classification, indicators, requires_investigation "
            "FROM security_events WHERE id = ?"
        ),
        "fim": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "event_type AS event_category, change_type AS event_action, "
            "risk_score, confidence, reason AS description, "
            "mitre_techniques, NULL AS final_classification, NULL AS indicators, "
            "0 AS requires_investigation "
            "FROM fim_events WHERE id = ?"
        ),
        "persistence": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "event_type AS event_category, change_type AS event_action, "
            "risk_score, confidence, reason AS description, "
            "mitre_techniques, NULL AS final_classification, NULL AS indicators, "
            "1 AS requires_investigation "
            "FROM persistence_events WHERE id = ?"
        ),
        "flow": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, NULL AS collection_agent, "
            "protocol AS event_category, NULL AS event_action, "
            "threat_score AS risk_score, 0.5 AS confidence, "
            "'Flow: ' || COALESCE(src_ip,'?') || ' -> ' || COALESCE(dst_ip,'?') AS description, "
            "NULL AS mitre_techniques, NULL AS final_classification, NULL AS indicators, "
            "CAST(is_suspicious AS INT) AS requires_investigation "
            "FROM flow_events WHERE id = ?"
        ),
        "process": (
            "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
            "process_category AS event_category, NULL AS event_action, "
            "anomaly_score AS risk_score, confidence_score AS confidence, "
            "exe AS description, NULL AS mitre_techniques, NULL AS final_classification, "
            "NULL AS indicators, CAST(is_suspicious AS INT) AS requires_investigation "
            "FROM process_events WHERE id = ?"
        ),
    }

    try:
        # 1) Load seed event — try specified source table, then fall back
        seed = None
        tables_to_try = [source_table] if source_table in _SEED_QUERIES else []
        tables_to_try += [t for t in _SEED_QUERIES if t != source_table]

        for tbl in tables_to_try:
            cursor = store.db.execute(_SEED_QUERIES[tbl], (event_id,))
            row = cursor.fetchone()
            if row:
                cols = [d[0] for d in cursor.description]
                seed = dict(zip(cols, row))
                break

        if not seed:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        # Parse JSON fields
        seed["mitre_techniques"] = _parse_mitre(seed.get("mitre_techniques"))
        seed["indicators"] = _parse_indicators(seed.get("indicators"))

        # 2) Extract correlation keys
        seed_ts_ns = seed.get("timestamp_ns", 0)
        seed_device = seed.get("device_id", "")
        seed_indicators = seed.get("indicators", {})
        seed_ip = (
            seed_indicators.get("source_ip")
            or seed_indicators.get("src_ip")
            or seed_indicators.get("dst_ip")
            or ""
        )
        seed_mitre = seed.get("mitre_techniques", [])

        # Time window
        window_ns = window_minutes * 60 * int(1e9)
        start_ns = seed_ts_ns - window_ns
        end_ns = seed_ts_ns + window_ns

        # 3) Find correlated events across all domain tables
        correlated = []
        _CORR_QUERIES = [
            (
                "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
                "event_category, event_action, risk_score, confidence, description, "
                "mitre_techniques, final_classification, indicators "
                "FROM security_events "
                "WHERE id != ? AND timestamp_ns BETWEEN ? AND ? "
                "ORDER BY timestamp_ns ASC LIMIT ?",
                (event_id, start_ns, end_ns, max_results),
            ),
            (
                "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
                "event_type AS event_category, change_type AS event_action, "
                "risk_score, confidence, reason AS description, "
                "mitre_techniques, NULL AS final_classification, NULL AS indicators "
                "FROM fim_events "
                "WHERE timestamp_ns BETWEEN ? AND ? "
                "ORDER BY timestamp_ns ASC LIMIT ?",
                (start_ns, end_ns, max_results),
            ),
            (
                "SELECT id, timestamp_ns, timestamp_dt, device_id, collection_agent, "
                "event_type AS event_category, change_type AS event_action, "
                "risk_score, confidence, reason AS description, "
                "mitre_techniques, NULL AS final_classification, NULL AS indicators "
                "FROM persistence_events "
                "WHERE timestamp_ns BETWEEN ? AND ? "
                "ORDER BY timestamp_ns ASC LIMIT ?",
                (start_ns, end_ns, max_results),
            ),
        ]
        for query, params in _CORR_QUERIES:
            try:
                cursor = store.db.execute(query, params)
            except Exception:
                continue
            cols2 = [d[0] for d in cursor.description]
            for r in cursor.fetchall():
                evt = dict(zip(cols2, r))
                evt["mitre_techniques"] = _parse_mitre(evt.get("mitre_techniques"))
                evt["indicators"] = _parse_indicators(evt.get("indicators"))

                # Score correlation strength
                score = 0
                evt_device = evt.get("device_id", "")
                evt_indicators = (
                    evt.get("indicators", {})
                    if isinstance(evt.get("indicators"), dict)
                    else {}
                )
                evt_ip = (
                    evt_indicators.get("source_ip")
                    or evt_indicators.get("src_ip")
                    or evt_indicators.get("dst_ip")
                    or ""
                )
                evt_mitre = evt.get("mitre_techniques", [])

                if seed_device and evt_device == seed_device:
                    score += 3
                if seed_ip and evt_ip and seed_ip == evt_ip:
                    score += 2
                if seed_mitre and evt_mitre:
                    shared = set(seed_mitre) & set(evt_mitre)
                    score += len(shared)

                if score > 0:
                    evt["correlation_score"] = score
                    correlated.append(evt)

        # Sort by timestamp
        correlated.sort(key=lambda e: e.get("timestamp_ns", 0))

        # 4) Build phases (group by 60-second gaps)
        phases = []
        if correlated:
            all_events = [seed] + correlated
            all_events.sort(key=lambda e: e.get("timestamp_ns", 0))
            current_phase = {"name": "Phase 1", "events": [all_events[0]]}
            phase_count = 1
            for i in range(1, len(all_events)):
                gap = (
                    all_events[i].get("timestamp_ns", 0)
                    - all_events[i - 1].get("timestamp_ns", 0)
                ) / 1e9
                if gap > 60:
                    phases.append(current_phase)
                    phase_count += 1
                    current_phase = {
                        "name": f"Phase {phase_count}",
                        "events": [all_events[i]],
                    }
                else:
                    current_phase["events"].append(all_events[i])
            phases.append(current_phase)

            # Label phases by category
            _PHASE_LABELS = {
                "persistence": "Persistence",
                "ssh_bruteforce": "Brute Force",
                "off_hours_login": "Unauthorized Access",
                "execution": "Execution",
                "lolbin": "Defense Evasion",
                "dns": "Command & Control",
                "flow": "Network Activity",
                "usb": "Physical Access",
                "critical_file": "File Tampering",
                "suid": "Privilege Escalation",
            }
            for phase in phases:
                cats = [e.get("event_category", "") for e in phase["events"]]
                label = phase["name"]
                for prefix, name in _PHASE_LABELS.items():
                    if any(c.startswith(prefix) for c in cats):
                        label = name
                        break
                phase["label"] = label
                phase["event_count"] = len(phase["events"])
                phase["start_time"] = phase["events"][0].get("timestamp_dt", "")
                phase["end_time"] = phase["events"][-1].get("timestamp_dt", "")

        # 5) Build MITRE chain
        mitre_chain = []
        seen_mitre = set()
        for evt in [seed] + correlated:
            for tech in evt.get("mitre_techniques", []):
                if tech not in seen_mitre:
                    seen_mitre.add(tech)
                    mitre_chain.append(tech)

        # 6) Timeline span
        all_ts = [seed.get("timestamp_ns", 0)] + [
            e.get("timestamp_ns", 0) for e in correlated
        ]
        span_seconds = (max(all_ts) - min(all_ts)) / 1e9 if all_ts else 0

        return jsonify(
            {
                "status": "success",
                "seed_event": seed,
                "correlated_events": correlated,
                "total_correlated": len(correlated),
                "phases": phases,
                "mitre_chain": mitre_chain,
                "timeline_span_seconds": span_seconds,
                "window_minutes": window_minutes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Metrics History ───────────────────────────────────────────────


@dashboard_bp.route("/api/metrics/history")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def metrics_history_api():
    """Historical metrics for time-series charts."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    metric = request.args.get("metric", "cpu_percent")
    hours = request.args.get("hours", 24, type=int)

    if store is None:
        return jsonify({"status": "success", "data": [], "metric": metric})

    data = store.get_metrics_history(metric, hours=hours)
    return jsonify(
        {
            "status": "success",
            "data": data,
            "metric": metric,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ── Agent Deep Overview ──────────────────────────────────────────

# Static agent metadata for the v2 security agents
_AGENT_COLORS = {
    "proc": "#4ECDC4",
    "flow": "#F38181",
    "dns": "#AA96DA",
    "auth": "#FF6B35",
    "fim": "#00ff88",
    "persistence": "#FCBAD3",
    "peripheral": "#FF6B9D",
    "kernel_audit": "#FFD93D",
    "device_discovery": "#6BCB77",
    "protocol_collectors": "#00B4D8",
    "applog": "#E8A87C",
    "db_activity": "#20B2AA",
    "http_inspector": "#7B68EE",
    "internet_activity": "#DA70D6",
    "net_scanner": "#FF7F50",
    "macos_security_monitor": "#FFD700",
    "macos_unified_log": "#87CEEB",
    "macos_dns": "#AA96DA",
    "macos_applog": "#E8A87C",
    "macos_discovery": "#6BCB77",
    "macos_internet_activity": "#DA70D6",
    "macos_db_activity": "#20B2AA",
    "macos_http_inspector": "#7B68EE",
}

_AGENT_CATEGORY_DISPLAY = {
    "endpoint": "Endpoint",
    "network": "Network",
    "application": "Application",
    "platform": "Platform",
    "physical": "Physical",
    "kernel": "Kernel",
    "identity": "Identity",
}


_AGENT_DEEP_META_CACHE = None


def _get_agent_deep_meta():
    """Build agent metadata lazily from AGENT_REGISTRY (single source of truth).

    Lazy because AGENT_REGISTRY imports agent classes which may fail at module
    import time (e.g., missing certs directory).
    """
    global _AGENT_DEEP_META_CACHE
    if _AGENT_DEEP_META_CACHE is not None:
        return _AGENT_DEEP_META_CACHE

    try:
        from amoskys.agents import AGENT_REGISTRY
    except Exception:
        return {}

    import sys as _sys

    is_darwin = _sys.platform == "darwin"
    # On macOS, these 6 agents resolve to Observatory implementations via platform routing
    _PLATFORM_ROUTED = {"proc", "auth", "persistence", "fim", "flow", "peripheral"}

    meta = {}
    for aid, reg in AGENT_REGISTRY.items():
        cat = reg.get("category", "endpoint")
        platforms = reg.get("platforms", [])

        # Determine agent source/provenance
        if aid.startswith("macos_"):
            source = "Observatory"
        elif aid == "kernel_audit":
            source = "Linux"
        elif aid in _PLATFORM_ROUTED and is_darwin:
            source = "Observatory"
        else:
            source = "Shared"

        meta[aid] = {
            "name": reg["name"],
            "short": aid,
            "description": reg["description"],
            "color": _AGENT_COLORS.get(aid, "#00d9ff"),
            "icon": reg.get("icon", aid),
            "category": _AGENT_CATEGORY_DISPLAY.get(cat, cat.title()),
            "platforms": platforms,
            "source": source,
        }

    _AGENT_DEEP_META_CACHE = meta
    return meta


# Map agent short names to event category prefixes for counting
_AGENT_EVENT_CATEGORIES = {
    "proc": [
        "process_spawned",
        "lolbin_execution",
        "suspicious_process_tree",
        "high_resource_process",
        "unexpectedly_long_process",
        "process_wrong_user",
        "execution_from_temp",
        "suspicious_script_execution",
        "dylib_injection",
        "code_signature_invalid",
    ],
    "flow": [
        "flow_portscan",
        "flow_lateral",
        "flow_exfil",
        "flow_c2",
        "flow_cleartext",
        "flow_suspicious_tunnel",
        "flow_internal_dns",
        "flow_new_external",
        "flow_network_extension",
    ],
    "dns": [
        "dns_query",
        "dga_domain",
        "dns_beaconing",
        "suspicious_tld",
        "nxdomain_burst",
        "dns_tunneling",
        "fast_flux",
        "dns_rebinding",
        "new_domain_for_process",
        "blocked_domain",
        "suspicious_domain",
    ],
    "auth": [
        "ssh_bruteforce",
        "ssh_password_spray",
        "impossible_travel",
        "sudo_",
        "off_hours_login",
        "mfa_bypass",
        "mfa_fatigue",
        "account_lockout",
        "first_time_sudo",
        "lockout_storm",
    ],
    "fim": [
        "critical_file_tampered",
        "suid_bit_added",
        "sgid_bit_added",
        "service_created",
        "service_modified",
        "webshell_detected",
        "ssh_config_backdoor",
        "sudoers_backdoor",
        "linker_config",
        "new_system_library",
        "bootloader_modified",
        "world_writable",
        "quarantine_xattr",
    ],
    "persistence": [
        "persistence_launchd",
        "persistence_systemd",
        "persistence_cron",
        "persistence_ssh_key",
        "persistence_shell_profile",
        "persistence_browser_extension",
        "persistence_startup_item",
        "persistence_hidden_loader",
        "persistence_config_profile",
        "persistence_auth_plugin",
        "persistence_user_launch_agent",
    ],
    "peripheral": [
        "usb_inventory",
        "usb_device_connected",
        "usb_device_disconnected",
        "usb_storage",
        "usb_network_adapter",
        "new_keyboard",
        "bluetooth_device",
        "peripheral_risk",
    ],
    "kernel_audit": [
        "kernel_execve",
        "kernel_privesc",
        "kernel_module",
        "kernel_ptrace",
        "kernel_file_permission",
        "kernel_audit_tamper",
        "kernel_syscall_flood",
        "suid_bit_added",
        "sgid_bit_added",
    ],
    "device_discovery": [
        "device_discovered",
        "port_scan_result",
        "device_risk_assessment",
        "rogue_dhcp",
        "rogue_dns",
        "shadow_it",
        "vulnerable_banner",
    ],
    "protocol_collectors": ["protocol_threat"],
    # L7 Gap-Closure Agents
    "applog": [
        "applog_log_tampering",
        "applog_credential_harvest",
        "applog_error_spike",
        "applog_webshell_access",
        "applog_suspicious_4xx_5xx",
        "applog_log_injection",
        "applog_privesc_log",
        "applog_container_breakout",
    ],
    "db_activity": [
        "db_privilege_escalation",
        "db_bulk_extraction",
        "db_schema_enumeration",
        "db_stored_proc_abuse",
        "db_credential_query",
        "db_sql_injection",
        "db_unauthorized_access",
        "db_ddl_change",
    ],
    "http_inspector": [
        "http_xss_detected",
        "http_ssrf_detected",
        "http_path_traversal",
        "http_api_abuse",
        "http_data_exfil",
        "http_suspicious_upload",
        "http_websocket_abuse",
        "http_csrf_missing",
    ],
    "internet_activity": [
        "internet_cloud_exfiltration",
        "internet_tor_vpn_detected",
        "internet_crypto_mining",
        "internet_suspicious_download",
        "internet_shadow_it",
        "internet_unusual_geo",
        "internet_long_lived_connection",
        "internet_doh_detected",
    ],
    "net_scanner": [
        "netscan_new_service",
        "netscan_port_change",
        "netscan_rogue_service",
        "netscan_ssl_cert_issue",
        "netscan_vulnerable_banner",
        "netscan_unauthorized_listener",
        "netscan_topology_change",
    ],
}


_deep_overview_cache = {"data": None, "ts": 0}


@dashboard_bp.route("/api/agents/deep-overview")
@require_login
@require_rate_limit(max_requests=30, window_seconds=60)
def agents_deep_overview():
    """Comprehensive agent overview with probes, MITRE, events, and health."""
    import os
    import platform as _platform

    now_ts = time.time()
    # 60-second cache aligned with probe health cache
    if _deep_overview_cache["data"] and (now_ts - _deep_overview_cache["ts"]) < 60:
        return jsonify(_deep_overview_cache["data"])

    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    target = "darwin" if _platform.system() == "Darwin" else "linux"

    # 1) Run probe audit for health status
    probe_results = []
    try:
        from amoskys.observability.probe_audit import run_audit

        probe_results = run_audit(target)
    except Exception:
        pass

    # 2) Get event counts per agent across ALL domain tables (last 7 days)
    event_counts_by_cat = {}
    event_counts_by_agent = {}  # canonical agent_id -> count
    if store:
        cutoff_ns = int((time.time() - 7 * 24 * 3600) * 1e9)
        # Use read pool for all queries (avoids serialisation with writes)
        with store._read_pool.connection() as rdb:
            # Query each domain table for collection_agent counts
            _EVENT_TABLES_WITH_AGENT = [
                ("security_events", "collection_agent"),
                ("process_events", "collection_agent"),
                ("dns_events", "collection_agent"),
                ("persistence_events", "collection_agent"),
                ("peripheral_events", "collection_agent"),
            ]
            for table, col in _EVENT_TABLES_WITH_AGENT:
                try:
                    cursor = rdb.execute(
                        f"SELECT {col}, COUNT(*) FROM {table} "
                        f"WHERE timestamp_ns > ? GROUP BY {col}",
                        (cutoff_ns,),
                    )
                    for row in cursor.fetchall():
                        raw_agent = row[0] or ""
                        canonical = _normalize_agent_id(raw_agent)
                        event_counts_by_agent[canonical] = (
                            event_counts_by_agent.get(canonical, 0) + row[1]
                        )
                except Exception:
                    pass
            # observation_events: count by domain -> agent mapping
            _OBS_DOMAIN_TO_AGENT = {
                "security": "macos_security_monitor",
                "unified_log": "macos_unified_log",
                "dns": "macos_dns",
                "applog": "macos_applog",
                "discovery": "macos_discovery",
                "internet_activity": "macos_internet_activity",
                "db_activity": "macos_db_activity",
                "http_inspector": "macos_http_inspector",
                "net_scanner": "net_scanner",
            }
            try:
                cursor = rdb.execute(
                    "SELECT domain, COUNT(*) FROM observation_events "
                    "WHERE timestamp_ns > ? GROUP BY domain",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    domain_val = row[0] or ""
                    mapped_agent = _OBS_DOMAIN_TO_AGENT.get(domain_val, domain_val)
                    event_counts_by_agent[mapped_agent] = (
                        event_counts_by_agent.get(mapped_agent, 0) + row[1]
                    )
            except Exception:
                pass
            # Tables without collection_agent: count totals
            for table, agent_id in [
                ("flow_events", "flow"),
                ("fim_events", "fim"),
                ("audit_events", "kernel_audit"),
            ]:
                try:
                    row = rdb.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE timestamp_ns > ?",
                        (cutoff_ns,),
                    ).fetchone()
                    if row and row[0]:
                        event_counts_by_agent[agent_id] = (
                            event_counts_by_agent.get(agent_id, 0) + row[0]
                        )
                except Exception:
                    pass
            # Also get event_category counts for backward compat
            try:
                cursor = rdb.execute(
                    "SELECT event_category, COUNT(*) FROM security_events "
                    "WHERE timestamp_ns > ? GROUP BY event_category",
                    (cutoff_ns,),
                )
                for row in cursor.fetchall():
                    event_counts_by_cat[row[0]] = row[1]
            except Exception:
                pass

    # 3) Build per-agent deep data
    agents = []
    total_probes = 0
    total_events = 0
    total_mitre = set()

    # Pre-load probe objects for MITRE/description extraction
    _probe_objects_by_agent = {}
    try:
        from amoskys.observability.probe_audit import AGENT_PROBE_MAP

        for aid, mod_info in AGENT_PROBE_MAP.items():
            try:
                mod = importlib.import_module(mod_info["module"])
                factory = getattr(mod, mod_info["factory"])
                _probe_objects_by_agent[aid] = {
                    getattr(p, "name", ""): p for p in factory()
                }
            except Exception:
                pass
    except Exception:
        pass

    for agent_id, meta in _get_agent_deep_meta().items():
        # Get probes for this agent from audit results
        agent_probes = [r for r in probe_results if r.get("agent") == agent_id]
        probe_list = []
        agent_mitre = set()
        probe_objs = _probe_objects_by_agent.get(agent_id, {})

        for p in agent_probes:
            probe_name = p.get("probe", "unknown")
            probe_obj = probe_objs.get(probe_name)

            mitre_techs = (
                list(getattr(probe_obj, "mitre_techniques", [])) if probe_obj else []
            )
            description = getattr(probe_obj, "description", "") if probe_obj else ""
            fields = (
                list(getattr(probe_obj, "requires_fields", []))
                if probe_obj
                else p.get("requires_fields", [])
            )

            agent_mitre.update(mitre_techs)
            probe_list.append(
                {
                    "name": probe_name,
                    "description": description,
                    "status": p.get("verdict", "UNKNOWN"),
                    "mitre": mitre_techs,
                    "fields": fields if fields else [],
                    "issues": p.get("issues", []),
                }
            )

        # Count events for this agent (multi-table unified counts)
        agent_event_count = event_counts_by_agent.get(agent_id, 0)
        # Fallback: also check event_category prefix matching
        if agent_event_count == 0:
            cat_prefixes = _AGENT_EVENT_CATEGORIES.get(agent_id, [])
            for cat, count in event_counts_by_cat.items():
                for prefix in cat_prefixes:
                    if cat.startswith(prefix) or cat == prefix:
                        agent_event_count += count
                        break

        # Probe health summary
        real = sum(1 for p in probe_list if p["status"] == "REAL")
        degraded = sum(1 for p in probe_list if p["status"] == "DEGRADED")
        broken = sum(1 for p in probe_list if p["status"] == "BROKEN")
        disabled = sum(1 for p in probe_list if p["status"] == "DISABLED")

        total_probes += sum(1 for p in probe_list if p["status"] not in ("SKIPPED",))
        total_events += agent_event_count
        total_mitre.update(agent_mitre)

        agents.append(
            {
                "id": agent_id,
                "name": meta["name"],
                "short": meta["short"],
                "description": meta["description"],
                "color": meta["color"],
                "icon": meta["icon"],
                "category": meta["category"],
                "platforms": meta.get("platforms", []),
                "source": meta.get("source", "Shared"),
                "probes": probe_list,
                "probe_summary": {
                    "total": len(probe_list),
                    "real": real,
                    "degraded": degraded,
                    "broken": broken,
                    "disabled": disabled,
                },
                "event_count": agent_event_count,
                "mitre_techniques": sorted(agent_mitre),
                "mitre_count": len(agent_mitre),
                "signing_enabled": os.path.exists("certs/agent.ed25519"),
            }
        )

    # Sort agents by event count descending
    agents.sort(key=lambda a: a["event_count"], reverse=True)

    response = {
        "status": "success",
        "agents": agents,
        "summary": {
            "total_agents": len(agents),
            "total_probes": total_probes,
            "total_events": total_events,
            "total_mitre": len(total_mitre),
            "active_probes": sum(
                a["probe_summary"]["real"] + a["probe_summary"]["degraded"]
                for a in agents
            ),
            "signing_enabled": os.path.exists("certs/agent.ed25519"),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    _deep_overview_cache["data"] = response
    _deep_overview_cache["ts"] = now_ts
    return jsonify(response)


# ── Per-Agent Live Events API ────────────────────────────────────


@dashboard_bp.route("/api/agents/<agent_id>/live-data")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agent_live_data(agent_id):
    """Live telemetry data for a specific agent — events, process info, logs."""
    import os
    import socket as _socket
    from pathlib import Path

    from .agent_control import get_agent_status
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    limit = min(request.args.get("limit", 25, type=int), 100)

    # Map deep-overview IDs (proc, dns) to AGENT_CATALOG IDs (proc_agent, dns_agent)
    _id_map = {
        "proc": "proc_agent",
        "dns": "dns_agent",
        "auth": "auth_agent",
        "fim": "fim_agent",
        "flow": "flow_agent",
        "persistence": "persistence_agent",
        "peripheral": "peripheral_agent",
        "kernel_audit": "kernel_audit_agent",
        "device_discovery": "device_discovery_agent",
        "protocol_collectors": "protocol_collectors_agent",
        # L7 Gap-Closure Agents
        "applog": "applog_agent",
        "db_activity": "db_activity_agent",
        "http_inspector": "http_inspector_agent",
        "internet_activity": "internet_activity_agent",
        "net_scanner": "net_scanner_agent",
        # macOS Observatory Agents (catalog ID = registry ID)
        "macos_security_monitor": "macos_security_monitor",
        "macos_unified_log": "macos_unified_log",
        "macos_dns": "macos_dns",
        "macos_applog": "macos_applog",
        "macos_discovery": "macos_discovery",
        "macos_internet_activity": "macos_internet_activity",
        "macos_db_activity": "macos_db_activity",
        "macos_http_inspector": "macos_http_inspector",
    }
    catalog_id = _id_map.get(agent_id) or agent_id

    # 1) Process status (PID, CPU, memory, uptime)
    process_info = {}
    try:
        status = get_agent_status(catalog_id)
        process_info = status if isinstance(status, dict) else {}
    except Exception:
        pass

    # 2) Recent events — query BOTH security_events AND domain-specific tables
    recent_events = []
    cat_prefixes = _AGENT_EVENT_CATEGORIES.get(agent_id, [])

    # 2a) Security events (high-level detections)
    if store and cat_prefixes:
        try:
            placeholders = " OR ".join([f"event_category LIKE ?" for _ in cat_prefixes])
            params = [f"{p}%" for p in cat_prefixes]
            query = (
                f"SELECT id, timestamp_dt, device_id, event_category, "
                f"event_action, risk_score, confidence, description, "
                f"mitre_techniques, final_classification, indicators "
                f"FROM security_events WHERE ({placeholders}) "
                f"ORDER BY id DESC LIMIT ?"
            )
            params.append(limit)
            cursor = store.db.execute(query, params)
            cols = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                evt = dict(zip(cols, row))
                evt["source_table"] = "security_events"
                mt = evt.get("mitre_techniques", "")
                if isinstance(mt, str) and mt.startswith("["):
                    try:
                        import json as _json

                        evt["mitre_techniques"] = _json.loads(mt)
                    except Exception:
                        evt["mitre_techniques"] = []
                recent_events.append(evt)
        except Exception:
            pass

    # 2b) Domain-specific events (raw observables from the agent's own table)
    _AGENT_DOMAIN_QUERIES = {
        "proc": (
            "process_events",
            "SELECT id, timestamp_dt, device_id, pid, exe, cmdline, username, "
            "cpu_percent, memory_percent, is_suspicious, anomaly_score, "
            "collection_agent "
            "FROM process_events ORDER BY id DESC LIMIT ?",
        ),
        "dns": (
            "dns_events",
            "SELECT id, timestamp_dt, device_id, domain, query_type, "
            "response_code, risk_score, dga_score, is_beaconing, "
            "collection_agent, mitre_techniques "
            "FROM dns_events ORDER BY id DESC LIMIT ?",
        ),
        "flow": (
            "flow_events",
            "SELECT id, timestamp_dt, device_id, src_ip, dst_ip, "
            "src_port, dst_port, protocol, bytes_tx, bytes_rx, "
            "threat_score, is_suspicious "
            "FROM flow_events ORDER BY id DESC LIMIT ?",
        ),
        "fim": (
            "fim_events",
            "SELECT id, timestamp_dt, device_id, path, change_type, "
            "risk_score, mitre_techniques, collection_agent "
            "FROM fim_events ORDER BY id DESC LIMIT ?",
        ),
        "persistence": (
            "persistence_events",
            "SELECT id, timestamp_dt, device_id, mechanism, path, "
            "command, risk_score, mitre_techniques, collection_agent "
            "FROM persistence_events ORDER BY id DESC LIMIT ?",
        ),
        "peripheral": (
            "peripheral_events",
            "SELECT id, timestamp_dt, device_id, event_type, device_type, "
            "vendor_id, product_id, serial_number, is_authorized, risk_score, "
            "collection_agent "
            "FROM peripheral_events ORDER BY id DESC LIMIT ?",
        ),
        "kernel_audit": (
            "audit_events",
            "SELECT id, timestamp_dt, device_id, syscall, event_type, "
            "pid, uid, exe, target_path, risk_score, mitre_techniques "
            "FROM audit_events ORDER BY id DESC LIMIT ?",
        ),
    }
    domain_q = _AGENT_DOMAIN_QUERIES.get(agent_id)
    recent_processes = []
    if store and domain_q:
        table_name, sql = domain_q
        try:
            cursor = store.db.execute(sql, (limit,))
            cols = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                evt = dict(zip(cols, row))
                evt["source_table"] = table_name
                # Build a description for display
                if agent_id == "proc":
                    evt["event_category"] = "process_event"
                    evt["description"] = (
                        f"{evt.get('exe', '?')} (PID {evt.get('pid', '?')}) — {evt.get('username', '?')}"
                    )
                    recent_processes.append(dict(evt))
                elif agent_id == "dns":
                    evt["event_category"] = "dns_query"
                    evt["description"] = (
                        f"{evt.get('domain', '?')} ({evt.get('query_type', '?')})"
                    )
                elif agent_id == "flow":
                    evt["event_category"] = "network_flow"
                    evt["description"] = (
                        f"{evt.get('protocol', '?')} → {evt.get('dst_ip', '?')}:{evt.get('dst_port', '?')}"
                    )
                elif agent_id == "fim":
                    evt["event_category"] = "file_modification"
                    evt["description"] = (
                        f"{evt.get('path', '?')} ({evt.get('change_type', '?')})"
                    )
                elif agent_id == "persistence":
                    evt["event_category"] = evt.get("mechanism", "persistence")
                    evt["description"] = (
                        f"{evt.get('mechanism', '?')}: {evt.get('path', '?')}"
                    )
                elif agent_id == "peripheral":
                    evt["event_category"] = evt.get("event_type", "peripheral")
                    evt["description"] = (
                        f"{evt.get('device_type', '?')} — {evt.get('vendor_id', '?')}:{evt.get('product_id', '?')}"
                    )
                elif agent_id == "kernel_audit":
                    evt["event_category"] = evt.get("event_type", "kernel_audit")
                    evt["description"] = (
                        f"syscall:{evt.get('syscall', '?')} — {evt.get('exe', '?')}"
                    )

                # Parse MITRE techniques
                mt = evt.get("mitre_techniques", "")
                if isinstance(mt, str) and mt.startswith("["):
                    try:
                        import json as _json

                        evt["mitre_techniques"] = _json.loads(mt)
                    except Exception:
                        evt["mitre_techniques"] = []

                recent_events.append(evt)
        except Exception:
            pass

    # 3) observation_events — primary data source for Observatory agents
    #    Also covers agents without dedicated domain tables
    _AGENT_OBS_DOMAIN = {
        "macos_security_monitor": "security",
        "macos_unified_log": "unified_log",
        "macos_dns": "dns",
        "macos_applog": "applog",
        "macos_discovery": "discovery",
        "macos_internet_activity": "internet_activity",
        "macos_db_activity": "db_activity",
        "macos_http_inspector": "http_inspector",
        # Shared agents also write to observation_events
        "applog": "applog",
        "db_activity": "db_activity",
        "http_inspector": "http_inspector",
        "internet_activity": "internet_activity",
        "device_discovery": "discovery",
        "net_scanner": "net_scanner",
    }
    obs_domain = _AGENT_OBS_DOMAIN.get(agent_id)
    if store and obs_domain:
        try:
            cursor = store.db.execute(
                "SELECT id, timestamp_dt, device_id, domain, event_type, "
                "attributes, risk_score, collection_agent "
                "FROM observation_events WHERE domain = ? "
                "ORDER BY id DESC LIMIT ?",
                (obs_domain, limit),
            )
            cols = [d[0] for d in cursor.description]
            for row in cursor.fetchall():
                evt = dict(zip(cols, row))
                evt["source_table"] = "observation_events"
                evt["event_category"] = evt.get("event_type") or obs_domain
                # Extract description from attributes JSON
                attrs = evt.get("attributes", "")
                if isinstance(attrs, str) and attrs.startswith("{"):
                    try:
                        import json as _json

                        parsed = _json.loads(attrs)
                        # Build a meaningful description from attributes
                        desc = parsed.get("description") or parsed.get("summary")
                        if not desc:
                            # Fallback: compose from common fields
                            parts = []
                            for k in (
                                "event_type",
                                "process",
                                "sender",
                                "domain",
                                "path",
                                "exe",
                                "src_ip",
                                "dst_ip",
                            ):
                                if k in parsed and parsed[k]:
                                    parts.append(f"{k}={parsed[k]}")
                            msg = parsed.get("message", "")
                            if msg:
                                parts.append(str(msg)[:80])
                            desc = " | ".join(parts) if parts else obs_domain + " event"
                        evt["description"] = desc
                        evt["mitre_techniques"] = parsed.get("mitre_techniques", [])
                    except Exception:
                        evt["description"] = obs_domain + " observation"
                recent_events.append(evt)
        except Exception:
            pass

    # 4) Device info
    device_info = {
        "hostname": _socket.gethostname(),
        "ip_address": _get_local_ip(),
        "platform": os.uname().sysname if hasattr(os, "uname") else "Unknown",
    }
    if store:
        try:
            row = store.db.execute(
                "SELECT device_id, ip_address, device_type "
                "FROM device_telemetry ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row:
                device_info["device_id"] = row[0]
                if row[1]:
                    device_info["ip_address"] = row[1]
                device_info["device_type"] = row[2]
        except Exception:
            pass

    # 5) Agent log tail (last 30 lines)
    log_lines = []
    repo_root = Path(__file__).resolve().parents[3]
    # Map agent IDs to log file names
    log_name_map = {
        "proc": "proc_agent",
        "dns": "dns_agent",
        "auth": "auth_agent",
        "fim": "fim_agent",
        "flow": "flow_agent",
        "persistence": "persistence_agent",
        "peripheral": "peripheral_agent",
        "kernel_audit": "kernel_audit_agent",
        "device_discovery": "device_discovery_agent",
        "protocol_collectors": "protocol_collectors_agent",
        # L7 Gap-Closure Agents
        "applog": "applog_agent",
        "db_activity": "db_activity_agent",
        "http_inspector": "http_inspector_agent",
        "internet_activity": "internet_activity_agent",
        "net_scanner": "net_scanner_agent",
        # macOS Observatory Agents
        "macos_security_monitor": "macos_security_monitor",
        "macos_unified_log": "macos_unified_log",
        "macos_dns": "macos_dns",
        "macos_applog": "macos_applog",
        "macos_discovery": "macos_discovery",
        "macos_internet_activity": "macos_internet_activity",
        "macos_db_activity": "macos_db_activity",
        "macos_http_inspector": "macos_http_inspector",
    }
    log_file = repo_root / "logs" / f"{log_name_map.get(agent_id, agent_id)}.err.log"
    if log_file.exists():
        try:
            lines = log_file.read_text().strip().split("\n")
            log_lines = lines[-30:]
        except Exception:
            pass

    # 6) Event timeline stats (hourly distribution over last 24h)
    #    Query BOTH security_events AND the agent's domain table
    hourly_buckets = {}  # hour_str -> count

    # 6a) security_events hourly
    if store and cat_prefixes:
        try:
            placeholders = " OR ".join([f"event_category LIKE ?" for _ in cat_prefixes])
            params = [f"{p}%" for p in cat_prefixes]
            cursor = store.db.execute(
                f"SELECT substr(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt "
                f"FROM security_events WHERE ({placeholders}) "
                f"GROUP BY hour ORDER BY hour DESC LIMIT 24",
                params,
            )
            for row in cursor.fetchall():
                hourly_buckets[row[0]] = hourly_buckets.get(row[0], 0) + row[1]
        except Exception:
            pass

    # 6b) domain table hourly
    if store and domain_q:
        table_name = domain_q[0]
        try:
            cursor = store.db.execute(
                f"SELECT substr(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt "
                f"FROM {table_name} "
                f"GROUP BY hour ORDER BY hour DESC LIMIT 24",
            )
            for row in cursor.fetchall():
                hourly_buckets[row[0]] = hourly_buckets.get(row[0], 0) + row[1]
        except Exception:
            pass

    # 6c) observation_events hourly (for Observatory agents)
    if store and obs_domain:
        try:
            cursor = store.db.execute(
                "SELECT substr(timestamp_dt, 1, 13) as hour, COUNT(*) as cnt "
                "FROM observation_events WHERE domain = ? "
                "GROUP BY hour ORDER BY hour DESC LIMIT 24",
                (obs_domain,),
            )
            for row in cursor.fetchall():
                hourly_buckets[row[0]] = hourly_buckets.get(row[0], 0) + row[1]
        except Exception:
            pass

    hourly_stats = sorted(
        [{"hour": h, "count": c} for h, c in hourly_buckets.items()],
        key=lambda x: x["hour"],
        reverse=True,
    )[:24]

    return jsonify(
        {
            "status": "success",
            "agent_id": agent_id,
            "process": process_info,
            "device": device_info,
            "recent_events": recent_events,
            "recent_processes": recent_processes,
            "log_tail": log_lines,
            "hourly_stats": hourly_stats,
            "event_count": len(recent_events),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ── Agent Activity & Domain Data APIs ────────────────────────────


@dashboard_bp.route("/api/agents/activity")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agents_activity():
    """Per-agent event rates for last 1 min and last 60 min.

    Queries ALL event tables, not just security_events.
    """
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    result = {}

    if store:
        now_ns = int(time.time() * 1e9)
        one_min_ns = now_ns - 60 * int(1e9)
        sixty_min_ns = now_ns - 3600 * int(1e9)

        def _add_activity(agent_id, last_min, last_hour):
            aid = _normalize_agent_id(agent_id)
            if aid not in result:
                result[aid] = {"last_min": 0, "last_hour": 0}
            result[aid]["last_min"] += last_min
            result[aid]["last_hour"] += last_hour

        with store._read_pool.connection() as rdb:
            try:
                # 1. security_events — use event_category prefix matching
                cursor = rdb.execute(
                    """SELECT event_category,
                       SUM(CASE WHEN timestamp_ns > ? THEN 1 ELSE 0 END) as last_min,
                       COUNT(*) as last_hour
                       FROM security_events
                       WHERE timestamp_ns > ?
                       GROUP BY event_category""",
                    (one_min_ns, sixty_min_ns),
                )
                for row in cursor.fetchall():
                    cat, last_min, last_hour = row[0], row[1], row[2]
                    for agent_id, prefixes in _AGENT_EVENT_CATEGORIES.items():
                        for prefix in prefixes:
                            if cat and (cat.startswith(prefix) or cat == prefix):
                                _add_activity(agent_id, last_min, last_hour)
                                break
            except Exception:
                pass

            # 2. Domain tables with collection_agent column
            for table, default_agent in [
                ("process_events", "proc"),
                ("dns_events", "dns"),
                ("persistence_events", "persistence"),
            ]:
                try:
                    cursor = rdb.execute(
                        f"""SELECT COALESCE(collection_agent, ?) as agent,
                           SUM(CASE WHEN timestamp_ns > ? THEN 1 ELSE 0 END) as last_min,
                           COUNT(*) as last_hour
                           FROM {table}
                           WHERE timestamp_ns > ?
                           GROUP BY agent""",
                        (default_agent, one_min_ns, sixty_min_ns),
                    )
                    for row in cursor.fetchall():
                        _add_activity(row[0] or default_agent, row[1], row[2])
                except Exception:
                    pass

            # 3. Tables without collection_agent (fixed agent assignment)
            for table, agent_id in [("flow_events", "flow"), ("fim_events", "fim")]:
                try:
                    row = rdb.execute(
                        f"""SELECT
                           SUM(CASE WHEN timestamp_ns > ? THEN 1 ELSE 0 END) as last_min,
                           COUNT(*) as last_hour
                           FROM {table}
                           WHERE timestamp_ns > ?""",
                        (one_min_ns, sixty_min_ns),
                    ).fetchone()
                    if row and (row[0] or row[1]):
                        _add_activity(agent_id, row[0] or 0, row[1] or 0)
                except Exception:
                    pass

    return jsonify(
        {
            "status": "success",
            "activity": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@dashboard_bp.route("/api/agents/<agent_id>/domain-data")
@require_login
@require_rate_limit(max_requests=60, window_seconds=60)
def agent_domain_data(agent_id):
    """Domain-specific structured data for Agent Monitor page."""
    from .telemetry_bridge import get_telemetry_store

    store = get_telemetry_store()
    limit = min(request.args.get("limit", 50, type=int), 200)
    rows = []
    schema = "generic"

    if store:
        try:
            if agent_id == "dns":
                schema = "dns_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, domain, query_type, response_code, "
                    "risk_score, dga_score, is_beaconing FROM dns_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "fim":
                schema = "fim_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, path, event_type, change_type, "
                    "old_hash, new_hash, risk_score FROM fim_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "flow":
                schema = "flow_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, src_ip, dst_ip, dst_port, protocol, "
                    "bytes_tx, bytes_rx, threat_score, is_suspicious FROM flow_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "proc":
                schema = "process_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, pid, exe, username, "
                    "cpu_percent, memory_percent, is_suspicious FROM process_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "kernel_audit":
                schema = "audit_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, syscall, event_type, pid, uid, "
                    "exe, target_path, risk_score FROM audit_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "peripheral":
                schema = "peripheral_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, event_type, device_type, vendor_id, "
                    "product_id, serial_number, is_authorized, risk_score "
                    "FROM peripheral_events ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

            elif agent_id == "persistence":
                schema = "persistence_events"
                cursor = store.db.execute(
                    "SELECT timestamp_dt, event_type, mechanism, path, "
                    "command, change_type, risk_score FROM persistence_events "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                cols = [d[0] for d in cursor.description]
                rows = [dict(zip(cols, r)) for r in cursor.fetchall()]

        except Exception:
            pass

    return jsonify(
        {
            "status": "success",
            "agent_id": agent_id,
            "schema": schema,
            "data": rows,
            "count": len(rows),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
