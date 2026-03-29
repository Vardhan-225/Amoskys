"""NEXUS API routes — verdict funnel, probe calibration, SOMA stats, ASV.

Provides the data backing for the Cortex NEXUS dashboard panels:
  - /api/nexus/verdict-funnel: event counts at each NEXUS pipeline stage
  - /api/nexus/probe-calibration: per-probe precision weights
  - /api/nexus/soma-stats: baseline maturity + top suppressors
  - /api/nexus/asv-status: current Agent Signature Vector state
"""

import json
import logging
import sqlite3
import time
from pathlib import Path

from flask import jsonify, request

from ..middleware import require_login
from . import dashboard_bp

logger = logging.getLogger("web.app.dashboard.nexus")

TELEMETRY_DB = Path("data/telemetry.db")
SOMA_DB = Path("data/igris/memory.db")
PROBE_CAL_DB = Path("data/intel/probe_calibration.db")
FUSION_DB = Path("data/intel/fusion.db")
MESH_DB = Path("data/mesh_events.db")


def _ro_conn(db_path: Path) -> sqlite3.Connection:
    """Open a read-only SQLite connection."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


# ── Verdict Funnel ──────────────────────────────────────────────────────


@dashboard_bp.route("/api/nexus/verdict-funnel")
@require_login
def nexus_verdict_funnel():
    """Return event counts at each NEXUS pipeline stage.

    Stages:
      total_events → noise (SOMA familiar, low risk) → baseline (known patterns)
      → suspicious (medium risk) → threats (high risk) → incidents (correlated)
    """
    hours = int(request.args.get("hours", 24))
    cutoff_ns = int((time.time() - hours * 3600) * 1e9)

    try:
        # Load average probe precision to weight the tier thresholds.
        # When probes are uncalibrated (precision ~0.05), a raw risk of 0.7
        # is unreliable and should be classified as baseline, not threat.
        # Effective risk = raw_risk * probe_precision_factor.
        # We invert this: raise tier thresholds by 1/precision_factor.
        probe_conf = 1.0  # default: trust raw scores
        if PROBE_CAL_DB.exists():
            try:
                pcal = _ro_conn(PROBE_CAL_DB)
                row = pcal.execute(
                    "SELECT AVG(alpha / (alpha + beta)) as avg_prec, "
                    "COUNT(CASE WHEN total_updates >= 10 THEN 1 END) as active "
                    "FROM probe_calibration"
                ).fetchone()
                pcal.close()
                if row and row["active"] and row["active"] > 0:
                    probe_conf = max(0.05, min(1.0, row["avg_prec"]))
            except Exception:
                pass

        # Dynamic thresholds: divide base thresholds by probe confidence.
        # Base: noise < 0.3, baseline < 0.5, suspicious < 0.7, threats >= 0.7
        # If probe_conf = 0.1, thresholds become: 0.3/0.1=3.0 (capped at 1.0)
        # → effectively everything is noise until probes earn trust.
        t_noise = min(0.3 / probe_conf, 1.0)
        t_base = min(0.5 / probe_conf, 1.0)
        t_susp = min(0.7 / probe_conf, 1.0)

        conn = _ro_conn(TELEMETRY_DB)

        # Total security events
        total = conn.execute(
            "SELECT COUNT(*) FROM security_events " "WHERE event_timestamp_ns > ?",
            (cutoff_ns,),
        ).fetchone()[0]

        # By risk tier — thresholds adjusted by probe confidence
        tiers = conn.execute(
            """
            SELECT
                COUNT(CASE WHEN risk_score < ? THEN 1 END) as noise,
                COUNT(CASE WHEN risk_score >= ? AND risk_score < ? THEN 1 END) as baseline,
                COUNT(CASE WHEN risk_score >= ? AND risk_score < ? THEN 1 END) as suspicious,
                COUNT(CASE WHEN risk_score >= ? THEN 1 END) as threats
            FROM security_events
            WHERE event_timestamp_ns > ?
        """,
            (t_noise, t_noise, t_base, t_base, t_susp, t_susp, cutoff_ns),
        ).fetchone()

        # Incident count
        incidents = 0
        try:
            incidents = conn.execute(
                "SELECT COUNT(*) FROM incidents "
                "WHERE created_at > datetime('now', ?)",
                (f"-{hours} hours",),
            ).fetchone()[0]
        except Exception:
            pass

        # Active agents count
        active_agents = conn.execute(
            "SELECT COUNT(DISTINCT collection_agent) FROM security_events "
            "WHERE event_timestamp_ns > ?",
            (cutoff_ns,),
        ).fetchone()[0]

        # Total observation events
        total_observations = 0
        try:
            total_observations = conn.execute(
                "SELECT COUNT(*) FROM observation_events " "WHERE timestamp_ns > ?",
                (cutoff_ns,),
            ).fetchone()[0]
        except Exception:
            pass

        # Total flow events
        total_flows = 0
        try:
            total_flows = conn.execute(
                "SELECT COUNT(*) FROM flow_events " "WHERE timestamp_ns > ?",
                (cutoff_ns,),
            ).fetchone()[0]
        except Exception:
            pass

        conn.close()

        return jsonify(
            {
                "total_events": total + total_observations + total_flows,
                "security_events": total,
                "observations": total_observations,
                "flows": total_flows,
                "noise": tiers["noise"],
                "baseline": tiers["baseline"],
                "suspicious": tiers["suspicious"],
                "threats": tiers["threats"],
                "incidents": incidents,
                "active_agents": active_agents,
                "probe_confidence": round(probe_conf, 4),
                "hours": hours,
            }
        )
    except Exception as e:
        logger.warning("Verdict funnel failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ── Probe Calibration ───────────────────────────────────────────────────


@dashboard_bp.route("/api/nexus/probe-calibration")
@require_login
def nexus_probe_calibration():
    """Return per-probe precision weights from Beta-Binomial tracking."""
    if not PROBE_CAL_DB.exists():
        return jsonify({"probes": [], "total": 0})

    try:
        conn = _ro_conn(PROBE_CAL_DB)
        rows = conn.execute(
            """
            SELECT probe_name,
                   ROUND(alpha / (alpha + beta), 4) as precision,
                   ROUND(alpha, 2) as alpha,
                   ROUND(beta, 2) as beta,
                   total_updates,
                   CASE WHEN total_updates >= 10 THEN 'active' ELSE 'learning' END as status
            FROM probe_calibration
            ORDER BY alpha / (alpha + beta) ASC
        """
        ).fetchall()
        conn.close()

        probes = [
            {
                "name": r["probe_name"],
                "precision": r["precision"],
                "alpha": r["alpha"],
                "beta": r["beta"],
                "updates": r["total_updates"],
                "status": r["status"],
            }
            for r in rows
        ]

        return jsonify(
            {
                "probes": probes,
                "total": len(probes),
                "active_count": sum(1 for p in probes if p["status"] == "active"),
            }
        )
    except Exception as e:
        logger.warning("Probe calibration API failed: %s", e)
        return jsonify({"probes": [], "total": 0, "error": str(e)})


# ── SOMA Stats ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/nexus/soma-stats")
@require_login
def nexus_soma_stats():
    """Return SOMA baseline maturity and top suppressors."""
    if not SOMA_DB.exists():
        return jsonify(
            {
                "total_patterns": 0,
                "total_observations": 0,
                "known": 0,
                "learning": 0,
                "novel": 0,
                "maturity_pct": 0,
                "maturity_label": "cold_start",
                "top_suppressors": [],
            }
        )

    try:
        conn = _ro_conn(SOMA_DB)

        stats = conn.execute(
            """
            SELECT
                COUNT(*) as total_patterns,
                COALESCE(SUM(seen_count), 0) as total_observations,
                COUNT(CASE WHEN seen_count >= 5 THEN 1 END) as known,
                COUNT(CASE WHEN seen_count > 1 AND seen_count < 5 THEN 1 END) as learning,
                COUNT(CASE WHEN seen_count = 1 THEN 1 END) as novel
            FROM soma_observations
        """
        ).fetchone()

        total = stats["total_patterns"] or 1
        known = stats["known"]
        maturity_pct = round(100.0 * known / total, 1)

        if known >= 100:
            maturity_label = "mature"
        elif known >= 30:
            maturity_label = "baseline"
        elif known >= 5:
            maturity_label = "learning"
        else:
            maturity_label = "cold_start"

        # Top suppressors — patterns that fire most often
        top_rows = conn.execute(
            """
            SELECT event_category, process_name, seen_count,
                   ROUND(risk_score, 3) as avg_risk
            FROM soma_observations
            WHERE seen_count >= 10
            ORDER BY seen_count DESC
            LIMIT 8
        """
        ).fetchall()

        conn.close()

        return jsonify(
            {
                "total_patterns": stats["total_patterns"],
                "total_observations": stats["total_observations"],
                "known": known,
                "learning": stats["learning"],
                "novel": stats["novel"],
                "maturity_pct": maturity_pct,
                "maturity_label": maturity_label,
                "top_suppressors": [
                    {
                        "category": r["event_category"],
                        "process": r["process_name"],
                        "seen_count": r["seen_count"],
                        "avg_risk": r["avg_risk"],
                    }
                    for r in top_rows
                ],
            }
        )
    except Exception as e:
        logger.warning("SOMA stats API failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ── ASV Status ──────────────────────────────────────────────────────────


@dashboard_bp.route("/api/nexus/asv-status")
@require_login
def nexus_asv_status():
    """Return current Agent Signature Vector — which agents fired recently."""
    hours = float(request.args.get("hours", 1))
    cutoff_ns = int((time.time() - hours * 3600) * 1e9)

    # Canonical agent list (must match inads_engine.py ASV_AGENTS)
    asv_agents = [
        "macos_auth",
        "macos_discovery",
        "macos_dns",
        "macos_filesystem",
        "macos_infostealer_guard",
        "macos_internet_activity",
        "macos_network",
        "macos_persistence",
        "macos_process",
        "macos_provenance",
        "macos_quarantine_guard",
        "macos_realtime_sensor",
        "macos_unified_log",
        "network_sentinel",
    ]

    try:
        conn = _ro_conn(TELEMETRY_DB)

        # Get distinct agents that fired security events in the window
        rows = conn.execute(
            "SELECT DISTINCT collection_agent, COUNT(*) as cnt "
            "FROM security_events "
            "WHERE event_timestamp_ns > ? "
            "GROUP BY collection_agent",
            (cutoff_ns,),
        ).fetchall()

        conn.close()

        active_agents = {r["collection_agent"]: r["cnt"] for r in rows}

        agents = []
        for name in asv_agents:
            agents.append(
                {
                    "name": name,
                    "short": name.replace("macos_", "").replace("_", " "),
                    "active": name in active_agents,
                    "event_count": active_agents.get(name, 0),
                }
            )

        active_count = sum(1 for a in agents if a["active"])
        ratio = round(active_count / len(asv_agents), 4) if asv_agents else 0

        return jsonify(
            {
                "agents": agents,
                "active_count": active_count,
                "total_agents": len(asv_agents),
                "ratio": ratio,
                "window_hours": hours,
            }
        )
    except Exception as e:
        logger.warning("ASV status API failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ── Agent Constellation ────────────────────────────────────────────────


@dashboard_bp.route("/api/nexus/constellation")
@require_login
def nexus_constellation():
    """Return agent co-firing arcs for the constellation visualization.

    Two agents "co-fire" when both produce security events within a 60s window.
    Returns nodes (agents) and edges (co-firing pairs with strength).
    """
    hours = float(request.args.get("hours", 24))
    cutoff_ns = int((time.time() - hours * 3600) * 1e9)

    # Scale co-fire threshold with window: longer windows need higher thresholds
    # to keep arcs sparse on quiet machines. Target ~6-10 arcs during normal ops.
    min_strength = max(5, int(hours * 1.5))

    asv_agents = [
        "macos_auth",
        "macos_discovery",
        "macos_dns",
        "macos_filesystem",
        "macos_infostealer_guard",
        "macos_internet_activity",
        "macos_network",
        "macos_persistence",
        "macos_process",
        "macos_provenance",
        "macos_quarantine_guard",
        "macos_realtime_sensor",
        "macos_unified_log",
        "network_sentinel",
    ]

    try:
        conn = _ro_conn(TELEMETRY_DB)

        # Per-agent: event count in full window
        agent_rows = conn.execute(
            "SELECT collection_agent, COUNT(*) as cnt "
            "FROM security_events WHERE event_timestamp_ns > ? "
            "GROUP BY collection_agent",
            (cutoff_ns,),
        ).fetchall()
        agent_stats = {r["collection_agent"]: {"cnt": r["cnt"]} for r in agent_rows}

        # Recent risk (last 1h) — drives node COLOR so quiet machines look calm
        recent_cutoff = int((time.time() - 3600) * 1e9)
        risk_rows = conn.execute(
            "SELECT collection_agent, "
            "MAX(risk_score) as max_risk, AVG(risk_score) as avg_risk "
            "FROM security_events WHERE event_timestamp_ns > ? "
            "GROUP BY collection_agent",
            (recent_cutoff,),
        ).fetchall()
        recent_risk = {r["collection_agent"]: dict(r) for r in risk_rows}

        # Merge recent risk into agent_stats
        for name in agent_stats:
            rr = recent_risk.get(name, {})
            agent_stats[name]["max_risk"] = rr.get("max_risk", 0) or 0
            agent_stats[name]["avg_risk"] = rr.get("avg_risk", 0) or 0

        # Co-firing: self-join security_events within 30s windows.
        # Tight window so quiet machines show 5-8 arcs, attacks show 30+.
        cofiring = conn.execute(
            """
            SELECT a.agent AS a1, b.agent AS b1, COUNT(*) AS strength,
                   MAX(a.max_risk + b.max_risk) AS combined_risk
            FROM (
                SELECT collection_agent AS agent,
                       CAST(event_timestamp_ns / 30000000000 AS INTEGER) AS bucket,
                       MAX(risk_score) AS max_risk
                FROM security_events
                WHERE event_timestamp_ns > ?
                GROUP BY collection_agent, bucket
            ) a
            JOIN (
                SELECT collection_agent AS agent,
                       CAST(event_timestamp_ns / 30000000000 AS INTEGER) AS bucket,
                       MAX(risk_score) AS max_risk
                FROM security_events
                WHERE event_timestamp_ns > ?
                GROUP BY collection_agent, bucket
            ) b ON a.bucket = b.bucket AND a.agent < b.agent
            GROUP BY a.agent, b.agent
            HAVING strength >= ?
            ORDER BY combined_risk DESC, strength DESC
            LIMIT 20
        """,
            (cutoff_ns, cutoff_ns, min_strength),
        ).fetchall()

        # Recent probe detections (last 1h) — drives probe visibility/intensity
        # Map event_category → probe_name (they use different naming)
        EVENT_TO_PROBE = {
            "process_spawned": "macos_process_spawn",
            "lolbin_execution": "macos_lolbin",
            "suspicious_script": "macos_script_interpreter",
            "high_cpu": "macos_resource_abuse",
            "new_external_connection": "macos_new_connection",
            "unexpected_listener": "macos_unexpected_listener",
            "exfil_spike": "macos_exfil_spike",
            "c2_beacon": "macos_c2_beacon",
            "dns_beaconing_detected": "macos_dns_beaconing",
            "arp_scan": "macos_discovery_arp",
            "rogue_dhcp": "macos_discovery_rogue_dhcp",
            "topology_new_route": "macos_discovery_topology",
            "new_device_risk": "macos_discovery_new_device_risk",
            "bluetooth_inventory": "macos_bluetooth_inventory",
            "macos_config_backdoor_modified": "macos_config_backdoor",
            "macos_quarantine_bypass": "macos_quarantine_bypass",
            "account_lockout": "macos_account_lockout",
            "credential_access": "macos_credential_access",
            "off_hours_login": "macos_off_hours_login",
            "cloud_exfil": "macos_internet_cloud_exfil",
            "exfil_timing": "macos_internet_exfil_timing",
            "geo_anomaly": "macos_internet_geo_anomaly",
            "browser_to_terminal": "macos_provenance_browser_to_terminal",
            "full_kill_chain": "macos_provenance_full_kill_chain",
            "fake_password_dialog": "macos_infostealer_fake_dialog",
            "browser_cache_localstorage": "macos_infostealer_browser_cache_localstorage",
            "gatekeeper_block": "rt_gatekeeper",
            "tcc_permission_granted": "rt_tcc_permission",
            "tcc_permission_denied": "rt_tcc_permission",
        }
        recent_probe_cutoff = int((time.time() - 3600) * 1e9)
        probe_detections = {}
        try:
            det_rows = conn.execute(
                "SELECT event_category, COUNT(*) as cnt, MAX(risk_score) as max_risk "
                "FROM security_events WHERE event_timestamp_ns > ? "
                "GROUP BY event_category",
                (recent_probe_cutoff,),
            ).fetchall()
            for dr in det_rows:
                probe_name = EVENT_TO_PROBE.get(dr["event_category"])
                if probe_name:
                    existing = probe_detections.get(
                        probe_name, {"count": 0, "max_risk": 0}
                    )
                    existing["count"] += dr["cnt"]
                    existing["max_risk"] = max(
                        existing["max_risk"], dr["max_risk"] or 0
                    )
                    probe_detections[probe_name] = existing
        except Exception:
            pass

        conn.close()

        # ── Probe-to-agent mapping (derived from probe name prefix) ──
        PROBE_AGENT_MAP = {
            "macos_process_spawn": "macos_process",
            "macos_lolbin": "macos_process",
            "macos_script_interpreter": "macos_process",
            "macos_resource_abuse": "macos_process",
            "macos_new_connection": "macos_network",
            "macos_unexpected_listener": "macos_network",
            "macos_exfil_spike": "macos_network",
            "macos_c2_beacon": "macos_network",
            "macos_dns_beaconing": "macos_dns",
            "macos_discovery_arp": "macos_discovery",
            "macos_discovery_rogue_dhcp": "macos_discovery",
            "macos_discovery_topology": "macos_discovery",
            "macos_discovery_new_device_risk": "macos_discovery",
            "macos_bluetooth_inventory": "macos_discovery",
            "macos_config_backdoor": "macos_persistence",
            "macos_quarantine_bypass": "macos_quarantine_guard",
            "macos_account_lockout": "macos_auth",
            "macos_credential_access": "macos_auth",
            "macos_off_hours_login": "macos_auth",
            "macos_internet_cloud_exfil": "macos_internet_activity",
            "macos_internet_exfil_timing": "macos_internet_activity",
            "macos_internet_geo_anomaly": "macos_internet_activity",
            "macos_provenance_browser_to_terminal": "macos_provenance",
            "macos_provenance_full_kill_chain": "macos_provenance",
            "macos_infostealer_fake_dialog": "macos_infostealer_guard",
            "macos_infostealer_browser_cache_localstorage": "macos_infostealer_guard",
            "rt_gatekeeper": "macos_realtime_sensor",
            "rt_tcc_permission": "macos_realtime_sensor",
        }

        # Load probe calibration data
        probes_by_agent = {}  # agent_id -> [probe_data]
        try:
            pcal_conn = _ro_conn(PROBE_CAL_DB)
            probe_rows = pcal_conn.execute(
                "SELECT probe_name, alpha, beta, total_updates, "
                "ROUND(alpha/(alpha+beta), 4) as precision "
                "FROM probe_calibration"
            ).fetchall()
            pcal_conn.close()

            for pr in probe_rows:
                agent_id = PROBE_AGENT_MAP.get(pr["probe_name"], "unknown")
                if agent_id not in probes_by_agent:
                    probes_by_agent[agent_id] = []
                # Match probe to recent detections by category
                det = probe_detections.get(pr["probe_name"], {})
                probes_by_agent[agent_id].append(
                    {
                        "name": pr["probe_name"]
                        .replace("macos_", "")
                        .replace("_", " "),
                        "id": pr["probe_name"],
                        "precision": pr["precision"],
                        "updates": pr["total_updates"],
                        "detections": det.get("count", 0),
                        "det_risk": round(det.get("max_risk", 0), 3),
                        "active": det.get("count", 0)
                        > 0,  # only "active" if it fired recently
                    }
                )
        except Exception:
            pass

        # Build nodes
        nodes = []
        for name in asv_agents:
            stats = agent_stats.get(name, {})
            nodes.append(
                {
                    "id": name,
                    "short": name.replace("macos_", "").replace("_", " "),
                    "events": stats.get("cnt", 0),
                    "max_risk": round(stats.get("max_risk", 0) or 0, 3),
                    "avg_risk": round(stats.get("avg_risk", 0) or 0, 3),
                    "active": name in agent_stats,
                    "probes": probes_by_agent.get(name, []),
                }
            )

        # Build edges
        edges = []
        for row in cofiring:
            edges.append(
                {
                    "source": row["a1"],
                    "target": row["b1"],
                    "strength": row["strength"],
                    "risk": round(row["combined_risk"] or 0, 3),
                }
            )

        return jsonify(
            {
                "nodes": nodes,
                "edges": edges,
                "total_agents": len(asv_agents),
                "active_count": sum(1 for n in nodes if n["active"]),
                "total_probes": sum(len(n["probes"]) for n in nodes),
                "hours": hours,
            }
        )
    except Exception as e:
        logger.warning("Constellation API failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ── INADS Status ───────────────────────────────────────────────────


@dashboard_bp.route("/api/nexus/inads-status")
@require_login
def nexus_inads_status():
    """Return INADS engine status, device risk, and mesh events."""
    # ── 1. INADS engine status ──
    engine_status = {
        "engine": "INADS",
        "version": "3.0",
        "trained": False,
        "clusters": {},
    }
    cluster_descriptions = {
        "process_tree": "Process tree anomaly detection",
        "network_seq": "Network sequence analysis",
        "kill_chain": "Kill chain stage correlation",
        "system_anomaly": "System-level anomaly scoring",
        "file_path": "File path risk assessment",
        "agent_signature": "Multi-agent behavioral signature",
    }
    cluster_weights = {
        "process_tree": 0.25,
        "network_seq": 0.15,
        "kill_chain": 0.15,
        "system_anomaly": 0.10,
        "file_path": 0.10,
        "agent_signature": 0.25,
    }
    try:
        from amoskys.intel.inads_engine import INADSEngine

        inads = INADSEngine()
        raw = inads.status()
        engine_status["trained"] = raw.get("trained", False)
        raw_clusters = raw.get("clusters", {})
        weights = raw.get("weights", cluster_weights)
        for cname, cinfo in raw_clusters.items():
            engine_status["clusters"][cname] = {
                "trained": cinfo.get("trained", False),
                "n_features": cinfo.get("n_features", 0),
                "weight": weights.get(cname, 0),
                "description": cluster_descriptions.get(cname, cname),
            }
    except Exception as e:
        logger.info("INADS engine not available: %s", e)
        # Populate with defaults so the UI still renders
        for cname, desc in cluster_descriptions.items():
            engine_status["clusters"][cname] = {
                "trained": False,
                "n_features": 0,
                "weight": cluster_weights.get(cname, 0),
                "description": desc,
            }

    # ── 2. Device risk from fusion.db ──
    device_risk = None
    try:
        if FUSION_DB.exists():
            conn = _ro_conn(FUSION_DB)
            row = conn.execute(
                "SELECT * FROM device_risk ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()
            conn.close()
            if row:
                device_risk = {k: row[k] for k in row.keys()}
                # Parse reason_tags if stored as JSON string
                tags = device_risk.get("reason_tags")
                if isinstance(tags, str):
                    try:
                        device_risk["reason_tags"] = json.loads(tags)
                    except (json.JSONDecodeError, TypeError):
                        device_risk["reason_tags"] = [tags] if tags else []
    except Exception as e:
        logger.info("Fusion DB device_risk query failed: %s", e)

    # ── 3. Mesh events from mesh_events.db ──
    mesh_events = []
    try:
        if MESH_DB.exists():
            import sqlite3 as _sq

            conn = _sq.connect(str(MESH_DB), timeout=2)
            conn.row_factory = _sq.Row
            rows = conn.execute(
                "SELECT * FROM mesh_events ORDER BY timestamp_ns DESC LIMIT 50"
            ).fetchall()
            conn.close()
            for r in rows:
                evt = dict(r)
                # Parse JSON payload
                if isinstance(evt.get("payload"), str):
                    try:
                        evt["payload"] = json.loads(evt["payload"])
                    except (json.JSONDecodeError, TypeError):
                        pass
                mesh_events.append(evt)
    except Exception as e:
        logger.info("Mesh events query failed: %s", e)

    return jsonify(
        {
            "engine": engine_status["engine"],
            "version": engine_status["version"],
            "trained": engine_status["trained"],
            "clusters": engine_status["clusters"],
            "device_risk": device_risk,
            "mesh_events": mesh_events,
            "total_probes": 109,
            "total_agents": 18,
        }
    )
