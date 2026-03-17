"""
IGRIS Security Toolkit — 22 query tools + 11 action tools.

Query tools: read-only SQL against TelemetryStore/FusionEngine/AGENT_REGISTRY.
Action tools: confidence-gated operations via ActionExecutor (mesh/actions.py).

Tool-use pattern (same as Microsoft Security Copilot, Splunk AI, CrowdStrike Charlotte):
  User question → LLM picks tool(s) → execute → LLM synthesizes answer
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("igris.tools")


class IgrisToolkit:
    """33 security tools (22 query + 11 action) backed by AMOSKYS data layer."""

    def __init__(self, telemetry_db: str = "data/telemetry.db",
                 fusion_db: str = "data/intel/fusion.db",
                 reliability_db: str = "data/intel/reliability.db",
                 action_executor=None):
        self._telemetry_db = telemetry_db
        self._fusion_db = fusion_db
        self._action_executor = action_executor
        self._reliability_db = reliability_db

    def _query(self, db_path: str, sql: str, params: tuple = ()) -> List[Dict]:
        """Execute a read-only query and return list of dicts."""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            result = [dict(r) for r in rows]
            conn.close()
            return result
        except sqlite3.Error as e:
            logger.error("Query failed: %s — %s", sql[:80], e)
            return []

    def _query_one(self, db_path: str, sql: str, params: tuple = ()) -> Optional[Dict]:
        rows = self._query(db_path, sql, params)
        return rows[0] if rows else None

    def _count(self, db_path: str, sql: str, params: tuple = ()) -> int:
        try:
            conn = sqlite3.connect(db_path)
            row = conn.execute(sql, params).fetchone()
            conn.close()
            return int(row[0]) if row else 0
        except sqlite3.Error:
            return 0

    # ══════════════════════════════════════════════════════════════
    # Tool definitions (schema for Claude tool-use)
    # ══════════════════════════════════════════════════════════════

    def get_tool_definitions(self) -> List[Dict]:
        """Return tool definitions for all query + action tools."""
        defs = [
            {
                "name": "get_threat_posture",
                "description": "Get current device threat posture: risk score, active threats, agent health, MITRE techniques seen, and overall security stance.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Lookback window in hours", "default": 24}
                    },
                },
            },
            {
                "name": "query_security_events",
                "description": "Search security detection events by time range, risk score, agent, or MITRE technique. Returns probe-generated detections from all agents.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24},
                        "min_risk": {"type": "number", "description": "Minimum risk score (0.0-1.0)"},
                        "agent": {"type": "string", "description": "Filter by collection_agent name"},
                        "category": {"type": "string", "description": "Filter by event_category"},
                        "limit": {"type": "integer", "default": 20},
                    },
                },
            },
            {
                "name": "list_incidents",
                "description": "List security incidents filtered by severity or status. Incidents are confirmed threats from FusionEngine correlation.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                        "status": {"type": "string", "enum": ["open", "investigating", "contained", "resolved", "closed"]},
                        "limit": {"type": "integer", "default": 10},
                    },
                },
            },
            {
                "name": "get_incident_detail",
                "description": "Get full detail for a specific incident including title, description, MITRE techniques, indicators, timeline, and linked signals.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "incident_id": {"type": "integer", "description": "Incident ID from list_incidents"}
                    },
                    "required": ["incident_id"],
                },
            },
            {
                "name": "query_signals",
                "description": "List signals (pre-incident detections). Signals are aggregated patterns: threshold breaches, anomaly bursts, kill chain stage progressions.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "signal_type": {"type": "string", "enum": ["kill_chain", "threshold", "anomaly_burst", "manual"]},
                        "status": {"type": "string", "enum": ["open", "promoted", "dismissed", "expired"]},
                        "limit": {"type": "integer", "default": 15},
                    },
                },
            },
            {
                "name": "get_agent_health",
                "description": "Get status of all AMOSKYS agents: which are registered, their probe counts, platforms, and categories.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "query_probes_fired",
                "description": "List which probes fired detections, with event counts and MITRE technique mappings.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24},
                        "agent": {"type": "string", "description": "Filter by agent name"},
                    },
                },
            },
            {
                "name": "explain_mitre_technique",
                "description": "Explain a MITRE ATT&CK technique ID (e.g. T1059) and show which AMOSKYS probes and detections cover it.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string", "description": "MITRE technique ID like T1059 or T1555.001"}
                    },
                    "required": ["technique_id"],
                },
            },
            {
                "name": "query_dns_events",
                "description": "Search DNS events for specific domains, DGA suspects, or beaconing patterns.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain name to search (partial match)"},
                        "hours": {"type": "integer", "default": 24},
                        "limit": {"type": "integer", "default": 20},
                    },
                },
            },
            {
                "name": "query_process_events",
                "description": "Search process events by executable name, PID, user, or suspicious flag.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "exe": {"type": "string", "description": "Executable name (partial match)"},
                        "pid": {"type": "integer"},
                        "user": {"type": "string"},
                        "suspicious_only": {"type": "boolean", "default": False},
                        "hours": {"type": "integer", "default": 24},
                        "limit": {"type": "integer", "default": 20},
                    },
                },
            },
            {
                "name": "query_flow_events",
                "description": "Search network flow events by destination IP, port, process, or threat score.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "dst_ip": {"type": "string"},
                        "dst_port": {"type": "integer"},
                        "process_name": {"type": "string"},
                        "suspicious_only": {"type": "boolean", "default": False},
                        "hours": {"type": "integer", "default": 24},
                        "limit": {"type": "integer", "default": 20},
                    },
                },
            },
            {
                "name": "query_fim_events",
                "description": "Search file integrity monitoring events. Shows file modifications, creations, deletions in critical system paths.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path filter (partial match)"},
                        "hours": {"type": "integer", "default": 24},
                        "limit": {"type": "integer", "default": 20},
                    },
                },
            },
            {
                "name": "query_persistence_events",
                "description": "List persistence mechanism entries: LaunchAgents, LaunchDaemons, cron jobs, SSH keys, login items.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "description": "Persistence type filter (e.g. LaunchAgent, cron, ssh_key)"},
                        "limit": {"type": "integer", "default": 30},
                    },
                },
            },
            {
                "name": "query_auth_events",
                "description": "Search authentication/authorization events: SSH logins, sudo usage, privilege escalation attempts.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24},
                        "limit": {"type": "integer", "default": 20},
                    },
                },
            },
            {
                "name": "query_peripheral_events",
                "description": "List USB, Bluetooth, and Thunderbolt device events. Shows connected peripherals and volume mounts.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24},
                        "limit": {"type": "integer", "default": 20},
                    },
                },
            },
            {
                "name": "get_kill_chain_summary",
                "description": "Get active kill chain state: which MITRE tactics have been observed, contributing events per tactic stage.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24}
                    },
                },
            },
            {
                "name": "get_mitre_coverage",
                "description": "Get MITRE ATT&CK technique coverage: which techniques have been observed in detections, how many times each.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24}
                    },
                },
            },
            {
                "name": "get_igris_status",
                "description": "Get IGRIS supervisor status: observation cycles, baselines, active governance signals, coherence verdict.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_flow_geo_summary",
                "description": "Get network flow geographic summary: which countries/ASNs traffic is going to, with volume counts.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24}
                    },
                },
            },
            {
                "name": "get_reliability_scores",
                "description": "Get AMRDR agent reliability scores: trust weights, drift status, quarantine status for each agent.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_sigma_rule_hits",
                "description": "Get Sigma rule detection hits: which rules fired, how many times, linked MITRE techniques.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24}
                    },
                },
            },
            {
                "name": "get_event_timeline",
                "description": "Get a chronological timeline of all security-relevant events for forensic analysis.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 1},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
            # ── Sub-Agent Tools (agentic AI) ──
            {
                "name": "spawn_threat_hunter",
                "description": "Spawn an autonomous threat hunter sub-agent to trace an IOC (IP, domain, PID, or file path) across all AMOSKYS data sources in parallel. Returns correlated findings with risk assessment.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ioc_type": {"type": "string", "enum": ["ip", "domain", "pid", "path"], "description": "Type of indicator of compromise"},
                        "ioc_value": {"type": "string", "description": "The IOC value to hunt (e.g., '185.220.101.1', 'evil.com', '1234', '/tmp/payload.sh')"},
                    },
                    "required": ["ioc_value"],
                },
            },
            {
                "name": "spawn_incident_analyst",
                "description": "Spawn an autonomous incident analyst sub-agent to build the full forensic narrative for an incident. Traces contributing events, checks kill chain, and recommends containment.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "incident_id": {"type": "integer", "description": "Incident ID to analyze"},
                    },
                    "required": ["incident_id"],
                },
            },
            {
                "name": "spawn_pattern_scout",
                "description": "Spawn an autonomous pattern scout sub-agent to scan for emerging threats, anomalies, and drift across the entire system. Returns concerns and recommendations.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Lookback window in hours", "default": 1},
                    },
                },
            },
            {
                "name": "spawn_parallel_investigation",
                "description": "Spawn multiple sub-agents in parallel for comprehensive investigation. Each task runs concurrently and results are collected together.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tasks": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "agent_type": {"type": "string", "enum": ["threat_hunter", "incident_analyst", "pattern_scout"]},
                                    "ioc_type": {"type": "string"},
                                    "ioc_value": {"type": "string"},
                                    "incident_id": {"type": "integer"},
                                    "hours": {"type": "integer"},
                                },
                                "required": ["agent_type"],
                            },
                            "description": "List of sub-agent tasks to run in parallel",
                        },
                    },
                    "required": ["tasks"],
                },
            },
        ]

        # Append action tool definitions if ActionExecutor is available
        if self._action_executor is not None:
            try:
                action_defs = self._action_executor.get_tool_definitions()
                defs.extend(action_defs)
            except Exception:
                pass

        return defs

    # ══════════════════════════════════════════════════════════════
    # Tool implementations
    # ══════════════════════════════════════════════════════════════

    def execute(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """Execute a tool by name. Returns JSON-serializable result."""
        # Sub-agent tools
        if tool_name.startswith("spawn_"):
            return self._execute_sub_agent(tool_name, args)

        # Check action tools first (if executor available)
        if self._action_executor is not None:
            action_method = getattr(self._action_executor, tool_name, None)
            if action_method and callable(action_method):
                try:
                    receipt = action_method(**args)
                    if hasattr(receipt, 'to_dict'):
                        return receipt.to_dict()
                    return {"status": "ok", "result": str(receipt)}
                except Exception as e:
                    return {"status": "error", "error": str(e)}

        handler = getattr(self, f"_tool_{tool_name}", None)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}
        try:
            return handler(**args)
        except Exception as e:
            logger.error("Tool %s failed: %s", tool_name, e)
            return {"error": str(e)}

    def _execute_sub_agent(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """Execute sub-agent tools (agentic AI)."""
        from .sub_agents import SubAgentManager

        mgr = SubAgentManager(self)

        if tool_name == "spawn_threat_hunter":
            result = mgr.spawn("threat_hunter", args, blocking=True)
        elif tool_name == "spawn_incident_analyst":
            result = mgr.spawn("incident_analyst", args, blocking=True)
        elif tool_name == "spawn_pattern_scout":
            result = mgr.spawn("pattern_scout", args, blocking=True)
        elif tool_name == "spawn_parallel_investigation":
            tasks = args.get("tasks", [])
            results = mgr.spawn_parallel(tasks)
            return {
                "status": "completed",
                "agents_spawned": len(tasks),
                "results": [
                    {
                        "agent_id": r.agent_id,
                        "agent_type": r.agent_type,
                        "task": r.task,
                        "status": r.status,
                        "summary": r.summary,
                        "findings_count": len(r.findings),
                        "findings": r.findings[:10],
                        "confidence": r.confidence,
                        "recommendations": r.recommendations,
                        "duration_ms": r.duration_ms,
                        "tool_calls": r.tool_calls_made,
                    }
                    for r in results
                ],
            }
        else:
            return {"error": f"Unknown sub-agent tool: {tool_name}"}

        return {
            "agent_id": result.agent_id,
            "agent_type": result.agent_type,
            "task": result.task,
            "status": result.status,
            "summary": result.summary,
            "findings_count": len(result.findings),
            "findings": result.findings[:10],
            "confidence": result.confidence,
            "recommendations": result.recommendations,
            "duration_ms": result.duration_ms,
            "tool_calls": result.tool_calls_made,
        }

    def _cutoff_ns(self, hours: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return int(cutoff.timestamp() * 1e9)

    # ── 1. Threat Posture ──

    def _tool_get_threat_posture(self, hours: int = 24) -> Dict:
        cutoff = self._cutoff_ns(hours)
        sec_count = self._count(self._telemetry_db,
            "SELECT COUNT(*) FROM security_events WHERE timestamp_ns > ?", (cutoff,))
        incident_count = self._count(self._telemetry_db,
            "SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')")
        signal_count = self._count(self._telemetry_db,
            "SELECT COUNT(*) FROM signals WHERE status = 'open'")

        # Risk from fusion
        risk = self._query_one(self._fusion_db,
            "SELECT score, level FROM device_risk ORDER BY updated_at DESC LIMIT 1") or {}

        # MITRE techniques seen
        techniques = set()
        for r in self._query(self._telemetry_db,
            "SELECT mitre_techniques FROM security_events WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL",
            (cutoff,)):
            try:
                for t in json.loads(r["mitre_techniques"]):
                    techniques.add(t)
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "device_risk_score": risk.get("score", 0),
            "device_risk_level": risk.get("level", "UNKNOWN"),
            "security_events_count": sec_count,
            "open_incidents": incident_count,
            "open_signals": signal_count,
            "mitre_techniques_observed": sorted(techniques),
            "mitre_technique_count": len(techniques),
            "lookback_hours": hours,
        }

    # ── 2. Security Events ──

    def _tool_query_security_events(self, hours: int = 24, min_risk: float = None,
                                     agent: str = None, category: str = None,
                                     limit: int = 20) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        conditions = ["timestamp_ns > ?"]
        params: list = [cutoff]
        if min_risk is not None:
            conditions.append("risk_score >= ?")
            params.append(min_risk)
        if agent:
            conditions.append("collection_agent = ?")
            params.append(agent)
        if category:
            conditions.append("event_category LIKE ?")
            params.append(f"%{category}%")
        where = " AND ".join(conditions)
        return self._query(self._telemetry_db,
            f"SELECT id, timestamp_dt, device_id, event_category, risk_score, "
            f"confidence, final_classification, description, collection_agent, "
            f"mitre_techniques, geo_src_country, asn_src_org, threat_intel_match "
            f"FROM security_events WHERE {where} ORDER BY risk_score DESC LIMIT ?",
            tuple(params) + (limit,))

    # ── 3. Incidents ──

    def _tool_list_incidents(self, severity: str = None, status: str = None,
                              limit: int = 10) -> List[Dict]:
        conditions = []
        params: list = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if status:
            conditions.append("status = ?")
            params.append(status)
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        return self._query(self._telemetry_db,
            f"SELECT id, title, severity, status, created_at, description, "
            f"mitre_techniques, assignee FROM incidents {where} "
            f"ORDER BY created_at DESC LIMIT ?",
            tuple(params) + (limit,))

    # ── 4. Incident Detail ──

    def _tool_get_incident_detail(self, incident_id: int) -> Optional[Dict]:
        return self._query_one(self._telemetry_db,
            "SELECT * FROM incidents WHERE id = ?", (incident_id,))

    # ── 5. Signals ──

    def _tool_query_signals(self, signal_type: str = None, status: str = None,
                             limit: int = 15) -> List[Dict]:
        conditions = []
        params: list = []
        if signal_type:
            conditions.append("signal_type = ?")
            params.append(signal_type)
        if status:
            conditions.append("status = ?")
            params.append(status)
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        return self._query(self._telemetry_db,
            f"SELECT signal_id, device_id, signal_type, trigger_summary, "
            f"risk_score, status, contributing_event_ids "
            f"FROM signals {where} ORDER BY created_ns DESC LIMIT ?",
            tuple(params) + (limit,))

    # ── 6. Agent Health ──

    def _tool_get_agent_health(self) -> Dict:
        try:
            import grpc
            grpc.__version__ = '1.78.0'
            from amoskys.agents import AGENT_REGISTRY
            agents = []
            for aid, meta in AGENT_REGISTRY.items():
                agents.append({
                    "agent_id": aid,
                    "name": meta.get("name", aid),
                    "platforms": meta.get("platforms", []),
                    "probes": meta.get("probes", 0),
                    "category": meta.get("category", ""),
                })
            return {"agents": agents, "total": len(agents)}
        except Exception as e:
            return {"error": str(e)}

    # ── 7. Probes Fired ──

    def _tool_query_probes_fired(self, hours: int = 24, agent: str = None) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        conditions = ["timestamp_ns > ?"]
        params: list = [cutoff]
        if agent:
            conditions.append("collection_agent = ?")
            params.append(agent)
        where = " AND ".join(conditions)
        return self._query(self._telemetry_db,
            f"SELECT collection_agent, event_category, COUNT(*) as count, "
            f"AVG(risk_score) as avg_risk, MAX(risk_score) as max_risk, "
            f"GROUP_CONCAT(DISTINCT mitre_techniques) as techniques "
            f"FROM security_events WHERE {where} "
            f"GROUP BY collection_agent, event_category "
            f"ORDER BY count DESC",
            tuple(params))

    # ── 8. MITRE Technique Explain ──

    def _tool_explain_mitre_technique(self, technique_id: str) -> Dict:
        # Find detections using this technique
        rows = self._query(self._telemetry_db,
            "SELECT collection_agent, event_category, risk_score, description "
            "FROM security_events WHERE mitre_techniques LIKE ? "
            "ORDER BY risk_score DESC LIMIT 10",
            (f"%{technique_id}%",))
        return {
            "technique_id": technique_id,
            "detections_using_technique": rows,
            "detection_count": len(rows),
        }

    # ── 9. DNS Events ──

    def _tool_query_dns_events(self, domain: str = None, hours: int = 24,
                                limit: int = 20) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        if domain:
            return self._query(self._telemetry_db,
                "SELECT * FROM dns_events WHERE timestamp_ns > ? AND domain LIKE ? "
                "ORDER BY timestamp_ns DESC LIMIT ?",
                (cutoff, f"%{domain}%", limit))
        return self._query(self._telemetry_db,
            "SELECT domain, COUNT(*) as query_count FROM dns_events "
            "WHERE timestamp_ns > ? AND domain IS NOT NULL "
            "GROUP BY domain ORDER BY query_count DESC LIMIT ?",
            (cutoff, limit))

    # ── 10. Process Events ──

    def _tool_query_process_events(self, exe: str = None, pid: int = None,
                                    user: str = None, suspicious_only: bool = False,
                                    hours: int = 24, limit: int = 20) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        conditions = ["timestamp_ns > ?"]
        params: list = [cutoff]
        if exe:
            conditions.append("process_name LIKE ?")
            params.append(f"%{exe}%")
        if pid:
            conditions.append("pid = ?")
            params.append(pid)
        if user:
            conditions.append("conn_user LIKE ?")
            params.append(f"%{user}%")
        if suspicious_only:
            conditions.append("is_suspicious = 1")
        where = " AND ".join(conditions)
        return self._query(self._telemetry_db,
            f"SELECT pid, process_name, ppid, timestamp_dt, "
            f"is_suspicious, anomaly_score "
            f"FROM process_events WHERE {where} "
            f"ORDER BY timestamp_ns DESC LIMIT ?",
            tuple(params) + (limit,))

    # ── 11. Flow Events ──

    def _tool_query_flow_events(self, dst_ip: str = None, dst_port: int = None,
                                 process_name: str = None, suspicious_only: bool = False,
                                 hours: int = 24, limit: int = 20) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        conditions = ["timestamp_ns > ?", "dst_ip IS NOT NULL", "dst_ip != ''"]
        params: list = [cutoff]
        if dst_ip:
            conditions.append("dst_ip LIKE ?")
            params.append(f"%{dst_ip}%")
        if dst_port:
            conditions.append("dst_port = ?")
            params.append(dst_port)
        if process_name:
            conditions.append("process_name LIKE ?")
            params.append(f"%{process_name}%")
        if suspicious_only:
            conditions.append("is_suspicious = 1")
        where = " AND ".join(conditions)
        return self._query(self._telemetry_db,
            f"SELECT pid, process_name, src_ip, dst_ip, dst_port, protocol, "
            f"state, bytes_tx, bytes_rx, geo_dst_country, asn_dst_org, "
            f"threat_intel_match, threat_score "
            f"FROM flow_events WHERE {where} "
            f"ORDER BY timestamp_ns DESC LIMIT ?",
            tuple(params) + (limit,))

    # ── 12. FIM Events ──

    def _tool_query_fim_events(self, path: str = None, hours: int = 24,
                                limit: int = 20) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        if path:
            return self._query(self._telemetry_db,
                "SELECT * FROM fim_events WHERE timestamp_ns > ? "
                "AND raw_attributes_json LIKE ? ORDER BY timestamp_ns DESC LIMIT ?",
                (cutoff, f"%{path}%", limit))
        return self._query(self._telemetry_db,
            "SELECT COUNT(*) as count FROM fim_events WHERE timestamp_ns > ?",
            (cutoff,))

    # ── 13. Persistence Events ──

    def _tool_query_persistence_events(self, type: str = None,
                                        limit: int = 30) -> List[Dict]:
        if type:
            return self._query(self._telemetry_db,
                "SELECT * FROM persistence_events WHERE raw_attributes_json LIKE ? "
                "ORDER BY timestamp_ns DESC LIMIT ?",
                (f"%{type}%", limit))
        return self._query(self._telemetry_db,
            "SELECT COUNT(*) as count FROM persistence_events")

    # ── 14. Auth Events ──

    def _tool_query_auth_events(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        return self._query(self._telemetry_db,
            "SELECT * FROM security_events WHERE timestamp_ns > ? "
            "AND collection_agent = 'macos_auth' ORDER BY timestamp_ns DESC LIMIT ?",
            (cutoff, limit))

    # ── 15. Peripheral Events ──

    def _tool_query_peripheral_events(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        return self._query(self._telemetry_db,
            "SELECT * FROM peripheral_events WHERE timestamp_ns > ? "
            "ORDER BY timestamp_ns DESC LIMIT ?",
            (cutoff, limit))

    # ── 16. Kill Chain Summary ──

    def _tool_get_kill_chain_summary(self, hours: int = 24) -> Dict:
        cutoff = self._cutoff_ns(hours)
        # Group MITRE techniques by tactic stage
        rows = self._query(self._telemetry_db,
            "SELECT mitre_techniques, event_category, collection_agent, risk_score "
            "FROM security_events WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL",
            (cutoff,))
        techniques = {}
        for r in rows:
            try:
                for t in json.loads(r["mitre_techniques"]):
                    techniques.setdefault(t, []).append({
                        "agent": r["collection_agent"],
                        "category": r["event_category"],
                        "risk": r["risk_score"],
                    })
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            "techniques_observed": len(techniques),
            "technique_details": {k: {"count": len(v), "agents": list(set(e["agent"] for e in v)),
                                       "max_risk": max(e["risk"] for e in v)}
                                  for k, v in sorted(techniques.items())},
        }

    # ── 17. MITRE Coverage ──

    def _tool_get_mitre_coverage(self, hours: int = 24) -> Dict:
        cutoff = self._cutoff_ns(hours)
        rows = self._query(self._telemetry_db,
            "SELECT mitre_techniques FROM security_events "
            "WHERE timestamp_ns > ? AND mitre_techniques IS NOT NULL",
            (cutoff,))
        counts: Dict[str, int] = {}
        for r in rows:
            try:
                for t in json.loads(r["mitre_techniques"]):
                    counts[t] = counts.get(t, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass
        return {
            "total_techniques": len(counts),
            "technique_counts": dict(sorted(counts.items(), key=lambda x: -x[1])),
        }

    # ── 18. IGRIS Status ──

    def _tool_get_igris_status(self) -> Dict:
        try:
            from amoskys.igris import get_igris
            igris = get_igris()
            return igris.get_status()
        except Exception:
            # Fallback: read state file directly
            try:
                import json as _json
                with open("data/igris/state.json") as f:
                    return _json.load(f)
            except Exception as e:
                return {"error": str(e)}

    # ── 19. Flow Geo Summary ──

    def _tool_get_flow_geo_summary(self, hours: int = 24) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        return self._query(self._telemetry_db,
            "SELECT geo_dst_country, asn_dst_org, COUNT(*) as flow_count, "
            "SUM(bytes_tx) as total_bytes_tx, SUM(bytes_rx) as total_bytes_rx "
            "FROM flow_events WHERE timestamp_ns > ? AND geo_dst_country IS NOT NULL "
            "GROUP BY geo_dst_country, asn_dst_org ORDER BY flow_count DESC LIMIT 20",
            (cutoff,))

    # ── 20. Reliability Scores ──

    def _tool_get_reliability_scores(self) -> List[Dict]:
        return self._query(self._reliability_db,
            "SELECT agent_id, fusion_weight as weight, drift_type, "
            "recalibration_tier, alpha, beta FROM agent_reliability "
            "ORDER BY fusion_weight ASC")

    # ── 21. Sigma Rule Hits ──

    def _tool_get_sigma_rule_hits(self, hours: int = 24) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        return self._query(self._telemetry_db,
            "SELECT detection_rule_id, detection_rule_source, COUNT(*) as hit_count, "
            "AVG(risk_score) as avg_risk "
            "FROM security_events WHERE timestamp_ns > ? "
            "AND detection_rule_id IS NOT NULL "
            "GROUP BY detection_rule_id ORDER BY hit_count DESC",
            (cutoff,))

    # ── 22. Event Timeline ──

    def _tool_get_event_timeline(self, hours: int = 1, limit: int = 50) -> List[Dict]:
        cutoff = self._cutoff_ns(hours)
        return self._query(self._telemetry_db,
            "SELECT timestamp_dt, event_category, risk_score, description, "
            "collection_agent, mitre_techniques, final_classification "
            "FROM security_events WHERE timestamp_ns > ? "
            "ORDER BY timestamp_ns DESC LIMIT ?",
            (cutoff, limit))
