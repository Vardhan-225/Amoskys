"""IGRIS Sub-Agents — Autonomous investigation threads.

IGRIS can spawn sub-agents to investigate in parallel:
  - ThreatHunter: given an IOC, traces it across all data sources
  - IncidentAnalyst: given an incident, builds the full forensic narrative
  - PatternScout: watches for emerging patterns across the mesh

Sub-agents run as background threads, query the same toolkit, and report
findings back to the orchestrator for action decisions.

Architecture:
  IGRIS Chat → spawns SubAgent → SubAgent queries tools → reports to mesh
  IGRISOrchestrator → receives SubAgent findings → decides actions
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .tools import IgrisToolkit

logger = logging.getLogger("igris.sub_agents")


@dataclass
class SubAgentResult:
    """Result from a sub-agent investigation."""

    agent_id: str
    agent_type: str
    task: str
    status: str  # "completed" | "failed" | "timeout"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    confidence: float = 0.0
    duration_ms: float = 0.0
    tool_calls_made: int = 0
    recommendations: List[str] = field(default_factory=list)


class SubAgent:
    """Base class for autonomous investigation sub-agents.

    Each sub-agent:
    1. Receives a task (IOC, incident ID, pattern description)
    2. Plans an investigation strategy
    3. Executes tool calls against the IgrisToolkit
    4. Correlates findings
    5. Returns a structured result
    """

    AGENT_TYPE = "base"
    MAX_TOOL_CALLS = 15
    TIMEOUT_S = 30

    def __init__(self, toolkit: IgrisToolkit):
        self.toolkit = toolkit
        self.agent_id = f"{self.AGENT_TYPE}_{uuid.uuid4().hex[:8]}"
        self._tool_calls = 0

    def _query(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """Execute a tool call with tracking."""
        self._tool_calls += 1
        if self._tool_calls > self.MAX_TOOL_CALLS:
            raise RuntimeError(f"Sub-agent {self.agent_id} exceeded tool call limit")
        result = self.toolkit.execute(tool_name, params)
        return result

    def investigate(self, task: Dict[str, Any]) -> SubAgentResult:
        """Override in subclass."""
        raise NotImplementedError


class ThreatHunter(SubAgent):
    """Given an IOC (IP, domain, PID, file path), trace it across all data sources.

    Investigation strategy:
    1. Identify what type of IOC we have
    2. Search each relevant data source for the IOC
    3. Build a correlation chain (who contacted this IP? what process accessed this file?)
    4. Score the threat based on evidence breadth
    """

    AGENT_TYPE = "threat_hunter"

    def investigate(self, task: Dict[str, Any]) -> SubAgentResult:
        t0 = time.time()
        ioc_type = task.get("ioc_type", "")  # "ip" | "domain" | "pid" | "path"
        ioc_value = task.get("ioc_value", "")
        findings = []
        recommendations = []

        try:
            if ioc_type == "ip":
                findings.extend(self._hunt_ip(ioc_value))
            elif ioc_type == "domain":
                findings.extend(self._hunt_domain(ioc_value))
            elif ioc_type == "pid":
                findings.extend(self._hunt_pid(int(ioc_value)))
            elif ioc_type == "path":
                findings.extend(self._hunt_path(ioc_value))
            else:
                # Auto-detect IOC type
                if ioc_value.replace(".", "").isdigit():
                    findings.extend(self._hunt_ip(ioc_value))
                elif "/" in ioc_value:
                    findings.extend(self._hunt_path(ioc_value))
                elif "." in ioc_value:
                    findings.extend(self._hunt_domain(ioc_value))
                else:
                    try:
                        findings.extend(self._hunt_pid(int(ioc_value)))
                    except ValueError:
                        pass

            # Score based on evidence breadth
            high_risk = [f for f in findings if f.get("risk", 0) >= 0.7]
            confidence = min(1.0, len(high_risk) * 0.2 + len(findings) * 0.05)

            if high_risk:
                recommendations.append(
                    f"HIGH RISK: {len(high_risk)} findings warrant immediate investigation"
                )
            if any(f.get("source") == "flow" and f.get("geo") for f in findings):
                recommendations.append("Check geo-location of destination IPs")

            summary = (
                f"Hunted {ioc_type}={ioc_value}: {len(findings)} findings "
                f"({len(high_risk)} high-risk), confidence={confidence:.2f}"
            )

            return SubAgentResult(
                agent_id=self.agent_id,
                agent_type=self.AGENT_TYPE,
                task=f"Hunt {ioc_type}={ioc_value}",
                status="completed",
                findings=findings,
                summary=summary,
                confidence=confidence,
                duration_ms=(time.time() - t0) * 1000,
                tool_calls_made=self._tool_calls,
                recommendations=recommendations,
            )

        except Exception as e:
            return SubAgentResult(
                agent_id=self.agent_id,
                agent_type=self.AGENT_TYPE,
                task=f"Hunt {ioc_type}={ioc_value}",
                status="failed",
                summary=f"Investigation failed: {e}",
                duration_ms=(time.time() - t0) * 1000,
                tool_calls_made=self._tool_calls,
            )

    def _hunt_ip(self, ip: str) -> List[Dict]:
        findings = []
        # Check flow events
        flows = self._query("query_flow_events", {"hours": 24, "limit": 50})
        if isinstance(flows, list):
            for f in flows:
                if ip in str(f.get("dst_ip", "")) or ip in str(f.get("src_ip", "")):
                    findings.append({
                        "source": "flow",
                        "detail": f"Flow: {f.get('process_name', '?')} → {f.get('dst_ip')}:{f.get('dst_port')}",
                        "risk": f.get("threat_score", 0),
                        "geo": f.get("geo_dst_country"),
                        "process": f.get("process_name"),
                        "pid": f.get("pid"),
                    })

        # Check geo summary
        geo = self._query("get_flow_geo_summary", {"hours": 24})
        if isinstance(geo, list):
            for g in geo:
                if ip in str(g):
                    findings.append({
                        "source": "geo",
                        "detail": f"Geo: {g.get('geo_dst_country')} via {g.get('asn_dst_org')}",
                        "risk": 0.3,
                    })

        return findings

    def _hunt_domain(self, domain: str) -> List[Dict]:
        findings = []
        dns = self._query("query_dns_events", {"hours": 24, "limit": 50})
        if isinstance(dns, list):
            for d in dns:
                if domain.lower() in str(d.get("domain", "")).lower():
                    findings.append({
                        "source": "dns",
                        "detail": f"DNS: {d.get('domain')} (queries={d.get('query_count', 0)})",
                        "risk": 0.5,
                    })
        return findings

    def _hunt_pid(self, pid: int) -> List[Dict]:
        findings = []
        procs = self._query("query_process_events", {"hours": 24, "limit": 50})
        if isinstance(procs, list):
            for p in procs:
                if p.get("pid") == pid or p.get("ppid") == pid:
                    findings.append({
                        "source": "process",
                        "detail": f"Process: PID={p.get('pid')} name={p.get('name')} exe={p.get('exe')}",
                        "risk": 0.4,
                        "cmdline": p.get("cmdline"),
                    })
        return findings

    def _hunt_path(self, path: str) -> List[Dict]:
        findings = []
        fim = self._query("query_fim_events", {"hours": 24, "limit": 50})
        if isinstance(fim, dict) and "count" in fim:
            findings.append({
                "source": "fim",
                "detail": f"FIM: {fim.get('count', 0)} file events in last 24h",
                "risk": 0.3,
            })
        return findings


class IncidentAnalyst(SubAgent):
    """Given an incident ID, builds the full forensic narrative.

    Investigation strategy:
    1. Get incident detail (title, severity, MITRE techniques, event IDs)
    2. Trace each contributing event back to its source agent
    3. Build timeline of events
    4. Check for kill chain progression
    5. Recommend containment actions
    """

    AGENT_TYPE = "incident_analyst"

    def investigate(self, task: Dict[str, Any]) -> SubAgentResult:
        t0 = time.time()
        incident_id = task.get("incident_id")
        findings = []
        recommendations = []

        try:
            # 1. Get incident detail
            detail = self._query("get_incident_detail", {"incident_id": incident_id})
            if isinstance(detail, dict) and "error" not in detail:
                findings.append({
                    "source": "incident",
                    "detail": f"Incident #{incident_id}: {detail.get('title', 'unknown')}",
                    "severity": detail.get("severity", "unknown"),
                    "mitre": detail.get("mitre_techniques", "[]"),
                })

            # 2. Get kill chain state
            kill_chain = self._query("get_kill_chain_summary", {})
            if isinstance(kill_chain, dict):
                tech_count = kill_chain.get("techniques_observed", 0)
                findings.append({
                    "source": "kill_chain",
                    "detail": f"Kill chain: {tech_count} techniques observed",
                    "techniques": kill_chain.get("technique_details", {}),
                })

            # 3. Check MITRE coverage for this incident's techniques
            mitre = self._query("get_mitre_coverage", {})
            if isinstance(mitre, dict):
                findings.append({
                    "source": "mitre_coverage",
                    "detail": f"Total MITRE coverage: {mitre.get('total_techniques', 0)} techniques",
                })

            # 4. Get event timeline
            timeline = self._query("get_event_timeline", {"hours": 4})
            if isinstance(timeline, list):
                high_risk_events = [
                    e for e in timeline if (e.get("risk_score") or 0) >= 0.7
                ]
                findings.append({
                    "source": "timeline",
                    "detail": (
                        f"Timeline (4h): {len(timeline)} events, "
                        f"{len(high_risk_events)} high-risk"
                    ),
                    "high_risk_count": len(high_risk_events),
                })

            # 5. Recommendations
            severity = detail.get("severity", "low") if isinstance(detail, dict) else "unknown"
            if severity in ("critical", "high"):
                recommendations.append("Immediate investigation required")
                recommendations.append("Check process tree for lateral movement indicators")
                recommendations.append("Verify no data exfiltration in flow events")

            confidence = 0.8 if findings else 0.3
            summary = (
                f"Incident #{incident_id} analysis: {len(findings)} data points, "
                f"severity={severity}, {len(recommendations)} recommendations"
            )

            return SubAgentResult(
                agent_id=self.agent_id,
                agent_type=self.AGENT_TYPE,
                task=f"Analyze incident #{incident_id}",
                status="completed",
                findings=findings,
                summary=summary,
                confidence=confidence,
                duration_ms=(time.time() - t0) * 1000,
                tool_calls_made=self._tool_calls,
                recommendations=recommendations,
            )

        except Exception as e:
            return SubAgentResult(
                agent_id=self.agent_id,
                agent_type=self.AGENT_TYPE,
                task=f"Analyze incident #{incident_id}",
                status="failed",
                summary=f"Analysis failed: {e}",
                duration_ms=(time.time() - t0) * 1000,
                tool_calls_made=self._tool_calls,
            )


class PatternScout(SubAgent):
    """Scans for emerging patterns across the mesh — runs without being asked.

    Investigation strategy:
    1. Check threat posture for changes
    2. Look for new MITRE techniques in last hour
    3. Check for agent health anomalies
    4. Check SOMA model status
    5. Check for repeated events that might indicate persistence or C2
    """

    AGENT_TYPE = "pattern_scout"

    def investigate(self, task: Dict[str, Any]) -> SubAgentResult:
        t0 = time.time()
        lookback_hours = task.get("hours", 1)
        findings = []
        recommendations = []

        try:
            # 1. Current posture
            posture = self._query("get_threat_posture", {"hours": lookback_hours})
            if isinstance(posture, dict):
                risk = posture.get("device_risk_score", 0)
                techniques = posture.get("mitre_techniques_observed", [])
                findings.append({
                    "source": "posture",
                    "detail": f"Risk: {risk}/100, {len(techniques)} techniques, "
                    f"{posture.get('open_incidents', 0)} incidents",
                    "risk_score": risk,
                    "techniques": techniques,
                })

            # 2. IGRIS status
            igris = self._query("get_igris_status", {})
            if isinstance(igris, dict):
                active_signals = igris.get("active_signal_count", 0)
                coherence = igris.get("coherence", "unknown")
                fleet = igris.get("fleet_summary", {})
                findings.append({
                    "source": "igris",
                    "detail": f"Coherence: {coherence}, signals: {active_signals}, "
                    f"fleet: {fleet.get('healthy', 0)}/{fleet.get('total', 0)}",
                })

                if coherence == "degraded":
                    recommendations.append("System coherence degraded — investigate governance signals")
                if fleet.get("offline", 0) > 0:
                    recommendations.append(
                        f"{fleet['offline']} agents offline — check fleet health"
                    )

            # 3. Reliability scores
            reliability = self._query("get_reliability_scores", {})
            if isinstance(reliability, list):
                low_reliability = [
                    r for r in reliability
                    if isinstance(r, dict) and (r.get("reliability_score") or 1.0) < 0.7
                ]
                if low_reliability:
                    findings.append({
                        "source": "reliability",
                        "detail": f"{len(low_reliability)} agents with low reliability",
                        "agents": [r.get("agent_id") for r in low_reliability],
                    })
                    recommendations.append("Review low-reliability agents for drift")

            # 4. Sigma rule hits
            sigma = self._query("get_sigma_rule_hits", {"hours": lookback_hours})
            if isinstance(sigma, list) and sigma:
                findings.append({
                    "source": "sigma",
                    "detail": f"{len(sigma)} Sigma rule hits in last {lookback_hours}h",
                    "rules": sigma[:5],
                })

            confidence = 0.5
            if any(f.get("risk_score", 0) >= 70 for f in findings):
                confidence = 0.8
            if recommendations:
                confidence = max(confidence, 0.6)

            summary = (
                f"Pattern scan ({lookback_hours}h): {len(findings)} data points, "
                f"{len(recommendations)} concerns"
            )

            return SubAgentResult(
                agent_id=self.agent_id,
                agent_type=self.AGENT_TYPE,
                task=f"Pattern scan ({lookback_hours}h)",
                status="completed",
                findings=findings,
                summary=summary,
                confidence=confidence,
                duration_ms=(time.time() - t0) * 1000,
                tool_calls_made=self._tool_calls,
                recommendations=recommendations,
            )

        except Exception as e:
            return SubAgentResult(
                agent_id=self.agent_id,
                agent_type=self.AGENT_TYPE,
                task=f"Pattern scan ({lookback_hours}h)",
                status="failed",
                summary=f"Scan failed: {e}",
                duration_ms=(time.time() - t0) * 1000,
                tool_calls_made=self._tool_calls,
            )


# ── Sub-Agent Manager ────────────────────────────────────────────────────────


class SubAgentManager:
    """Manages sub-agent lifecycle — spawn, track, collect results.

    IGRIS uses this to launch parallel investigations and collect findings.
    """

    AGENT_TYPES = {
        "threat_hunter": ThreatHunter,
        "incident_analyst": IncidentAnalyst,
        "pattern_scout": PatternScout,
    }

    def __init__(self, toolkit: IgrisToolkit):
        self.toolkit = toolkit
        self._active: Dict[str, threading.Thread] = {}
        self._results: Dict[str, SubAgentResult] = {}
        self._lock = threading.Lock()

    def spawn(
        self,
        agent_type: str,
        task: Dict[str, Any],
        blocking: bool = True,
    ) -> SubAgentResult:
        """Spawn a sub-agent to investigate a task.

        Args:
            agent_type: "threat_hunter" | "incident_analyst" | "pattern_scout"
            task: Task-specific parameters
            blocking: If True, wait for result. If False, return immediately.

        Returns:
            SubAgentResult (if blocking) or placeholder result (if async)
        """
        cls = self.AGENT_TYPES.get(agent_type)
        if cls is None:
            return SubAgentResult(
                agent_id="error",
                agent_type=agent_type,
                task=str(task),
                status="failed",
                summary=f"Unknown agent type: {agent_type}. "
                f"Available: {list(self.AGENT_TYPES.keys())}",
            )

        agent = cls(self.toolkit)

        if blocking:
            return agent.investigate(task)

        # Async: run in background thread
        def _run():
            result = agent.investigate(task)
            with self._lock:
                self._results[agent.agent_id] = result

        t = threading.Thread(
            target=_run, name=f"subagent-{agent.agent_id}", daemon=True
        )
        t.start()
        with self._lock:
            self._active[agent.agent_id] = t

        return SubAgentResult(
            agent_id=agent.agent_id,
            agent_type=agent_type,
            task=str(task),
            status="running",
            summary=f"Sub-agent {agent.agent_id} spawned — investigating",
        )

    def get_result(self, agent_id: str) -> Optional[SubAgentResult]:
        """Get result from a completed sub-agent."""
        with self._lock:
            return self._results.get(agent_id)

    def get_all_results(self) -> List[SubAgentResult]:
        """Get all completed sub-agent results."""
        with self._lock:
            return list(self._results.values())

    def spawn_parallel(
        self,
        tasks: List[Dict[str, Any]],
    ) -> List[SubAgentResult]:
        """Spawn multiple sub-agents in parallel and wait for all results.

        Each task dict must include "agent_type" and task-specific fields.
        """
        threads = []
        results = [None] * len(tasks)

        def _run(idx, agent_type, task):
            cls = self.AGENT_TYPES.get(agent_type)
            if cls:
                agent = cls(self.toolkit)
                results[idx] = agent.investigate(task)

        for i, task in enumerate(tasks):
            agent_type = task.pop("agent_type", "pattern_scout")
            t = threading.Thread(target=_run, args=(i, agent_type, task), daemon=True)
            t.start()
            threads.append(t)

        # Wait for all
        for t in threads:
            t.join(timeout=30)

        return [r for r in results if r is not None]
