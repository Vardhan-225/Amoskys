"""
Explanation Engine — Human-Readable Analysis for Events, Incidents, and Agents

Generates structured explanations that answer:
  - Event:    "Why was this event flagged?"
  - Incident: "What happened and how confident are we?"
  - Agent:    "How reliable is this agent and is it drifting?"

Each explanation includes contributing factors, confidence breakdowns,
and actionable recommendations. Template-driven narratives use the
scoring engine's factor decomposition and AMRDR reliability data.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# MITRE tactic ID → human-readable kill chain phase
_TACTIC_PHASES = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
}

# Technique ID → (tactic, description) for narrative generation
_TECHNIQUE_CONTEXT = {
    "T1110": ("credential-access", "brute force authentication attempts"),
    "T1110.001": ("credential-access", "password guessing attacks"),
    "T1078": ("initial-access", "use of valid credentials from an external source"),
    "T1552": ("credential-access", "access to unsecured credential files"),
    "T1543.001": ("persistence", "installation of a macOS Launch Agent"),
    "T1543.004": ("persistence", "installation of a macOS Launch Daemon"),
    "T1053.003": ("persistence", "creation or modification of cron jobs"),
    "T1547.015": ("persistence", "modification of login items"),
    "T1548.003": ("privilege-escalation", "abuse of sudo privileges"),
    "T1548.001": ("privilege-escalation", "setuid/setgid bit manipulation"),
    "T1070.002": ("defense-evasion", "clearing of system logs"),
    "T1222": ("defense-evasion", "file or directory permission modifications"),
    "T1562.001": ("defense-evasion", "disabling or modifying security tools"),
    "T1071.004": ("command-and-control", "DNS-based command and control"),
    "T1071.001": ("command-and-control", "HTTP/S-based beaconing behavior"),
    "T1568.002": ("command-and-control", "domain generation algorithm activity"),
    "T1046": ("discovery", "network service scanning/enumeration"),
    "T1057": ("discovery", "process enumeration"),
    "T1059": ("execution", "use of command/scripting interpreters"),
    "T1059.004": ("execution", "reverse shell via Unix shell"),
    "T1005": ("collection", "access to sensitive local files"),
    "T1021.004": ("lateral-movement", "SSH-based lateral movement"),
    "T1048.003": ("exfiltration", "data exfiltration over DNS"),
    "T1200": ("initial-access", "hardware device insertion"),
    # Parent techniques for agents that emit sub-technique IDs
    "T1036": ("defense-evasion", "file or process name/location masquerading"),
    "T1036.005": ("defense-evasion", "match legitimate name or location to evade detection"),
    "T1547": ("persistence", "boot or logon autostart execution"),
    "T1547.001": ("persistence", "registry run keys or startup folder persistence"),
    "T1543": ("persistence", "creation or modification of system-level processes"),
    "T1053": ("persistence", "abuse of task scheduling for execution or persistence"),
    "T1204": ("execution", "user execution of malicious file or link"),
    "T1204.002": ("execution", "user opened a malicious file"),
    "T1218": ("defense-evasion", "system binary proxy execution to bypass controls"),
    "T1218.010": ("defense-evasion", "abuse of Regsvr32 for proxy execution"),
    "T1218.011": ("defense-evasion", "abuse of Rundll32 for proxy execution"),
    # Privilege escalation & defense evasion
    "T1548": ("privilege-escalation", "abuse of elevation control mechanism"),
    "T1134": ("privilege-escalation", "access token manipulation"),
    "T1068": ("privilege-escalation", "exploitation for privilege escalation"),
    "T1055": ("defense-evasion", "process injection for code execution in another process"),
    "T1027": ("defense-evasion", "obfuscated files or information to hinder analysis"),
    "T1070": ("defense-evasion", "indicator removal to cover tracks on host"),
    "T1070.004": ("defense-evasion", "file deletion to remove indicators"),
    "T1564": ("defense-evasion", "hide artifacts to evade detection"),
    "T1112": ("defense-evasion", "modification of registry keys for defense evasion"),
    "T1497": ("defense-evasion", "virtualization or sandbox evasion checks"),
    "T1014": ("defense-evasion", "rootkit to hide system activity"),
    # Credential access
    "T1003": ("credential-access", "OS credential dumping"),
    "T1003.001": ("credential-access", "LSASS memory credential extraction"),
    "T1556": ("credential-access", "modify authentication process"),
    "T1558": ("credential-access", "Kerberos ticket theft or forgery"),
    # Discovery
    "T1082": ("discovery", "system information discovery"),
    "T1016": ("discovery", "system network configuration discovery"),
    "T1049": ("discovery", "system network connections discovery"),
    "T1033": ("discovery", "system owner or user discovery"),
    "T1083": ("discovery", "file and directory discovery"),
    "T1087": ("discovery", "account discovery and enumeration"),
    "T1018": ("discovery", "remote system discovery"),
    "T1135": ("discovery", "network share discovery"),
    # Lateral movement
    "T1021": ("lateral-movement", "remote services used for lateral movement"),
    "T1021.001": ("lateral-movement", "RDP-based lateral movement"),
    "T1021.002": ("lateral-movement", "SMB/Windows Admin Shares lateral movement"),
    "T1570": ("lateral-movement", "lateral tool transfer between systems"),
    # Collection & exfiltration
    "T1056": ("collection", "input capture including keylogging"),
    "T1113": ("collection", "screen capture"),
    "T1119": ("collection", "automated data collection"),
    "T1560": ("collection", "data staged in archive for exfiltration"),
    "T1048": ("exfiltration", "exfiltration over alternative protocol"),
    "T1041": ("exfiltration", "exfiltration over C2 channel"),
    "T1567": ("exfiltration", "exfiltration over web service"),
    # Command and control
    "T1071": ("command-and-control", "application layer protocol for C2"),
    "T1105": ("command-and-control", "ingress tool transfer"),
    "T1090": ("command-and-control", "proxy usage for command and control"),
    "T1573": ("command-and-control", "encrypted channel for C2 communications"),
    "T1095": ("command-and-control", "non-application layer protocol for C2"),
    "T1572": ("command-and-control", "protocol tunneling for C2"),
    "T1568": ("command-and-control", "dynamic resolution for C2 infrastructure"),
    # Impact
    "T1486": ("impact", "data encrypted for impact (ransomware)"),
    "T1489": ("impact", "service stop to disrupt availability"),
    "T1529": ("impact", "system shutdown or reboot"),
    "T1485": ("impact", "data destruction"),
    "T1490": ("impact", "inhibit system recovery"),
    "T1499": ("impact", "endpoint denial of service"),
    # Initial access
    "T1190": ("initial-access", "exploitation of public-facing application"),
    "T1566": ("initial-access", "phishing delivery"),
    "T1566.001": ("initial-access", "spear-phishing with malicious attachment"),
    "T1133": ("initial-access", "external remote services access"),
    "T1195": ("initial-access", "supply chain compromise"),
    # Persistence extras
    "T1098": ("persistence", "account manipulation for persistence"),
    "T1136": ("persistence", "create account for persistent access"),
    "T1574": ("persistence", "hijack execution flow via DLL or path manipulation"),
    "T1546": ("persistence", "event-triggered execution"),
    "T1546.004": ("persistence", "Unix shell profile modification"),
}

# Rule name → narrative template
_RULE_NARRATIVES = {
    "ssh_brute_force": (
        "Between {start} and {end}, {event_count} failed SSH authentication "
        "attempts were detected from {source}. This pattern is consistent with "
        "a brute force attack targeting {target}."
    ),
    "persistence_chain": (
        "A persistence mechanism was installed on {device}: {detail}. "
        "This occurred {timing} and may indicate an attacker establishing "
        "a foothold for continued access."
    ),
    "suspicious_sudo": (
        "Suspicious sudo activity was detected on {device}: {detail}. "
        "The privilege escalation pattern suggests potential unauthorized "
        "administrative access."
    ),
    "multi_tactic_attack": (
        "A coordinated attack sequence was detected across {tactic_count} "
        "MITRE ATT&CK tactics on {device}. Events span from {start} to {end}, "
        "involving {agent_count} monitoring agents."
    ),
    "lateral_movement": (
        "Lateral movement was detected: SSH access from {source} to {device} "
        "following suspicious activity. This suggests an attacker is "
        "expanding their foothold within the network."
    ),
    "dns_exfiltration": (
        "Potential data exfiltration via DNS was detected from {device}. "
        "Anomalous DNS query patterns with high entropy domains suggest "
        "DNS tunneling or data staging."
    ),
}


class EventExplainer:
    """Generates human-readable explanations for individual security events.

    Uses the scoring engine's factor decomposition to explain why an event
    was classified as legitimate, suspicious, or malicious.
    """

    def explain_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Explain why a security event was classified the way it was.

        Args:
            event: Event dict with score_factors from ScoringEngine, or
                   raw event dict (explanation will be less detailed).

        Returns:
            Explanation dict with verdict, confidence, factors, MITRE context,
            and recommendation.
        """
        classification = event.get("final_classification", "legitimate")
        composite = event.get("composite_score", 0.0)
        factors = event.get("score_factors", [])
        mitre = event.get("mitre_techniques", [])
        if isinstance(mitre, str):
            try:
                import json

                mitre = json.loads(mitre)
            except (ValueError, TypeError):
                mitre = []

        # Build MITRE context string + structured technique detail
        mitre_context = self._build_mitre_context(mitre, event)
        mitre_detail = self._build_mitre_detail(mitre)

        # Determine recommendation
        recommendation = self._recommend(classification, composite, event)

        # If no factors from scoring engine, generate basic ones
        if not factors:
            factors = self._infer_factors(event)

        return {
            "verdict": classification,
            "confidence": (
                round(composite, 3)
                if composite
                else round(event.get("risk_score", 0.0) or 0.0, 3)
            ),
            "factors": factors,
            "mitre_context": mitre_context,
            "mitre_techniques_detail": mitre_detail,
            "recommendation": recommendation,
            "scores": {
                "geometric": event.get("geometric_score", 0.0),
                "temporal": event.get("temporal_score", 0.0),
                "behavioral": event.get("behavioral_score", 0.0),
                "composite": composite,
            },
        }

    def _build_mitre_detail(self, techniques: List[str]) -> List[Dict[str, str]]:
        """Build structured MITRE technique detail for rich UI rendering."""
        detail = []
        _TACTIC_DISPLAY = {
            "initial-access": "Initial Access",
            "execution": "Execution",
            "persistence": "Persistence",
            "privilege-escalation": "Privilege Escalation",
            "defense-evasion": "Defense Evasion",
            "credential-access": "Credential Access",
            "discovery": "Discovery",
            "lateral-movement": "Lateral Movement",
            "collection": "Collection",
            "exfiltration": "Exfiltration",
            "command-and-control": "Command & Control",
            "impact": "Impact",
        }
        for tid in techniques[:5]:
            ctx = _TECHNIQUE_CONTEXT.get(tid)
            if not ctx and "." in tid:
                # Fall back to parent technique (T1059.004 → T1059)
                ctx = _TECHNIQUE_CONTEXT.get(tid.split(".")[0])
            if ctx:
                tactic_slug, desc = ctx
                detail.append({
                    "id": tid,
                    "tactic": _TACTIC_DISPLAY.get(tactic_slug, tactic_slug),
                    "description": desc,
                })
            else:
                # Last resort: still provide the technique ID with generic label
                detail.append({"id": tid, "tactic": "ATT&CK Technique", "description": "MITRE ATT&CK technique " + tid})
        return detail

    def _build_mitre_context(self, techniques: List[str], event: Dict[str, Any]) -> str:
        """Build a contextual string from MITRE technique IDs."""
        if not techniques:
            return ""

        parts = []
        for tid in techniques[:3]:  # Cap at 3 for readability
            ctx = _TECHNIQUE_CONTEXT.get(tid)
            if ctx:
                parts.append(f"{tid} — {ctx[1]}")
            else:
                parts.append(tid)

        return "; ".join(parts)

    def _recommend(
        self, classification: str, confidence: float, event: Dict[str, Any]
    ) -> str:
        """Generate action recommendation based on classification."""
        if classification == "malicious" and confidence >= 0.8:
            return "investigate"
        if classification == "malicious":
            return "investigate"
        if classification == "suspicious":
            return "monitor"
        return "dismiss"

    def _infer_factors(self, event: Dict[str, Any]) -> List[Dict]:
        """Generate basic factors when score_factors is not available."""
        factors = []
        risk = event.get("risk_score", 0.0) or 0.0
        if risk >= 0.5:
            factors.append(
                {
                    "name": "Agent Risk Score",
                    "contribution": risk,
                    "detail": f"Agent reported risk score of {risk:.2f}",
                }
            )

        if event.get("requires_investigation"):
            factors.append(
                {
                    "name": "Investigation Flag",
                    "contribution": 0.15,
                    "detail": "Agent flagged this event for manual review",
                }
            )

        category = event.get("event_category", "")
        if category:
            factors.append(
                {
                    "name": "Event Category",
                    "contribution": 0.1,
                    "detail": f"Category: {category}",
                }
            )

        return factors


class IncidentExplainer:
    """Generates narrative explanations for correlated security incidents.

    Produces structured analysis including:
      - Natural language narrative of what happened
      - Kill chain phase identification
      - Confidence breakdown (rule + agent agreement + AMRDR)
      - True/false positive indicators
      - Contributing evidence summary
    """

    def explain_incident(
        self,
        incident: Dict[str, Any],
        events: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate a comprehensive incident explanation.

        Args:
            incident: Incident dict from FusionEngine.get_recent_incidents()
            events: Optional list of contributing event dicts for richer detail

        Returns:
            Explanation dict with narrative, kill chain phase,
            confidence breakdown, evidence, and TP/FP indicators.
        """
        rule_name = incident.get("rule_name", "unknown")
        severity = incident.get("severity", "MEDIUM")
        tactics = incident.get("tactics", [])
        techniques = incident.get("techniques", [])
        event_ids = incident.get("event_ids", [])
        # event_ids may arrive as a JSON string from the DB
        if isinstance(event_ids, str):
            try:
                event_ids = json.loads(event_ids)
            except (json.JSONDecodeError, TypeError):
                event_ids = []
        contributing_agents = incident.get("contributing_agents", [])
        agent_weights = incident.get("agent_weights", {})
        weighted_confidence = incident.get("weighted_confidence", 1.0)

        # Generate narrative
        narrative = self._build_narrative(incident, events)

        # Determine kill chain phase
        kill_chain = self._determine_kill_chain(tactics, techniques)

        # Build confidence breakdown
        confidence = self._build_confidence(
            incident, contributing_agents, agent_weights, weighted_confidence
        )

        # Build contributing evidence
        evidence = self._build_evidence(contributing_agents, agent_weights, events)

        # Generate TP/FP indicators
        tp_indicators, fp_indicators = self._analyze_indicators(incident, events)

        return {
            "narrative": narrative,
            "kill_chain_phase": kill_chain,
            "confidence_breakdown": confidence,
            "contributing_evidence": evidence,
            "true_positive_indicators": tp_indicators,
            "false_positive_indicators": fp_indicators,
        }

    def _build_narrative(
        self, incident: Dict[str, Any], events: Optional[List[Dict]] = None
    ) -> str:
        """Build a natural language narrative for the incident."""
        rule_name = incident.get("rule_name", "unknown")
        summary = incident.get("summary", "")
        device = incident.get("device_id", "unknown device")
        start = incident.get("start_ts", "")
        end = incident.get("end_ts", "")
        event_count = len(incident.get("event_ids", []))
        techniques = incident.get("techniques", [])

        # Try template-based narrative
        template = _RULE_NARRATIVES.get(rule_name)
        if template:
            # Extract source from events or metadata
            source = "an external source"
            if events:
                ips = set()
                for e in events:
                    ip = e.get("source_ip", "")
                    if isinstance(e.get("indicators"), dict):
                        ip = ip or e["indicators"].get("source_ip", "")
                    if ip:
                        ips.add(ip)
                if ips:
                    source = ", ".join(sorted(ips)[:3])

            try:
                return template.format(
                    start=self._fmt_time(start),
                    end=self._fmt_time(end),
                    event_count=event_count,
                    source=source,
                    device=device,
                    target=device,
                    detail=summary[:200],
                    timing=f"at {self._fmt_time(start)}",
                    tactic_count=len(incident.get("tactics", [])),
                    agent_count=len(incident.get("contributing_agents", [])),
                )
            except (KeyError, IndexError):
                pass

        # Fallback: generic narrative from summary
        tech_str = ""
        if techniques:
            contexts = []
            for t in techniques[:3]:
                ctx = _TECHNIQUE_CONTEXT.get(t)
                if ctx:
                    contexts.append(ctx[1])
            if contexts:
                tech_str = f" Techniques observed: {', '.join(contexts)}."

        return (
            f"On {device}, {summary or 'a security incident was detected'}. "
            f"{event_count} events were correlated between "
            f"{self._fmt_time(start)} and {self._fmt_time(end)}.{tech_str}"
        )

    def _determine_kill_chain(self, tactics: List[str], techniques: List[str]) -> str:
        """Map tactics/techniques to kill chain phase."""
        # Check tactics first
        for tactic in tactics:
            phase = _TACTIC_PHASES.get(tactic)
            if phase:
                return phase

        # Fall back to technique → tactic mapping
        for tech in techniques:
            ctx = _TECHNIQUE_CONTEXT.get(tech)
            if ctx:
                return ctx[0]

        return "unknown"

    def _build_confidence(
        self,
        incident: Dict[str, Any],
        agents: List[str],
        weights: Dict[str, float],
        weighted_conf: float,
    ) -> Dict[str, Any]:
        """Build confidence breakdown."""
        # Rule confidence: based on severity
        severity = incident.get("severity", "MEDIUM").upper()
        rule_conf = {
            "CRITICAL": 0.95,
            "HIGH": 0.85,
            "MEDIUM": 0.70,
            "LOW": 0.50,
            "INFO": 0.30,
        }.get(severity, 0.50)

        # Agent agreement: what fraction of agents contributed
        agent_agreement = 1.0
        if agents and weights:
            # Agreement = average weight of contributing agents
            w_values = [weights.get(a, 1.0) for a in agents]
            agent_agreement = sum(w_values) / len(w_values) if w_values else 1.0

        # Composite
        composite = round(
            0.4 * rule_conf + 0.3 * agent_agreement + 0.3 * weighted_conf, 3
        )

        return {
            "rule_confidence": round(rule_conf, 3),
            "agent_agreement": round(agent_agreement, 3),
            "amrdr_weight": round(weighted_conf, 3),
            "composite": composite,
        }

    def _build_evidence(
        self,
        agents: List[str],
        weights: Dict[str, float],
        events: Optional[List[Dict]] = None,
    ) -> List[Dict[str, Any]]:
        """Build contributing evidence list per agent."""
        evidence = []
        for agent in agents:
            entry = {
                "agent": agent,
                "weight": round(weights.get(agent, 1.0), 3),
            }
            if events:
                # Count events from this agent
                count = sum(1 for e in events if e.get("collection_agent") == agent)
                entry["events"] = count
            evidence.append(entry)

        # Sort by weight descending
        evidence.sort(key=lambda x: x["weight"], reverse=True)
        return evidence

    def _analyze_indicators(
        self,
        incident: Dict[str, Any],
        events: Optional[List[Dict]] = None,
    ) -> tuple:
        """Generate true-positive and false-positive indicator lists."""
        tp = []
        fp = []

        severity = incident.get("severity", "").upper()
        event_count = len(incident.get("event_ids", []))
        techniques = incident.get("techniques", [])
        agents = incident.get("contributing_agents", [])
        weighted_conf = incident.get("weighted_confidence", 1.0)

        # TP indicators
        if event_count > 10:
            tp.append(f"{event_count} correlated events exceed normal threshold")
        if len(agents) > 1:
            tp.append(f"Corroborated by {len(agents)} independent agents")
        if len(techniques) > 1:
            tp.append(f"Multiple MITRE techniques matched ({len(techniques)})")
        if severity in ("CRITICAL", "HIGH"):
            tp.append(f"Severity assessed as {severity}")
        if weighted_conf >= 0.8:
            tp.append(f"High AMRDR-weighted confidence ({weighted_conf:.2f})")

        # FP indicators
        if event_count <= 3:
            fp.append(f"Only {event_count} events — may be coincidental")
        if len(agents) == 1:
            fp.append("Single agent detection — no independent corroboration")
        if weighted_conf < 0.5:
            fp.append(
                f"Low AMRDR confidence ({weighted_conf:.2f}) — agent may be unreliable"
            )

        # Ensure at least one indicator in each category
        if not tp:
            tp.append("Detection matched established correlation rule")
        if not fp:
            fp.append("No false positive indicators identified")

        return tp, fp

    def _fmt_time(self, ts: Any) -> str:
        """Format a timestamp for narrative display."""
        if not ts:
            return "an unknown time"
        if isinstance(ts, datetime):
            return ts.strftime("%H:%M UTC on %Y-%m-%d")
        ts_str = str(ts)
        if "T" in ts_str:
            return ts_str.replace("T", " ").split(".")[0] + " UTC"
        return ts_str


class AgentExplainer:
    """Explains agent reliability state from AMRDR tracking."""

    def explain_agent(self, agent_id: str, state: Any) -> Dict[str, Any]:
        """Generate agent reliability explanation.

        Args:
            agent_id: Agent identifier.
            state: ReliabilityState dataclass from BayesianReliabilityTracker.

        Returns:
            Explanation dict with reliability score, tier, drift status,
            and trend assessment.
        """
        alpha = getattr(state, "alpha", 1.0)
        beta = getattr(state, "beta", 1.0)
        reliability = getattr(state, "reliability_score", 0.5)
        tier = getattr(state, "tier", None)
        tier_name = tier.name if tier else "NOMINAL"
        drift = getattr(state, "drift_type", None)
        drift_name = drift.name if drift else "NONE"
        weight = getattr(state, "fusion_weight", 1.0)

        # Calculate observation counts
        confirmed = int(alpha - 1)  # Subtract prior
        dismissed = int(beta - 1)
        total = confirmed + dismissed
        history = f"{total} observations: {confirmed} confirmed, {dismissed} dismissed"

        # Assess trend
        if total < 10:
            trend = "insufficient-data"
        elif reliability >= 0.85:
            trend = "stable" if drift_name == "NONE" else "degrading"
        elif reliability >= 0.6:
            trend = "degrading" if drift_name != "NONE" else "stable"
        else:
            trend = "degrading"

        # Drift description
        drift_desc = {
            "NONE": "No drift detected — agent performance is consistent",
            "ABRUPT": "Abrupt drift detected — sudden change in agent accuracy",
            "GRADUAL": "Gradual drift detected — slow degradation in accuracy",
        }.get(drift_name, "Unknown drift status")

        return {
            "agent_id": agent_id,
            "reliability": round(reliability, 3),
            "tier": tier_name,
            "fusion_weight": round(weight, 3),
            "history": history,
            "drift_status": drift_desc,
            "trend": trend,
            "observations": {
                "total": total,
                "confirmed": confirmed,
                "dismissed": dismissed,
            },
        }
