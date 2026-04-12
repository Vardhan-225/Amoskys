"""
Agent Mind — Per-agent Claude reasoning that activates on anomalies.

Each of the 17 macOS agents gets a Mind: a domain-specific Claude instance
that reasons about anomalies in its own territory. Minds are cheap (Haiku),
fast (1-3 tool calls max), and focused (domain-specific prompt + tools).

Architecture:
    ESF/Collector → Probes evaluate (microseconds)
                  → Normal? observation tier → SOMA baseline
                  → Anomaly? attack tier → AgentMind.on_anomaly()
                      → Claude reasons (Haiku, ~200ms)
                      → Consults other agents via MeshBus if needed
                      → Delivers verdict
                      → Escalates to IGRIS commander if warranted

Minds do NOT:
    - Run on every event (only on attack-tier anomalies)
    - Make cross-domain decisions (that's IGRIS commander)
    - Execute destructive actions (that requires IGRIS + confirmation)

Minds DO:
    - Reason about whether an anomaly is real or noise
    - Ask other agents questions via MeshBus
    - Self-calibrate their probes based on findings
    - Escalate corroborated threats to IGRIS commander
    - Remember what they've learned across restarts
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("agent.mind")


# ═══════════════════════════════════════════════════════════════════
# Data types
# ═══════════════════════════════════════════════════════════════════


@dataclass
class AgentVerdict:
    """Verdict from an agent mind's reasoning about an anomaly."""

    agent: str
    verdict: str  # "clean", "suspicious", "malicious"
    confidence: float  # 0.0 - 1.0
    reasoning: str
    escalate: bool = False
    probe_adjustment: Optional[Dict[str, str]] = None  # {probe, action, reason}
    consulted_agents: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    cost_usd: float = 0.0


@dataclass
class MeshQuestion:
    """Question from one agent mind to another via MeshBus."""

    source_agent: str
    target_agent: str
    question: str
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MeshAnswer:
    """Answer to a MeshQuestion."""

    agent: str
    answer: str
    data: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════
# Domain expertise prompts (one per agent type)
# ═══════════════════════════════════════════════════════════════════

DOMAIN_PROMPTS = {
    "auth": (
        "You are the authentication & credential expert. You understand SSH brute force, "
        "sudo escalation, impossible travel, credential dumping via Keychain/security CLI, "
        "TCC permission abuse, and off-hours login patterns on macOS. You know that "
        "every sudo for 'brew install' is normal but 'sudo rm -rf /etc/sudoers' is not."
    ),
    "network": (
        "You are the network flow expert. You understand C2 beaconing (interval + jitter), "
        "exfiltration spikes, lateral SSH movement, tunnel detection (TOR/VPN/chisel/ngrok), "
        "cleartext protocol risk, and unexpected listeners. You read lsof output like prose."
    ),
    "dns": (
        "You are the DNS intelligence expert. You understand DGA detection (entropy + "
        "consonant ratio), DNS tunneling (long labels, base64 encoding, TXT flood), "
        "beaconing patterns, cache poisoning, fast flux, and DoH evasion. You know that "
        "a domain with entropy 4.2 and consonant ratio 0.78 is almost certainly DGA."
    ),
    "process": (
        "You are the process behavior expert. You understand LOLBin abuse, process tree "
        "anomalies, masquerading (wrong exe path for known name), DYLD injection, "
        "unsigned binaries from /tmp, and suspicious parent-child chains on macOS."
    ),
    "filesystem": (
        "You are the file integrity expert. You understand SUID/SGID abuse, webshell "
        "deployment, SIP status, quarantine bypass (xattr removal), log tampering, "
        "hidden files in sensitive paths, and timestomping on macOS."
    ),
    "persistence": (
        "You are the persistence mechanism expert. You understand LaunchAgents, "
        "LaunchDaemons, cron jobs, shell profile injection, SSH authorized_keys, "
        "login items, folder actions, kernel extensions, and periodic scripts on macOS. "
        "You know every standard Apple plist and can spot an attacker's addition."
    ),
    "peripheral": (
        "You are the peripheral device expert. You understand USB device fingerprinting, "
        "Bluetooth device tracking, removable media monitoring, and BadUSB detection."
    ),
    "discovery": (
        "You are the network discovery expert. You understand ARP table analysis, "
        "MAC address vendor identification, rogue DHCP detection, Bonjour/mDNS service "
        "discovery, and port scanning patterns."
    ),
    "applog": (
        "You are the application log expert. You understand webshell access patterns, "
        "log tampering indicators, error rate spikes, credential harvesting in logs, "
        "and SQL injection signatures in web server logs."
    ),
    "internet_activity": (
        "You are the internet activity expert. You understand cloud exfiltration to "
        "S3/GCS/Azure, TOR/VPN usage, crypto mining connections, CDN masquerading "
        "for C2, and shadow IT detection."
    ),
    "infostealer_guard": (
        "You are the macOS infostealer expert. You understand AMOS, Poseidon, Banshee, "
        "and Lumma stealer families. You know the kill chain: fake password dialog via "
        "osascript, browser credential DB theft (Login Data, cookies.sqlite), crypto "
        "wallet theft, session cookie theft for MFA bypass, and SSH key exfiltration."
    ),
    "quarantine_guard": (
        "You are the Gatekeeper/quarantine expert. You understand quarantine xattr "
        "bypass (post-Sequoia delivery), ClickFix terminal paste attacks, DMG mount + "
        "execute chains, unsigned download execution, and installer script abuse."
    ),
    "provenance": (
        "You are the process provenance expert. You understand download-to-execute "
        "chains, browser-to-terminal pivots, message app to download delivery, "
        "and PID-to-network correlation for kill chain tracking."
    ),
    "correlation": (
        "You are the cross-agent correlation expert. You understand LOLBin + network "
        "confirmation, binary identity mismatch, persistence + execution chains, "
        "download-execute-persist patterns, and cumulative exfiltration tracking."
    ),
    "network_sentinel": (
        "You are the network threat detection expert. You understand HTTP scan storms, "
        "connection floods, attack tool fingerprinting (sqlmap, nikto, nmap), and "
        "web attack chains (recon -> exploit -> post-exploit)."
    ),
    "db_activity": (
        "You are the database security expert. You understand bulk extraction, "
        "privilege escalation queries, SQL injection patterns, credential queries, "
        "data destruction, and exfiltration via COPY/INTO OUTFILE."
    ),
    "http_inspector": (
        "You are the HTTP traffic expert. You understand XSS detection, SSRF, "
        "path traversal, API abuse, webshell upload, C2 over HTTP, cookie theft, "
        "and data exfiltration via POST payloads."
    ),
}


# ═══════════════════════════════════════════════════════════════════
# Agent Mind
# ═══════════════════════════════════════════════════════════════════


class AgentMind:
    """Claude-powered reasoning for a single agent domain.

    Activates ONLY when probes detect an attack-tier anomaly.
    Uses Haiku for fast, cheap per-event reasoning.
    """

    def __init__(
        self,
        agent_name: str,
        toolkit=None,
        mesh_bus=None,
        memory_db: str = None,
    ):
        self.agent_name = agent_name
        self.toolkit = toolkit
        self.mesh_bus = mesh_bus
        self.domain_prompt = DOMAIN_PROMPTS.get(agent_name, "")
        self._memory_db = memory_db or f"data/igris/minds/{agent_name}.db"
        self._backend = None
        self._init_memory()

    def _init_memory(self) -> None:
        """Initialize persistent memory for this mind."""
        db_path = Path(self._memory_db)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            conn = sqlite3.connect(str(db_path))
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS verdicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_ns INTEGER NOT NULL,
                    event_type TEXT,
                    verdict TEXT NOT NULL,
                    confidence REAL,
                    reasoning TEXT,
                    escalated BOOLEAN DEFAULT 0,
                    probe_adjustment TEXT
                )
            """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_key TEXT UNIQUE NOT NULL,
                    verdict TEXT NOT NULL,
                    times_seen INTEGER DEFAULT 1,
                    last_seen_ns INTEGER,
                    notes TEXT
                )
            """
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.warning("Mind %s memory init failed: %s", self.agent_name, e)

    def _get_backend(self):
        """Lazy-init the AgentMindBackend."""
        if self._backend is None:
            from amoskys.igris.backends import AgentMindBackend

            # Build domain-specific tools (subset of full toolkit)
            tools = []
            tool_executor = None
            if self.toolkit:
                tools = self._get_domain_tools()
                tool_executor = self.toolkit.execute

            self._backend = AgentMindBackend(
                agent_name=self.agent_name,
                domain_prompt=self.domain_prompt,
                tools=tools,
                tool_executor=tool_executor,
                max_turns=3,
            )
        return self._backend

    def _get_domain_tools(self) -> List[Dict[str, Any]]:
        """Get tools relevant to this agent's domain."""
        # Every mind gets posture + its own domain query
        all_tools = self.toolkit.get_tool_definitions()

        # Common tools every mind can use
        common = {
            "get_threat_posture",
            "query_security_events",
            "get_kill_chain_summary",
            "verify_code_signing",
        }

        # Domain-specific tools
        domain_tools = {
            "auth": {"query_auth_events"},
            "network": {"query_flow_events"},
            "dns": {"query_dns_events"},
            "process": {"query_process_events"},
            "filesystem": {"query_fim_events"},
            "persistence": {"query_persistence_events"},
            "peripheral": {"query_peripheral_events"},
        }

        allowed = common | domain_tools.get(self.agent_name, set())
        return [t for t in all_tools if t.get("name") in allowed]

    def on_anomaly(
        self,
        event_type: str,
        severity: str,
        confidence: float,
        description: str,
        data: Dict[str, Any],
    ) -> AgentVerdict:
        """Called when a probe fires an attack-tier event.

        Claude reasons about whether this is a real threat.
        Returns a verdict with confidence and optional escalation.
        """
        start = time.monotonic()

        # Check learned patterns first (skip Claude for known patterns)
        pattern_key = f"{event_type}:{data.get('exe', '')}:{data.get('remote_ip', '')}"
        learned = self._check_learned(pattern_key)
        if learned and learned["times_seen"] >= 3:
            elapsed = int((time.monotonic() - start) * 1000)
            return AgentVerdict(
                agent=self.agent_name,
                verdict=learned["verdict"],
                confidence=min(confidence, 0.95),
                reasoning=f"Known pattern (seen {learned['times_seen']}x): {learned.get('notes', '')}",
                escalate=learned["verdict"] == "malicious",
                duration_ms=elapsed,
            )

        # Build anomaly description for Claude
        anomaly_text = (
            f"ANOMALY DETECTED by {self.agent_name} agent\n"
            f"Event: {event_type}\n"
            f"Severity: {severity}\n"
            f"Probe confidence: {confidence}\n"
            f"Description: {description}\n"
            f"Data: {json.dumps(data, default=str)[:3000]}"
        )

        # Ask Claude
        backend = self._get_backend()
        result = backend.reason(anomaly_text)

        # Parse verdict from Claude's response
        verdict = self._parse_verdict(result.text)
        elapsed = int((time.monotonic() - start) * 1000)

        agent_verdict = AgentVerdict(
            agent=self.agent_name,
            verdict=verdict.get("verdict", "suspicious"),
            confidence=verdict.get("confidence", confidence),
            reasoning=verdict.get("reasoning", result.text[:500]),
            escalate=verdict.get("escalate", False),
            probe_adjustment=verdict.get("probe_adjustment"),
            duration_ms=elapsed,
            cost_usd=result.input_tokens * 1.0 / 1_000_000
            + result.output_tokens * 5.0 / 1_000_000,
        )

        # Record verdict and learn
        self._record_verdict(event_type, agent_verdict)
        self._learn_pattern(pattern_key, agent_verdict)

        return agent_verdict

    def consult(self, target_agent: str, question: str, context: Dict = None) -> str:
        """Ask another agent mind a question via MeshBus.

        Returns the other agent's answer as a string.
        """
        if not self.mesh_bus:
            return f"Cannot consult {target_agent}: no MeshBus configured"

        q = MeshQuestion(
            source_agent=self.agent_name,
            target_agent=target_agent,
            question=question,
            context=context or {},
        )

        try:
            answer = self.mesh_bus.ask(q)
            if isinstance(answer, MeshAnswer):
                return answer.answer
            return str(answer)
        except Exception as e:
            logger.warning(
                "Mind %s failed to consult %s: %s",
                self.agent_name,
                target_agent,
                e,
            )
            return f"Consultation failed: {e}"

    def _parse_verdict(self, text: str) -> Dict[str, Any]:
        """Parse Claude's verdict response (expects JSON)."""
        # Try to extract JSON from response
        try:
            # Look for JSON block in response
            if "{" in text:
                start = text.index("{")
                # Find matching closing brace
                depth = 0
                for i, ch in enumerate(text[start:], start):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            return json.loads(text[start : i + 1])
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: parse key terms from text
        text_lower = text.lower()
        if "malicious" in text_lower:
            return {"verdict": "malicious", "confidence": 0.8, "escalate": True, "reasoning": text[:300]}
        elif "clean" in text_lower or "benign" in text_lower or "legitimate" in text_lower:
            return {"verdict": "clean", "confidence": 0.7, "escalate": False, "reasoning": text[:300]}
        return {"verdict": "suspicious", "confidence": 0.6, "escalate": True, "reasoning": text[:300]}

    def _check_learned(self, pattern_key: str) -> Optional[Dict]:
        """Check if we've seen this pattern before."""
        try:
            conn = sqlite3.connect(self._memory_db)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM learned_patterns WHERE pattern_key = ?",
                (pattern_key,),
            ).fetchone()
            conn.close()
            return dict(row) if row else None
        except sqlite3.Error:
            return None

    def _learn_pattern(self, pattern_key: str, verdict: AgentVerdict) -> None:
        """Record pattern for future fast-path lookup."""
        try:
            conn = sqlite3.connect(self._memory_db)
            conn.execute(
                """
                INSERT INTO learned_patterns (pattern_key, verdict, last_seen_ns, notes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(pattern_key) DO UPDATE SET
                    times_seen = times_seen + 1,
                    last_seen_ns = excluded.last_seen_ns,
                    verdict = excluded.verdict
            """,
                (
                    pattern_key,
                    verdict.verdict,
                    int(time.time() * 1e9),
                    verdict.reasoning[:200],
                ),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.debug("Mind %s learn failed: %s", self.agent_name, e)

    def _record_verdict(self, event_type: str, verdict: AgentVerdict) -> None:
        """Record verdict for history and analysis."""
        try:
            conn = sqlite3.connect(self._memory_db)
            conn.execute(
                """
                INSERT INTO verdicts (timestamp_ns, event_type, verdict, confidence,
                    reasoning, escalated, probe_adjustment)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    int(time.time() * 1e9),
                    event_type,
                    verdict.verdict,
                    verdict.confidence,
                    verdict.reasoning[:500],
                    verdict.escalate,
                    json.dumps(verdict.probe_adjustment) if verdict.probe_adjustment else None,
                ),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.debug("Mind %s record failed: %s", self.agent_name, e)


# ═══════════════════════════════════════════════════════════════════
# Mind Registry — creates and manages all 17 agent minds
# ═══════════════════════════════════════════════════════════════════


class MindRegistry:
    """Registry of all agent minds. Creates on demand, caches instances."""

    def __init__(self, toolkit=None, mesh_bus=None):
        self.toolkit = toolkit
        self.mesh_bus = mesh_bus
        self._minds: Dict[str, AgentMind] = {}

    def get(self, agent_name: str) -> AgentMind:
        """Get or create an agent mind."""
        if agent_name not in self._minds:
            self._minds[agent_name] = AgentMind(
                agent_name=agent_name,
                toolkit=self.toolkit,
                mesh_bus=self.mesh_bus,
            )
        return self._minds[agent_name]

    def on_anomaly(
        self,
        agent_name: str,
        event_type: str,
        severity: str,
        confidence: float,
        description: str,
        data: Dict[str, Any],
    ) -> AgentVerdict:
        """Route an anomaly to the correct agent mind."""
        mind = self.get(agent_name)
        return mind.on_anomaly(event_type, severity, confidence, description, data)

    @property
    def active_minds(self) -> List[str]:
        """List of agent minds that have been activated."""
        return list(self._minds.keys())
