"""
IGRIS Attack Story Narrator
=============================
Produces human-readable attack briefings from StoryEngine output.

Two modes:
  1. Template narration (default, free, instant) — for known attack patterns
  2. Claude API narration (premium, ~2s latency) — for novel/complex patterns

Install as: src/amoskys/igris/narrator.py

Usage:
    from amoskys.intel.story_engine import StoryEngine, AttackStory
    from amoskys.igris.narrator import Narrator

    engine = StoryEngine()
    stories = engine.build_stories(hours=1)
    narrator = Narrator()
    for story in stories:
        briefing = narrator.narrate(story)
        print(briefing.text)
        for action in briefing.recommended_actions:
            print(f"  - {action}")
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from amoskys.intel.story_engine import AttackStory

logger = logging.getLogger(__name__)


# ── Narration Output ────────────────────────────────────────────


@dataclass
class Briefing:
    """A narrated attack briefing."""

    story_id: str
    title: str  # e.g., "AMOS Stealer Kill Chain Detected"
    severity: str
    confidence: float
    text: str  # The narrative paragraph
    recommended_actions: List[str]  # Numbered action items
    kill_chain_summary: str  # e.g., "persistence → credential_access → exfiltration"
    technique_count: int
    event_count: int
    duration_display: str  # e.g., "2 minutes" or "47 seconds"
    source: str  # "template" or "claude"
    timestamp: float = field(default_factory=time.time)

    def to_terminal(self, colors: bool = True) -> str:
        """Format briefing for terminal display."""
        if colors:
            return self._colored()
        return self._plain()

    def _colored(self) -> str:
        R = "\033[0m"
        B = "\033[1m"
        D = "\033[2m"
        RED = "\033[91m"
        GRN = "\033[92m"
        YEL = "\033[93m"
        CYN = "\033[96m"
        WHT = "\033[97m"
        BG_R = "\033[41m"
        BG_B = "\033[44m"

        sev_c = {
            "critical": f"{BG_R}{WHT}{B}",
            "high": RED,
            "medium": YEL,
            "low": CYN,
        }.get(self.severity, D)

        lines = [
            "",
            f"  {BG_B}{WHT} IGRIS BRIEFING {R}  {sev_c}{self.severity.upper()}{R}  {B}{self.title}{R}",
            f"  {D}Confidence: {self.confidence:.0%} | {self.technique_count} techniques | "
            f"{self.event_count} events | {self.duration_display} | "
            f"Chain: {self.kill_chain_summary}{R}",
            f"  {D}{'─' * 64}{R}",
            "",
        ]

        # Wrap narrative text at ~70 chars
        words = self.text.split()
        line = "  "
        for word in words:
            if len(line) + len(word) > 72:
                lines.append(line)
                line = "  "
            line += word + " "
        if line.strip():
            lines.append(line)

        lines.append("")
        lines.append(f"  {B}Recommended Actions:{R}")
        for i, action in enumerate(self.recommended_actions, 1):
            lines.append(f"  {GRN}{i}.{R} {action}")

        lines.append(f"  {D}{'─' * 64}{R}")
        lines.append(f"  {D}[{self.source}] story={self.story_id}{R}")
        lines.append("")

        return "\n".join(lines)

    def _plain(self) -> str:
        lines = [
            f"=== IGRIS BRIEFING: {self.title} ===",
            f"Severity: {self.severity.upper()} | Confidence: {self.confidence:.0%}",
            f"Chain: {self.kill_chain_summary}",
            f"{self.technique_count} techniques, {self.event_count} events, {self.duration_display}",
            "",
            self.text,
            "",
            "Recommended Actions:",
        ]
        for i, action in enumerate(self.recommended_actions, 1):
            lines.append(f"  {i}. {action}")
        return "\n".join(lines)


# ── Narrator ────────────────────────────────────────────────────


class Narrator:
    """Produces human-readable briefings from AttackStory objects.

    Template mode (default): Instant, free, covers known patterns.
    Claude mode: Called for novel patterns or on explicit request.
    """

    def __init__(
        self,
        use_claude: bool = False,
        claude_model: str = "claude-sonnet-4-6",
        api_key: Optional[str] = None,
    ):
        self.use_claude = use_claude
        self.claude_model = claude_model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._claude_client = None

    def narrate(self, story: "AttackStory") -> Briefing:
        """Produce a briefing for an attack story.

        Uses templates for known patterns, falls back to Claude
        for novel patterns (if enabled).
        """
        # Try template first (always)
        if story.pattern_name:
            return self._narrate_template(story)

        # Novel pattern — try Claude if enabled
        if self.use_claude and self.api_key:
            try:
                return self._narrate_claude(story)
            except Exception as e:
                logger.warning(
                    "Claude narration failed: %s — falling back to template", e
                )

        # Generic template fallback
        return self._narrate_generic(story)

    # ── Template Narration ─────────────────────────────────────

    def _narrate_template(self, story: "AttackStory") -> Briefing:
        """Produce a briefing using a pre-written template."""
        pattern = story.pattern_name
        ctx = story.narrative_context

        title = f"{story.pattern_label} Detected"
        duration = self._format_duration(story.duration_seconds)
        chain_summary = " → ".join(story.stage_names)

        # Get pattern-specific narrative
        if pattern == "amos_stealer":
            text, actions = self._template_amos(story, ctx)
        elif pattern == "credential_harvest":
            text, actions = self._template_credential_harvest(story, ctx)
        elif pattern == "ssh_brute_force":
            text, actions = self._template_ssh_brute(story, ctx)
        elif pattern == "dns_c2":
            text, actions = self._template_dns_c2(story, ctx)
        elif pattern == "privilege_escalation":
            text, actions = self._template_privesc(story, ctx)
        elif pattern == "clickfix_stealer":
            text, actions = self._template_clickfix(story, ctx)
        elif pattern == "reverse_shell":
            text, actions = self._template_reverse_shell(story, ctx)
        else:
            text, actions = self._template_generic_body(story, ctx)

        return Briefing(
            story_id=story.story_id,
            title=title,
            severity=story.severity,
            confidence=story.confidence,
            text=text,
            recommended_actions=actions,
            kill_chain_summary=chain_summary,
            technique_count=len(story.techniques),
            event_count=story.raw_event_count,
            duration_display=duration,
            source="template",
        )

    def _template_amos(self, story, ctx) -> tuple:
        files = ctx.get("file_paths", [])
        plist = next((f for f in files if ".plist" in f), "a LaunchAgent plist")
        browser = "T1555.003" in story.techniques
        keychain = "T1555.001" in story.techniques
        cookies = "T1539" in story.techniques
        exfil = "T1041" in story.techniques

        parts = [f"An AMOS Stealer variant was detected on your Mac."]
        parts.append(
            f"A persistence mechanism was planted at {plist} — this runs automatically on every login."
        )

        stolen = []
        if keychain:
            stolen.append("Keychain passwords (security dump-keychain)")
        if browser:
            stolen.append("browser saved credentials (Chrome/Firefox/Safari)")
        if cookies:
            stolen.append("session cookies (can hijack your active logins)")
        if stolen:
            parts.append(f"The following were accessed: {'; '.join(stolen)}.")

        if exfil:
            parts.append("Data was staged and exfiltration was attempted via HTTP.")

        parts.append(
            f"This attack spanned {len(story.kill_chain)} kill chain stages over "
            f"{self._format_duration(story.duration_seconds)} with "
            f"{story.raw_event_count} related events."
        )

        actions = [
            (
                f"Remove the persistence plist: rm {plist}"
                if ".plist" in plist
                else "Check ~/Library/LaunchAgents/ for unknown plists"
            ),
            "Rotate ALL saved passwords immediately (Keychain + browser)",
            "Revoke active browser sessions (Google, GitHub, banking)",
            "Check ~/.ssh/authorized_keys for unauthorized entries",
            "Run: crontab -l to check for backdoor cron jobs",
            "Monitor for repeat execution via: PYTHONPATH=src python -m amoskys.daemon --interval 10 --respond",
        ]

        return " ".join(parts), actions

    def _template_credential_harvest(self, story, ctx) -> tuple:
        browser = "T1555.003" in story.techniques
        keychain = "T1555.001" in story.techniques
        cookies = "T1539" in story.techniques
        exfil = "T1041" in story.techniques

        parts = ["Credential harvesting activity was detected on your Mac."]

        stolen = []
        if browser:
            stolen.append("browser saved credentials (Chrome/Firefox/Safari)")
        if keychain:
            stolen.append("Keychain passwords")
        if cookies:
            stolen.append("session cookies")
        if not stolen:
            stolen.append("stored credentials")
        parts.append(f"The following were accessed: {'; '.join(stolen)}.")

        if exfil:
            parts.append("Exfiltration of the harvested credentials was attempted.")

        parts.append(
            f"This activity spanned {len(story.kill_chain)} stages over "
            f"{self._format_duration(story.duration_seconds)} with "
            f"{story.raw_event_count} correlated events."
        )

        actions = [
            "Rotate ALL saved passwords immediately (Keychain + browser)",
            "Revoke active browser sessions (Google, GitHub, banking)",
            "Check ~/Library/LaunchAgents/ for unauthorized persistence",
            "Review ~/.ssh/authorized_keys for unauthorized entries",
            "Run: crontab -l to check for backdoor cron jobs",
        ]

        return " ".join(parts), actions

    def _template_ssh_brute(self, story, ctx) -> tuple:
        ips = ctx.get("ips", ["unknown IP"])
        src_ip = ips[0] if ips else "unknown"

        text = (
            f"An SSH brute force attack from {src_ip} was detected. "
            f"Multiple authentication attempts were made against your Mac's SSH service. "
        )
        if "T1078" in story.techniques:
            text += "A successful login was achieved after the brute force phase. "
        if "T1543.001" in story.techniques:
            text += "Following access, persistence was installed via a LaunchAgent. "

        text += (
            f"This attack spanned {len(story.kill_chain)} stages over "
            f"{self._format_duration(story.duration_seconds)}."
        )

        actions = [
            f"Block source IP {src_ip} at your firewall or router",
            "Change the compromised account's password immediately",
            "Check ~/Library/LaunchAgents/ for newly added plists",
            "Review ~/.ssh/authorized_keys for unauthorized entries",
            "Consider disabling SSH: sudo systemsetup -setremotelogin off",
            "Enable key-only SSH authentication (disable password auth)",
        ]

        return text, actions

    def _template_dns_c2(self, story, ctx) -> tuple:
        domains = ctx.get("domains", [])
        domain_str = ", ".join(domains[:3]) if domains else "suspicious domains"

        text = (
            f"DNS-based command and control communication was detected. "
            f"Queries were observed to {domain_str} exhibiting patterns consistent with "
        )
        if "T1568.002" in story.techniques:
            text += "domain generation algorithms (DGA) — randomly generated domains used to evade blocking. "
        if "T1071.004" in story.techniques:
            text += "DNS tunneling — data encoded in DNS query labels for covert exfiltration. "
        if "T1572" in story.techniques:
            text += "protocol tunneling — non-DNS traffic encapsulated in DNS queries. "

        text += (
            f"This activity involved {story.raw_event_count} events over "
            f"{self._format_duration(story.duration_seconds)}."
        )

        actions = [
            "Identify which process is making the DNS queries (check lsof -i UDP:53)",
            "Block the identified domains at your DNS resolver",
            "If using DGA domains, the C2 infrastructure rotates — block the source process instead",
            "Check for persistence mechanisms that may restart the C2 client",
            "Consider network-level DNS filtering (Pi-hole, NextDNS, Cloudflare Gateway)",
        ]

        return text, actions

    def _template_privesc(self, story, ctx) -> tuple:
        text = "A privilege escalation and defense evasion sequence was detected. "
        if "T1548.003" in story.techniques:
            text += "Sudo was abused — possibly via sudoers modification for passwordless root access. "
        if "T1562.001" in story.techniques:
            text += "Security tools were disabled (Gatekeeper, firewall, or XProtect). "
        if "T1070.002" in story.techniques:
            text += "System logs were cleared to destroy forensic evidence. "
        if "T1564.001" in story.techniques:
            text += "Hidden files were created to conceal attacker tools. "

        text += (
            f"This sequence spanned {len(story.kill_chain)} stages with "
            f"{story.raw_event_count} events."
        )

        actions = [
            "Re-enable Gatekeeper: sudo spctl --master-enable",
            "Check sudoers for backdoors: sudo visudo and inspect /etc/sudoers.d/",
            "Verify SIP status: csrutil status",
            "Check for hidden files: ls -la /tmp/.* and find ~ -name '.*' -maxdepth 2",
            "Review system logs for gaps: log show --last 1h --predicate 'process == \"sudo\"'",
        ]

        return text, actions

    def _template_clickfix(self, story, ctx) -> tuple:
        text = (
            "A ClickFix-style social engineering attack was detected. This technique tricks "
            "users into pasting malicious commands into Terminal. An AppleScript-based fake "
            "password dialog was likely used to harvest your macOS login credentials. "
            "Once obtained, the credentials enable keychain access and privilege escalation."
        )

        actions = [
            "Change your macOS login password immediately",
            "Rotate all Keychain-stored credentials",
            "Check for unauthorized LaunchAgents and cron jobs",
            "Review Terminal history: cat ~/.zsh_history | tail -20",
            "Never paste commands from websites into Terminal unless you understand every character",
        ]

        return text, actions

    def _template_reverse_shell(self, story, ctx) -> tuple:
        ips = ctx.get("ips", [])
        text = (
            "A reverse shell was detected. A script was executed from a temporary directory "
            "that established an outbound connection to an attacker-controlled host"
        )
        if ips:
            text += f" ({ips[0]})"
        text += (
            ". Following access, system discovery commands were executed to fingerprint "
            "the target, and credential enumeration was attempted."
        )

        actions = [
            "Kill the shell process: find processes connecting to the attacker IP",
            "Check /tmp and /var/tmp for scripts: ls -la /tmp/.* /var/tmp/.*",
            "Block the outbound IP at your firewall",
            "Review browser credentials and rotate if accessed",
            "Check for persistence that may re-establish the shell on reboot",
        ]

        return text, actions

    # ── Generic Narration ──────────────────────────────────────

    def _narrate_generic(self, story: "AttackStory") -> Briefing:
        """Generic narration for unknown attack patterns."""
        title = "Attack Chain Detected"
        duration = self._format_duration(story.duration_seconds)
        chain_summary = " → ".join(story.stage_names)
        text, actions = self._template_generic_body(story, story.narrative_context)

        return Briefing(
            story_id=story.story_id,
            title=title,
            severity=story.severity,
            confidence=story.confidence,
            text=text,
            recommended_actions=actions,
            kill_chain_summary=chain_summary,
            technique_count=len(story.techniques),
            event_count=story.raw_event_count,
            duration_display=duration,
            source="template",
        )

    def _template_generic_body(self, story, ctx) -> tuple:
        stages = [s.stage.replace("_", " ") for s in story.kill_chain]
        tech_names = [
            story.narrative_context.get("technique_descriptions", {}).get(t, t)
            for t in story.techniques[:5]
        ]

        text = (
            f"An attack chain spanning {len(stages)} kill chain stages was detected: "
            f"{', '.join(stages)}. "
            f"Techniques observed include: {', '.join(tech_names)}. "
            f"A total of {story.raw_event_count} events were correlated across "
            f"{self._format_duration(story.duration_seconds)}."
        )

        assets = story.affected_assets[:5]
        if assets:
            text += f" Affected assets: {', '.join(assets)}."

        actions = [
            "Review the affected files and processes listed above",
            "Check ~/Library/LaunchAgents/ for unauthorized persistence",
            "Review ~/.ssh/authorized_keys for unauthorized entries",
            "Run crontab -l to check for backdoor cron jobs",
            "Rotate credentials for any accessed accounts",
        ]

        return text, actions

    # ── Claude API Narration ───────────────────────────────────

    def _narrate_claude(self, story: "AttackStory") -> Briefing:
        """Call Claude API to narrate a novel attack pattern."""
        if not self._claude_client:
            import anthropic

            self._claude_client = anthropic.Anthropic(api_key=self.api_key)

        ctx = story.narrative_context
        chain_summary = " → ".join(story.stage_names)

        prompt = self._build_claude_prompt(story, ctx)

        response = self._claude_client.messages.create(
            model=self.claude_model,
            max_tokens=800,
            system=(
                "You are IGRIS, the security intelligence of AMOSKYS endpoint security platform. "
                "You narrate attack stories for Mac users — be direct, forensic, and actionable. "
                "Write in plain English. No jargon unless necessary. "
                "Return a JSON object with two keys: "
                '"narrative" (string, 150-250 words) and '
                '"actions" (array of 4-6 short action strings).'
            ),
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse response
        raw = response.content[0].text
        try:
            parsed = json.loads(raw)
            text = parsed.get("narrative", raw)
            actions = parsed.get("actions", [])
        except (json.JSONDecodeError, TypeError):
            text = raw
            actions = [
                "Review all affected assets listed in the incident",
                "Check for persistence mechanisms",
                "Rotate compromised credentials",
                "Monitor for repeat activity",
            ]

        return Briefing(
            story_id=story.story_id,
            title=(
                f"{story.pattern_label} Detected"
                if story.pattern_label != "Unknown Attack Chain"
                else "Novel Attack Chain Detected"
            ),
            severity=story.severity,
            confidence=story.confidence,
            text=text,
            recommended_actions=actions,
            kill_chain_summary=chain_summary,
            technique_count=len(story.techniques),
            event_count=story.raw_event_count,
            duration_display=self._format_duration(story.duration_seconds),
            source="claude",
        )

    def _build_claude_prompt(self, story, ctx) -> str:
        """Build a focused prompt for Claude narration."""
        stages_text = ""
        for stage in ctx.get("stages", []):
            stages_text += (
                f"\n  Stage: {stage['name']}\n"
                f"  Techniques: {', '.join(stage['technique_names'])}\n"
                f"  Summary: {stage['summary']}\n"
                f"  Events: {stage['event_count']}, Duration: {stage['duration_seconds']:.0f}s\n"
            )

        assets = ctx.get("affected_assets", [])[:10]
        agents = ctx.get("contributing_agents", [])

        return f"""Narrate this attack story for a Mac user. Be specific about what was accessed and what to do.

ATTACK OVERVIEW:
  Severity: {story.severity}
  Confidence: {story.confidence:.0%}
  Duration: {self._format_duration(story.duration_seconds)}
  Total events: {story.raw_event_count}
  Kill chain: {' → '.join(story.stage_names)}

KILL CHAIN STAGES:
{stages_text}

AFFECTED ASSETS:
  {chr(10).join('  - ' + a for a in assets)}

TECHNIQUES: {', '.join(story.techniques)}

DETECTING AGENTS: {', '.join(agents)}

Return JSON with "narrative" (plain English, 150-250 words) and "actions" (4-6 specific remediation steps)."""

    # ── Helpers ─────────────────────────────────────────────────

    def _format_duration(self, seconds: float) -> str:
        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.0f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
