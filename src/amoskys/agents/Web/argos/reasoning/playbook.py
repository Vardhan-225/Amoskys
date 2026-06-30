"""The Argos engagement playbook.

An `EngagementState` tracks what we know about a target; a `Playbook`
contains PlaybookMoves ranked by preconditions. An agent (human or
LLM) calls `playbook.next_move(state)` to get a ranked list of moves
it can legally and ethically take, each with a mandate citation.

This is the "reasoning on top of tools" layer the operator requested.
It's deliberately declarative — no control flow, just data — so a
Claude instance driving Argos over MCP can reason with it like a
lookup table.

Stage boundary (hard)
─────────────────────
Moves are tagged with `stage: 1 | 2`. Stage 1 = no consent. Stage 2 =
requires a verified consent token (DNS TXT, customer dashboard, or
signed engagement letter). The playbook REFUSES to return Stage-2
moves unless the state carries `consent_verified = True`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional

# ── State ─────────────────────────────────────────────────────────


@dataclass
class EngagementState:
    """Everything known so far about one target."""

    target_host: str
    stage: Literal[1, 2] = 1
    consent_verified: bool = False
    # What we've already done
    moves_executed: List[str] = field(default_factory=list)
    # What we've learned
    has_robots_txt: Optional[bool] = None
    has_security_txt: Optional[bool] = None
    is_wordpress: Optional[bool] = None
    plugin_inventory: List[Dict[str, str]] = field(default_factory=list)  # [{slug,ver}]
    visible_usernames: List[str] = field(default_factory=list)
    exposed_dev_artifacts: List[str] = field(default_factory=list)
    # Friction signals from target
    got_rate_limited: bool = False
    got_permanent_block: bool = False
    # Operational
    http_request_budget_remaining: int = 500

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "stage": self.stage,
            "consent_verified": self.consent_verified,
            "moves_executed": self.moves_executed,
            "has_robots_txt": self.has_robots_txt,
            "has_security_txt": self.has_security_txt,
            "is_wordpress": self.is_wordpress,
            "plugin_count": len(self.plugin_inventory),
            "username_count": len(self.visible_usernames),
            "dev_artifact_count": len(self.exposed_dev_artifacts),
            "got_rate_limited": self.got_rate_limited,
            "got_permanent_block": self.got_permanent_block,
            "budget_remaining": self.http_request_budget_remaining,
        }


# ── Move ──────────────────────────────────────────────────────────


@dataclass
class PlaybookMove:
    move_id: str  # stable identifier
    stage: Literal[1, 2]
    title: str  # human-short
    description: str  # 1-3 sentence "what this move does"
    mandate: str  # why this move advances the engagement; research-backed
    tool_hint: str  # which MCP tool / module accomplishes this move
    request_cost: int  # typical HTTP request count
    # preconditions — all must be True given state; if any is False we skip this move
    preconditions: List[Callable[[EngagementState], bool]] = field(default_factory=list)
    # when should this move fire? higher priority = earlier
    priority: int = 50

    def can_run(self, state: EngagementState) -> bool:
        if self.stage == 2 and not state.consent_verified:
            return False
        if state.got_permanent_block:
            return False
        if self.move_id in state.moves_executed:
            return False
        if state.http_request_budget_remaining < self.request_cost:
            return False
        for p in self.preconditions:
            try:
                if not p(state):
                    return False
            except Exception:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "move_id": self.move_id,
            "stage": self.stage,
            "title": self.title,
            "description": self.description,
            "mandate": self.mandate,
            "tool_hint": self.tool_hint,
            "request_cost": self.request_cost,
            "priority": self.priority,
        }


# ── Playbook ──────────────────────────────────────────────────────


class Playbook:
    def __init__(self, moves: List[PlaybookMove]):
        self.moves = sorted(moves, key=lambda m: -m.priority)

    def next_move(self, state: EngagementState) -> Optional[PlaybookMove]:
        for m in self.moves:
            if m.can_run(state):
                return m
        return None

    def available_moves(self, state: EngagementState) -> List[PlaybookMove]:
        return [m for m in self.moves if m.can_run(state)]

    def as_dict(self, state: Optional[EngagementState] = None) -> Dict[str, Any]:
        """Flattened view for MCP consumption."""
        return {
            "state": state.to_dict() if state else None,
            "all_moves": [m.to_dict() for m in self.moves],
            "available_now": (
                [m.to_dict() for m in self.available_moves(state)] if state else []
            ),
        }


# ── Default playbook ──────────────────────────────────────────────


def default_playbook() -> Playbook:
    """The out-of-the-box engagement playbook — Stage 1 first, Stage 2
    only after consent_verified=True.
    """
    return Playbook(
        [
            # ── Stage 1 — no consent required ────────────────────────
            PlaybookMove(
                move_id="preflight.robots_and_security_txt",
                stage=1,
                title="Preflight — read robots.txt + security.txt",
                description=(
                    "Fetch the target's crawler policy and disclosure contact "
                    "before any other probe. Sets the ethical baseline: we "
                    "honor disallows and route findings to contact if present."
                ),
                mandate=(
                    "RFC 9309 (robots.txt) and RFC 9116 (security.txt) are the "
                    "standard contracts between sites and automated agents. "
                    "Starting any engagement without reading them is both rude "
                    "and unprofessional — and in most jurisdictions signals "
                    "lack of good-faith intent to judges and CFPB-adjacent "
                    "regulators."
                ),
                tool_hint="LegitimacyProfile.preflight(target_url)",
                request_cost=2,
                priority=100,
            ),
            PlaybookMove(
                move_id="recon.dns_and_tls",
                stage=1,
                title="DNS + TLS cert snapshot (passive)",
                description=(
                    "Resolve A/AAAA/MX/TXT records, collect TLS cert SANs and "
                    "issuer. All data already publicly served by nameservers "
                    "and TLS handshake — zero load on the target's webserver."
                ),
                mandate=(
                    "DNS and TLS are the authoritative public facts about any "
                    "domain — queryable from any resolver worldwide. Per ICANN "
                    "policy these records are explicitly public; CT logs (RFC "
                    "6962) require all publicly-trusted certs to be published. "
                    "Using them is equivalent to reading a phone book."
                ),
                tool_hint="argos.recon.dns_resolve + tls_cert + ct_logs",
                request_cost=0,  # not HTTP to target
                priority=95,
            ),
            PlaybookMove(
                move_id="recon.stealth_sweep",
                stage=1,
                title="Stealth browser sweep (7 categories)",
                description=(
                    "One polite HTTP-GET sweep across WP core fingerprints, "
                    "dev-artifact leaks, plugin inventory in HTML, infra "
                    "headers, user enumeration, and third-party script origins."
                ),
                mandate=(
                    "Each probe in this sweep is an HTTP GET to a path that any "
                    "curious visitor could request. CFAA §1030(a)(2)(C) "
                    "covers access to information beyond authorization — but "
                    "anything a webserver serves unauthenticated is by "
                    "definition within authorization. See also the 2021 Supreme "
                    "Court ruling in Van Buren v. United States narrowing "
                    "'exceeds authorized access' to explicit auth bypass."
                ),
                tool_hint="argos.recon.stealth.StealthRecon.run()",
                request_cost=25,
                priority=90,
            ),
            PlaybookMove(
                move_id="pitch.generate_report",
                stage=1,
                title="Generate PitchDossier + business-language report",
                description=(
                    "Convert technical findings into a prospect-ready HTML "
                    "report and first-touch email text. Output goes to sales/"
                    "outreach — NOT to the target site; zero additional HTTP."
                ),
                mandate=(
                    "The pitch is our ethical alternative to cold-scanning at "
                    "scale. Every contact includes the ROE transparency note: "
                    "'only information your site serves publicly.' This is "
                    "the same standard Have I Been Pwned and Shodan use, and "
                    "has stood legal scrutiny for 10+ years."
                ),
                tool_hint="argos.pitch.to_email_text + to_html_report",
                request_cost=0,
                priority=80,
                preconditions=[
                    lambda s: "recon.stealth_sweep" in s.moves_executed,
                ],
            ),
            # ── Stage 1 → Stage 2 transition ─────────────────────────
            # This is the gate move: verifying consent is what UNLOCKS
            # stage 2. The move itself is stage=1 (no consent required to
            # read public DNS) but its successful execution flips the
            # state's consent_verified bit.
            PlaybookMove(
                move_id="consent.verify_dns_txt",
                stage=1,
                title="Verify consent token via DNS TXT",
                description=(
                    "Look up _amoskys-consent.<domain>. Expects a TXT record "
                    "with a signed consent token tying this engagement to a "
                    "specific authorized scope + expiry. This is how Stage 2 "
                    "is unlocked."
                ),
                mandate=(
                    "DNS TXT is the simplest strong-authorization primitive: "
                    "only someone who controls the domain's nameservers can "
                    "set it. Same pattern used by ACME/Let's Encrypt DNS-01 "
                    "challenge, so it's familiar to any sysadmin. Signed "
                    "tokens prevent replay."
                ),
                tool_hint="argos.customer.verify_dns_consent(domain)",
                request_cost=0,
                priority=100,
                preconditions=[
                    # Only surface this move when the operator has set stage=2
                    # (intends to do a pentest). On a stage=1 pitch run we
                    # don't bother reading the consent record.
                    lambda s: s.stage
                    == 2,
                ],
            ),
            # ── Stage 2 — consent required ──────────────────────────
            PlaybookMove(
                move_id="scan.ast_plugin_inventory",
                stage=2,
                title="Download every installed plugin + run AST scanners",
                description=(
                    "Given the plugin inventory extracted from public HTML, "
                    "fetch each plugin's exact version from wp.org SVN and run "
                    "all 6 AST scanners (SQLi, file_upload, POI, CSRF, SSRF, "
                    "rest_authz) against the source. Zero traffic to target — "
                    "source comes from public wp.org."
                ),
                mandate=(
                    "Running static analysis against publicly-available plugin "
                    "source is research, not attack. wp.org explicitly publishes "
                    "this source under GPLv2 specifically to enable such review. "
                    "Every vuln we find is reportable either to wp.org's "
                    "plugin-review team or to the individual plugin author."
                ),
                tool_hint="argos.hunt.Hunt + argos.corpus.WPOrgCorpus",
                request_cost=0,  # zero HTTP to target
                priority=95,
                preconditions=[
                    lambda s: s.consent_verified,
                    lambda s: len(s.plugin_inventory) > 0,
                ],
            ),
            PlaybookMove(
                move_id="scan.live_cve_match",
                stage=2,
                title="Live CVE-match against installed plugin versions",
                description=(
                    "Cross-reference the plugin inventory with WPScan and "
                    "Patchstack CVE databases. No new HTTP requests to target — "
                    "uses the inventory we already have."
                ),
                mandate=(
                    "Database cross-references are public. We're connecting two "
                    "public facts (your plugin versions + published CVEs). The "
                    "act of connecting them is straightforward threat-modeling, "
                    "not offensive action."
                ),
                tool_hint="argos.tools.wpscan (version-match mode)",
                request_cost=0,
                priority=90,
                preconditions=[
                    lambda s: s.consent_verified,
                    lambda s: len(s.plugin_inventory) > 0,
                ],
            ),
            PlaybookMove(
                move_id="probe.nuclei_templates",
                stage=2,
                title="Nuclei template scan (rate-limited, consent-scoped)",
                description=(
                    "Run Nuclei with a WordPress-specific template set at 1 "
                    "request/second against the consented target. Templates "
                    "are community-curated CVE checks."
                ),
                mandate=(
                    "Nuclei templates are widely used in authorized pentests "
                    "and bug-bounty programs. The consent token caps the scope "
                    "(single domain, no subdomains unless explicitly included) "
                    "and the rate-limit keeps impact below 'one visitor' level."
                ),
                tool_hint="argos.tools.nuclei with --rate-limit 1",
                request_cost=200,
                priority=70,
                preconditions=[
                    lambda s: s.consent_verified,
                ],
            ),
            PlaybookMove(
                move_id="report.pentest_deliverable",
                stage=2,
                title="Generate PDF pentest report",
                description=(
                    "Aggregate Stage-1 + Stage-2 findings into a formal "
                    "pentest-report PDF — executive summary, per-finding "
                    "technical detail + reproduction steps + remediation, "
                    "CVSS scores. This is the customer deliverable."
                ),
                mandate=(
                    "The written report is the one artifact that legally "
                    "discharges our obligation to the customer. Every finding "
                    "is tagged with a CVE-ID or a novel-finding category so "
                    "the customer can submit to bounty if they wish."
                ),
                tool_hint="argos.report.PDFGenerator",
                request_cost=0,
                priority=20,
                preconditions=[
                    lambda s: s.consent_verified,
                    lambda s: "scan.ast_plugin_inventory" in s.moves_executed,
                ],
            ),
        ]
    )
