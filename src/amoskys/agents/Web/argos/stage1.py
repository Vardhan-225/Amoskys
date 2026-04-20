"""Argos Stage 1 — OSINT + Pitch generation (NO CONSENT REQUIRED).

The legal line
──────────────
Stage 1 does NOT require target consent because every technique it
uses is equivalent to what any anonymous visitor could do from a
browser. Specifically we limit ourselves to:

  - DNS resolution (public DNS answers)
  - Certificate Transparency log lookups (public indexes)
  - WHOIS (public registrar data)
  - A single polite browser visit to the site (what Safari would do
    when you type the domain)
  - One polite visit to /robots.txt and /.well-known/security.txt
  - A small curated set of public artifact checks
    (/readme.html, /wp-json/, <meta generator>, etc.) — each one
    individually is a normal browser fetch a user might do

This satisfies CFAA §1030(a)(2)(C) "authorized access" — we access
only what is publicly served without authentication bypass, and
without any request that could reasonably be mistaken for attack
tooling.

What Stage 1 explicitly will NOT do
────────────────────────────────────
  - Port-scan (beyond the standard HTTPS port)
  - Fuzz parameters
  - Submit any form (no POST, ever)
  - Try any input as an injection payload
  - Enumerate through `?author=N` with N>1 (we probe N=1 once; more
    than that is active enumeration with intent)
  - Request any `/.git/objects/...` tree traversal beyond confirming
    /.git/HEAD exists

Output
──────
`PitchDossier` — a business-language summary of what the target is
leaking. Meant to be the first email to a prospect: "here are 12
things about your WordPress site that any attacker can see. We
can show you the rest under consent."

Rate & ethics
─────────────
All HTTP requests go through the legitimacy layer — gaussian pacing,
sticky UA, robots-respected, retry-after-honored. A full Stage 1 run
against one target takes 2-5 minutes of wall time (this is
intentional). The per-request cost to the target is roughly the same
as one visitor clicking through half a dozen pages.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from amoskys.agents.Web.argos.legitimacy import (
    BackoffController,
    LegitimacyProfile,
    Pacer,
    UserAgentPool,
)
from amoskys.agents.Web.argos.recon.stealth import (
    StealthFinding,
    StealthRecon,
)

logger = logging.getLogger("amoskys.argos.stage1")


@dataclass
class PitchFinding:
    """One line-item for the pitch report, framed in business language."""

    category: str           # Infrastructure, Code, People, Supply Chain, Posture
    title: str              # business-language headline
    severity: str           # info | low | medium | high
    one_line_impact: str    # one sentence, non-technical — what it means for the owner
    evidence: str           # raw technical detail (for the PDF appendix)
    mandate: str            # research-backed "why this matters"
    references: List[str] = field(default_factory=list)


@dataclass
class PitchDossier:
    target_url:        str
    target_host:       str
    ran_at:            float
    duration_s:        float
    http_requests:     int
    aborted:           bool = False
    abort_reason:      Optional[str] = None
    # Findings, organized
    findings:          List[PitchFinding] = field(default_factory=list)
    # Raw sub-results (available for anyone who wants the technical detail)
    stealth_findings:  List[StealthFinding] = field(default_factory=list)
    robots_summary:    Optional[Dict[str, Any]] = None
    security_txt:      Optional[Dict[str, Any]] = None
    dns_summary:       Optional[Dict[str, Any]] = None
    # Operator guidance for the next step
    next_steps:        List[str] = field(default_factory=list)

    def severity_counts(self) -> Dict[str, int]:
        out = {"info": 0, "low": 0, "medium": 0, "high": 0}
        for f in self.findings:
            if f.severity in out:
                out[f.severity] += 1
        return out

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "target_url":  self.target_url,
            "target_host": self.target_host,
            "ran_at":      self.ran_at,
            "duration_s":  self.duration_s,
            "http_requests": self.http_requests,
            "aborted":     self.aborted,
            "abort_reason": self.abort_reason,
            "summary":     self.severity_counts(),
            "findings":    [asdict(f) for f in self.findings],
            "robots_summary": self.robots_summary,
            "security_txt":   self.security_txt,
            "dns_summary":    self.dns_summary,
            "next_steps":  self.next_steps,
        }, indent=indent, default=str)


# ── Orchestrator ──────────────────────────────────────────────────


class Stage1:
    """Run OSINT + pitch against one target. No consent needed."""

    def __init__(self, target_url: str,
                 legitimacy: Optional[LegitimacyProfile] = None,
                 dns_resolve=None):
        # Normalize target URL
        if "://" not in target_url:
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.target_url)
        self.host = parsed.netloc

        self.legitimacy = legitimacy or LegitimacyProfile()
        # Dependency-inject DNS resolver so tests don't need real network.
        # Real implementation lives in recon/dns_resolve.py
        self._dns_resolve = dns_resolve

    def run(self) -> PitchDossier:
        t0 = time.time()
        dossier = PitchDossier(
            target_url=self.target_url,
            target_host=self.host,
            ran_at=t0,
            duration_s=0.0,
            http_requests=0,
        )

        # 1. Preflight — fetch robots + security.txt (counts as 2 HTTP req).
        try:
            self.legitimacy.preflight(self.target_url)
            dossier.http_requests += 2
        except Exception as e:  # noqa: BLE001
            logger.warning("preflight failed: %s", e)

        # Store preflight summaries.
        if self.legitimacy.robots:
            dossier.robots_summary = {
                "has_robots_txt":   self.legitimacy.robots.raw is not None,
                "disallow_count":   len(self.legitimacy.robots.disallows_for_us),
                "disallowed_paths": self.legitimacy.robots.disallows_for_us[:20],
                "crawl_delay_s":    self.legitimacy.robots.crawl_delay_s,
                "sitemaps":         self.legitimacy.robots.sitemaps,
            }
        if self.legitimacy.security_txt:
            dossier.security_txt = {
                "contacts":           self.legitimacy.security_txt.contact,
                "canonical":          self.legitimacy.security_txt.canonical,
                "preferred_languages": self.legitimacy.security_txt.preferred_languages,
                "expires":            self.legitimacy.security_txt.expires,
            }

        # 2. DNS snapshot (passive).
        if self._dns_resolve:
            try:
                dns = self._dns_resolve(self.host)
                dossier.dns_summary = dns
            except Exception:
                pass

        # 3. Stealth recon (v1.2) — passes the legitimacy headers + pacing.
        stealth = StealthRecon(
            self.target_url,
            user_agent=self.legitimacy.ua_pool.identity().ua,
            polite=True,
        )
        try:
            stealth_dossier = stealth.run()
            dossier.stealth_findings = stealth_dossier.findings
            dossier.http_requests += stealth_dossier.http_checks
        except Exception as e:  # noqa: BLE001
            dossier.aborted = True
            dossier.abort_reason = f"stealth recon failed: {e}"
            dossier.duration_s = round(time.time() - t0, 2)
            return dossier

        # 4. Derive pitch-level findings from raw signals.
        self._derive_pitch_findings(dossier)

        # 5. Next-steps recommendations.
        dossier.next_steps = self._recommend_next_steps(dossier)

        dossier.duration_s = round(time.time() - t0, 2)
        return dossier

    # ── Pitch translation ──────────────────────────────────────────

    def _derive_pitch_findings(self, dossier: PitchDossier) -> None:
        """Re-frame technical stealth findings as business-language items."""
        # Group stealth findings by category for pitch purposes.
        by_cat: Dict[str, List[StealthFinding]] = {}
        for sf in dossier.stealth_findings:
            by_cat.setdefault(sf.category, []).append(sf)

        # wp_core + dev_leaks → "Information disclosure"
        disclosure = by_cat.get("wp_core", []) + by_cat.get("dev_leaks", [])
        if disclosure:
            # Pick a representative headline
            hi = sum(1 for x in disclosure if x.severity == "high")
            lo = sum(1 for x in disclosure if x.severity != "high")
            headline_sev = "high" if hi else ("medium" if lo >= 3 else "low")
            dossier.findings.append(PitchFinding(
                category="Information Disclosure",
                title=(
                    f"{len(disclosure)} public artifacts reveal your stack to "
                    "anyone who knows where to look."
                ),
                severity=headline_sev,
                one_line_impact=(
                    "These files tell a would-be attacker which WordPress "
                    "version you run, which plugins, and sometimes "
                    "credentials. They pick the fastest exploit from there."
                ),
                evidence="; ".join(
                    f"{x.check_id}={x.title}" for x in disclosure[:6]
                ),
                mandate=(
                    "Per WPScan quarterly reports and Wordfence incident "
                    "data, stack fingerprinting is the first step in 80%+ "
                    "of successful WordPress compromises. Each artifact "
                    "shortens the attacker's search from 'try everything' "
                    "to 'exploit this specific version'."
                ),
                references=[
                    "https://wpscan.com/blog/",
                    "https://www.wordfence.com/threat-intel/",
                ],
            ))

        # plugin_inventory → "Plugin exposure"
        if by_cat.get("plugin_inventory"):
            pi = by_cat["plugin_inventory"][0]
            dossier.findings.append(PitchFinding(
                category="Plugin Exposure",
                title="Your full plugin list and versions are visible to the public.",
                severity=pi.severity,
                one_line_impact=(
                    "A stranger can list every plugin and its exact version "
                    "without touching your admin area. Known-CVE matching "
                    "becomes trivial."
                ),
                evidence=pi.observed,
                mandate=(
                    "Public-HTML plugin inventory via `?ver=` strings is the "
                    "single most reliable plugin-fingerprint vector. Every "
                    "commercial vuln scanner — WPScan, Patchstack, Wordfence "
                    "Intel — treats it as the canonical identifier."
                ),
                references=[
                    "https://wpscan.com/",
                    "https://patchstack.com/database/",
                ],
            ))

        # infra → "Hosting posture"
        for i in by_cat.get("infra", []):
            dossier.findings.append(PitchFinding(
                category="Hosting Posture",
                title=i.title,
                severity=i.severity,
                one_line_impact=(
                    "Your hosting stack and CDN are identified from the "
                    "response headers — this tells attackers which CVE "
                    "class to probe next."
                ),
                evidence=i.observed,
                mandate=i.mandate,
                references=i.references,
            ))

        # user_enum → "Account exposure"
        if by_cat.get("user_enum"):
            ue = by_cat["user_enum"][0]
            dossier.findings.append(PitchFinding(
                category="Account Exposure",
                title="Administrator usernames are publicly listable.",
                severity="high" if any(x.severity == "high" for x in by_cat["user_enum"]) else "medium",
                one_line_impact=(
                    "Brute-force attacks become surgically targeted — the "
                    "attacker has half the login credential already."
                ),
                evidence="; ".join(x.observed for x in by_cat["user_enum"][:3]),
                mandate=ue.mandate,
                references=ue.references,
            ))

        # supply_chain → "Third-Party Surface"
        for sc in by_cat.get("supply_chain", []):
            dossier.findings.append(PitchFinding(
                category="Third-Party Surface",
                title=sc.title,
                severity=sc.severity,
                one_line_impact=(
                    "Every external script is a supply-chain dependency — "
                    "if the provider gets compromised, your visitors do too."
                ),
                evidence=sc.observed,
                mandate=sc.mandate,
                references=sc.references,
            ))

        # robots.txt intent leak
        if dossier.robots_summary and dossier.robots_summary.get("disallow_count", 0) > 0:
            disallowed = dossier.robots_summary["disallowed_paths"]
            dossier.findings.append(PitchFinding(
                category="Intent Leak",
                title="Your robots.txt tells attackers what you're hiding.",
                severity="info",
                one_line_impact=(
                    "Paths listed as 'Disallow' are essentially a to-do "
                    "list of interesting endpoints for anyone curious."
                ),
                evidence=f"Disallow directives: {disallowed}",
                mandate=(
                    "robots.txt is a crawler-etiquette file, not a "
                    "security boundary. Per RFC 9309, compliant bots "
                    "honor it — but attackers read it for reconnaissance. "
                    "Any path you care about enough to list here deserves "
                    "real authentication, not a crawler hint."
                ),
                references=[
                    "https://datatracker.ietf.org/doc/html/rfc9309",
                ],
            ))

        # Positive signal: security.txt exists
        if dossier.security_txt and dossier.security_txt.get("contacts"):
            dossier.findings.append(PitchFinding(
                category="Security Posture (positive)",
                title="You publish a security.txt — that puts you ahead of ~95% of sites.",
                severity="info",
                one_line_impact=(
                    "Having a published vulnerability-disclosure contact is "
                    "both a compliance signal and a sign of a mature posture."
                ),
                evidence=f"Contacts: {dossier.security_txt['contacts']}",
                mandate=(
                    "Per RFC 9116 (2022), publishing .well-known/security.txt "
                    "is the standard signal that an organization accepts "
                    "vulnerability reports. Most sites do not."
                ),
                references=["https://datatracker.ietf.org/doc/html/rfc9116"],
            ))

    # ── Next-step recommendations ──────────────────────────────────

    def _recommend_next_steps(self, dossier: PitchDossier) -> List[str]:
        """Produce 3-5 concrete next actions for the operator / sales flow."""
        steps = []
        counts = dossier.severity_counts()
        if counts["high"] >= 1:
            steps.append(
                f"Send pitch email highlighting the {counts['high']} high-severity "
                f"public exposures; offer a free live demo of Aegis blocking "
                f"an equivalent attack."
            )
        if dossier.security_txt and dossier.security_txt.get("contacts"):
            steps.append(
                f"Route any vuln findings to target's published "
                f"security.txt contact: {dossier.security_txt['contacts'][0]}"
            )
        # Plugin inventory → probable next targets for Stage 2
        plug_finding = next(
            (f for f in dossier.findings if f.category == "Plugin Exposure"), None,
        )
        if plug_finding:
            steps.append(
                "Request Stage-2 consent so Argos can run its AST scanners "
                "against the exact installed plugin versions — every CVE "
                "match converts to a bounty-submittable or customer-pitch "
                "finding."
            )
        if not steps:
            steps.append(
                "Target surface looks well-hardened — low-priority lead. "
                "Re-scan in 30 days; posture can drift with any plugin update."
            )
        return steps
