"""Campaign orchestrator — the master kill chain.

Runs every Argos module in the correct order against one target,
emitting events throughout so a UI can render real-time progress.

Stages
------
  consent         verify authorization for the target domain
  recon           DNS + WHOIS + robots.txt + sitemap (passive)
  fingerprint     architecture profile (CDN/WAF/origin/runtime/DB/OS)
  strategy        select tactics tuned to the profile
  origin_bypass   discover + confirm origin IP (only if CDN fronted)
  smuggle         HTTP request smuggling detection (only if consent ≥ confirm)
  auth_probe      JWT / session / rate-limit checks (only if endpoints exist)
  zeroday         AST + taint + fuzzer + polyglot (only if plugin dir given)
  precision       adaptive precision probes (only consent ≥ exploit)
  chain           exploit-chain reasoner
  report          render final artifacts

Modes gate stages. "report" runs consent→recon→fingerprint→strategy
→origin_bypass→chain→report (all non-invasive). "confirm" adds
smuggle + stealth probes. "exploit" adds auth_probe, precision, and
any finding-specific replay.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from amoskys.agents.Web.argos.adapt import (
    ArchitectureProfile, fingerprint_architecture,
    AdaptedStrategy, pick_strategy,
    OriginCandidate, discover_origin,
)
from amoskys.agents.Web.argos.auth import (
    scan_jwt, bypass_case_variation,
)
from amoskys.agents.Web.argos.campaign.events import EventBus, EventKind
from amoskys.agents.Web.argos.chain import (
    ChainFinding, reason_chains, ExploitChain,
    reason_graph,
)
from amoskys.agents.Web.argos.smuggle import detect_smuggling
from amoskys.agents.Web.argos.campaign.wp_probe import run_wp_probe
from amoskys.agents.Web.argos.zeroday import (
    HIDDEN_PARAM_WORDLIST, discover_hidden_params,
)

logger = logging.getLogger("amoskys.argos.campaign.orchestrator")


class CampaignMode:
    REPORT  = "report"      # OSINT + passive only — any domain
    CONFIRM = "confirm"     # + low-volume probes — consent advised
    EXPLOIT = "exploit"     # + active exploitation — written authorization required


# ── Data model ────────────────────────────────────────────────────


@dataclass
class CampaignReport:
    target_url: str
    target_host: str
    mode: str
    started_at: float
    finished_at: float = 0.0
    profile: Optional[Dict[str, Any]] = None
    strategy: Optional[Dict[str, Any]] = None
    origin_candidates: List[Dict[str, Any]] = field(default_factory=list)
    smuggle_report: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    chains: List[Dict[str, Any]] = field(default_factory=list)
    max_severity: str = "low"
    events: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    consent_verified: bool = False
    consent_method: str = "none"
    graph: Optional[Dict[str, Any]] = None   # graph reasoner extras

    def to_dict(self):
        return {
            "target_url":        self.target_url,
            "target_host":       self.target_host,
            "mode":              self.mode,
            "started_at":        self.started_at,
            "finished_at":       self.finished_at,
            "duration_s":        max(0.0, self.finished_at - self.started_at),
            "profile":           self.profile,
            "strategy":          self.strategy,
            "origin_candidates": list(self.origin_candidates),
            "smuggle_report":    self.smuggle_report,
            "findings":          list(self.findings),
            "chains":            list(self.chains),
            "max_severity":      self.max_severity,
            "events":            list(self.events),
            "errors":            list(self.errors),
            "consent_verified":  self.consent_verified,
            "consent_method":    self.consent_method,
            "graph":             self.graph,
        }


# ── Campaign runner ───────────────────────────────────────────────


class Campaign:
    """Run a full Argos kill chain with live event streaming."""

    def __init__(self, target_url: str, mode: str = CampaignMode.REPORT,
                 consent_token: Optional[str] = None,
                 bus: Optional[EventBus] = None,
                 http_get: Optional[Callable] = None,
                 smuggle_sender: Optional[Callable] = None,
                 plugin_source_dir: Optional[str] = None,
                 precision_sender: Optional[Callable] = None,
                 prebuilt_findings: Optional[List[ChainFinding]] = None):
        """
        target_url         : fully-qualified https://host URL
        mode               : one of CampaignMode.*
        consent_token      : operator-supplied evidence of authorization
                             (signed token, bug-bounty scope string,
                             "bounty:<program>", or "AMOSKYS_CONSENT_DOMAIN")
        bus                : EventBus for live events (web UI subscribes here)
        http_get           : injectable HTTP client for fingerprint + origin
                             signature http_get(url, timeout, headers) -> (status, headers, body)
        smuggle_sender     : injectable raw-socket sender for smuggle detect
        plugin_source_dir  : path to local plugin source, enables zeroday/TOCTOU
        precision_sender   : injectable for precision probes in EXPLOIT mode
        prebuilt_findings  : optional pre-collected findings (AST scanner run
                             externally). Chains over these regardless of mode.
        """
        self.target_url = target_url.rstrip("/")
        self.mode = mode
        self.consent_token = consent_token
        self.bus = bus or EventBus()
        self.http_get = http_get
        self.smuggle_sender = smuggle_sender
        self.plugin_source_dir = plugin_source_dir
        self.precision_sender = precision_sender
        self.prebuilt_findings = list(prebuilt_findings or [])

        parsed = urllib.parse.urlparse(self.target_url)
        self.target_host = parsed.hostname or self.target_url
        self._report = CampaignReport(
            target_url=self.target_url,
            target_host=self.target_host,
            mode=self.mode,
            started_at=time.time(),
        )

    # ── Consent gate ----------------------------------------------

    def _verify_consent(self) -> bool:
        """Check the operator is authorized to attack this domain.

        Accepts any of:
          - AMOSKYS_CONSENT_DOMAIN env matching target host (lab work)
          - consent_token starting with "bounty:" (bug-bounty scope self-attest)
          - consent_token starting with "sow:" (signed statement of work)
          - target host == "localhost" or "127.*" (local dev)
          - CampaignMode.REPORT — no consent required (OSINT only)
        """
        stage = "consent"
        self.bus.stage_start(stage, f"verifying authorization for {self.target_host}",
                              mode=self.mode)
        if self.mode == CampaignMode.REPORT:
            self._report.consent_verified = True
            self._report.consent_method = "report-mode-no-consent-required"
            self.bus.stage_end(stage, "report mode — OSINT-only, no consent gate")
            return True

        host = self.target_host.lower()
        if host in ("localhost", "127.0.0.1") or host.startswith("127."):
            self._report.consent_verified = True
            self._report.consent_method = "localhost"
            self.bus.stage_end(stage, "localhost — implicit consent")
            return True

        env_domain = os.environ.get("AMOSKYS_CONSENT_DOMAIN", "").strip().lower()
        if env_domain and (host == env_domain or host.endswith("." + env_domain)):
            self._report.consent_verified = True
            self._report.consent_method = f"env:AMOSKYS_CONSENT_DOMAIN={env_domain}"
            self.bus.stage_end(stage, f"consent via env match: {env_domain}")
            return True

        token = (self.consent_token or "").strip()
        if token.startswith("bounty:"):
            self._report.consent_verified = True
            self._report.consent_method = token
            self.bus.stage_end(
                stage, f"consent via bug-bounty scope: {token}",
                note="operator self-attests target is in a public bug-bounty scope")
            return True
        if token.startswith("sow:"):
            self._report.consent_verified = True
            self._report.consent_method = token
            self.bus.stage_end(stage, f"consent via SOW: {token}")
            return True
        if token.startswith("dev:"):
            self._report.consent_verified = True
            self._report.consent_method = token
            self.bus.stage_end(
                stage, f"consent via dev-mode token: {token}",
                note="dev/test run — production deployments require a real consent token")
            return True

        self._report.consent_verified = False
        self._report.consent_method = "NONE"
        self.bus.fatal(
            stage,
            f"NO CONSENT for {host}. Mode={self.mode} requires authorization. "
            f"Set AMOSKYS_CONSENT_DOMAIN=<host>, pass consent_token='bounty:<program>', "
            f"or run in mode='report' (OSINT only).",
        )
        self._report.errors.append("consent verification failed")
        return False

    # ── Passive recon --------------------------------------------

    def _passive_recon(self):
        stage = "recon"
        self.bus.stage_start(stage, "DNS + robots + OSINT")
        items = {
            "robots_txt":    f"{self.target_url}/robots.txt",
            "sitemap_xml":   f"{self.target_url}/sitemap.xml",
            "humans_txt":    f"{self.target_url}/humans.txt",
            "security_txt":  f"{self.target_url}/.well-known/security.txt",
        }
        found: Dict[str, str] = {}
        if self.http_get is not None:
            for name, url in items.items():
                try:
                    status, _h, body = self.http_get(url, 8.0, {})
                    if status == 200 and body:
                        snippet = body[:200].replace("\n", " ")
                        found[name] = snippet
                        self.bus.evidence(stage, f"{name}: {snippet[:80]}", url=url, status=status)
                except Exception as exc:  # noqa: BLE001
                    self.bus.log(stage, f"{name} fetch failed: {exc}")
                self.bus.progress(stage, len(found), len(items))
        else:
            self.bus.log(stage, "http_get not provided — skipping recon fetches")
        self.bus.stage_end(stage, f"{len(found)} assets collected", items=found)
        return found

    # ── Architecture fingerprint ---------------------------------

    def _fingerprint(self) -> ArchitectureProfile:
        stage = "fingerprint"
        self.bus.stage_start(stage, "probing CDN/WAF/origin/runtime/DB/OS/framework")
        try:
            profile = fingerprint_architecture(self.target_url, http_get=self.http_get)
        except Exception as exc:  # noqa: BLE001
            self.bus.error(stage, f"fingerprint failed: {exc}")
            self._report.errors.append(f"fingerprint: {exc}")
            profile = ArchitectureProfile(target_url=self.target_url,
                                           target_host=self.target_host)
        # Emit per-layer evidence
        if profile.cdn_name:
            self.bus.evidence(stage, f"CDN: {profile.cdn_name} (conf={profile.cdn_confidence})")
        if profile.waf_names:
            self.bus.evidence(stage, f"WAF: {', '.join(profile.waf_names)}")
        if profile.origin_server:
            self.bus.evidence(stage, f"Origin server: {profile.origin_server} {profile.origin_version or ''}")
        if profile.runtime:
            self.bus.evidence(stage, f"Runtime: {profile.runtime} {profile.runtime_version or ''}")
        if profile.database:
            self.bus.evidence(stage, f"Database: {profile.database}")
        if profile.os_family:
            self.bus.evidence(stage, f"OS: {profile.os_family}")
        if profile.framework:
            self.bus.evidence(stage, f"Framework: {profile.framework} {profile.framework_version or ''}")
        if profile.debug_mode or profile.verbose_errors:
            self.bus.finding(stage, "verbose_errors", self.target_url, "low",
                             "Target leaks debug info / stack traces")
        self._report.profile = profile.to_dict()
        self.bus.stage_end(stage,
            f"profiled in {profile.fingerprint_time_ms}ms "
            f"({profile.http_requests_used} reqs)")
        return profile

    # ── Strategy selection ---------------------------------------

    def _strategy(self, profile: ArchitectureProfile) -> AdaptedStrategy:
        stage = "strategy"
        self.bus.stage_start(stage, "picking tactics tuned to observed architecture")
        try:
            strategy = pick_strategy(profile)
        except Exception as exc:  # noqa: BLE001
            self.bus.error(stage, f"pick_strategy failed: {exc}")
            strategy = AdaptedStrategy(profile_target=self.target_url)
        for note in strategy.notes:
            self.bus.decision(stage, note)
        self.bus.decision(stage, f"probe_order={strategy.probe_order[:6]}")
        self.bus.decision(stage, f"encoding_cascade={strategy.encoding_cascade}")
        self.bus.decision(stage, f"rps_ceiling={strategy.rps_ceiling}")
        if strategy.origin_bypass:
            self.bus.decision(stage, "origin_bypass enabled — will run discover_origin")
        self._report.strategy = strategy.to_dict()
        self.bus.stage_end(stage, "strategy locked")
        return strategy

    # ── Origin bypass --------------------------------------------

    def _origin_bypass(self, strategy: AdaptedStrategy):
        if not strategy.origin_bypass:
            return
        stage = "origin_bypass"
        self.bus.stage_start(stage, "discovering direct origin IP behind CDN")
        try:
            cands = discover_origin(self.target_host, http_get=self.http_get)
        except Exception as exc:  # noqa: BLE001
            self.bus.error(stage, f"discover_origin failed: {exc}")
            self._report.errors.append(f"origin_bypass: {exc}")
            cands = []
        for c in cands[:5]:
            label = f"{c.ip} ({c.source}, conf={c.confidence})"
            if c.confirmed:
                self.bus.finding(stage, "cdn_bypass", c.ip, "high",
                                 f"origin IP confirmed: {c.ip} via {c.source}")
            else:
                self.bus.evidence(stage, f"candidate: {label}")
        self._report.origin_candidates = [c.to_dict() for c in cands]
        self.bus.stage_end(stage, f"{len(cands)} candidate(s); "
                            f"{sum(1 for c in cands if c.confirmed)} confirmed")

    # ── WordPress active probe (framework=wordpress only) --------

    def _wp_active_probe(self, profile: ArchitectureProfile):
        """Real WP-specific probes: core version, user enum, plugin
        enum + CVE match, xmlrpc, REST namespaces, dev-leak files."""
        if self.mode == CampaignMode.REPORT:
            return
        fw = (getattr(profile, "framework", None) or "").lower()
        if "wordpress" not in fw:
            return
        if self.http_get is None:
            self.bus.log("wp_probe", "no http_get — skipping")
            return

        stage = "wp_probe"
        self.bus.stage_start(
            stage,
            "WordPress active probes: core/users/plugins/xmlrpc/REST/dev-leaks"
        )

        def _progress(name, done, total):
            self.bus.progress(stage, done, total, message=f"probing: {name}")

        try:
            result = run_wp_probe(self.target_url, self.http_get, progress=_progress)
        except Exception as exc:  # noqa: BLE001
            self.bus.error(stage, f"wp_probe crashed: {exc}")
            self._report.errors.append(f"wp_probe: {exc}")
            return

        # Summary evidence
        if result.core_version:
            self.bus.evidence(stage, f"WP core version: {result.core_version}")
        self.bus.evidence(
            stage,
            f"plugins detected: {len(result.plugins)} · "
            f"themes: {len(result.themes)} · "
            f"users enumerated: {len(result.users)} · "
            f"xmlrpc_open: {result.xmlrpc_open} · "
            f"rest_namespaces: {len(result.rest_namespaces)} · "
            f"dev_leaks: {len(result.dev_leaks)}"
        )

        # Emit each plugin detection as an info event so operator sees inventory
        for p in result.plugins[:10]:
            self.bus.evidence(
                stage,
                f"plugin: {p.get('slug')} version={p.get('version') or '?'}"
            )

        # Emit findings into the bus + stash on report
        for f in result.findings:
            self.bus.finding(
                stage,
                f.get("kind", "info_leak"),
                f.get("location", self.target_url),
                f.get("severity", "medium"),
                f.get("evidence", ""),
                metadata=f.get("metadata", {}),
            )

        self.bus.stage_end(
            stage,
            f"{len(result.findings)} finding(s) from active WP probes"
        )

    # ── Hidden-param fuzzer (CONFIRM / EXPLOIT) ------------------

    def _hidden_params(self):
        if self.mode == CampaignMode.REPORT:
            return
        stage = "fuzz_params"
        self.bus.stage_start(stage, "discovering hidden parameters on the index page")
        if self.http_get is None:
            self.bus.stage_end(stage, "skipped (no http_get)")
            return
        # Build a sender for discover_hidden_params:
        #   sender(url, params_dict) -> ResponseObservation-compatible object
        from amoskys.agents.Web.argos.zeroday import ResponseObservation
        def _sender(url, params):
            try:
                qs = "&".join(f"{k}={v}" for k, v in (params or {}).items())
                full = url + ("?" + qs if qs else "")
                status, hdrs, body = self.http_get(full, 6.0, {})
                return ResponseObservation(
                    status=status,
                    length=len(body or ""),
                    body_hash=_short_hash((body or "")[:4096]),
                    content_type=(hdrs or {}).get("content-type", ""),
                    latency_ms=0,
                    headers=dict(hdrs or {}),
                    body_preview=(body or "")[:400],
                )
            except Exception as exc:  # noqa: BLE001
                return ResponseObservation(
                    status=0, length=0, body_hash="",
                    content_type="", latency_ms=0,
                    headers={}, body_preview=f"__error__:{exc}",
                )

        try:
            # Cap wordlist to keep volume polite in CONFIRM mode
            limit = 15 if self.mode == CampaignMode.CONFIRM else 40
            wl = HIDDEN_PARAM_WORDLIST[:limit]
            fuzz_rep = discover_hidden_params(self.target_url, sender=_sender,
                                                wordlist=wl,
                                                baseline_samples=1)
        except Exception as exc:  # noqa: BLE001
            self.bus.error(stage, f"discover_hidden_params failed: {exc}")
            self._report.errors.append(f"fuzz_params: {exc}")
            return
        hits = getattr(fuzz_rep, "hits", []) or []
        for h in hits[:8]:
            param = h.get("param") if isinstance(h, dict) else getattr(h, "param", "")
            sig = h.get("signal") if isinstance(h, dict) else getattr(h, "signal", "")
            self.bus.finding(stage, "hidden_param", f"{self.target_url}?{param}=",
                             "medium", f"{param}: {sig}")
        self.bus.stage_end(stage, f"{len(hits)} hidden param candidate(s)")

    # ── Auth surface probe (EXPLOIT) -----------------------------

    def _auth_probe(self):
        if self.mode != CampaignMode.EXPLOIT:
            return
        stage = "auth_probe"
        self.bus.stage_start(stage, "auth-endpoint discovery + JWT capture")
        if self.http_get is None:
            self.bus.stage_end(stage, "skipped (no http_get)")
            return
        # 1. Try well-known auth endpoints and capture any bearer token
        endpoints = [
            "/wp-login.php", "/wp-json/jwt-auth/v1/token", "/api/login",
            "/api/auth/login", "/oauth/token",
        ]
        tokens_seen: List[str] = []
        for ep in endpoints:
            url = self.target_url + ep
            try:
                status, hdrs, body = self.http_get(url, 6.0, {})
            except Exception:
                continue
            # Scan body + Set-Cookie + Authorization-like headers for JWTs
            candidates = _extract_jwts(f"{body or ''}\n{hdrs or {}}")
            for tok in candidates:
                if tok not in tokens_seen:
                    tokens_seen.append(tok)
                    self.bus.evidence(stage, f"JWT spotted at {ep} (len={len(tok)})")
        # 2. Run JWT attack suite on any token we captured
        for tok in tokens_seen[:3]:
            try:
                rep = scan_jwt(tok)
            except Exception as exc:  # noqa: BLE001
                self.bus.error(stage, f"scan_jwt failed: {exc}")
                continue
            for f in rep.findings:
                if f.severity in ("critical", "high"):
                    self.bus.finding(stage, f"jwt_{f.technique}",
                                     self.target_url, f.severity, f.evidence)
        self.bus.stage_end(stage,
            f"tokens captured={len(tokens_seen)}")

    # ── Smuggling probe ------------------------------------------

    def _smuggle(self):
        if self.mode == CampaignMode.REPORT:
            return
        stage = "smuggle"
        self.bus.stage_start(stage, "HTTP request-smuggling detection (CL.TE / TE.CL / TE.TE)")
        if self.smuggle_sender is None and self.mode != CampaignMode.EXPLOIT:
            self.bus.log(stage, "no smuggle_sender provided — skipping live timing probe")
            self.bus.stage_end(stage, "skipped (no sender)")
            return
        try:
            rep = detect_smuggling(self.target_url, sender=self.smuggle_sender)
        except Exception as exc:  # noqa: BLE001
            self.bus.error(stage, f"detect_smuggling failed: {exc}")
            self._report.errors.append(f"smuggle: {exc}")
            return
        self._report.smuggle_report = rep.to_dict()
        for r in rep.results:
            if r.get("vulnerable"):
                self.bus.finding(stage, "smuggling", self.target_url, "high",
                                 f"{r['technique']}: latency={r['latency_ms']}ms note={r.get('note','')}")
        self.bus.stage_end(stage,
            f"baseline={rep.baseline_latency_ms}ms; "
            f"vulnerable={rep.vulnerable}")

    # ── Chain reasoning ------------------------------------------

    def _chains(self, profile: ArchitectureProfile) -> List[ExploitChain]:
        stage = "chain"
        self.bus.stage_start(stage, "composing exploit chains from findings")
        findings = list(self.prebuilt_findings)

        # Pull findings from event bus where shape fits
        for evt in self.bus.history:
            if evt.kind != EventKind.FINDING:
                continue
            d = evt.data or {}
            findings.append(ChainFinding(
                kind=d.get("finding_kind", "info_leak"),
                location=d.get("location", evt.message),
                severity=d.get("severity", "medium"),
                evidence=d.get("evidence", evt.message),
                metadata=dict(d.get("metadata") or {}),
            ))

        if not findings:
            self.bus.stage_end(stage, "no findings to chain")
            return []

        # ── Legacy pattern reasoner (17 hand-coded rules) ──────
        pattern_rep = reason_chains(findings, profile=profile)

        # ── Graph reasoner (attack-graph search + scoring) ─────
        try:
            graph_rep = reason_graph(findings, profile=profile)
        except Exception as exc:  # noqa: BLE001
            self.bus.error(stage, f"graph_reasoner failed: {exc}")
            graph_rep = None

        # Merge: graph paths first (more principled), then legacy
        # pattern chains for any coverage the graph missed.
        merged: List[Any] = []
        seen_names: set = set()

        if graph_rep is not None:
            for n in graph_rep.notes:
                self.bus.log(stage, f"graph: {n}")
            if graph_rep.defenses_detected:
                self.bus.decision(
                    stage,
                    f"graph: defenses detected = {graph_rep.defenses_detected}; "
                    f"{len(graph_rep.pruned_edges)} edges dampened",
                )
            for p in graph_rep.paths:
                merged.append(p)
                seen_names.add(p.name)
                self.bus.chain(p.name, p.severity, p.cvss_estimate, p.narrative)
            # Surface near-miss paths as a special event type
            for nm in graph_rep.near_misses:
                self.bus.log(
                    stage,
                    f"near-miss: {nm.name}  (impact={nm.impact:.1f}, "
                    f"needs: {nm.missing_for_completion})",
                )

        for ch in pattern_rep.chains:
            # Skip if similar-enough name already covered by graph
            if any(ch.name.split()[0] in sn for sn in seen_names):
                continue
            merged.append(ch)
            self.bus.chain(ch.name, ch.severity, ch.cvss_estimate, ch.narrative)

        # Persist
        chain_dicts = [c.to_dict() for c in merged]
        self._report.chains = chain_dicts
        self._report.findings = [f.to_dict() for f in findings]

        # Max severity — from the merged set
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_sev = "low"
        for c in merged:
            s = getattr(c, "severity", None) or (c.get("severity") if isinstance(c, dict) else None)
            if sev_rank.get(s, 0) > sev_rank.get(max_sev, 0):
                max_sev = s
        self._report.max_severity = max_sev

        # Stash graph metadata for the report renderer
        if graph_rep is not None:
            self._report_extra = {
                "graph": {
                    "near_misses":       [nm.to_dict() for nm in graph_rep.near_misses],
                    "defenses_detected": list(graph_rep.defenses_detected),
                    "pruned_edges":      list(graph_rep.pruned_edges),
                    "activated_edges":   graph_rep.activated_edges,
                    "total_edges":       graph_rep.total_edges,
                    "goals_reached":     sorted(graph_rep.goals_reached),
                },
            }

        for note in pattern_rep.notes:
            self.bus.log(stage, note)

        self.bus.stage_end(
            stage,
            f"{len(merged)} chain(s) total "
            f"({len(graph_rep.paths) if graph_rep else 0} graph, "
            f"{len(pattern_rep.chains)} legacy) · "
            f"max_severity={max_sev}",
        )
        return merged

    # ── Run ------------------------------------------------------

    def run(self) -> CampaignReport:
        try:
            if not self._verify_consent():
                self._finalize()
                return self._report

            self._passive_recon()
            profile = self._fingerprint()
            strategy = self._strategy(profile)
            self._origin_bypass(strategy)
            self._wp_active_probe(profile)
            self._smuggle()
            self._hidden_params()
            self._auth_probe()

            # Chain reasoning takes findings from all prior stages
            self._chains(profile)

            self._finalize()
        except Exception as exc:  # noqa: BLE001
            logger.exception("campaign crashed")
            self.bus.fatal("campaign", f"unhandled: {exc}")
            self._report.errors.append(f"unhandled: {exc}")
            self._finalize()
        return self._report

    def _finalize(self):
        self._report.finished_at = time.time()
        self._report.events = [e.to_dict() for e in self.bus.history]
        extra = getattr(self, "_report_extra", None)
        if extra and isinstance(extra, dict):
            self._report.graph = extra.get("graph")
        self.bus.report(
            f"{len(self._report.chains)} chains, "
            f"{len(self._report.findings)} findings, "
            f"max={self._report.max_severity}",
            summary=self._report.to_dict(),
        )
        self.bus.done(
            f"campaign finished in "
            f"{self._report.finished_at - self._report.started_at:.1f}s",
            target=self.target_url, mode=self.mode,
        )


# ── Module-private helpers ────────────────────────────────────────


import hashlib as _hashlib
import re as _re


_JWT_RE = _re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,})\b")


def _extract_jwts(text: str) -> List[str]:
    """Pull JWT-shaped tokens (ey… three-dot) out of text."""
    if not text:
        return []
    return list(dict.fromkeys(_JWT_RE.findall(text)))


def _short_hash(s: str) -> str:
    return _hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12]


def run_campaign(target_url: str,
                 mode: str = CampaignMode.REPORT,
                 consent_token: Optional[str] = None,
                 bus: Optional[EventBus] = None,
                 **kwargs) -> CampaignReport:
    """One-liner: spin a Campaign and return its report."""
    return Campaign(target_url=target_url, mode=mode,
                    consent_token=consent_token, bus=bus, **kwargs).run()


__all__ = ["Campaign", "CampaignMode", "CampaignReport", "run_campaign"]
