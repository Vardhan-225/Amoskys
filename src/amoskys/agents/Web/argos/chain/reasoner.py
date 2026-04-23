"""Chain reasoner — compose individual findings into exploit paths.

Data flow
---------
    Findings (from AST / evasion / zeroday / fingerprint / origin)
        │
        ▼
    ChainReasoner.reason()
        │
        ├── apply each CHAIN_RULES pattern
        ├── score composed chains (sum + synergy bonus)
        └── rank; return ChainReport
        │
        ▼
    Operator review + precision.execute() (with consent token)

Design
------
Each rule is a `(predicate, composer)` pair:
    predicate(findings) -> Optional[List[ChainFinding]]
        returns the subset of findings that match, or None
    composer(subset, profile) -> ExploitChain
        builds the narrative + CVSS-style severity

We intentionally keep the ruleset small (15 rules) and focused on
WordPress-adjacent ecosystems. Adding a rule is an order of
magnitude cheaper than building a new scanner, so this module's
value compounds over time.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("amoskys.argos.chain")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class ChainFinding:
    """Shape the reasoner understands. All Argos outputs can be
    coerced into this — see `from_argos()` helper."""
    kind: str                         # "sqli", "xss_stored", "lfi", "ssrf", "poi", "rest_authz",
                                      # "file_upload", "csrf", "verbose_errors", "debug_mode",
                                      # "exposed_config", "info_leak", "smuggling", "cdn_bypass"
    location: str                     # URL, file, param — human description
    severity: str = "medium"          # low / medium / high / critical
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "kind": self.kind, "location": self.location,
            "severity": self.severity, "evidence": self.evidence,
            "metadata": dict(self.metadata),
        }


@dataclass
class ExploitChain:
    name: str                         # "SSRF→IMDSv1→AWS root"
    severity: str                     # final composed severity
    cvss_estimate: float              # 0.0–10.0 (rough mapping)
    links: List[ChainFinding] = field(default_factory=list)
    narrative: str = ""               # step-by-step exploitation plan
    business_impact: str = ""         # what the attacker gets at the end
    evidence_trail: List[str] = field(default_factory=list)
    confidence: int = 0               # 0–100; pattern strength

    def to_dict(self):
        return {
            "name": self.name, "severity": self.severity,
            "cvss_estimate": self.cvss_estimate,
            "links": [l.to_dict() for l in self.links],
            "narrative": self.narrative,
            "business_impact": self.business_impact,
            "evidence_trail": list(self.evidence_trail),
            "confidence": self.confidence,
        }


@dataclass
class ChainReport:
    target: str
    chains: List[ExploitChain] = field(default_factory=list)
    unchained: List[ChainFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        highest = 0
        label = "low"
        for c in self.chains:
            lvl = order.get(c.severity, 0)
            if lvl > highest:
                highest = lvl
                label = c.severity
        return label

    def to_dict(self):
        return {
            "target": self.target,
            "chains":    [c.to_dict() for c in self.chains],
            "unchained": [f.to_dict() for f in self.unchained],
            "notes":     list(self.notes),
            "max_severity": self.max_severity,
        }


# ── Helpers: finding lookup ───────────────────────────────────────


def _find(findings: List[ChainFinding], kind: str) -> List[ChainFinding]:
    return [f for f in findings if f.kind == kind]


def _any(findings: List[ChainFinding], kinds: List[str]) -> List[ChainFinding]:
    ks = set(kinds)
    return [f for f in findings if f.kind in ks]


SEV_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_CVSS   = {"low": 3.0, "medium": 5.5, "high": 8.0, "critical": 9.8}


def _bump(sev: str, steps: int = 1) -> str:
    lvl = SEV_LEVELS.get(sev, 2) + steps
    lvl = max(1, min(4, lvl))
    for k, v in SEV_LEVELS.items():
        if v == lvl:
            return k
    return sev


# ── Rule library ──────────────────────────────────────────────────
#
# Each entry: (name, predicate, composer, confidence)
# Composer is called only if predicate returns non-empty list of findings.


def _rule_ssrf_to_imds(findings, profile):
    ssrf = _find(findings, "ssrf")
    if not ssrf:
        return None
    # Only fires if target runs on a cloud VM — infer from profile notes
    # OR if ssrf evidence mentioned 169.254.169.254
    cloud_hint = any(
        "aws" in (f.evidence or "").lower() or "169.254.169.254" in (f.evidence or "")
        for f in ssrf
    )
    if not cloud_hint and profile is not None:
        notes = " ".join(getattr(profile, "evidence", []) + getattr(profile, "errors", []))
        if "aws" in notes.lower() or "ec2" in notes.lower():
            cloud_hint = True
    if not cloud_hint:
        return None
    links = [ssrf[0]]
    return ExploitChain(
        name="SSRF → IMDSv1 → AWS IAM takeover",
        severity="critical", cvss_estimate=9.6,
        links=links,
        narrative=(
            "1. Trigger SSRF at {loc} with payload "
            "`http://169.254.169.254/latest/meta-data/iam/security-credentials/`\n"
            "2. Extract IAM role name from response\n"
            "3. Fetch `/iam/security-credentials/<role>` to harvest "
            "AccessKey+SecretKey+Token\n"
            "4. Export credentials and enumerate S3/EC2/RDS with awscli"
        ).format(loc=links[0].location),
        business_impact="Full AWS account compromise; lateral movement to all services the role can reach.",
        evidence_trail=[links[0].evidence, "profile hints cloud/AWS"],
        confidence=80,
    )


def _rule_lfi_to_wpconfig(findings, profile):
    lfi = _find(findings, "lfi")
    if not lfi:
        return None
    # Only elevate if framework is WordPress
    if profile is not None:
        fw = (getattr(profile, "framework", None) or "").lower()
        if "wordpress" not in fw:
            return None
    return ExploitChain(
        name="LFI → wp-config.php → DB takeover",
        severity="critical", cvss_estimate=9.3,
        links=[lfi[0]],
        narrative=(
            "1. LFI at {loc} reads `wp-config.php` "
            "(via php://filter/convert.base64-encode/resource=wp-config)\n"
            "2. Decode to extract DB_USER, DB_PASSWORD, DB_HOST, AUTH_KEY + salts\n"
            "3. If DB port is internet-reachable: connect directly and rewrite wp_users.user_pass "
            "to attacker-controlled hash\n"
            "4. Forge session cookies with the salts even if DB is internal"
        ).format(loc=lfi[0].location),
        business_impact="WordPress admin takeover + persistent backdoor + plaintext secrets.",
        evidence_trail=[lfi[0].evidence, "WordPress framework confirmed"],
        confidence=85,
    )


def _rule_xss_stored_to_admin(findings, profile):
    xss = [f for f in findings if f.kind in ("xss_stored", "xss")]
    stored = [f for f in xss if f.kind == "xss_stored" or "admin" in (f.location or "").lower()]
    if not stored:
        return None
    return ExploitChain(
        name="Stored XSS → admin session theft → plugin install",
        severity="critical", cvss_estimate=9.0,
        links=[stored[0]],
        narrative=(
            "1. Stored XSS at {loc} fires in admin context\n"
            "2. Payload exfiltrates `wp_<id>_session_tokens` meta + nonce for plugin install\n"
            "3. Attacker uses stolen session to POST `/wp-admin/plugin-install.php?action=upload-plugin` "
            "with malicious ZIP\n"
            "4. Plugin executes on activation → webshell"
        ).format(loc=stored[0].location),
        business_impact="RCE as web user via admin-XSS → plugin-upload pivot.",
        evidence_trail=[stored[0].evidence],
        confidence=70,
    )


def _rule_rest_authz_to_admin(findings, profile):
    rest = _find(findings, "rest_authz")
    if not rest:
        return None
    return ExploitChain(
        name="Unauth REST write → option change → admin takeover",
        severity="critical", cvss_estimate=9.1,
        links=[rest[0]],
        narrative=(
            "1. POST {loc} as anonymous (no permission_callback set)\n"
            "2. Update `users_can_register=1` and `default_role=administrator`\n"
            "3. Register attacker account via `/wp-login.php?action=register`\n"
            "4. Log in — admin role granted on first login"
        ).format(loc=rest[0].location),
        business_impact="Site takeover without any credentials or user interaction.",
        evidence_trail=[rest[0].evidence],
        confidence=85,
    )


def _rule_sqli_blind_to_dump(findings, profile):
    sqli = _find(findings, "sqli")
    if not sqli:
        return None
    db = (getattr(profile, "database", None) or "unknown") if profile else "unknown"
    return ExploitChain(
        name=f"SQLi → DB {db} dump → credential reuse",
        severity="high", cvss_estimate=8.5,
        links=[sqli[0]],
        narrative=(
            "1. Confirmed SQLi at {loc}\n"
            "2. Enumerate schema: information_schema.tables / pg_catalog\n"
            "3. Dump `wp_users` — bcrypt hashes crackable ~$/GPU-hr each\n"
            "4. Reuse cracked passwords across customer's SaaS (LinkedIn / Gmail via password-reuse)"
        ).format(loc=sqli[0].location),
        business_impact="Credential harvest + downstream account compromise via password reuse.",
        evidence_trail=[sqli[0].evidence, f"database={db}"],
        confidence=75,
    )


def _rule_upload_plus_lfi(findings, profile):
    up = _find(findings, "file_upload")
    lfi = _find(findings, "lfi")
    if not up or not lfi:
        return None
    return ExploitChain(
        name="Arbitrary file upload + LFI → RCE",
        severity="critical", cvss_estimate=9.5,
        links=[up[0], lfi[0]],
        narrative=(
            "1. Upload polyglot `shell.jpg` via {up_loc} (server rejects .php but accepts .jpg)\n"
            "2. Include it as PHP via {lfi_loc}: "
            "`?page=../uploads/shell.jpg` (LFI executes image as PHP)\n"
            "3. Webshell → sudo pivot → root"
        ).format(up_loc=up[0].location, lfi_loc=lfi[0].location),
        business_impact="Remote code execution as web user; persistence via cron.",
        evidence_trail=[up[0].evidence, lfi[0].evidence],
        confidence=90,
    )


def _rule_csrf_plus_privileged_endpoint(findings, profile):
    csrf = _find(findings, "csrf")
    if not csrf:
        return None
    # Only elevate if endpoint path implies privilege
    privileged = [f for f in csrf if any(
        p in (f.location or "").lower() for p in ("admin", "user", "role", "settings", "import"))]
    if not privileged:
        return None
    return ExploitChain(
        name="CSRF on privileged endpoint → admin account creation",
        severity="high", cvss_estimate=8.1,
        links=[privileged[0]],
        narrative=(
            "1. Lure logged-in admin to visit attacker page\n"
            "2. Hidden <form> POSTs {loc} with `role=administrator&user_login=attacker`\n"
            "3. Browser replays admin session cookie (no nonce enforcement)\n"
            "4. Attacker logs in with known password"
        ).format(loc=privileged[0].location),
        business_impact="Site takeover via a single phishing click.",
        evidence_trail=[privileged[0].evidence],
        confidence=80,
    )


def _rule_info_leak_plus_any_injection(findings, profile):
    leaks = _any(findings, ["verbose_errors", "debug_mode", "exposed_config", "info_leak"])
    injections = _any(findings, ["sqli", "xss", "xss_stored", "lfi", "ssrf", "rce"])
    if not leaks or not injections:
        return None
    return ExploitChain(
        name="Info leak + injection → accelerated exploitation",
        severity=_bump(injections[0].severity, 1),
        cvss_estimate=min(10.0, SEV_CVSS.get(injections[0].severity, 5.5) + 1.0),
        links=[leaks[0], injections[0]],
        narrative=(
            "1. Verbose errors at {leak_loc} disclose stack traces + SQL dialect + DB name\n"
            "2. Inject at {inj_loc} using error-based payloads — exfil ≥10x faster than blind\n"
            "3. Detection windows shorter; telemetry-quality lower"
        ).format(leak_loc=leaks[0].location, inj_loc=injections[0].location),
        business_impact="Same final outcome as the bare injection, but 10–100× faster "
                        "(and correspondingly harder to catch).",
        evidence_trail=[leaks[0].evidence, injections[0].evidence],
        confidence=70,
    )


def _rule_smuggling_plus_waf(findings, profile):
    smug = _find(findings, "smuggling")
    if not smug:
        return None
    waf = getattr(profile, "waf_names", []) if profile else []
    if not waf:
        return None
    return ExploitChain(
        name="Request smuggling → WAF bypass to origin",
        severity="critical", cvss_estimate=9.2,
        links=[smug[0]],
        narrative=(
            "1. CL.TE disagreement between {waf} edge and origin confirmed\n"
            "2. Smuggle POST /wp-admin/admin-ajax.php with malicious `action`\n"
            "3. Origin processes smuggled request under next victim's session (queue poisoning)\n"
            "4. Every normal user triggers the attack; WAF rules never see the payload"
        ).format(waf="+".join(waf)),
        business_impact="WAF becomes useless for the affected routes; credential replay at scale.",
        evidence_trail=[smug[0].evidence, f"WAF present: {waf}"],
        confidence=85,
    )


def _rule_cdn_bypass_plus_weak_origin(findings, profile):
    bypass = _find(findings, "cdn_bypass")
    if not bypass:
        return None
    # Relevant only if origin exposes weaker posture than edge
    if profile is not None:
        verbose = getattr(profile, "verbose_errors", False) or getattr(profile, "debug_mode", False)
    else:
        verbose = False
    if not verbose:
        return None
    return ExploitChain(
        name="CDN bypass → direct origin hit with WAF disabled",
        severity="high", cvss_estimate=8.3,
        links=[bypass[0]],
        narrative=(
            "1. Origin IP {loc} discovered via CT / SPF\n"
            "2. Direct `curl -H 'Host: target' http://IP/` returns verbose errors\n"
            "3. All subsequent probes bypass CDN-layer WAF\n"
            "4. Any injection finding escalates by one severity tier"
        ).format(loc=bypass[0].location),
        business_impact="WAF rules render irrelevant; defender loses primary detection layer.",
        evidence_trail=[bypass[0].evidence],
        confidence=80,
    )


def _rule_cve_match_is_its_own_chain(findings, profile):
    """Every detected CVE is ITSELF a chain — it has a discoverable
    exploitation path, known severity, and concrete impact. Earlier
    versions of the reasoner required two or more findings to compose
    a chain, but a cve_match finding already carries CVE metadata
    (cve_id, component, version) and a published exploit narrative."""
    cves = _find(findings, "cve_match")
    if not cves:
        return None
    # Group by CVE id so duplicate matches don't explode into N chains
    by_id: Dict[str, ChainFinding] = {}
    for f in cves:
        cve = (f.metadata or {}).get("cve") or "UNKNOWN-CVE"
        if cve not in by_id:
            by_id[cve] = f
    # Emit one chain per unique CVE
    chains: List[ExploitChain] = []
    for cve_id, f in by_id.items():
        sev = f.severity or "medium"
        comp = (f.metadata or {}).get("component") or "unknown"
        ver = (f.metadata or {}).get("version") or "?"
        cvss_map = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.5}
        cvss = cvss_map.get(sev, 5.5)
        chains.append(ExploitChain(
            name=f"{cve_id} applies to {comp} {ver}",
            severity=sev, cvss_estimate=cvss,
            links=[f],
            narrative=(
                f"1. Argos detected {comp} version {ver} via readme.txt / "
                f"meta-generator / style.css headers.\n"
                f"2. {cve_id} publicly affects {(f.metadata or {}).get('affected', '')} "
                f"— operator's site matches that range.\n"
                f"3. {f.evidence}\n"
                f"4. Public exploit paths for {cve_id} are documented on "
                f"Wordfence, Patchstack, and NVD. A prepared attacker reaches "
                f"exploitation within minutes of Argos's finding."
            ),
            business_impact=(
                f"{f.evidence.split('—')[-1].strip() if '—' in f.evidence else f.evidence}. "
                f"Remediation: update {comp} beyond {ver}."
            ),
            evidence_trail=[f.evidence, f"version detected: {ver}"],
            confidence=85,
        ))
    # Return the single highest-severity chain; others will be produced
    # on subsequent rule passes if the reasoner loop permits. For the
    # current one-pass-per-rule loop we pick a deterministic best-of.
    chains.sort(key=lambda c: (SEV_LEVELS.get(c.severity, 2), c.cvss_estimate), reverse=True)
    return chains[0]


def _rule_cve_match_all(findings, profile):
    """Second pass so we catch every CVE, not just the top one. This
    is a hack around the single-return rule contract — returning a
    synthetic 'summary' chain when >1 distinct CVE exists."""
    cves = _find(findings, "cve_match")
    ids = set()
    for f in cves:
        cid = (f.metadata or {}).get("cve")
        if cid:
            ids.add(cid)
    if len(ids) < 2:
        return None
    # Compose a portfolio summary chain
    worst_sev = "low"
    for f in cves:
        if SEV_LEVELS.get(f.severity, 0) > SEV_LEVELS.get(worst_sev, 0):
            worst_sev = f.severity
    return ExploitChain(
        name=f"{len(ids)} CVEs applicable — portfolio risk",
        severity=worst_sev,
        cvss_estimate=SEV_CVSS.get(worst_sev, 5.5),
        links=list(cves),
        narrative=(
            f"Argos matched {len(ids)} distinct published CVEs against detected "
            f"versions on this target:\n"
            + "\n".join(
                f"  • {(f.metadata or {}).get('cve', '?')}  "
                f"(severity: {f.severity}, component: {(f.metadata or {}).get('component', '?')})"
                for f in cves[:8]
            )
            + "\n\nEach of these has a public exploit path. The more CVEs "
              "stack up on one target, the more likely an opportunistic "
              "attacker already has the runbook."
        ),
        business_impact=(
            "Portfolio-level exposure — update the affected components to "
            "close all matched CVEs at once rather than triaging each."
        ),
        evidence_trail=[f.evidence for f in cves[:5]],
        confidence=80,
    )


def _rule_user_enum_plus_xmlrpc(findings, profile):
    """Classic WordPress credential-spray chain: enumerated usernames
    + open xmlrpc.php = brute-force at amplified scale. xmlrpc's
    system.multicall lets an attacker try 1000 passwords per HTTP
    request — even a 1000-password wordlist fits in ONE request."""
    info_leaks = _find(findings, "info_leak")
    user_enum = [f for f in info_leaks if "user" in (f.location or "").lower()
                 or "user" in (f.evidence or "").lower()]
    xmlrpc = [f for f in info_leaks if "xmlrpc" in (f.location or "").lower()]
    if not (user_enum and xmlrpc):
        return None
    return ExploitChain(
        name="User enumeration + xmlrpc = credential spray at 1000x",
        severity="high", cvss_estimate=8.1,
        links=[user_enum[0], xmlrpc[0]],
        narrative=(
            "1. REST API public user endpoint discloses site usernames "
            "(Argos harvested the list in §5).\n"
            "2. xmlrpc.php is reachable and implements system.multicall — "
            "lets an attacker batch 1,000+ login attempts per single HTTP "
            "request.\n"
            "3. Attacker cycles known usernames × common-passwords wordlist "
            "via multicall; at 1 req/sec they try 1M passwords in 17 minutes.\n"
            "4. Successful login → admin dashboard → plugin upload → RCE."
        ),
        business_impact=(
            "Brute-force at scale that tripwire-style rate limits usually miss "
            "because all attempts arrive in one POST. Any weak password on "
            "ANY enumerated user is game over."
        ),
        evidence_trail=[user_enum[0].evidence, xmlrpc[0].evidence],
        confidence=88,
    )


def _rule_user_enum_plus_cve(findings, profile):
    """User enumeration + any CVE targeting account-level exploitation
    (auth bypass, priv esc, password reset) becomes a targeted attack
    with high success probability."""
    info_leaks = _find(findings, "info_leak")
    user_enum = [f for f in info_leaks if "user" in (f.location or "").lower()]
    cves = _find(findings, "cve_match")
    # Only fire for CVEs that mention auth / password / reset / priv esc
    auth_cves = [f for f in cves if any(kw in (f.evidence or "").lower()
                 for kw in ("auth", "password", "reset", "priv", "user", "takeover"))]
    if not (user_enum and auth_cves):
        return None
    return ExploitChain(
        name="Targeted exploitation: username list + auth-affecting CVE",
        severity="critical", cvss_estimate=9.2,
        links=[user_enum[0]] + auth_cves[:1],
        narrative=(
            f"1. Argos harvested specific usernames via the public REST API.\n"
            f"2. {(auth_cves[0].metadata or {}).get('cve','?')} affects the "
            f"detected version and impacts authentication / authorization.\n"
            f"3. Attacker combines the username list + CVE's exploit path to "
            f"compromise SPECIFIC known accounts, not random brute-force.\n"
            f"4. Each successful compromise scales to admin via vertical "
            f"privilege escalation."
        ),
        business_impact=(
            "Known targets × known exploit = near-certain compromise. This is "
            "not a statistical attack; it's a named-hit campaign."
        ),
        evidence_trail=[user_enum[0].evidence, auth_cves[0].evidence],
        confidence=85,
    )


def _rule_exposed_config_leak(findings, profile):
    """An exposed .env, .git/HEAD, wp-config.php.bak, or debug.log is
    game-over on its own. No chain partner required — the artifact
    IS the compromise."""
    leaks = _find(findings, "exposed_config")
    if not leaks:
        return None
    worst = sorted(leaks, key=lambda f: SEV_LEVELS.get(f.severity, 0), reverse=True)[0]
    return ExploitChain(
        name="Development artifact exposure → instant compromise",
        severity="critical", cvss_estimate=9.8,
        links=[worst],
        narrative=(
            f"1. Argos fetched {worst.location} directly over HTTPS and "
            f"received a 200 OK with content.\n"
            f"2. Evidence: {worst.evidence[:200]}\n"
            f"3. If the exposed file is .env / wp-config.php.bak — it contains "
            f"DB credentials, AUTH_KEY salts, and service API keys.\n"
            f"4. If .git/HEAD — attacker runs `git-dumper` to reconstruct the "
            f"full source tree, including uncommitted secrets.\n"
            f"5. If debug.log — it often contains recent stack traces that "
            f"reveal internal paths, user emails, and session tokens."
        ),
        business_impact=(
            "Full application compromise without exploiting any vulnerability — "
            "the target simply published the keys to the kingdom. Typical "
            "remediation: rotate every credential, add the file to nginx deny "
            "rules, scrub the webroot."
        ),
        evidence_trail=[worst.evidence],
        confidence=95,
    )


def _rule_rest_namespace_authz_audit(findings, profile):
    """Third-party REST namespaces registered on a WP site are
    potential authz holes. Every namespace registered by a plugin
    theoretically exposes routes that may be missing a permission
    callback."""
    ra = _find(findings, "rest_authz")
    if not ra:
        return None
    return ExploitChain(
        name="Third-party REST namespaces — authz audit required",
        severity="medium", cvss_estimate=6.5,
        links=[ra[0]],
        narrative=(
            "1. Argos enumerated registered REST namespaces at /wp-json/ "
            "and identified third-party (non-core) routes.\n"
            "2. Each third-party namespace potentially exposes routes without "
            "a permission_callback — WordPress core defaults to public access "
            "when the callback is missing.\n"
            "3. Argos recommends auditing each route for:\n"
            "   • permission_callback set (not omitted, not '__return_true')\n"
            "   • capability checks matching the action's sensitivity\n"
            "   • nonce verification for state-changing operations\n"
            "4. Public tooling (wp-json-scanner, WPScan) automates this audit."
        ),
        business_impact=(
            "Unauthed REST routes are the single largest bug-bounty class on "
            "WordPress: stored XSS, option writes, user creates, even RCE via "
            "file_put_contents through misconfigured routes."
        ),
        evidence_trail=[ra[0].evidence],
        confidence=75,
    )


def _rule_poi_plus_rce_gadget(findings, profile):
    poi = _find(findings, "poi")
    rce = _find(findings, "rce")
    if not poi:
        return None
    return ExploitChain(
        name="PHP object injection → gadget chain → RCE",
        severity="critical", cvss_estimate=9.4,
        links=[poi[0]] + rce[:1],
        narrative=(
            "1. unserialize() reachable at {loc}\n"
            "2. Chain Guzzle/Monolog/Symfony gadgets via phpggc to reach a system() call\n"
            "3. Webshell drops; persistence via WP cron or must-use-plugin"
        ).format(loc=poi[0].location),
        business_impact="RCE as web user; full site + adjacent services compromise.",
        evidence_trail=[poi[0].evidence] + [r.evidence for r in rce[:1]],
        confidence=65,  # phpggc chains require Composer presence — calibrated lower
    )


CHAIN_RULES: List[Tuple[str, Callable, int]] = [
    ("ssrf_to_imds",             _rule_ssrf_to_imds,             80),
    ("lfi_to_wpconfig",          _rule_lfi_to_wpconfig,          85),
    ("xss_stored_to_admin",      _rule_xss_stored_to_admin,      70),
    ("rest_authz_to_admin",      _rule_rest_authz_to_admin,      85),
    ("sqli_blind_to_dump",       _rule_sqli_blind_to_dump,       75),
    ("upload_plus_lfi",          _rule_upload_plus_lfi,          90),
    ("csrf_plus_privileged",     _rule_csrf_plus_privileged_endpoint, 80),
    ("info_leak_plus_injection", _rule_info_leak_plus_any_injection,  70),
    ("smuggling_plus_waf",       _rule_smuggling_plus_waf,       85),
    ("cdn_bypass_plus_weak",     _rule_cdn_bypass_plus_weak_origin, 80),
    ("poi_plus_rce_gadget",      _rule_poi_plus_rce_gadget,      65),
    # New in v2.5 — cover findings emitted by wp_probe
    ("cve_match_is_chain",       _rule_cve_match_is_its_own_chain,   85),
    ("cve_portfolio",            _rule_cve_match_all,                80),
    ("user_enum_plus_xmlrpc",    _rule_user_enum_plus_xmlrpc,        88),
    ("user_enum_plus_cve",       _rule_user_enum_plus_cve,           85),
    ("exposed_config_leak",      _rule_exposed_config_leak,          95),
    ("rest_ns_authz_audit",      _rule_rest_namespace_authz_audit,   75),
]


# ── Reasoner ──────────────────────────────────────────────────────


class ChainReasoner:
    def __init__(self, profile=None):
        self.profile = profile

    def reason(self, findings: List[ChainFinding]) -> ChainReport:
        target = getattr(self.profile, "target_url", "") or getattr(self.profile, "target_host", "<unknown>") \
                 if self.profile else "<unknown>"
        report = ChainReport(target=target)

        used_ids: set = set()
        for name, rule, _default_conf in CHAIN_RULES:
            try:
                chain = rule(findings, self.profile)
            except Exception as exc:  # noqa: BLE001
                report.notes.append(f"rule {name} raised {exc.__class__.__name__}: {exc}")
                continue
            if chain is None:
                continue
            report.chains.append(chain)
            for link in chain.links:
                used_ids.add(id(link))

        # Rank chains by severity then cvss then confidence
        report.chains.sort(
            key=lambda c: (SEV_LEVELS.get(c.severity, 2), c.cvss_estimate, c.confidence),
            reverse=True,
        )

        # Unchained findings
        report.unchained = [f for f in findings if id(f) not in used_ids]

        # Synergy summary
        if len(report.chains) >= 3:
            report.notes.append(
                f"{len(report.chains)} independent chains present — compound "
                "severity exceeds any individual finding. Strongly recommend "
                "prioritized remediation over whack-a-mole patching."
            )

        return report


def reason_chains(findings: List[ChainFinding], profile=None) -> ChainReport:
    """Convenience wrapper: one-shot reason()."""
    return ChainReasoner(profile).reason(findings)


__all__ = [
    "ChainFinding", "ExploitChain", "ChainReport",
    "ChainReasoner", "reason_chains",
]
