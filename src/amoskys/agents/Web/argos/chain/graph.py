"""Attack graph — nodes, edges, and a curated WordPress attack catalog.

Replaces flat if/else chain rules with a real attack graph.

Model
-----
    AttackState     A discrete state the attacker can reach (e.g.
                    UNAUTHENTICATED, ACCOUNT_USER, CODE_EXECUTION,
                    FULL_COMPROMISE). Nodes in the graph.

    AttackEdge      A transition between states triggered by a finding
                    or combination of findings. Carries:
                      - trigger_kinds / trigger_predicate — when does
                          this edge "activate" based on discovered
                          findings?
                      - cost_minutes       attacker-time to execute
                      - success_prob       conditional on preconditions
                      - detectability      chance the defender notices
                      - mitre_technique    ATT&CK T-ID
                      - defense_pruned_by  sensor / WAF families that
                                           kill this edge

    AttackGraph     Holds edges; activate(findings, profile) returns
                    the subgraph whose edges fire; paths(start, goal)
                    enumerates all simple paths.

Reasoning math
--------------
For a path P = [e1, e2, ..., en]:
    cost(P)         = Σ cost_minutes
    prob(P)         = ∏ success_prob
    detectable(P)   = 1 - ∏ (1 - detectability)
    impact(goal)    = value-of-goal-state (e.g. CODE_EXECUTION = 9.0)
    stealth(P)      = 1 - detectable(P)
    expected_value(P) = prob(P) × impact(goal) × stealth(P)

The reasoner ranks paths by expected_value and surfaces the top K.

Defense-aware pruning
---------------------
If Wordfence is detected, edges tagged `defense_pruned_by={"wordfence"}`
are pruned (their success_prob is multiplied by 0.25 rather than
wholly removed, because Wordfence is not perfect). Same pattern for
Cloudflare WAF, Sucuri, ModSecurity, Aegis.

Near-miss paths
---------------
We also return paths that would reach the goal if ONE additional
edge were active. Each near-miss names the missing finding class —
"if SQLi were found here, this critical chain would open". Real
attackers remember these.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ── States ────────────────────────────────────────────────────────


class AttackState:
    """Discrete states the attacker can reach. Strings so they
    serialize trivially into the JSON report."""
    UNAUTHENTICATED     = "unauthenticated"
    USERNAME_ENUM       = "username_enum"           # has a target username list
    CREDENTIALS_LEAKED  = "credentials_leaked"      # cleartext or recoverable
    ACCOUNT_SUBSCRIBER  = "account_subscriber"      # low-priv login
    ACCOUNT_EDITOR      = "account_editor"          # mid-priv
    ACCOUNT_ADMIN       = "account_admin"           # wp-admin access
    DATABASE_READ       = "database_read"           # read-only DB access
    DATABASE_WRITE      = "database_write"          # can write/modify
    FILE_READ           = "file_read"               # arbitrary file read
    FILE_WRITE          = "file_write"              # write webroot
    CODE_EXECUTION      = "code_execution"          # PHP exec as web user
    PERSISTENCE         = "persistence"             # survives reboots
    LATERAL             = "lateral"                 # pivoted to other hosts
    DATA_EXFIL          = "data_exfil"              # customer data out
    FULL_COMPROMISE     = "full_compromise"         # game over


# State impact values — used by the reasoner to score a path's payoff.
# Tuned to roughly match CVSS severities for the "achieved state".
_STATE_IMPACT = {
    AttackState.UNAUTHENTICATED:    0.0,
    AttackState.USERNAME_ENUM:      1.0,
    AttackState.CREDENTIALS_LEAKED: 6.0,
    AttackState.ACCOUNT_SUBSCRIBER: 3.0,
    AttackState.ACCOUNT_EDITOR:     5.5,
    AttackState.ACCOUNT_ADMIN:      8.5,
    AttackState.DATABASE_READ:      7.0,
    AttackState.DATABASE_WRITE:     8.5,
    AttackState.FILE_READ:          7.5,
    AttackState.FILE_WRITE:         8.5,
    AttackState.CODE_EXECUTION:     9.5,
    AttackState.PERSISTENCE:        9.0,
    AttackState.LATERAL:            8.5,
    AttackState.DATA_EXFIL:         9.5,
    AttackState.FULL_COMPROMISE:    10.0,
}

# Terminal goals the reasoner searches TOWARD. Any path reaching
# one of these is recorded.
_TERMINAL_GOALS = [
    AttackState.ACCOUNT_ADMIN,
    AttackState.CODE_EXECUTION,
    AttackState.DATABASE_WRITE,
    AttackState.FILE_WRITE,
    AttackState.PERSISTENCE,
    AttackState.DATA_EXFIL,
    AttackState.FULL_COMPROMISE,
]


def state_impact(state: str) -> float:
    return _STATE_IMPACT.get(state, 0.0)


# ── Edge ──────────────────────────────────────────────────────────


@dataclass
class AttackEdge:
    """One transition in the attack graph."""

    name: str
    from_state: str
    to_state:   str

    # Activation: which finding kinds + (optional) metadata predicates?
    trigger_kinds: Tuple[str, ...] = ()          # finding.kind ∈ trigger_kinds → candidate
    # Optional refinement — called with (finding, profile), returns True to keep.
    trigger_predicate: Optional[Callable] = None

    # Attack economics
    cost_minutes:   int = 5            # attacker-time estimate
    success_prob:   float = 0.8        # P(edge succeeds | precondition held)
    detectability:  float = 0.3        # P(defender notices this step)

    # ATT&CK technique — single string for simplicity
    mitre_technique: str = ""

    # Defense awareness — if one of these WAFs/sensors is active, reduce prob.
    defense_pruned_by: Tuple[str, ...] = ()

    # Narrative
    attacker_action:  str = ""         # "Attacker does X"
    defender_should_see: str = ""      # "Blue team should see Y in logs"

    # Optional replay command template — operator can verify/reproduce.
    replay_command: str = ""

    def activated_by(self, findings: List, profile=None) -> Optional[Any]:
        """Return the triggering finding if this edge activates given
        the available findings; else None."""
        if not self.trigger_kinds:
            # Edge with no trigger is always passive (e.g. terminal
            # composition). Caller decides.
            return None
        for f in findings:
            k = getattr(f, "kind", None) or (f.get("kind") if isinstance(f, dict) else None)
            if k not in self.trigger_kinds:
                continue
            if self.trigger_predicate and not self.trigger_predicate(f, profile):
                continue
            return f
        return None


# ── AttackGraph ───────────────────────────────────────────────────


class AttackGraph:
    """Directed graph of attack transitions."""

    def __init__(self):
        self._edges_by_src: Dict[str, List[AttackEdge]] = {}
        self._all_edges:   List[AttackEdge] = []

    def add(self, edge: AttackEdge) -> None:
        self._edges_by_src.setdefault(edge.from_state, []).append(edge)
        self._all_edges.append(edge)

    def extend(self, edges: List[AttackEdge]) -> None:
        for e in edges:
            self.add(e)

    def outgoing(self, state: str) -> List[AttackEdge]:
        return list(self._edges_by_src.get(state, ()))

    def all_edges(self) -> List[AttackEdge]:
        return list(self._all_edges)

    def paths(self, start: str, goal: str,
              max_depth: int = 6) -> List[List[AttackEdge]]:
        """DFS over the graph to enumerate all simple (no-cycle) paths
        from `start` to `goal` up to `max_depth` edges."""
        out: List[List[AttackEdge]] = []

        def _dfs(curr: str, visited: Set[str], path: List[AttackEdge]):
            if len(path) > max_depth:
                return
            if curr == goal and path:
                out.append(list(path))
                return
            for e in self.outgoing(curr):
                if e.to_state in visited:
                    continue
                path.append(e)
                visited.add(e.to_state)
                _dfs(e.to_state, visited, path)
                visited.discard(e.to_state)
                path.pop()

        _dfs(start, {start}, [])
        return out


# ── Curated WP attack graph ───────────────────────────────────────
#
# Hand-built from public research: WPScan vulnerability patterns,
# Wordfence CVE reviews, HackerOne WP reports, PortSwigger labs,
# the existing CVE catalog in wp_probe.py, and typical real-attack
# kill chains. Not exhaustive — focused on the top-20 highest-payoff
# paths an attacker takes against a typical WP install.


def _is_wp(f, profile):
    fw = getattr(profile, "framework", None) if profile else None
    return (fw or "").lower() == "wordpress"


def _is_auth_related_cve(f, profile):
    ev = (getattr(f, "evidence", "") or "").lower()
    return any(kw in ev for kw in ("auth", "password", "reset", "priv", "takeover",
                                     "account", "session", "bypass"))


def _is_rce_related_cve(f, profile):
    ev = (getattr(f, "evidence", "") or "").lower()
    return any(kw in ev for kw in ("rce", "remote code", "eval", "command injection",
                                     "object injection", "deserialization", "file upload"))


def _is_sqli_related_cve(f, profile):
    ev = (getattr(f, "evidence", "") or "").lower()
    return any(kw in ev for kw in ("sql", "sqli", "query", "injection via"))


def _is_xss_related_cve(f, profile):
    ev = (getattr(f, "evidence", "") or "").lower()
    return any(kw in ev for kw in ("xss", "cross-site scripting", "stored xss", "script"))


def _is_user_enum_leak(f, profile):
    return "user" in (getattr(f, "location", "") or "").lower() or \
           "user" in (getattr(f, "evidence", "") or "").lower()


def _is_xmlrpc_leak(f, profile):
    return "xmlrpc" in (getattr(f, "location", "") or "").lower()


def _is_dangerous_config_leak(f, profile):
    loc = (getattr(f, "location", "") or "").lower()
    return any(s in loc for s in (".env", "wp-config", ".git", "debug.log"))


def build_wordpress_graph() -> AttackGraph:
    g = AttackGraph()

    # ── Discovery / information-gathering edges ───────────────────

    g.add(AttackEdge(
        name="REST user-endpoint enumeration",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.USERNAME_ENUM,
        trigger_kinds=("info_leak",),
        trigger_predicate=_is_user_enum_leak,
        cost_minutes=1, success_prob=0.99, detectability=0.1,
        mitre_technique="T1087.001 — Local Account Discovery",
        attacker_action=("GET /wp-json/wp/v2/users?per_page=100 — public by "
                         "default, returns every registered user's id + slug."),
        defender_should_see=("1+ hits on /wp-json/wp/v2/users from a new IP. "
                             "Rate-limit or require_caps the endpoint."),
        replay_command="curl -s 'https://TARGET/wp-json/wp/v2/users?per_page=100' | jq '.[].slug'",
    ))

    # ── Credential acquisition edges ──────────────────────────────

    g.add(AttackEdge(
        name="xmlrpc credential spray (system.multicall)",
        from_state=AttackState.USERNAME_ENUM,
        to_state=AttackState.CREDENTIALS_LEAKED,
        trigger_kinds=("info_leak",),
        trigger_predicate=_is_xmlrpc_leak,
        cost_minutes=30, success_prob=0.35, detectability=0.5,
        mitre_technique="T1110.003 — Password Spraying",
        defense_pruned_by=("wordfence", "aegis"),
        attacker_action=("POST /xmlrpc.php with system.multicall carrying "
                         "1,000 wp.getUsersBlogs login attempts per request. "
                         "Cycle known-usernames × top-10k-passwords."),
        defender_should_see=("Spike in POST /xmlrpc.php from ONE IP in a "
                             "single HTTP request. Wordfence and Aegis both "
                             "fingerprint this signature."),
        replay_command=(
            "python -c \"import xmlrpc.client; "
            "s=xmlrpc.client.ServerProxy('https://TARGET/xmlrpc.php'); "
            "print(s.system.listMethods())\""),
    ))

    g.add(AttackEdge(
        name="Credential reuse (leaked in breach corpus)",
        from_state=AttackState.USERNAME_ENUM,
        to_state=AttackState.CREDENTIALS_LEAKED,
        trigger_kinds=("info_leak",),
        trigger_predicate=_is_user_enum_leak,
        cost_minutes=10, success_prob=0.20, detectability=0.1,
        mitre_technique="T1078 — Valid Accounts",
        attacker_action=("Look up enumerated usernames in HaveIBeenPwned + "
                         "Collection #1/2/3. If any user reused a breached "
                         "password, login from a residential IP pool."),
        defender_should_see=("Successful wp-login from a new IP with "
                             "no prior history. Requires anomaly baselining."),
    ))

    # ── CVE exploitation edges (parametric — one catalog-driven edge) ──

    g.add(AttackEdge(
        name="Published CVE → authentication bypass",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.ACCOUNT_ADMIN,
        trigger_kinds=("cve_match",),
        trigger_predicate=_is_auth_related_cve,
        cost_minutes=15, success_prob=0.75, detectability=0.3,
        mitre_technique="T1190 — Exploit Public-Facing Application",
        defense_pruned_by=("wordfence",),
        attacker_action=("Run the public PoC for the matched CVE (see "
                         "Patchstack / Wordfence writeup) against the "
                         "unpatched plugin version."),
        defender_should_see=("Wordfence premium signature for that CVE "
                             "should fire at request time. Free tier delays."),
    ))

    g.add(AttackEdge(
        name="Published CVE → SQL injection → DB read",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.DATABASE_READ,
        trigger_kinds=("cve_match",),
        trigger_predicate=_is_sqli_related_cve,
        cost_minutes=20, success_prob=0.70, detectability=0.5,
        mitre_technique="T1190 → T1213 — Data from Information Repositories",
        defense_pruned_by=("wordfence", "cloudflare", "sucuri"),
        attacker_action=("sqlmap against the affected parameter documented "
                         "in the CVE advisory; UNION-based extraction of "
                         "wp_users rows."),
        replay_command="sqlmap -u 'https://TARGET/<VULN_PATH>' --batch --tables",
    ))

    g.add(AttackEdge(
        name="Published CVE → stored XSS in admin context",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.ACCOUNT_ADMIN,
        trigger_kinds=("cve_match",),
        trigger_predicate=_is_xss_related_cve,
        cost_minutes=45, success_prob=0.40, detectability=0.4,
        mitre_technique="T1059.007 — JavaScript / JScript",
        defense_pruned_by=("wordfence", "cloudflare"),
        attacker_action=("Plant payload via the unauth XSS sink documented "
                         "in the CVE; wait for admin to view the affected "
                         "page; exfil admin session cookie via fetch()."),
        defender_should_see=("XSS payload pattern in POST body; admin "
                             "session access from unusual IP soon after."),
    ))

    g.add(AttackEdge(
        name="Published CVE → arbitrary file upload → webshell",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.FILE_WRITE,
        trigger_kinds=("cve_match",),
        trigger_predicate=_is_rce_related_cve,
        cost_minutes=25, success_prob=0.80, detectability=0.5,
        mitre_technique="T1505.003 — Web Shell",
        defense_pruned_by=("wordfence", "aegis"),
        attacker_action=("Upload PHP polyglot (GIF89a;<?php…?>) via the "
                         "vulnerable endpoint. Invoke as /.../shell.php."),
        replay_command=(
            "curl -F 'file=@polyglot.php.gif' -F 'action=upload' "
            "https://TARGET/<VULN_ENDPOINT>"),
    ))

    # ── State-transition edges (independent of specific findings) ───

    g.add(AttackEdge(
        name="File write → PHP webshell → code execution",
        from_state=AttackState.FILE_WRITE,
        to_state=AttackState.CODE_EXECUTION,
        # No trigger — this edge is always traversable once FILE_WRITE is reached.
        trigger_kinds=(),
        cost_minutes=2, success_prob=0.95, detectability=0.35,
        mitre_technique="T1059 — Command and Scripting Interpreter",
        attacker_action=("GET /wp-content/uploads/shell.php?cmd=id — PHP "
                         "executes the embedded shell primitives."),
        defender_should_see=("Unusual 200 on a .php in /wp-content/uploads. "
                             "Aegis fingerprints this pattern."),
    ))

    g.add(AttackEdge(
        name="Admin account → malicious plugin install → code execution",
        from_state=AttackState.ACCOUNT_ADMIN,
        to_state=AttackState.CODE_EXECUTION,
        trigger_kinds=(),
        cost_minutes=3, success_prob=0.98, detectability=0.25,
        mitre_technique="T1505.003 — Web Shell",
        attacker_action=("Upload a crafted plugin ZIP via /wp-admin/plugin-"
                         "install.php?action=upload-plugin. Activate it. "
                         "Plugin runs arbitrary PHP on activation."),
        defender_should_see=("plugin_install log from unexpected IP; any "
                             "plugin install is a sensitive-action audit log."),
    ))

    g.add(AttackEdge(
        name="Credentials leaked → wp-login authentication",
        from_state=AttackState.CREDENTIALS_LEAKED,
        to_state=AttackState.ACCOUNT_ADMIN,
        trigger_kinds=(),
        cost_minutes=1, success_prob=0.90, detectability=0.10,
        mitre_technique="T1078 — Valid Accounts",
        attacker_action=("POST /wp-login.php with recovered credentials. "
                         "If the cracked account is admin, immediate access."),
        defender_should_see=("login success from new geo/IP. MFA or "
                             "geo-fencing would block this."),
    ))

    g.add(AttackEdge(
        name="Code execution → wp-config.php → DB write + secrets",
        from_state=AttackState.CODE_EXECUTION,
        to_state=AttackState.DATABASE_WRITE,
        trigger_kinds=(),
        cost_minutes=2, success_prob=0.95, detectability=0.20,
        mitre_technique="T1552.001 — Credentials In Files",
        attacker_action=("Shell reads wp-config.php — extracts DB_USER, "
                         "DB_PASSWORD, AUTH_KEY. Direct MySQL connection "
                         "(if port internet-reachable) or wpdb UPDATE from "
                         "within the PHP process."),
    ))

    g.add(AttackEdge(
        name="Code execution → cron + mu-plugin → persistence",
        from_state=AttackState.CODE_EXECUTION,
        to_state=AttackState.PERSISTENCE,
        trigger_kinds=(),
        cost_minutes=5, success_prob=0.95, detectability=0.40,
        mitre_technique="T1053.003 — Scheduled Task/Cron",
        attacker_action=("Drop a must-use-plugin at wp-content/mu-plugins/ "
                         "(auto-loaded, survives core updates) + wp_cron "
                         "entry pinging a C2 every 15 min."),
        defender_should_see=("new file in /wp-content/mu-plugins/. Aegis "
                             "file-integrity sensor fires on this."),
    ))

    g.add(AttackEdge(
        name="Exposed wp-config.php.bak → credentials + salts",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.CREDENTIALS_LEAKED,
        trigger_kinds=("exposed_config",),
        trigger_predicate=_is_dangerous_config_leak,
        cost_minutes=1, success_prob=0.99, detectability=0.05,
        mitre_technique="T1592.004 — Gather Victim Host Information: Client Configurations",
        attacker_action=("GET /wp-config.php.bak — file returned with 200. "
                         "Contains DB creds, salts, secrets. Game over without "
                         "exploiting a single vulnerability."),
        defender_should_see=("Any request to *.bak / .git / .env should be "
                             "blocked at nginx level, not served."),
        replay_command="curl -s https://TARGET/wp-config.php.bak | head -50",
    ))

    g.add(AttackEdge(
        name="Database write → forge admin user",
        from_state=AttackState.DATABASE_WRITE,
        to_state=AttackState.ACCOUNT_ADMIN,
        trigger_kinds=(),
        cost_minutes=1, success_prob=0.99, detectability=0.20,
        mitre_technique="T1136 — Create Account",
        attacker_action=("INSERT INTO wp_users (user_login,user_pass,...) + "
                         "INSERT INTO wp_usermeta (user_id,meta_key,meta_value) "
                         "VALUES (N,'wp_capabilities','a:1:{s:13:\"administrator\"}'). "
                         "Log in normally."),
    ))

    g.add(AttackEdge(
        name="Admin account + admin-ajax RCE primitive → code execution",
        from_state=AttackState.ACCOUNT_ADMIN,
        to_state=AttackState.CODE_EXECUTION,
        trigger_kinds=(),
        cost_minutes=5, success_prob=0.85, detectability=0.30,
        mitre_technique="T1059 — Command and Scripting Interpreter",
        attacker_action=("Use theme-editor or plugin-editor in wp-admin to "
                         "inject PHP into a loaded file, then trigger it via "
                         "normal page load."),
    ))

    g.add(AttackEdge(
        name="Code execution → customer data → exfil",
        from_state=AttackState.CODE_EXECUTION,
        to_state=AttackState.DATA_EXFIL,
        trigger_kinds=(),
        cost_minutes=10, success_prob=0.95, detectability=0.45,
        mitre_technique="T1048 — Exfiltration Over Alternative Protocol",
        attacker_action=("mysqldump wp_users + WooCommerce tables + any "
                         "PII-bearing plugins. Compress and POST to attacker "
                         "C2 or tunnel via DNS-over-HTTPS."),
        defender_should_see=("egress traffic spike; outbound DNS TXT "
                             "queries of anomalous size."),
    ))

    g.add(AttackEdge(
        name="Code execution → lateral to shared-hosting neighbours",
        from_state=AttackState.CODE_EXECUTION,
        to_state=AttackState.LATERAL,
        trigger_kinds=(),
        cost_minutes=45, success_prob=0.40, detectability=0.30,
        mitre_technique="T1021 — Remote Services",
        attacker_action=("If on shared hosting: scan ../ for other WP sites "
                         "the web-user has read access to. Plant webshells "
                         "in each. At scale this is how single-site breaches "
                         "become mass breaches."),
    ))

    # REST authz placeholder — third-party namespace discovered
    g.add(AttackEdge(
        name="Unauth REST endpoint → option modify → admin takeover",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.ACCOUNT_ADMIN,
        trigger_kinds=("rest_authz",),
        cost_minutes=20, success_prob=0.45, detectability=0.35,
        mitre_technique="T1190 — Exploit Public-Facing Application",
        defense_pruned_by=("wordfence",),
        attacker_action=("POST /wp-json/<ns>/<route> anonymously (no "
                         "permission_callback). Set users_can_register=1 + "
                         "default_role=administrator. Register, log in."),
    ))

    # LFI → CODE_EXECUTION via log-poisoning
    g.add(AttackEdge(
        name="LFI → wp-config.php → DB creds + salts",
        from_state=AttackState.UNAUTHENTICATED,
        to_state=AttackState.CREDENTIALS_LEAKED,
        trigger_kinds=("lfi",),
        trigger_predicate=_is_wp,
        cost_minutes=10, success_prob=0.85, detectability=0.30,
        mitre_technique="T1552.001 — Credentials In Files",
        defense_pruned_by=("wordfence", "cloudflare"),
        attacker_action=("LFI reads /var/www/html/wp-config.php via "
                         "php://filter/convert.base64-encode/resource="),
    ))

    # FULL_COMPROMISE — terminal merge
    g.add(AttackEdge(
        name="Persistence + data exfil = full compromise",
        from_state=AttackState.PERSISTENCE,
        to_state=AttackState.FULL_COMPROMISE,
        trigger_kinds=(),
        cost_minutes=1, success_prob=0.95, detectability=0.0,
        mitre_technique="",
        attacker_action=("Once persistence is established, attacker returns "
                         "when convenient. Full compromise is the business "
                         "outcome, not a technical step."),
    ))

    g.add(AttackEdge(
        name="Code execution alone = full compromise",
        from_state=AttackState.CODE_EXECUTION,
        to_state=AttackState.FULL_COMPROMISE,
        trigger_kinds=(),
        cost_minutes=0, success_prob=1.0, detectability=0.0,
        mitre_technique="",
        attacker_action="RCE = full compromise of this host.",
    ))

    return g


__all__ = [
    "AttackState", "AttackEdge", "AttackGraph",
    "build_wordpress_graph",
    "state_impact",
    "_TERMINAL_GOALS",
]
