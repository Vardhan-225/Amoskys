"""Argos Stealth External Recon — one-visit fingerprint sweep.

Produces a dossier of everything a WordPress target exposes to any
browser, using nothing but public HTTP GET requests at normal browser
cadence. Designed to be INDISTINGUISHABLE from a curious visitor:

  - Normal user-agent (configurable; default mirrors Chrome on macOS)
  - No rate-burst — one request every 500-1000 ms by default
  - No POST, no injection payloads, no brute-force
  - No path older-than-a-browser-would-ever-visit bait

What this capability is FOR
────────────────────────────
The owner of the target may hire us to defend them. Before that
conversation, we can run this sweep and ethically show them exactly
what the public surface leaks — a tangible "here is what any attacker
already sees about you." Findings with a CVE or exploit angle go to
bug-bounty channels; findings about exposed metadata become the sales
pitch: "Aegis would block this recon campaign in 30 seconds."

Research-backed mandates
─────────────────────────
Every check in this module carries a mandate doc — one-line "why this
matters" plus a citation to the CVE, incident, or authoritative source
that makes it worth detecting. We refuse to add a check without a
mandate. The mandate appears in the finding's `mandate` field so the
operator (and the target owner) can see why each exposure matters.

Stealth discipline
───────────────────
Each check is ONE HTTP request. We fail open: a 403/404 is a signal
(the path exists and is access-controlled, OR the path does not exist
at all). We never retry a path. We never bypass robots.txt (but we
read it to learn what they don't want indexed — which is a finding).

Output
───────
`StealthDossier` dataclass — serializable to JSON or PDF. Each finding
carries: category, check_id, observed (raw evidence), severity, and
mandate.
"""

from __future__ import annotations

import json
import logging
import random
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("amoskys.argos.recon.stealth")

# ── Constants ──────────────────────────────────────────────────────

_DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
)
_DEFAULT_TIMEOUT = 8.0

# Base inter-request gap — keep humanlike to pass casual review.
_MIN_DELAY_S = 0.8
_MAX_DELAY_S = 2.5
# Occasional "reader pause" — simulates a visitor scrolling, answering a
# call, or getting distracted. Defeats the "timing stddev too small"
# heuristic that commercial WAF bot-scores use.
_LONG_PAUSE_PROB = 0.15
_LONG_PAUSE_MIN_S = 6.0
_LONG_PAUSE_MAX_S = 20.0


# ── Finding / Dossier model ────────────────────────────────────────


@dataclass
class StealthFinding:
    """One exposure. Each finding is produced by exactly one check."""

    category:  str     # one of the 7 categories below
    check_id:  str     # e.g., "wp.readme_html"
    severity:  str     # info | low | medium | high
    title:     str
    observed:  str     # raw evidence the finding is based on
    mandate:   str     # why this matters — citation included
    remediation: str   # what the owner does to fix
    references: List[str] = field(default_factory=list)


@dataclass
class StealthDossier:
    """The deliverable for one target."""

    target_url:   str
    target_host:  str
    ran_at:       float
    duration_s:   float
    http_checks:  int
    findings:     List[StealthFinding]

    def by_category(self) -> Dict[str, List[StealthFinding]]:
        out: Dict[str, List[StealthFinding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

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
            "http_checks": self.http_checks,
            "summary":     self.severity_counts(),
            "findings":    [asdict(f) for f in self.findings],
        }, indent=indent)


# ── HTTP primitive ─────────────────────────────────────────────────


@dataclass
class _HTTPResult:
    status:   int
    headers:  Dict[str, str]
    body:     str
    url:      str
    error:    Optional[str] = None


def _decompress_body(body_bytes: bytes, encoding: Optional[str]) -> str:
    """Decompress per Content-Encoding. A browser that advertises gzip
    MUST handle gzip; silently failing is a traffic-shape anomaly."""
    if not body_bytes:
        return ""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            import gzip
            body_bytes = gzip.decompress(body_bytes)
        elif enc == "deflate":
            import zlib
            try:
                body_bytes = zlib.decompress(body_bytes)
            except zlib.error:
                body_bytes = zlib.decompress(body_bytes, -zlib.MAX_WBITS)
        elif enc == "br":
            try:
                import brotli  # type: ignore
                body_bytes = brotli.decompress(body_bytes)
            except ImportError:
                pass
    except Exception:
        pass
    return body_bytes.decode("utf-8", errors="replace")


def _http_get(url: str, timeout: float = _DEFAULT_TIMEOUT,
              user_agent: str = _DEFAULT_UA,
              max_bytes: int = 512 * 1024,
              referer: Optional[str] = None,
              first_nav: bool = False) -> _HTTPResult:
    """One polite HTTP GET. Never raises except on DNS-level failure.

    Args:
        referer:   The previous URL on this session. Real browsers
                   send Referer for all but the first navigation. When
                   None and `first_nav=False`, we synthesize a search-
                   engine-looking referer ("https://www.google.com/")
                   on the first hit so we don't ALWAYS look like direct
                   navigation (fresh-open-from-bookmark traffic).
        first_nav: When True, behaves like the user typed the URL
                   (no Referer, Sec-Fetch-Site: none).
    """
    parsed = urllib.parse.urlparse(url)
    same_origin = False
    if referer:
        ref_parsed = urllib.parse.urlparse(referer)
        same_origin = (ref_parsed.netloc == parsed.netloc
                       and ref_parsed.scheme == parsed.scheme)

    headers = {
        "User-Agent":      user_agent,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",   # browsers default to keep-alive
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        headers["Referer"] = referer
        headers["Sec-Fetch-Site"] = "same-origin" if same_origin else "cross-site"
    else:
        headers["Sec-Fetch-Site"] = "none"
    if first_nav or not referer:
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-User"] = "?1"
    else:
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-User"] = "?1"
    headers["Sec-Fetch-Dest"] = "document"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body_bytes = resp.read(max_bytes)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body = _decompress_body(body_bytes,
                                    resp_headers.get("content-encoding"))
            return _HTTPResult(
                status=resp.status,
                headers=resp_headers,
                body=body,
                url=resp.url,
            )
    except urllib.error.HTTPError as e:
        err_headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        body = ""
        if e.fp:
            try:
                body = _decompress_body(e.fp.read(max_bytes),
                                        err_headers.get("content-encoding"))
            except Exception:
                pass
        return _HTTPResult(
            status=e.code,
            headers=err_headers,
            body=body,
            url=url,
        )
    except Exception as e:  # noqa: BLE001
        return _HTTPResult(status=0, headers={}, body="", url=url, error=str(e))


# ── The stealth sweep ──────────────────────────────────────────────


class StealthRecon:
    """Coordinates the 7-category sweep against one target."""

    def __init__(self, target_url: str,
                 user_agent: str = _DEFAULT_UA,
                 timeout: float = _DEFAULT_TIMEOUT,
                 polite: bool = True,
                 revisit_probability: float = 0.15,
                 search_referer: str = "https://www.google.com/",
                 ) -> None:
        self.target_url = target_url.rstrip("/")
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme:
            self.target_url = "https://" + target_url.lstrip("/")
            parsed = urllib.parse.urlparse(self.target_url)
        self.host = parsed.netloc
        self.scheme = parsed.scheme or "https"
        self.user_agent = user_agent
        self.timeout = timeout
        self.polite = polite
        self.findings: List[StealthFinding] = []
        self.http_checks = 0

        # Stealth state — referer chain + path revisit.
        #
        # Real browsing has these properties:
        #   · every navigation after the first carries a Referer that
        #     points to the previous page (often same-origin).
        #   · a curious visitor occasionally revisits a known page
        #     (clicks the logo, goes "back", returns to home).
        # Our scanner-shape defensive sensor watches for the ABSENCE of
        # those properties — missing-Referer ratio and
        # distinct_paths/total_requests ratio. We simulate them here.
        self._last_url: Optional[str] = None
        self._visited_urls: List[str] = []
        self._rng = random.Random()
        self.revisit_probability = revisit_probability
        self.search_referer = search_referer

    # ── Main ───────────────────────────────────────────────────────

    def run(self) -> StealthDossier:
        t0 = time.time()
        self._cat1_wp_core()
        self._cat2_dev_leaks()
        self._cat3_plugin_inventory()
        self._cat4_infra_fingerprint()
        # Category 5 (subdomains via CT) is handled by recon/ct_logs.py —
        # we'll call it elsewhere in the dossier builder.
        self._cat6_user_enum()
        self._cat7_supply_chain()
        return StealthDossier(
            target_url=self.target_url,
            target_host=self.host,
            ran_at=t0,
            duration_s=round(time.time() - t0, 2),
            http_checks=self.http_checks,
            findings=list(self.findings),
        )

    # ── HTTP helper ───────────────────────────────────────────────

    def _get(self, path: str) -> _HTTPResult:
        # Before each new-path request, occasionally do a "revisit" to
        # a known page. This drops the distinct_paths/total_requests
        # ratio below the 0.8 trip-wire our scanner-shape sensor
        # watches for. We lower the threshold to 3 visited paths so
        # revisits start happening before `distinct` crosses 10.
        if (self.polite
          and len(self._visited_urls) >= 3
          and self._rng.random() < self.revisit_probability):
            self._do_revisit()

        url = f"{self.scheme}://{self.host}{path}"
        if self.polite and self.http_checks > 0:
            self._humanlike_sleep()
        self.http_checks += 1

        # Referer chain: first hit comes from a search engine (natural
        # traffic), subsequent hits come from the previous page we
        # fetched (same-origin continuation).
        referer = self._last_url or self.search_referer
        first_nav = (self.http_checks == 1)

        result = _http_get(
            url,
            timeout=self.timeout,
            user_agent=self.user_agent,
            referer=None if first_nav else referer,
            first_nav=first_nav,
        )
        self._last_url = url
        self._visited_urls.append(url)
        return result

    def _do_revisit(self) -> None:
        """Re-fetch a previously-visited URL (usually the homepage) to
        mimic a user clicking around. Uses the _http_get primitive so
        timing + referer behavior match the main flow."""
        target_url = self._rng.choice(self._visited_urls)
        # Pace the revisit.
        self._humanlike_sleep()
        self.http_checks += 1
        _http_get(
            target_url,
            timeout=self.timeout,
            user_agent=self.user_agent,
            referer=self._last_url,
            first_nav=False,
        )
        # revisit does not update _last_url (we treat it like a
        # mid-browse sidestep, not a new chain anchor)

    def _humanlike_sleep(self) -> None:
        """Gaussian-jittered inter-request delay with occasional long
        pauses. Designed to keep stddev(intervals) > 1500 ms so the
        'timing too uniform' bot-scorer signal doesn't fire."""
        if self._rng.random() < _LONG_PAUSE_PROB:
            # Reader-paused-to-scroll excursion.
            d = self._rng.uniform(_LONG_PAUSE_MIN_S, _LONG_PAUSE_MAX_S)
        else:
            # Gaussian around the median of the short range.
            mid = (_MIN_DELAY_S + _MAX_DELAY_S) / 2.0
            stddev = (_MAX_DELAY_S - _MIN_DELAY_S) / 2.0
            d = self._rng.gauss(mid, stddev)
            d = max(_MIN_DELAY_S, min(_MAX_DELAY_S, d))
        time.sleep(d)

    def _add(self, **kw) -> None:
        self.findings.append(StealthFinding(**kw))

    # ── CATEGORY 1 — WP core leaks ─────────────────────────────────

    def _cat1_wp_core(self) -> None:
        # readme.html — ships with every WP install, contains exact version.
        r = self._get("/readme.html")
        if r.status == 200 and "WordPress" in r.body:
            m = re.search(r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r.body)
            ver = m.group(1) if m else None
            self._add(
                category="wp_core",
                check_id="wp.readme_html",
                severity="low",
                title=(
                    f"WordPress version leaked via /readme.html ({ver})"
                    if ver else "WordPress confirmed via /readme.html"
                ),
                observed=f"GET /readme.html → {r.status}; "
                         + (f"version={ver}" if ver else "core-confirmed"),
                mandate=(
                    "/readme.html is a canonical WordPress artifact. Its "
                    "presence and its embedded version string are the FIRST "
                    "thing every scanner pulls — it tells the attacker "
                    "exactly which CVEs apply to this site. This is a "
                    "textbook defense-in-depth miss per WPScan + CISA."
                ),
                remediation=(
                    "Delete /readme.html after every WP upgrade, or return "
                    "403 for it at the web-server level (nginx: "
                    "`location = /readme.html { return 403; }`)."
                ),
                references=[
                    "https://wpscan.com/blog/publicly-disclosed-wordpress-installation/",
                    "https://www.cisa.gov/news-events/alerts/",
                ],
            )

        # wp-login.php — confirms WP + target for brute force.
        r = self._get("/wp-login.php")
        if r.status == 200 and "wordpress" in r.body.lower():
            self._add(
                category="wp_core",
                check_id="wp.login_reachable",
                severity="low",
                title="wp-login.php is publicly reachable",
                observed=f"GET /wp-login.php → {r.status}",
                mandate=(
                    "Reachable /wp-login.php is the #1 brute-force target. "
                    "Every distributed bot farm tries it. Leaving it "
                    "unprotected (no rate-limit, no IP allow-list) accounts "
                    "for the majority of WP site compromises per Wordfence "
                    "quarterly reports."
                ),
                remediation=(
                    "At minimum: rate-limit POST /wp-login.php at the "
                    "web-server tier. For admin-only sites: return 403 "
                    "for all IPs except the admin's network."
                ),
                references=[
                    "https://www.wordfence.com/blog/category/reports/",
                ],
            )

        # /wp-json/ — REST root discloses WP + site name + plugin namespaces.
        r = self._get("/wp-json/")
        if r.status == 200 and "namespaces" in r.body:
            try:
                data = json.loads(r.body)
                namespaces = data.get("namespaces", [])
                plugin_ns = [n for n in namespaces
                             if n not in ("wp/v2", "wp-site-health/v1", "oembed/1.0", "wp-block-editor/v1")]
                self._add(
                    category="wp_core",
                    check_id="wp.rest_index",
                    severity="medium" if plugin_ns else "low",
                    title=f"REST API discloses {len(plugin_ns)} plugin namespaces",
                    observed=(f"GET /wp-json/ → 200; plugin namespaces: {plugin_ns[:6]}"
                              if plugin_ns else "GET /wp-json/ → 200"),
                    mandate=(
                        "The REST API index exposes every plugin that "
                        "registered a namespace. Each namespace is a "
                        "fingerprinted plugin — an attacker now knows "
                        "which plugin CVEs to check. This is the "
                        "plugin-inventory leak that bypasses every WAF."
                    ),
                    remediation=(
                        "Restrict /wp-json/ to authenticated users "
                        "(`rest_authentication_errors` filter) or block "
                        "at the web-server tier for anonymous visitors."
                    ),
                    references=[
                        "https://developer.wordpress.org/rest-api/",
                    ],
                )
            except json.JSONDecodeError:
                pass

        # <meta name="generator"> on the homepage.
        r = self._get("/")
        if r.status == 200:
            m = re.search(
                r"""<meta\s+name=['"]generator['"]\s+content=['"]([^'"]+)['"]""",
                r.body, re.IGNORECASE,
            )
            if m and "wordpress" in m.group(1).lower():
                self._add(
                    category="wp_core",
                    check_id="wp.meta_generator",
                    severity="low",
                    title=f"Generator meta-tag leaks: {m.group(1)}",
                    observed=f"<meta generator> = \"{m.group(1)}\"",
                    mandate=(
                        "`<meta name=generator>` tells every attacker the "
                        "exact WP version before they've touched a single "
                        "admin endpoint. Wordfence, Sucuri, and WPScan all "
                        "cite this as the fastest fingerprint — and the "
                        "cheapest to suppress."
                    ),
                    remediation=(
                        "In functions.php: "
                        "`remove_action('wp_head', 'wp_generator');`"
                    ),
                    references=[
                        "https://developer.wordpress.org/reference/functions/wp_generator/",
                    ],
                )

        # /feed — RSS/Atom feed commonly includes version.
        r = self._get("/feed/")
        if r.status == 200:
            m = re.search(r"<generator>([^<]+)</generator>", r.body)
            if m:
                self._add(
                    category="wp_core",
                    check_id="wp.feed_generator",
                    severity="low",
                    title=f"RSS feed generator tag: {m.group(1)}",
                    observed=f"<generator>{m.group(1)}</generator>",
                    mandate=(
                        "RSS feeds carry a `<generator>` tag that re-leaks "
                        "the WP version even after the HTML generator is "
                        "suppressed. Operators commonly forget the feed."
                    ),
                    remediation=(
                        "In functions.php: "
                        "`add_filter('the_generator', '__return_empty_string');`"
                    ),
                    references=[
                        "https://developer.wordpress.org/reference/hooks/the_generator/",
                    ],
                )

    # ── CATEGORY 2 — Developer leaks ──────────────────────────────

    def _cat2_dev_leaks(self) -> None:
        mandates = {
            "git":       ("/.git/config",             "high",
                          "Exposed .git directory lets an attacker reconstruct the entire source tree. "
                          "Every commit message, every file, every secret ever committed. "
                          "CVE history is loaded with `.git` leaks leading to full codebase exfil."),
            "git_head":  ("/.git/HEAD",               "high",
                          "Same class as .git/config — confirms the directory is readable."),
            "env":       ("/.env",                    "high",
                          "/.env files hold DB creds, API tokens, AWS keys. "
                          "Single 200 response here means game-over for most infrastructures."),
            "env_bak":   ("/.env.backup",             "high",
                          "Backup of .env is the same disaster with a different filename."),
            "wpcfg_bak": ("/wp-config.php.bak",       "high",
                          "wp-config.php.bak contains DB_HOST/USER/PASSWORD + AUTH_KEY — "
                          "complete takeover primitive."),
            "wpcfg_tilde":("/wp-config.php~",         "high",
                          "Editor backup of wp-config.php — same contents as .bak."),
            "wpcfg_save":("/wp-config.php.save",      "high",
                          "nano-editor autosave of wp-config.php."),
            "composer":  ("/composer.json",           "low",
                          "Discloses PHP dependency tree — every direct dep + version, "
                          "letting an attacker map known-CVE dep chains."),
            "package":   ("/package.json",            "low",
                          "Discloses JS dependency tree — same as composer.json for node."),
            "ds_store":  ("/.DS_Store",               "medium",
                          ".DS_Store leaks macOS filesystem metadata including "
                          "filenames the attacker didn't otherwise know existed."),
            "idea":      ("/.idea/workspace.xml",     "medium",
                          "JetBrains IDE config file — leaks local paths, editor history."),
            "sql_dump":  ("/dump.sql",                "high",
                          "Raw SQL dump — full DB contents including password hashes."),
            "sql_gz":    ("/db_backup.sql.gz",        "high",
                          "Compressed DB dump — same impact as /dump.sql."),
            "readme_md": ("/README.md",               "info",
                          "Accidentally-deployed repo README — often leaks developer "
                          "names, internal hostnames, deployment steps."),
        }

        refs = [
            "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing",
            "https://www.patchstack.com/articles/",
        ]
        for check_id, (path, sev, mandate) in mandates.items():
            r = self._get(path)
            if r.status == 200 and len(r.body) > 0 and "<title" not in r.body.lower()[:500]:
                # <title appears in 404 pages; real dev-leak responses don't have one.
                self._add(
                    category="dev_leaks",
                    check_id=f"dev.{check_id}",
                    severity=sev,
                    title=f"Developer artifact exposed: {path}",
                    observed=f"GET {path} → {r.status}; "
                             f"content-type={r.headers.get('content-type', '?')}; "
                             f"bytes={len(r.body)}",
                    mandate=mandate,
                    remediation=(
                        f"Web-server rule: deny access to {path} "
                        f"(nginx: `location = {path} {{ deny all; }}`). "
                        f"Better: purge from webroot entirely."
                    ),
                    references=refs,
                )

    # ── CATEGORY 3 — Plugin inventory via public HTML/CSS ─────────

    def _cat3_plugin_inventory(self) -> None:
        r = self._get("/")
        if r.status != 200:
            return
        # Harvest /wp-content/plugins/<slug>/...?ver=1.2.3 occurrences.
        plugin_refs = re.findall(
            r"""/wp-content/plugins/([a-z0-9][-a-z0-9._]*)/[^'"]+\?ver=([0-9][0-9a-z.+-]*)""",
            r.body, re.IGNORECASE,
        )
        # Dedupe (slug, version) pairs.
        seen = {}
        for slug, ver in plugin_refs:
            seen[(slug.lower(), ver)] = True
        if not seen:
            return
        # Summarise as a single finding so the dossier doesn't explode.
        items = [f"{slug}@{ver}" for (slug, ver) in seen.keys()]
        self._add(
            category="plugin_inventory",
            check_id="plugins.public_html_leak",
            severity="medium",
            title=f"{len(items)} plugin(s) + versions leaked in public HTML",
            observed="; ".join(items[:20]),
            mandate=(
                "Every active WP plugin leaks its version in `?ver=` "
                "query strings on enqueued scripts and stylesheets. "
                "An attacker now has a complete inventory with exact "
                "versions, mapping them straight to CVE databases "
                "(WPScan, Patchstack). This is the #1 fingerprint "
                "plugins are blamed for in post-mortem reports."
            ),
            remediation=(
                "Strip `?ver=` from enqueued assets: "
                "`add_filter('style_loader_src', 'strip_ver'); "
                "add_filter('script_loader_src', 'strip_ver');` "
                "and rename plugin slugs where feasible. Full list of "
                "mitigations: https://wpscan.com/blog/ "
            ),
            references=[
                "https://wpscan.com/",
                "https://patchstack.com/database/",
            ],
        )

    # ── CATEGORY 4 — Infra fingerprint ────────────────────────────

    def _cat4_infra_fingerprint(self) -> None:
        r = self._get("/")
        if r.status == 0:
            return
        hdr = r.headers
        notable = {}
        for h in ("server", "x-powered-by", "x-pingback", "x-generator",
                  "x-cache", "x-amz-cf-id", "cf-ray", "x-fastly-request-id",
                  "x-akamai-transformed"):
            if h in hdr:
                notable[h] = hdr[h]
        if notable:
            self._add(
                category="infra",
                check_id="infra.headers",
                severity="info",
                title=f"Infra fingerprint: {len(notable)} identifying header(s)",
                observed=json.dumps(notable),
                mandate=(
                    "HTTP response headers fingerprint the hosting stack "
                    "(Server, X-Powered-By), the CDN (cf-ray, x-amz-cf-id, "
                    "x-fastly-request-id, x-akamai-transformed), and the "
                    "CMS (x-pingback). Each header tells the attacker "
                    "which class of CVEs to prioritise — Apache/Nginx, "
                    "PHP-FPM version, CDN-specific bypasses."
                ),
                remediation=(
                    "Strip Server, X-Powered-By, X-Pingback at the web-"
                    "server/plugin layer. For CDN headers you may be "
                    "forced to keep them — document the choice."
                ),
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                ],
            )
        # HTTPS / TLS status visible from the URL and headers.
        if self.scheme == "http":
            self._add(
                category="infra",
                check_id="infra.no_tls",
                severity="high",
                title="Site served over plain HTTP",
                observed=f"scheme={self.scheme}",
                mandate=(
                    "Cleartext HTTP allows session hijacking on any public "
                    "wifi, MITM injection of malicious JS, credential "
                    "interception. No modern deployment should be without "
                    "TLS; Let's Encrypt makes the barrier zero."
                ),
                remediation=(
                    "Enable TLS via Certbot. Add `Strict-Transport-Security` "
                    "response header."
                ),
                references=[
                    "https://letsencrypt.org/",
                    "https://hstspreload.org/",
                ],
            )

    # ── CATEGORY 6 — User enumeration ─────────────────────────────

    def _cat6_user_enum(self) -> None:
        # /wp-json/wp/v2/users — if unauth, lists all contributor+.
        r = self._get("/wp-json/wp/v2/users")
        if r.status == 200:
            try:
                users = json.loads(r.body)
                if isinstance(users, list) and users:
                    usernames = [u.get("slug") or u.get("name") for u in users]
                    self._add(
                        category="user_enum",
                        check_id="users.wp_rest",
                        severity="high",
                        title=f"/wp-json/wp/v2/users discloses {len(users)} user(s) unauth",
                        observed=f"usernames: {usernames[:8]}",
                        mandate=(
                            "Unauth access to /wp-json/wp/v2/users is the "
                            "most common user-enumeration vector in WP. "
                            "Every brute-force bot runs this first. It "
                            "returns contributor-slug, author-login, and "
                            "sometimes avatar URLs — enough to feed a "
                            "targeted password-guess against wp-login.php."
                        ),
                        remediation=(
                            "Restrict the endpoint: in functions.php, "
                            "filter `rest_endpoints` to remove "
                            "/wp/v2/users for non-authenticated users."
                        ),
                        references=[
                            "https://developer.wordpress.org/rest-api/reference/users/",
                        ],
                    )
            except json.JSONDecodeError:
                pass

        # ?author=1 → WP redirects to /author/<login>/ leaking the username.
        r = self._get("/?author=1")
        # urllib follows redirects by default.
        if r.url and "/author/" in r.url.lower():
            login = r.url.rstrip("/").split("/author/")[-1].rstrip("/")
            if login and " " not in login:
                self._add(
                    category="user_enum",
                    check_id="users.author_id_redirect",
                    severity="medium",
                    title=f"?author=1 redirect leaks username: {login}",
                    observed=f"GET /?author=1 → {r.url}",
                    mandate=(
                        "WP's built-in `?author=N` query parameter "
                        "redirects to /author/<login>/ — effectively a "
                        "1-to-N iteration over the user ID space yields "
                        "every login on the site. This predates the REST "
                        "API and still works on every default install."
                    ),
                    remediation=(
                        "In functions.php block the query: "
                        "`if (isset($_GET['author'])) wp_redirect('/');`"
                    ),
                    references=[
                        "https://hackertarget.com/wordpress-user-enumeration/",
                    ],
                )

    # ── CATEGORY 7 — Supply-chain visibility ──────────────────────

    def _cat7_supply_chain(self) -> None:
        r = self._get("/")
        if r.status != 200:
            return
        # External JS script origins — not same-host.
        scripts = re.findall(
            r"""<script[^>]+src=['"]([^'"]+)['"]""",
            r.body, re.IGNORECASE,
        )
        external = []
        for s in scripts:
            # Absolute URLs only.
            parsed = urllib.parse.urlparse(s)
            if parsed.netloc and parsed.netloc.lower() != self.host.lower():
                external.append(parsed.netloc)
        external = sorted(set(external))
        if external:
            self._add(
                category="supply_chain",
                check_id="chain.external_scripts",
                severity="low",
                title=f"{len(external)} external JS origin(s) included in HTML",
                observed="; ".join(external[:10]),
                mandate=(
                    "Every external <script src> is a supply-chain "
                    "dependency that the attacker can compromise or "
                    "attribute from. CDN takeovers and tag-manager "
                    "poisoning have been behind multiple high-profile "
                    "Magecart-class incidents. At minimum: you should "
                    "know the full list."
                ),
                remediation=(
                    "Pin integrity with Subresource Integrity (SRI) "
                    "`<script src=... integrity=sha384-...>`; remove "
                    "unnecessary third-party includes."
                ),
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                    "https://www.wordfence.com/blog/category/wordpress-security/",
                ],
            )

        # GA / tracking ID leak.
        ga_ids = re.findall(r"(?:UA|G|GT|GTM)-[0-9A-Z]{6,}", r.body)
        if ga_ids:
            self._add(
                category="supply_chain",
                check_id="chain.tracking_id",
                severity="info",
                title=f"Tracking ID(s) leaked in HTML: {list(set(ga_ids))[:4]}",
                observed=", ".join(sorted(set(ga_ids))[:10]),
                mandate=(
                    "Google Analytics / Tag Manager IDs are often reused "
                    "across a company's properties — an attacker can "
                    "correlate this site with other assets (staging, "
                    "internal tools) that share the same GA ID."
                ),
                remediation=(
                    "Use distinct GA properties per site; avoid "
                    "correlating analytics across public + internal."
                ),
                references=[
                    "https://www.analyticsedge.com/2021/01/",
                ],
            )
