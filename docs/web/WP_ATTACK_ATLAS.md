# WordPress Attack Atlas v1

**Status:** living document. Last updated 2026-04-19.

**Purpose:** every door an attacker can touch on a WordPress site, cross-
referenced to (a) the existing Aegis sensor that watches it, (b) the
existing Argos tool/AST scanner that probes it, and (c) explicit `BLIND`
markers where we have no coverage yet. `BLIND` entries are the target
list for the next build cycle.

**Readers:** this is the single source of truth for "what is our
offensive and defensive coverage of WordPress right now?" Anyone asking
that should start here, not in the plugin code.

## How to read each row

```
L<layer>.<n>  <entry point>
  WATCH: <aegis sensor family or BLIND>
  PROBE: <argos tool/ast scanner or BLIND>
  CWE:   <primary CWE>
  NOTES: <known CVE families, exploitation pattern, reproducer pointer>
```

## Coverage score history

| Version | Aegis (defense) | Argos (offense) | Delta |
|---|---|---|---|
| v0.4 (baseline)        | 26/93 (28%) | 5/93 (5%)  | — |
| **v0.5 (SQLi pair)**   | **29/93 (31%)** | **9/93 (10%)** | **+3 WATCH, +4 PROBE** |

### v0.5 additions (this release)

**Defense — aegis.db.suspicious_query classifier** covers:
- L4.1 · SQLi in plugin AJAX/REST/shortcode (runtime `query` filter catches exploitation attempts regardless of which plugin was exploited)
- L6.1 · $wpdb->prepare format-string misuse (same runtime capture)
- L6.2 · Direct SQL without prepare (same)

**Offense — ast.sql_injection scanner** covers:
- L4.1 · SQLi in plugin source (interpolated query, prepare-with-interp, tainted global)
- L6.1 · $wpdb->prepare format-string misuse (static)
- L6.2 · Direct SQL without prepare (static)
- L9.6 · unserialize() detection → partial (not in this release, planned next)

### Current coverage

| Layer | Entries | Aegis | Argos |
|---|---|---|---|
| L0 · Edge/infra          | 9  | 2/9   | 0/9 |
| L1 · HTTP edge           | 10 | 3/10  | 2/10 |
| L2 · Core auth           | 9  | 6/9   | 1/9 |
| L3 · Core surface        | 11 | 7/11  | 1/11 |
| L4 · Plugins             | 14 | **4/14** | **2/14** |
| L5 · Themes              | 6  | 1/6   | 0/6 |
| L6 · DB/session          | 7  | **4/7**  | **2/7** |
| L7 · Filesystem          | 8  | 1/8   | 0/8 |
| L8 · Supply chain        | 6  | 1/6   | 0/6 |
| L9 · Server exec         | 7  | 0/7   | 0/7 |
| L10 · Business logic     | 6  | 0/6   | 0/6 |
| **Total**                | **93** | **29/93 (31%)** | **9/93 (10%)** |

Still not bug-bounty grade. The gap remains the build list — file-upload,
POI, CSRF, SSRF, XSS, dangerous-functions, and the sandbox infra.

---

## L0 — Edge / Infrastructure

```
L0.1 DNS takeover (dangling CNAME, subdomain to retired SaaS)
  WATCH: BLIND
  PROBE: argos.recon.dns_resolve (detects, doesn't flag)
  CWE:   CWE-350
  NOTES: Separate from WP entirely. We see it during recon.
         Detection: reverse-lookup every A record, flag NXDOMAIN on CNAME.

L0.2 TLS downgrade / weak cipher / no HSTS
  WATCH: BLIND
  PROBE: argos.recon.tls_cert (captures cert, no cipher audit)
  CWE:   CWE-326
  NOTES: Could be a passive offense scan (nmap ssl-enum-ciphers).

L0.3 Expose .git/ directory in webroot
  WATCH: aegis.404.observed (classifier: config_leak_probe)
  PROBE: BLIND (should be a 1-URL HEAD check in argos recon)
  CWE:   CWE-538
  NOTES: Classic. wp.org does not deploy via git so any /.git/config
         response ≠ 404 is exfiltrable history.

L0.4 Expose .env, wp-config.bak, wp-config~, wp-config.php.save
  WATCH: aegis.404.observed (wp_config_probe, config_leak_probe)
  PROBE: BLIND
  CWE:   CWE-538
  NOTES: 8 known variant filenames. Should be batched HEAD checks
         with a recon plugin; every 200 is a critical finding.

L0.5 phpMyAdmin / adminer / DB web UI reachable
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-284
  NOTES: /phpmyadmin, /pma, /dbadmin, /adminer.php. Typically
         operator-error, not WP itself.

L0.6 FPM socket / listener exposed beyond loopback
  WATCH: BLIND (host-level, not plugin-level)
  PROBE: BLIND (needs port-scan; too noisy for stealth)
  CWE:   CWE-284
  NOTES: CVE-2019-11043 class. Defense is nginx config review.

L0.7 xmlrpc.php reachable → pingback / system.multicall amplification
  WATCH: aegis.http.request (captures but doesn't flag)
  PROBE: BLIND (should have an argos.tools.xmlrpc_bruteforce)
  CWE:   CWE-307
  NOTES: 500-pass brute per request via system.multicall. Aegis
         needs to fingerprint this specifically, not just log it.

L0.8 wp-cron.php reachable as DOS amplifier
  WATCH: aegis.cron.run (sees internal runs, not external hits)
  PROBE: BLIND
  CWE:   CWE-400
  NOTES: Every external POST to /wp-cron.php spawns a sub-request.
         Hammer it → exhaust FPM workers. v0.4 block engine can
         now threshold this if we wire it as a strike rule.

L0.9 readme.html / wp-links-opml.php version disclosure
  WATCH: BLIND
  PROBE: BLIND (trivial: HEAD + regex)
  CWE:   CWE-200
  NOTES: First artifact every scanner pulls. Tells attacker exactly
         which CVEs apply.
```

## L1 — HTTP edge

```
L1.1 Direct plugin file access (e.g., /wp-content/plugins/<slug>/admin.php)
  WATCH: aegis.http.request + aegis.404.observed
  PROBE: BLIND
  CWE:   CWE-284
  NOTES: Many plugins ship admin helper files reachable directly,
         bypassing the wp-admin auth wrapper. Classic RCE source.

L1.2 Open proxy via media-library / tools-fetch endpoints
  WATCH: aegis.outbound.http (we see the egress, not the intent)
  PROBE: BLIND
  CWE:   CWE-918 (SSRF)
  NOTES: /wp-admin/tools.php action=fetch-oembed is a canonical
         SSRF source when plugins override oEmbed.

L1.3 Media upload accepting PHP via MIME confusion
  WATCH: aegis.media.uploaded (flags suspicious MIME)
  PROBE: argos.tools.nuclei (some templates)
  CWE:   CWE-434
  NOTES: .phtml, .phar, double-extension .jpg.php, content-sniff
         bypass. One of top-5 real-world RCE vectors.

L1.4 Theme ZIP upload backdoor
  WATCH: aegis.theme.switched + aegis.plugin.activated
  PROBE: BLIND
  CWE:   CWE-434
  NOTES: Legit admin action, but if the session is hijacked, this
         is how malware lands. Aegis sees it; we need a severity
         uplift when theme-switch is within N minutes of login from
         new IP.

L1.5 Plugin ZIP upload backdoor
  WATCH: aegis.plugin.activated
  PROBE: BLIND
  CWE:   CWE-434
  NOTES: Same pattern as L1.4. Trojaned plugins from unofficial
         marketplaces are the #1 initial-access method in WP surveys.

L1.6 admin-ajax.php nopriv action wildcard abuse
  WATCH: aegis.http.request (sees it, no classifier)
  PROBE: BLIND
  CWE:   CWE-862
  NOTES: Every plugin that registers wp_ajax_nopriv_<action> without
         an intended-public guard is an unauth attack surface.
         AST scanner: enumerate nopriv registrations, diff against
         a curated "safe" list.

L1.7 REST API route discovery via /wp-json/
  WATCH: aegis.rest.unauth_routes_detected
  PROBE: argos.tools.httpx (fetches the index)
  CWE:   CWE-200
  NOTES: Partial coverage — we see the index fetch.

L1.8 CORS misconfiguration on REST routes
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-942
  NOTES: Allow-Origin=* with Allow-Credentials=true on REST is
         a credential exfiltration bug.

L1.9 Open redirect (wp_safe_redirect bypass)
  WATCH: aegis.redirect.triggered (v0.3)
  PROBE: BLIND
  CWE:   CWE-601
  NOTES: v0.3 sees every redirect. Need severity classifier that
         flags external redirects emanating from a logged-out
         context (phishing chain).

L1.10 HTTP host-header poisoning in password reset
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-444
  NOTES: Classic CVE-2013-7459 class. wp_login_url() derives from
         Host; poisoned value lands in reset-email link.
```

## L2 — Core authentication

```
L2.1 wp-login.php brute force (standard password guessing)
  WATCH: aegis.auth.login_failed + aegis.nonce.failed
  PROBE: BLIND (by design — we don't brute-force targets)
  CWE:   CWE-307
  NOTES: v0.4 block engine catches 8 fails/60s → 10min block.

L2.2 xmlrpc.php credential brute (system.multicall)
  WATCH: aegis.auth.login_failed (partial — XMLRPC failures
         don't always hit wp_login_failed)
  PROBE: BLIND
  CWE:   CWE-307
  NOTES: Bypasses wp-login.php rate limiting if enforced there.

L2.3 Username enumeration via /wp-json/wp/v2/users
  WATCH: aegis.rest.response (sees the 200)
  PROBE: argos.tools.httpx
  CWE:   CWE-200
  NOTES: Aegis detects fetch, doesn't alarm. Need classifier:
         any unauth GET to /wp/v2/users returning a non-empty
         array is a finding.

L2.4 Username enumeration via ?author=<N>
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-200
  NOTES: Redirects to /author/<login>/ — classic enum.

L2.5 Password-reset token predictability / timing leak
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-330
  NOTES: core is mostly fine; plugins that re-implement reset
         are the vuln surface.

L2.6 Session fixation via persistent auth cookies
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-384
  NOTES: Pre-login cookies that survive login are the vector.

L2.7 Auth cookie forgery when AUTH_KEY is leaked
  WATCH: BLIND (would require wp-config.php SHA diff we already
         emit via aegis.fim.wpconfig_modified — but not a leak
         detector)
  PROBE: BLIND
  CWE:   CWE-798
  NOTES: If any of the 8 wp-config secrets leak, attacker forges
         admin auth without hitting login. Near-invisible.

L2.8 2FA bypass on plugins claiming MFA
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-287
  NOTES: Many "2FA" plugins have been broken by state-mismatched
         second-factor flows. Plugin-specific.

L2.9 Capability-escalation via roles editor
  WATCH: aegis.capability.denied + aegis.options.updated
  PROBE: BLIND
  CWE:   CWE-269
  NOTES: Modifying wp_user_roles option promotes attacker to admin.
         Aegis v0.3 sees the option update. Need classifier on it.
```

## L3 — WordPress core surface

```
L3.1 REST unauth-routes registered by any plugin
  WATCH: aegis.rest.unauth_routes_detected
  PROBE: argos.ast.rest_authz (permission_callback=true detector)
  CWE:   CWE-862
  NOTES: The AST scanner we already shipped. Extend it with
         (a) __return_true detector, (b) is_user_logged_in() alone
         without capability check.

L3.2 REST PHP Object Injection via serialized body
  WATCH: aegis.rest.poi_canary
  PROBE: BLIND
  CWE:   CWE-502
  NOTES: v0.4 canary fires; v0.4 block engine blocks on 1 hit.

L3.3 admin-ajax.php auth'd action CSRF
  WATCH: aegis.nonce.failed
  PROBE: BLIND
  CWE:   CWE-352
  NOTES: Aegis sees the failed nonce → strikes. Doesn't see actions
         that bypass nonce entirely.

L3.4 Media upload MIME-sniff bypass
  WATCH: aegis.media.uploaded (mime classifier)
  PROBE: BLIND
  CWE:   CWE-434
  NOTES: Need matching AST rule: any wp_handle_upload call in
         plugin source without the mimes-allowed filter is suspect.

L3.5 Media EXIF XSS / SVG script injection
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-79
  NOTES: SVG upload → stored XSS on preview. Core allows SVG if
         plugin enables it.

L3.6 oEmbed SSRF
  WATCH: aegis.outbound.http
  PROBE: BLIND
  CWE:   CWE-918
  NOTES: Attacker posts content containing a malicious oEmbed URL;
         server fetches. Aegis sees the egress.

L3.7 Options-table direct write (update_option of arbitrary key)
  WATCH: aegis.options.updated
  PROBE: BLIND
  CWE:   CWE-862
  NOTES: Aegis v0.3 sees every update_option. Classifier needed
         for sensitive keys: active_plugins, wp_user_roles,
         siteurl, home, admin_email, template, stylesheet.

L3.8 Serialized option tampering (PHP object injection)
  WATCH: aegis.options.updated (sees fact of update, not payload)
  PROBE: BLIND
  CWE:   CWE-502
  NOTES: Emit hash of new value; compare distribution.

L3.9 Post meta deserialization POI
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-502
  NOTES: Plugins that store object in postmeta and later unserialize
         untrusted input. AST scanner: unserialize( $_POST / $_REQUEST
         / get_post_meta ).

L3.10 Shortcode callback injection
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-79
  NOTES: Shortcodes that echo $atts without esc_*. AST scanner.

L3.11 Customizer option injection
  WATCH: aegis.options.updated
  PROBE: BLIND
  CWE:   CWE-79
  NOTES: Any theme_mod update that lands in <head> without
         esc_attr is a vector.
```

## L4 — Plugins (the kill zone)

```
L4.1  SQLi in plugin AJAX/REST/shortcode
  WATCH: aegis.db.suspicious_query (v0.5 — 8 pattern classes)
  PROBE: argos.ast.sql_injection (v0.5 — 5 rules, 16 tests passing)
  CWE:   CWE-89
  NOTES: Most common plugin CVE class by a wide margin. v0.5 both
         detects exploitation AT RUNTIME (via the `query` filter) and
         FINDS IT IN SOURCE (via the AST scanner). 2 strikes → block.

L4.2  Authz bypass (CVE-2023-52174 LayerSlider, CVE-2024-10924 Really
      Simple SSL class — wildly famous examples)
  WATCH: aegis.capability.denied (fires AFTER check — not when
         check is missing)
  PROBE: argos.ast.rest_authz (partial)
  CWE:   CWE-285
  NOTES: We see denials, not absences. The absence is the bug.

L4.3  Arbitrary file upload
  WATCH: aegis.media.uploaded
  PROBE: BLIND (AST: move_uploaded_file without mime/path checks)
  CWE:   CWE-434

L4.4  Arbitrary file read (LFI via download.php pattern)
  WATCH: BLIND
  PROBE: BLIND (AST: readfile/fopen with request-derived path)
  CWE:   CWE-22

L4.5  CSRF on state-change endpoints (missing check_admin_referer)
  WATCH: aegis.nonce.failed
  PROBE: BLIND (AST: admin_post_* / admin-ajax handlers without
         check_admin_referer in first 5 statements)
  CWE:   CWE-352

L4.6  IDOR on user-scoped resources
  WATCH: BLIND
  PROBE: BLIND (AST: get_post/get_user_meta with ID from request
         and no author-match check)
  CWE:   CWE-639

L4.7  SSRF via URL-fetch features
  WATCH: aegis.outbound.http
  PROBE: BLIND (AST: wp_remote_get(request-input) without host
         allow-list)
  CWE:   CWE-918

L4.8  Stored XSS
  WATCH: BLIND
  PROBE: BLIND (AST: echo of user-controlled value without
         esc_html/esc_attr/wp_kses)
  CWE:   CWE-79

L4.9  Reflected XSS
  WATCH: BLIND
  PROBE: argos.tools.nuclei (some templates)
  CWE:   CWE-79

L4.10 DOM XSS in plugin-shipped JS
  WATCH: aegis.browser.* (v0.4 beacon sees events, not XSS itself)
  PROBE: BLIND
  CWE:   CWE-79

L4.11 PHP Object Injection in plugin unserialize
  WATCH: aegis.rest.poi_canary (core surface only)
  PROBE: BLIND (AST: unserialize(request-input))
  CWE:   CWE-502

L4.12 Privilege escalation (capability check elsewhere than entry)
  WATCH: aegis.capability.denied
  PROBE: BLIND
  CWE:   CWE-269

L4.13 Nonce race (check-then-use with time-of-check bug)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-367

L4.14 Hardcoded credentials / API keys in plugin
  WATCH: BLIND
  PROBE: BLIND (AST: regex against known key prefixes — GitHub,
         AWS, Stripe, SendGrid)
  CWE:   CWE-798
```

## L5 — Themes

```
L5.1  Theme option CSRF
  WATCH: aegis.nonce.failed
  PROBE: BLIND
  CWE:   CWE-352

L5.2  Unsanitized shortcode attributes → XSS
  WATCH: BLIND
  PROBE: BLIND (AST)
  CWE:   CWE-79

L5.3  Customizer CSS injection
  WATCH: aegis.options.updated (sees the write)
  PROBE: BLIND
  CWE:   CWE-79

L5.4  TimThumb-class image-fetch SSRF
  WATCH: aegis.outbound.http
  PROBE: BLIND
  CWE:   CWE-918

L5.5  Theme update mechanism bypass (self-updater replay)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-494

L5.6  PHP execution inside uploaded theme file (if FTP mode)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-434
```

## L6 — Database / session

```
L6.1  $wpdb->prepare format-string misuse
  WATCH: aegis.db.suspicious_query (v0.5)
  PROBE: argos.ast.sql_injection — rule sql.prepare_with_interpolation
  CWE:   CWE-89

L6.2  Direct SQL without prepare
  WATCH: aegis.db.suspicious_query (v0.5)
  PROBE: argos.ast.sql_injection — rules sql.interpolation_in_query,
         sql.direct_request_query, sql.raw_mysqli_query
  CWE:   CWE-89

L6.3  Exposed DB port beyond loopback
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-284

L6.4  Session fixation
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-384

L6.5  Cookie forgery (AUTH_KEY leak)
  WATCH: aegis.fim.wpconfig_modified (sees change, not leak)
  PROBE: BLIND
  CWE:   CWE-798

L6.6  Backup archive readable in webroot
  WATCH: aegis.404.observed (classifier: config_leak_probe
         catches .sql, .zip)
  PROBE: BLIND (HEAD checks against common names)
  CWE:   CWE-538

L6.7  mysqldump output grabbable via cron-triggered path
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-538
```

## L7 — Filesystem

```
L7.1  wp-content writable by www-data user AND attacker
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-732

L7.2  .htaccess overwrite by plugin
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-732

L7.3  Symlink attack in multisite uploads/
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-61

L7.4  Temp file race (predictable tmpnam in plugin)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-362

L7.5  Session file disclosure (save_path readable)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-538

L7.6  wp-config.php unauthorized modification
  WATCH: aegis.fim.wpconfig_modified
  PROBE: BLIND
  CWE:   CWE-345

L7.7  Plugin-deposited PHP in uploads/
  WATCH: aegis.media.uploaded
  PROBE: BLIND
  CWE:   CWE-434

L7.8  Core file tampering (modified wp-includes)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-345
```

## L8 — Supply chain

```
L8.1  Plugin author acquisition → malicious update
  WATCH: aegis.supply_chain.drift (v0.4 AUTHOR_CHANGED)
  PROBE: BLIND
  CWE:   CWE-494
  NOTES: This is the rung we just built. EssentialPlugin class.

L8.2  Dormant-plugin reactivation → silent malicious release
  WATCH: aegis.supply_chain.drift (v0.4 SUDDEN_UPDATE_AFTER_LONG_SILENCE)
  PROBE: BLIND

L8.3  Abandoned plugin still installed
  WATCH: aegis.supply_chain.drift (v0.4 STALE_FOR_YEARS)
  PROBE: BLIND

L8.4  Compromised external JS CDN
  WATCH: BLIND (we don't hash external <script src=>)
  PROBE: BLIND
  CWE:   CWE-494

L8.5  Nulled-plugin trojan (unofficial pirate copy with backdoor)
  WATCH: BLIND
  PROBE: BLIND (AST: scan installed plugin source for
         base64_decode/eval/goto obfuscation)
  CWE:   CWE-506

L8.6  Update-server MITM or compromise
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-300
```

## L9 — Server-side execution

```
L9.1  eval() / assert() with request-derived input
  WATCH: BLIND
  PROBE: BLIND (AST: trivially scannable)
  CWE:   CWE-95

L9.2  preg_replace /e modifier
  WATCH: BLIND
  PROBE: BLIND (AST)
  CWE:   CWE-95
  NOTES: PHP 7+ removed /e — but legacy plugins still have it.

L9.3  create_function() with request input
  WATCH: BLIND
  PROBE: BLIND (AST)
  CWE:   CWE-95
  NOTES: Removed in PHP 8 — flag as deprecated, still seen in wild.

L9.4  system() / exec() / passthru() / shell_exec()
  WATCH: BLIND
  PROBE: BLIND (AST)
  CWE:   CWE-78

L9.5  include() / require() with request-derived path
  WATCH: BLIND
  PROBE: BLIND (AST: LFI)
  CWE:   CWE-98

L9.6  unserialize() with request-derived payload
  WATCH: aegis.rest.poi_canary (core surface only)
  PROBE: BLIND (AST for plugin coverage)
  CWE:   CWE-502

L9.7  XXE in XML parsing (libxml_disable_entity_loader off)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-611
```

## L10 — Business logic (WooCommerce & friends)

```
L10.1 Coupon stacking beyond intent
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-840

L10.2 Price manipulation via POST (cart_item_data tampering)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-840

L10.3 Order status forging (payment bypass)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-840

L10.4 Subscription renewal bypass
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-840

L10.5 Refund abuse
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-840

L10.6 Stock-level race (buy more than stock)
  WATCH: BLIND
  PROBE: BLIND
  CWE:   CWE-362
```

---

## The build list (derived from BLIND markers)

Ranked by (impact × feasibility):

**Tier 1 — AST scanners to add to `src/amoskys/agents/Web/argos/ast/`:**
1. `sql_injection.py` — $wpdb->query/prepare format-string misuse (L4.1, L6.1, L6.2)
2. `file_upload.py` — move_uploaded_file / wp_handle_upload without
   MIME/extension checks (L4.3, L7.7)
3. `file_read.py` — readfile/fopen/include with request-derived path
   (L4.4, L9.5)
4. `csrf.py` — admin_post_* handlers without check_admin_referer (L4.5)
5. `ssrf.py` — wp_remote_get/file_get_contents with request input (L4.7)
6. `xss.py` — echo of $_REQUEST/$_POST/$_GET without esc_* (L4.8, L4.9)
7. `poi.py` — unserialize(request) plugin-wide (L4.11, L9.6)
8. `dangerous_functions.py` — eval/assert/preg_replace-e/create_function/
   system family (L9.1–L9.4)
9. `nopriv_actions.py` — wp_ajax_nopriv_* registrations (L1.6)
10. `hardcoded_secrets.py` — AWS/Stripe/SendGrid/GitHub tokens (L4.14)

**Tier 2 — Aegis sensor additions:**
1. Version-disclosure classifier on readme.html / x-generator header (L0.9)
2. XML-RPC request classifier (L0.7, L2.2)
3. Sensitive-option classifier on active_plugins/wp_user_roles/siteurl/etc.
   (L3.7, L2.9)
4. Unauth /wp-json/wp/v2/users alarm (L2.3)
5. ?author=N enumeration detector (L2.4)
6. Theme-switch severity uplift when paired with new-IP admin login (L1.4)
7. External redirect classifier on aegis.redirect (L1.9)

**Tier 3 — Sandbox infrastructure:**
1. Live-site plugin inventory fetcher (extend existing
   `plugin_inventory.py`): capture plugin slug + version per target
2. Version-matched source puller from wp.org SVN tag
3. Per-target analysis container (Docker, read-only mount, semgrep +
   phpstan + our AST scanners)
4. Finding → Aegis-rule synthesis pipeline: every confirmed bug
   becomes a new detection rule
5. MCP tools: `hunt_target(url)`, `analyze_plugin(slug, version)`,
   `list_blind_spots()`

**Benchmark harness (Tier 4):**
1. CVE corpus: 20 plugins × 3 CVE per plugin, each with PoC
2. Automated deployment of vulnerable version to scratch WP
3. Argos runs engagement → Aegis observes → score: (detected ∩ CVE) / CVE
4. Measure MTTD (time between exploit fire and high-severity event)
5. Measure FP rate over 24h synthetic clean traffic

When all three tiers land, the scoreboard becomes real and we can call
ourselves bug-bounty grade. Until then, this doc is the honest picture.
