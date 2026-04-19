# The Aegis Observability Mandate v1

> *"We cannot detect or block what we cannot see."*
>
> Robust observation is non-negotiable. Detection, correlation, and
> response layers are all downstream of — and structurally bounded by —
> what the sensor tier captured in the first place. A blind sensor
> produces a blind brain, and a blind brain produces a blind product.
> That is where customer trust is earned or lost.

This document is the **governing constitution** for what Aegis must
observe, how strictly it must log, and the ladder along which we close
gaps as we grow.

It reads "top-down": principles → current state → the tiny-breath
mandate → the six-tier observability ladder → per-tier capture surface
→ gap inventory → closure roadmap.

---

## 1. Governing principles

### 1.1 The negative-space rule

Any event that occurs on a customer's WordPress site and is *not*
captured by Aegis is structurally invisible to every downstream
component of AMOSKYS Web. The brain cannot correlate it; the Proof
Spine cannot attest to it; IGRIS cannot respond to it; the customer
cannot be alerted about it.

We build as if every gap we leave is an attacker's chosen foothold.

### 1.2 Tiny-breath observability

We aspire to the smallest captureable signal in every tier. A "tiny
breath" is, concretely:

- One SQL query, with its timing, caller, and affected table
- One file byte written, with its path and the PHP stack that wrote it
- One capability check, with its user, target object, and outcome
- One REST route registration, including the permission callback it
  binds, at the moment it binds
- One failed nonce verification, with the action name and the source IP
- One option write, with the option name and the size delta
- One CSS preload, one 404, one redirect, one cron tick

Individually these are noise. At volume, under correlation, they become
the attack surface from the attacker's point of view. Forensics-ready
means recorded, chain-linked, immutable.

### 1.3 Strict logging doctrine

Strict means six things, all the time, no exceptions:

1. **Every event is chain-linked.** Aegis's SHA-256 prev_sig chain
   is the single proof-of-integrity surface. Any break is a signal.
2. **Every event has attribution.** Request IP, user-agent, user ID
   (if authed), request method + URI, timestamp in nanoseconds.
3. **No silent drops.** If `emit()` fails for any reason, the failure
   itself is recorded. Logging errors are first-class events.
4. **No sensor suppresses another.** A re-entrancy guard is correct;
   excluding noisy sensors is incorrect. Every sensor fires every
   time its trigger fires.
5. **PII is redacted, not omitted.** Option values containing
   secrets are replaced with their length + type; the option name
   itself is always recorded.
6. **The log is append-only and chain-verifiable.** Writes are flock-
   serialized; any integrity break on disk is visible in the chain
   on ingest.

---

## 2. Current state audit (v0.2 alpha)

### 2.1 What Aegis captures today

16 sensor families registered across 15 WordPress hook surfaces. Of
those, 15 are actively firing on `lab.amoskys.com` (the 16th,
`aegis.lifecycle.*`, fires only on Aegis's own activation and is
structurally one-off).

| Family | Hook surface | Coverage today |
|---|---|---|
| `aegis.auth` | `wp_login`, `wp_login_failed`, `set_user_role`, `user_register`, `password_reset` | Good |
| `aegis.rest` | `rest_api_init @ PHP_INT_MAX`, `rest_pre_dispatch` | Good (POI canary) |
| `aegis.plugin` | `activated_plugin`, `deactivated_plugin`, `upgrader_process_complete`, `delete_plugin` | Good |
| `aegis.theme` | `switch_theme` | Basic |
| `aegis.fim` | `shutdown` (wp-config hash) | **Narrow** |
| `aegis.outbound` | `pre_http_request` | Good (RPC signature) |
| `aegis.http` | `shutdown` (per-request) | Basic |
| `aegis.admin` | `admin_init` | Basic |
| `aegis.options` | `updated_option`, `added_option` | Good (with amoskys_* skip) |
| `aegis.cron` | `wp_loaded` DOING_CRON check | Basic |
| `aegis.mail` | `wp_mail_succeeded`, `wp_mail_failed` | Good |
| `aegis.post` | `save_post`, `transition_post_status`, `before_delete_post` | Good |
| `aegis.comment` | `wp_insert_comment` | Basic |
| `aegis.media` | `add_attachment`, `delete_attachment` | Good (with suspicious-MIME flag) |
| `aegis.db` | `shutdown` (query summary) | **Summary only** |
| `aegis.lifecycle` | `register_activation_hook` | One-off |

### 2.2 Baseline metrics from `lab.amoskys.com` (April 2026)

- 54,039 events captured cumulative
- 100% chain integrity
- External scanner pressure: **one IP (`139.87.112.106`) has generated
  42,309 events** — that's 78% of all traffic seen, sustained scanner
  reconnaissance over days
- 207 high-severity + 96 critical-severity events

### 2.3 What the current sensors do NOT see

This is the gap inventory — the honest "we're blind to this" list.

| Missing capture | Why it matters | Achievable in plugin tier? |
|---|---|---|
| Per-SQL-query (only summary today) | SQL injection detection; DB brute force; slow-query discovery | Yes — `query` filter, sampled |
| Per-capability-check | Privilege-escalation attempts (e.g. `current_user_can('manage_options')` from hostile code) | Yes — `user_has_cap` filter |
| File writes outside wp-config | Webshell drops, theme modification, plugin tampering | No — needs host-level FS watch |
| PHP errors / warnings | Attackers probe for error-message disclosures | Yes — `set_error_handler` |
| 404s | Scanner recon fingerprint; predictable probe patterns | Yes — `404_template` |
| Redirects | Open-redirect detection, phishing kits | Yes — `wp_redirect` filter |
| Shortcode invocations | Injected shortcodes (classic malvertising pattern) | Yes — `do_shortcode_tag` |
| Nonce verification attempts | CSRF probe rate | Yes — `check_admin_referer` |
| Registration attempts (vs successes) | Bot signup floods | Yes — `pre_user_registered` |
| REST response status | What the caller actually got back | Yes — `rest_post_dispatch` |
| Browser-side events | Cookie tampering, DOM injection, session stealing | Tier 6 (JS beacon) |
| TLS handshake fingerprint (JA3) | Scanner TLS signatures | Tier 4 (nginx module) |
| `eval`, `unserialize`, `assert` calls | PHP Object Injection, dynamic code execution | Tier 3 (PHP extension) |
| Network packet patterns | Layer-4 DDoS, slow-loris | Tier 5 (eBPF) |
| Pre-plugin-load HTTP | Attacks that run before plugins bootstrap | Tier 2 (auto_prepend) |

---

## 3. The six-tier observability ladder

We map sensors to six deployment tiers, each with distinct install
friction, capture surface, and bypass resistance.

```
┌─────────────────────────────────────────────────────────────────┐
│ TIER 0 — External (Argos)                                       │
│   What we see:  attacker's view — headers, JSON, public APIs    │
│   Install:      none (we own the scanner)                       │
│   Bypass:       impossible (caller can't hide from us)          │
├─────────────────────────────────────────────────────────────────┤
│ TIER 1 — WordPress plugin (Aegis today)                         │
│   What we see:  every WP hook; post-plugin-load lifecycle       │
│   Install:      WP admin → upload ZIP (2 min)                   │
│   Bypass:       any RCE in WP can unload us                     │
├─────────────────────────────────────────────────────────────────┤
│ TIER 2 — PHP auto_prepend_file                                  │
│   What we see:  every PHP request, BEFORE WordPress loads       │
│   Install:      php.ini edit (requires host-level access)       │
│   Bypass:       only by rewriting php.ini (harder)              │
├─────────────────────────────────────────────────────────────────┤
│ TIER 3 — PHP extension (.so / RASP)                             │
│   What we see:  every function call (eval, unserialize, exec)   │
│   Install:      php.ini extension= + worker restart             │
│   Bypass:       only by modifying php.ini or removing the .so   │
├─────────────────────────────────────────────────────────────────┤
│ TIER 4 — Web-server module (nginx / Apache)                     │
│   What we see:  raw HTTP, TLS handshake, pre-PHP drops          │
│   Install:      package + conf change + nginx reload            │
│   Bypass:       root on the host                                │
├─────────────────────────────────────────────────────────────────┤
│ TIER 5 — eBPF / kernel telemetry                                │
│   What we see:  every syscall, every socket, every file open    │
│   Install:      root on the host; modern kernel                 │
│   Bypass:       kernel root exploit only                        │
├─────────────────────────────────────────────────────────────────┤
│ TIER 6 — Browser JS beacon (customer-site assets)               │
│   What we see:  client-side DOM, cookie set, fetch, input       │
│   Install:      HTML snippet (one `<script>` tag)               │
│   Bypass:       attacker can block the script (adblock-style)   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.1 Capture surface per tier (the tiny-breath map)

For each tier, what's the smallest captureable signal?

| Tier | Tiny breath it can hear |
|---|---|
| 0 | HTTP status deltas, response-header drift, TLS cert change |
| **1** | **Every WP hook, every option write, every query start** |
| 2 | Every PHP SAPI variable, every `$_GET`/`$_POST` element pre-WP |
| 3 | Every `unserialize()` call, every `eval()`, every `file_get_contents()` to a variable URL |
| 4 | Every TLS handshake fingerprint, every HTTP method probe |
| 5 | Every fork, every connect() to a new IP, every inode write to `wp-content/` |
| 6 | Every keystroke timing, every form autofill, every fetch() |

### 3.2 Bypass resistance

The cost, to an attacker who has compromised the site at some level,
of silencing each tier:

| Tier | Attacker capability needed to bypass |
|---|---|
| 0 | Can never bypass — we don't install on their side |
| 1 | WP admin access OR arbitrary PHP write to plugin dir |
| 2 | `php.ini` write access (usually requires host-level creds) |
| 3 | Ability to remove `.so` or rewrite `extension=` line |
| 4 | Root + nginx reload |
| 5 | Kernel-level exploit |
| 6 | Can inject Content-Security-Policy; or compromise the served HTML |

Layered defence = attacker must bypass every tier to be fully silent.

---

## 4. The concrete closure plan (plugin-tier — immediately deployable)

These close every "Yes — plugin tier" gap from §2.3, in a single Aegis
sprint, without leaving the plugin.

### 4.1 New sensors to add (Aegis v0.3)

| Sensor | WP hook | Sampled? | Reason |
|---|---|---|---|
| `aegis.query.event` | `query` filter | 1-in-N for SELECT; all writes | SQLi, priv-esc via custom SQL |
| `aegis.query.slow` | `query` filter + duration | Always when > 100ms | Slow query discovery, brute DoS |
| `aegis.capability.denied` | `user_has_cap` filter | Always when denied | Privilege-escalation probe |
| `aegis.session.cookie_set` | `set_auth_cookie` | Always | Session hijack, cookie tampering |
| `aegis.session.cookie_cleared` | `clear_auth_cookie` | Always | Forced logout attempts |
| `aegis.nonce.failed` | `check_admin_referer` / `check_ajax_referer` | Always on fail | CSRF reconnaissance |
| `aegis.rest.response` | `rest_post_dispatch` | Always | Know what the caller got back |
| `aegis.redirect.triggered` | `wp_redirect`, `wp_safe_redirect` | Always | Open-redirect detection |
| `aegis.error.caught` | `set_error_handler` | Always (errors/warnings) | Error-message disclosure tracking |
| `aegis.404.observed` | `template_redirect` + `is_404()` | Always | Scanner pattern fingerprint |
| `aegis.shortcode.invoked` | `do_shortcode_tag` filter | 1-in-N (high volume) | Shortcode injection |
| `aegis.registration.attempted` | `pre_user_registered` | Always | Bot signup flood detection |
| `aegis.upload.bytes` | `wp_handle_upload_prefilter` | Always | Upload-size anomaly, suspicious MIME (extend media sensor) |
| `aegis.cache.miss` | `wp_cache` hooks | 1-in-N | Cache-poisoning reconnaissance |

That brings Aegis from 16 → 30 sensor families. Same hook surface
(`plugins_loaded@1`), same emitter, same chain-linked log.

### 4.2 Enrichments to existing sensors

| Sensor | Add | Why |
|---|---|---|
| `aegis.http.request` | Request-header hash, referer, X-Forwarded-For trust | Scanner fingerprinting beyond UA |
| `aegis.db.summary` | Per-table read/write counts | Catch tables being probed individually |
| `aegis.fim.wpconfig_modified` | Extend to hash all php files in /wp-content/plugins/ and /wp-content/themes/ (sampled on every 100th request) | Catch plugin-code tampering |
| `aegis.outbound.http` | Full URL host + path, response status, response time | Exfil-path characterization |
| `aegis.auth.login_failed` | Rolling burst count per IP (in memory) | Brute-force detection ready for IGRIS |
| `aegis.plugin.updated` | Compute sha256 of plugin main file, compare to prior update | Supply-chain anomaly |

### 4.3 Structural improvements

1. **Browser beacon (Tier 6, micro-scope)** — a tiny `<script>` that
   Aegis injects into `wp_head` for logged-in admin pages only.
   Captures page_visible, idle, click, visibilitychange, beforeunload.
   No tracking of public visitors; operator-observation only.

2. **Webhook ingest** — Aegis accepts `POST /aegis-ingest` for external
   probes (nginx-mirrored traffic, Cloudflare Workers, third-party
   scanners reporting their scan of your site). Signed with the same
   tenant bearer token.

3. **Strict chain enforcement on read** — the Command Center already
   verifies chain integrity on every snapshot. Formalize: any break
   is surfaced as a critical signal in the dashboard, not just a
   percentage.

4. **Burst compaction** — for high-volume sensors (http, db), write
   one event per (event_type, site_id, minute-bucket) with a count,
   in addition to the per-event chain. Two parallel logs: fine-grain
   for investigation, coarse-grain for trend/analytics.

---

## 5. The six-tier roadmap (with owners + timings)

| Tier | Scope | Engineering cost | When |
|---|---|---|---|
| 0 | Argos — done | — | Live |
| 1 (v0.3) | 14 new sensors + enrichments above | 1 focused sprint (~3 days) | Next week |
| 1.5 | Browser beacon (admin-only) | 1 day | After v0.3 lands |
| 2 | `auto_prepend_file` shim | 2 days + managed-host partnership | Month 2 |
| 3 | PHP extension (RASP) in C | 2-4 months | Month 4+ |
| 4 | nginx log-pipe module | 1 week | Month 3 |
| 5 | eBPF collector (Linux self-hosted only) | 2 weeks | Month 6 |
| 6 | Full public-visitor JS beacon | 2 weeks + privacy review | Month 3-4 |

---

## 6. Logging discipline — enforcement

Three things will enforce the strict-logging doctrine mechanically, so
human discipline isn't the only safeguard.

### 6.1 `tests/web_aegis/test_every_sensor_fires.php`

CI test that installs Aegis into a throwaway WordPress, triggers each
sensor's canonical cause (login_failed via POST, option change via
`update_option`, etc.), and asserts the corresponding event was
written to the log with the correct event_type and a valid chain
signature.

Any PR that breaks any sensor fails CI.

### 6.2 `tests/web_aegis/test_chain_integrity.php`

CI test that emits 1000 events from 8 concurrent workers (simulating
PHP-FPM), then reads the log back and asserts ≥ 90% chain integrity.
This is our regression guard on the flock-serialized writer.

### 6.3 Log-reader invariants (aegis_live.py)

On every `AegisTail.snapshot()`, we compute and record:

- total events
- chain break count + percentage
- events-per-minute rolling (detect silence = sensor death)
- unknown event types (detect schema drift)

Any silence gap > 10 minutes on a live site = ops signal.

---

## 7. "A tiny breath on the website you are logged" — commitment

This is what a customer subscribing to AMOSKYS Web is buying:

> *On your WordPress site, when a visitor loads a page, our plugin
> captures the request, the query batch, the options touched, the
> response status, the outbound calls made, the cookies set, and the
> time it took. When they click, scroll, or idle, our beacon records
> it. When they submit a form, every field's length, every nonce
> verification, every redirect, every shortcode that fired is logged.
> When they log out, every session lifecycle event is chained. Every
> one of those signals is cryptographically chain-linked to the next.
> You can hand the chain to an auditor at any time.*
>
> *When an attacker hits your site, they are doing it in a lit room
> we built.*

That is the mandate.

---

## Appendix A — Sensor catalog for v0.3

Complete list of Aegis sensors after v0.3 ships. 30 families total.

```
aegis.auth.{login_success, login_failed, role_change,
             user_registered, password_reset,
             cookie_set, cookie_cleared,
             nonce_failed}
aegis.rest.{unauth_routes_detected, poi_canary,
             dispatch_response}
aegis.plugin.{activated, deactivated, updated, deleted,
              supply_chain_drift}
aegis.theme.{switched, updated}
aegis.fim.{wpconfig_modified, plugin_file_modified,
           theme_file_modified}
aegis.outbound.{http, ethereum_rpc, suspicious_host}
aegis.http.{request}
aegis.admin.{page_view}
aegis.options.{added, updated, deleted, sensitive_accessed}
aegis.cron.{run}
aegis.mail.{sent, failed}
aegis.post.{saved, status_change, deleted}
aegis.comment.{posted}
aegis.media.{uploaded, deleted, suspicious_mime}
aegis.db.{summary, event, slow}
aegis.capability.{denied}
aegis.redirect.{triggered}
aegis.error.{caught}
aegis.404.{observed}
aegis.shortcode.{invoked}
aegis.registration.{attempted}
aegis.upload.{bytes}
aegis.cache.{miss}
aegis.lifecycle.{activated, deactivated}
```

---

## Appendix B — Enforcement artifacts (to build alongside v0.3)

- `deploy/web/aegis-tests/test_every_sensor.php` — CI test per §6.1
- `deploy/web/aegis-tests/test_chain_integrity.php` — CI test per §6.2
- `deploy/web/aegis-tests/README.md` — how to run locally + CI wiring
- `docs/web/AEGIS_SENSOR_CATALOG.md` — canonical list, maintained by hand

---

*This document governs what Aegis MUST see. When in doubt, the
 presumption is always in favor of capturing more, not less. Privacy
 is handled by redaction, not by blind spots.*
