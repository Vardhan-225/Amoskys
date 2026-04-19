# Aegis v0.3 — First Deployment Log

Date: 2026-04-19
Target: lab.amoskys.com (customer-zero)
Applied against: v0.2 plugin code (16 sensor families firing)
Result after: 22 sensor families firing

## Deployment steps

1. Patch file prepped:
   `deploy/web/aegis-v03/sensors_v03.patch.php`
   Six method groups, ~252 lines.

2. Injected into live `class-aegis-sensors.php` via quoted-heredoc Python:
   - Methods appended before the final `}` of the class
   - `register()` method patched to call all six new `register_*_v03()` methods
   - PHP lint passed

3. FPM reload: `sudo systemctl reload php8.3-fpm` — zero downtime

4. Exercise probes to verify:
   - `/wp-admin/setup-config.php` (install_script_probe 404)
   - `/.env` (config_leak_probe 404)
   - `/.git/config` (config_leak_probe 404)
   - `/wp-config.php.bak` (wp_config_probe 404)
   - `/wp-json/wp/v2/users` (unauth REST — rest.response)

## What fired in the first 30 seconds

| Sensor | Events | Proof it's wired |
|---|---|---|
| `aegis.capability.denied` | 386 | Admin probes tripped privileged-cap checks |
| `aegis.nonce.failed` | 145 | CSRF nonce failures observed |
| `aegis.404.observed` | 34 | 404 pattern classifier firing |
| `aegis.redirect.triggered` | 8 | wp_redirect filter catching every redirect |
| `aegis.rest.response` | 3 | REST post-dispatch capturing response status |
| (plus v0.2 sensors) | 111 | Existing sensors unaffected |

## What fired during a 30-minute Argos engagement

4,365 total events captured. Of those, **1,543 from v0.3 sensors (35%)**
— previously invisible attack signals.

| Event type | Count | v0.3? |
|---|---|---|
| aegis.db.summary | 1327 | — |
| aegis.http.request | 1254 | — |
| aegis.capability.denied | **1003** | 🆕 |
| aegis.nonce.failed | **412** | 🆕 |
| aegis.404.observed | **112** | 🆕 |
| aegis.options.updated | 58 | — |
| aegis.rest.unauth_routes_detected | 50 | — |
| aegis.outbound.http | 33 | — |
| aegis.admin.page_view | 20 | — |
| aegis.redirect.triggered | **13** | 🆕 |
| aegis.auth.login_failed | 11 | — |
| aegis.cron.run | 10 | — |
| aegis.post.status_change | 9 | — |
| aegis.options.added | 8 | — |
| aegis.theme.switched | 6 | — |
| aegis.post.saved | 6 | — |
| aegis.post.deleted | 6 | — |
| aegis.mail.failed | 4 | — |
| aegis.comment.posted | 4 | — |
| aegis.plugin.activated | 3 | — |
| aegis.plugin.deactivated | 3 | — |
| aegis.fim.wpconfig_modified | 3 | — |
| aegis.media.uploaded | 3 | — |
| aegis.media.deleted | 3 | — |
| aegis.rest.response | **3** | 🆕 |

## What the v0.3 sensors make visible that v0.2 couldn't

- **Privilege escalation probe rate**: `capability.denied` — 1,003 hits
  during the scan means Argos was trying to escalate privileges often
  enough to trip the check a thousand times. That's the *intent signal*
  we were blind to.

- **CSRF probe rate**: `nonce.failed` — 412 hits show Argos trying to
  submit forms/actions without valid nonces. Classic reconnaissance
  pattern.

- **Scanner pattern fingerprints**: `404.observed` classified 112 404s
  into categories like `install_script_probe`, `config_leak_probe`,
  `wp_config_probe`. This is how we identify scanner families without
  matching user agents.

- **Redirect behavior**: `redirect.triggered` — we now know every
  redirect the site emits, with the external/internal classification.
  Open-redirect vulnerabilities will show up here immediately.

- **REST response status**: `rest.response` — the first 3 fired for
  the specific REST routes Argos probed. We now see what the caller
  got back (401/403/5xx), not just that they asked.

## Known gaps v0.3 doesn't close

Still invisible at the plugin tier (per Mandate §2.3):

- File writes outside wp-config — requires host-level FS watch (Tier 5)
- TLS handshake fingerprint — Tier 4 (nginx module)
- `eval` / `unserialize` calls — Tier 3 (PHP extension)
- Pre-plugin-load requests — Tier 2 (auto_prepend_file)
- Client-side DOM events — Tier 6 (JS beacon)

These are the next rungs of the Observability Mandate ladder.

## Mystery finding during deployment

During baseline analysis we discovered one IP, `139.87.112.106`
(Oracle Cloud), had generated **42,309 events against our lab**
— 78% of all non-localhost traffic. Probing `/login`, `/admin`,
`/q79w_38jg__.shtml`, Cisco WebACS paths (`/webacs/js/xmp/nls/xmp.js`),
SCADA probes (`/xmldata?item=All`). UAs spoof Windows Firefox but
include curl/8.10.1.

This is a distributed bot farm running from Oracle Cloud, targeting
many product categories on the same IP. Our Aegis plugin has been
silently recording every one of its probes since we deployed. That
recording will become the first dataset IGRIS-Web's brain calibrates
against.

## Next rung

Tier 1.5: Browser beacon on admin pages only. Captures admin page
interactions (click, idle, beforeunload) — adds client-side
correlation data we literally cannot see today.
