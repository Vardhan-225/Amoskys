# Aegis v0.4 — Active Defense + Supply Chain + Browser Beacon

Date: 2026-04-19
Target: lab.amoskys.com (customer-zero)
Applied against: v0.3 plugin (22 sensor families firing)
Result after: 22 sensors + 3 new defensive subsystems

## What shipped

| Component | File | Purpose |
|---|---|---|
| Active defense | `class-aegis-block.php` | Burst-threshold IP blocking with 403 enforcement |
| Supply chain | `class-aegis-supply-chain.php` | Daily wp.org author/update drift detection |
| Browser beacon | `class-aegis-beacon.php` | Admin-page client-side telemetry (Tier 1.5) |
| Strike wiring | `wire_strikes.py` | Sensor→block handoff via `do_action('amoskys_aegis_strike')` |

## Block engine — rules & thresholds

| Rule | Source sensor | Threshold / 60s | Action |
|---|---|---|---|
| `auth_fail` | `on_login_failed` | 8 | 10-min block |
| `nonce_fail` | `on_nonce_user_logged_out` | 10 | 10-min block |
| `priv_esc` | `capability.denied` | 3 | 10-min block |
| `scanner_404` | `suspicious 404 patterns` | 5 | 10-min block |
| `poi_attempt` | `rest.poi_canary` | **1** | immediate block |

Enforcement: `plugins_loaded @ -2` (before any plugin init). Returns
HTTP 403, `Content-Type: text/plain`, `nocache_headers()`, and emits
`aegis.block.enforced` per blocked request.

## Deployment pitfalls hit (and fixed)

### 1. `register()` wired enforce too late
Initial version wired `enforce` in `register()`, but `register()` itself
was called at `plugins_loaded @ -1` — by then the hook had already fired,
so `enforce` never ran. **Zero `block.enforced` events in first 24h of
testing.** Fix: wire `enforce` DIRECTLY in the main plugin bootstrap at
`plugins_loaded @ -2` (beats register). After fix: 321 enforced events.

### 2. `block.started` fired on every strike past threshold
Old `block_ip()` had no idempotency check — each strike past threshold
re-emitted `block.started`. One attacker generated 3,375 duplicate events
for the same IP. Fix: `count_strike()` short-circuits if the block transient
already exists, and `block_ip()` double-checks before emitting. Post-fix
measurement shows 4 emissions per block under concurrent PHP-FPM workers
(a 99% reduction from pre-fix). Residual 4× is the worker-race
window — tightening further requires distributed lock (deferred to v0.5).

### 3. Googlebot + WP-Cron self-requests getting blocked
The original whitelist had no loopback check. Result: WordPress's internal
`wp-cron.php` POST to its own server (127.0.0.1, SERVER_ADDR) tripped
`priv_esc` and self-blocked. Googlebot (34.87.158.64) also tripped
`priv_esc` via privileged-endpoint probes. Fixes in `is_whitelisted()`:
- Loopback (`127.0.0.1`, `::1`) always whitelisted
- `$_SERVER['SERVER_ADDR']` always whitelisted
- Forward-confirmed reverse DNS for verified search bots (googlebot.com,
  google.com, search.msn.com, duckduckgo.com, yandex, crawl.baidu.com).
  Cached 24h per IP via transient.

## Observed blocking impact (live data from lab)

Within the first hour post-v0.4 deploy:

| Metric | Value |
|---|---|
| Unique IPs blocked | **15** |
| Total `block.enforced` (403s returned) | **321** |
| Most-blocked rule | `priv_esc` (11/15 IPs) |
| Second-most rule | `nonce_fail` (2/15 IPs) |
| Active-blocks card on Command Center | 3 at time of screenshot |

The 15 blocked IPs include both the **Oracle Cloud bot farm**
(documented in v0.3: `139.87.112.106` lineage) and new scanners from
`134.199.159.154`, `147.185.132.76`, `65.109.15.249`, etc. — every one
of them was silently probing *before* v0.3 and *observed* at v0.3;
v0.4 is the rung where observation becomes enforcement.

## Supply-chain watcher — first cycle

Initial daily cron:
- Installed plugins tracked: 1 in wp.org directory (only `amoskys-aegis`
  itself is active on customer-zero; others deferred)
- Drift detected: 0 (baseline snapshot, nothing to diff against yet)
- Schedule: `wp_schedule_event( time() + 300, 'daily' )`

Next 24h will establish the baseline; drift detection becomes meaningful
on cycle 2+. The AUTHOR_CHANGED, SUDDEN_UPDATE_AFTER_LONG_SILENCE, and
STALE_FOR_YEARS classifiers are all live.

## Browser beacon — wired, pending real test

- REST endpoint: `POST /wp-json/amoskys-aegis/v1/beacon`
- Injected inline via `admin_print_footer_scripts` (zero extra HTTP)
- Capture: `page_load`, `page_unload`, `visibility_change`, `idle_start/end`,
  `clipboard` (copy/paste → severity=warn), 30s heartbeats with
  click/keypress counts
- Auth: `is_user_logged_in()` + `wp_verify_nonce('wp_rest')`
- Transport: `navigator.sendBeacon()` on unload (survives page close)

Will exercise on next `amoskys_admin` login session — no events yet
because no admin has logged into WP since deploy.

## Command Center — two new widgets

Added to `/web/command?token=...`:

1. **Supply-chain drift banner** (red, at top) — only renders when
   `snap.supply_chain_drift` non-empty. Shows first 5 drifts with
   type + version + author.
2. **Active defense card** (mid-page) — shows `block.started` and
   `block.enforced` counters for last 10 min, plus a table of currently
   blocked IPs with rule, strikes, and since-when. Paired with
   supply-chain card showing last cycle stats + drift-class legend.

## Negative-space ledger (what v0.4 still does NOT close)

Same as v0.3 gaps plus:
- **Distributed block-state**: single-node transients only. Multi-site
  fleet needs Redis-backed block store (v0.5).
- **Block-bypass-by-IP-rotation**: attacker rotating across /24 defeats
  per-IP TTL. Fingerprint-based blocking (TLS JA3, request-pattern hash)
  requires Tier 4 (nginx module).
- **Paid-plugin supply chain**: wp.org API doesn't cover paid plugins.
  Hash-diff of plugin directories on update (Tier 5 FS watch) would
  close this.

## Next rung

Tier 1.5 → Tier 2: PHP `auto_prepend_file` so we see requests *before*
WordPress even parses them. First real attack-surface below the plugin
boundary. Planned for v0.5.
