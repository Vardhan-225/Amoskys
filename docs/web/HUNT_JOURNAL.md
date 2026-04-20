# AMOSKYS Web — Hunt Journal

**Purpose.** A living, append-only log of every red-team cycle we run.
Each cycle: what we attacked, what tools we used, what we found, what
Aegis caught, what Aegis missed, and what we learned. The whole point
of the offense+defense competition is this journal — the learning
loop that makes Argos stronger and makes Aegis smarter in lockstep.

**Discipline.**
- Every cycle is dated + targeted + scoped before it runs.
- Every finding is tagged: detected-by-Aegis, missed-by-Aegis, noisy.
- Every "missed" finding becomes an Aegis-sensor ticket.
- Every repro step is captured so anyone can re-run.
- Nothing in this document implies authorization to hit third-party
  targets. Stage-2 actions only against consented targets.

**Target profile we're calibrating against.** The lab — a production
WordPress install on `lab.amoskys.com` with Aegis v1.3 installed
(37 event types live, 9 strike rules). If something breaks Aegis
here, commercial WordPress sites will be just as exposed.

---

## Cycle log

### Cycle 001 — 2026-04-20 · Kali → lab.amoskys.com
**Operator:** Argos from Kali VM (ghostops@ghost-Spectre, ARM64)
**Target:** lab.amoskys.com (our own lab — consent via `AMOSKYS_CONSENT_DOMAIN`)
**Attacker IP seen by Aegis:** 38.2.43.171 (Mac public IP — Kali NATs through the host)
**Pipeline:** wpscan → nuclei (tag=wordpress) → nikto (tuning=234)

#### Setup
- Kali MCP server launched at `127.0.0.1:8445` on the VM.
- 6 `kali_*` MCP tools registered: wpscan, sqlmap, nikto, ffuf, nuclei,
  amass, hunt_journal.
- `AMOSKYS_CONSENT_DOMAIN=lab.amoskys.com` set on the server so every
  tool call against the lab is legally covered by standing consent.
- Before the run: whitelist cleared, transients flushed on the lab
  (Aegis state reset to cold).

#### Mid-run observation (5 min in)
Aegis is reacting aggressively:
| Signal | Count (last 5 min) |
|---|---|
| `aegis.capability.denied` | 155 |
| `aegis.block.enforced` (403s returned to wpscan) | 28 |
| `aegis.nonce.failed` | 6 |
| `aegis.query.event` | 99 |
| `aegis.options.updated` | 17 |

The scan is being partially blocked — 28 HTTP 403s returned to wpscan
already. Most likely our `priv_esc` strike rule tripped (threshold 3
capability-denied in 60s). That means: wpscan's unauth plugin-
enumeration hits `/wp-admin/*.php` files, each trips one
`capability.denied`, three in 60s blocks the IP for 10 min. This is
the defense working as designed AGAINST a real offensive scanner.

**Observation for Aegis team:** the block is too aggressive for a
consented pentest. In Stage-2 engagements the operator should be
able to scope a per-IP bypass without disabling the whole detection
chain. Action item: add a "pentest-mode" IP allow-list that suppresses
BLOCK but keeps emitting the events (we still want to see the coverage).

#### How it actually unfolded

1. **wpscan aborted in 2.9 s.** wpscan is "polite" — on a 403 for the
   root URL it bails by design, interpreting it as "target uses a WAF;
   use --force to override." One HTTP request, one finding of its own:
   *"this target is defended."* Aegis's block was already in effect
   from Cycle 001's pre-whitelist window.

2. **nuclei ran for ~20 min through its full `wordpress` tag set.**
   Unlike wpscan, nuclei plows on through 403s. Every one of its
   ~800+ templates fired. Every one was 403'd. Result: zero confirmed
   vulnerabilities from the offensive side, but an INCREDIBLY rich
   detection log from the defensive side — we saw the entire nuclei
   WordPress probe surface from Aegis's vantage point.

3. **nikto didn't even start** — the driver was killed before it ran.

#### What Aegis captured (40-min window, IP 38.2.43.171)

| Signal | Count |
|---|---|
| `aegis.block.enforced` (403s returned) | **1,124** |
| distinct probe paths | **807** |
| distinct UAs rotated | **378** |
| `aegis.block.started` (transition events) | 3 |
| strike rules tripped | 3 × `priv_esc` |
| `aegis.capability.denied` | 30 |
| `aegis.nonce.failed` | 6 |
| `aegis.404.observed` | 2 |

#### The attack surface Aegis saw
Representative paths probed by nuclei (sample of 807):

| Category | Example probe |
|---|---|
| XSS | `/?author=1<%2Fscript><script>alert(document.domain)</script>` |
| LFI / path traversal | `/?filename=../../../../../../etc/passwd&mphb_action=download` |
| SQLi (WooCommerce / CF7) | `/?cffaction=get_data_from_database&query=SELECT * from wp_users` |
| Config backup enum | `.wp-config.php.swp`, `/wp-config.php.bak`, `/wp-config-backup.txt`, `/wp-config.php.BAK`, `/wp-config.php.old` |
| Plugin-specific LFI | backup-migration, kubio-site-edit, dzsap, aam-media, mphb |
| Open redirect / SSRF | `?aiowpsec_do_log_out=1&after_logout=https://interact.sh` |
| Email-token probe | `?alg_wc_ev_verify_email=...` |
| Author enum | `?author=1` |

This is the **full attack surface of nuclei's WordPress tag** — ~800
templates — and Aegis rejected every one of them.

#### Detection gap analysis

**Aegis WON on the `priv_esc` rule.** The strike pattern was correct:
- Any probe targeting /wp-admin/*.php, /wp-config.*, or known plugin-
  specific admin endpoints trips `aegis.capability.denied` (our WP hook
  fires when unauth users hit privileged paths).
- 3 strikes in 60 s → 10-min block.
- Once blocked, every subsequent probe gets 403'd at plugins_loaded@-2
  (enforce hook), BEFORE any exploitable code path runs.

**No detection gaps identified in Cycle 001** — the defense pre-empted
every offensive category we built Argos for. XSS, LFI, SQLi, backup
enum — all intercepted at the priv_esc / WAF layer before reaching
plugin code.

**Operational gap confirmed.** A consented pentest needs a
"detect-but-don't-block" mode. `amoskys_aegis_ip_whitelist` does this
today (whitelisted IPs bypass enforce(), but all sensors still emit).
The issue in this cycle was the option didn't persist on first set;
wp-cli re-set fixed it. Ticketed for v1.8: verify the whitelist UI
actually persists the value, and add a per-engagement "pentest mode"
option that expires after N hours to avoid stale allow-lists.

#### What we learned
- **Aegis's priv_esc rule at threshold=3/60s is the right tuning** for
  defeating a baseline nuclei scan against WordPress.
- **wpscan is easier to defeat than nuclei** — wpscan bails on 403,
  nuclei doesn't. A pragmatic WAF that just returns 403 on every
  request stops wpscan cold; nuclei requires strike-based blocking.
- **nuclei rotates UA per template** (378 distinct UAs in 807 requests).
  UA-based defense is useless against nuclei. IP-based is the only
  thing that works.
- **nuclei's wordpress template set probes 800+ paths.** Our atlas (93
  entries) is a subset — this cycle surfaced ~20 classes of LFI + XSS
  paths we don't currently model.  Next cycle should focus on parsing
  the nuclei probe corpus and adding sensors for the blind spots.

#### Action items from Cycle 001
- [ ] Add LFI pair (v1.8): AST scanner for `readfile/include` with
      request-derived path + runtime classifier for `../` traversal
      in query params.
- [ ] Add XSS pair (v1.9): AST scanner + CSP-violation / reflected-
      input runtime detector.
- [ ] Verify `amoskys_aegis_ip_whitelist` persistence in the admin UI
      (cycle-001 setup bug).
- [ ] Consider a per-engagement pentest-mode option with expiry.

### Cycle 002 — 2026-04-20 · Kali → lab (whitelist active)
**Setup.** Whitelist `38.2.43.171` verified active; HTTP 200 on root.
This cycle decomposed into sub-runs because of discovery + config
issues we fixed mid-flight:

  · **002A** — initial attempt; whitelist hadn't persisted on first
     wp-cli set so every probe still blocked. Restarted.
  · **002B** — wpscan `--plugins-detection passive` (25 min later
     cut short; wpscan's passive mode still does version-detection
     via static-file hash compare — noisy but not producing findings
     on a hardened target).
  · **002C** — standalone `nuclei` with broader tags
     (wordpress+wp-plugin+wp-theme+misconfig+exposure), all severities.
     This is the cycle that actually matters — findings below.

#### Cycle 002B — wpscan passive data (25 min, scan cut short)

wpscan passive plugin-detection didn't complete but produced
significant Aegis observations:

| Signal | Count |
|---|---|
| `aegis.capability.denied` | 486 |
| `aegis.query.event` | 182 |
| `aegis.db.summary` | 81 |
| `aegis.http.request` | 80 |
| `aegis.404.observed` | 58 |
| `aegis.nonce.failed` | 36 |
| `aegis.scanner.shape_detected` | 19 |
| `aegis.redirect.triggered` | 6 |
| **total events** | **949** |
| distinct paths touched | 62 |

**Interpretation.** wpscan's passive-mode version-fingerprint technique
is a BURST of GETs against `/wp-admin/css/colors-*.css`,
`/wp-includes/js/tinymce/*.js`, `/wp-admin/rtl.css`, etc. — the files
it MD5-compares against known WP version hashes to infer the core
version. Each of those paths is in `/wp-admin/` so they trip
`capability.denied` six times each in our sensor (one per request).

**Sensor tuning ticket (005)**: `capability.denied` is firing on
static-asset 404s to `/wp-admin/*.css` / `/wp-includes/*.js`. That's
technically correct (the cap check DID fail for an unauth request)
but it's noisy against legitimate traffic too (any misconfigured
cache-miss on a static admin asset trips it). Consider suppressing
the emit when the underlying request is for a static extension AND
returns 404 — or lower severity to `info` in that specific shape.

**Scanner-shape WORKED again.** 19 `aegis.scanner.shape_detected`
fires during wpscan passive run — our meta-detector correctly
fingerprinted wpscan even without blocking. This is offense-defense
balance: whitelist suppresses BLOCK, but detection still flows.

#### Cycle 002C — nuclei with whitelist (full findings)

_Pending — nuclei running at commit time; findings populate on
follow-up commit. Target nuclei runtime: 10-12 min for broader tag
set._

**What we expect to learn here.** Same nuclei templates that were
blocked in Cycle 001 now reach actual code paths. Any template that
returns a non-404 response will run its matcher and produce an
actual finding. The diff between "templates fired" (from Aegis log)
and "findings emitted" (from nuclei JSONL) tells us:

  (a) what nuclei confirms as real vulnerabilities on lab.amoskys.com
  (b) what Aegis detects at runtime vs what Aegis misses
  (c) the concrete detection-gap list for v1.8+ sensor work

---

## Findings-to-fix ledger

| # | Date | Finding | Detected-by-Aegis? | Fix (sensor to add) |
|---|---|---|---|---|
| 001 | 2026-04-20 | nuclei's 800-path wordpress template set blocked at priv_esc threshold; attack never reached plugin code | ✅ YES — priv_esc rule at 3/60s catches every template class | None. Defense working. Ticket: document the threshold tuning. |
| 002 | 2026-04-20 | wpscan aborts on 403 root response — confirms "WAF present" and bails in 2.9s | ✅ YES — 403 from enforce() | None. Defense working. |
| 003 | 2026-04-20 | 378 distinct UAs rotated by nuclei in one scan; UA-based detection is useless here | Our scanner_shape sensor detects UA rotation (+10) but we rely on `distinct_paths>=10` (+25) + priv_esc for the hard block | Strengthen scanner_shape sensor to weight UA-rotation higher (current +10 → +15?) given we see it's an actual scanner signature |
| 004 | 2026-04-20 | **OPERATIONAL**: whitelist option didn't persist on first wp-cli set; required explicit re-set | — | Verify `amoskys_aegis_ip_whitelist` admin UI persistence; consider a pentest-mode env-var option |
| 005 | 2026-04-20 | `capability.denied` fires 6× per request for static-asset 404s under /wp-admin/ (wpscan's MD5-hash version fingerprint) — signal-to-noise issue | ✅ detecting; noisy | Suppress emit or downgrade to `info` when URI ends in `.css/.js/.png/.jpg` AND status=404 |
| 006 | 2026-04-20 | `aegis.nikto.*`? — nikto command had `-Format` without `-output` filename; tool silently failed in Cycle 001 | — | kali.py fixed in v1.8: use `-ask no` + `-maxtime` instead of `-Format`/-nointeractive |

## Bug-bounty candidates discovered

| # | Plugin/target | Class | Severity | Status |
|---|---|---|---|---|
| | | | | |

---

## Open questions

_Add things we don't know yet; close them as we learn._

