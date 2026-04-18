# Red Team Arena

The playground where Argos trains and Aegis is tested. Lives at
`lab.amoskys.com`. Four tiers, each answering a specific question.

## Principles

1. **Baseline before the fight.** Every measurement starts with a reading of
   the undisturbed system. "Did Argos find this?" is meaningless without
   "What does Argos find when there's nothing planted?"

2. **Ground truth is the labelset.** If we plant 10 vulnerabilities, we know
   exactly what Argos should find. Detection rate isn't a hand-wavy metric —
   it's (found / planted).

3. **Nothing in the arena leaves the arena.** Deliberately vulnerable
   installations must never be reachable to the public internet without
   explicit labeling that they are intentionally compromised. Kali rate-caps
   and Argos scope gates enforce this; the WP install's SEO settings
   (`noindex, nofollow, noarchive`) enforce it at the search-engine layer.

4. **The arena is our bug-bounty training ground.** Every technique we learn
   here must be reproducible on HackerOne test environments before we submit
   anything against real WordPress Core.

## Tier 1 — Baseline (pristine WordPress)

**Purpose**: establish the noise floor. What does a freshly-installed, up-to-
date WordPress look like to an external scanner?

**Setup**:
- `lab.amoskys.com/clean/` subdirectory (path structure already in
  `install-wordpress.sh`)
- WordPress 6.9.4 latest
- Default theme (Twenty Twenty-Six), default plugins (Akismet, Hello Dolly)
- No custom code
- Aegis deliberately **not** installed for the first Tier 1 run

**Runs**:
1. **Tier 1a**: Aegis absent. Argos scans. Record everything found.
2. **Tier 1b**: Install Aegis (no rules changed on WP). Argos scans. Confirm
   findings are identical — Aegis should NOT change attack surface.

**Expected Tier 1 findings** (what "noise floor" means):
- WordPress version disclosure (in `/wp-json/`, `meta generator`, `readme.html`)
- User enumeration via `/wp-json/wp/v2/users` (the `amoskys_admin` account)
- Three `__return_true` unauth REST routes (WordPress core's legitimate ones)
- `xmlrpc.php` responding (defaults to enabled)
- Plugin enumeration via `/wp-content/plugins/` directory listing behavior
- REST API namespace enumeration

These are NOT vulnerabilities — they are the unavoidable surface of
WordPress. Argos must learn to deprioritize them.

## Tier 2 — Known CVE replay

**Purpose**: measure Argos's detection rate against documented vulnerabilities
with public PoCs.

**Setup**: `lab.amoskys.com/vulnerable/` subdirectory with deliberately-old
plugin versions. Each plugin is labeled with the CVE it carries.

**Plant list (v0)**:

| Plugin | Version | CVE | Class | Public PoC? |
|---|---|---|---|---|
| LiteSpeed Cache | ≤ 6.4.0 | CVE-2024-28000 | Auth bypass → priv esc | Yes |
| LayerSlider | ≤ 7.9.11 | CVE-2024-2879 | SQL injection | Yes |
| Really Simple Security | ≤ 9.1.1.1 | CVE-2024-10924 | Auth bypass | Yes |
| WooCommerce | ≤ 8.7.0 | CVE-2023-28121 | Priv esc via REST | Yes |
| Elementor | ≤ 3.20.2 | CVE-2024-6661 | Stored XSS | Yes |

**EssentialPlugin backdoor** (special): obtain the Aug 2025 backdoored build of
Countdown Timer Ultimate v2.6.7 if possible. This tests the supply-chain
detection path specifically.

**Measurement**:
- Detection rate: `found / planted` (target v0: ≥ 80%)
- False positive rate: findings NOT in the plant list × 100 / baseline findings
- Time to first finding per CVE

**What failure looks like**: Argos misses a plant with a public nuclei
template. This means either nuclei isn't loading the template correctly, the
template's fingerprint check fails against our install, or Argos's scope
filters are over-restrictive. Each failure mode is a bug ticket.

## Tier 3 — Simulated active attacks (for Aegis training)

**Purpose**: validate the defensive side. Plant attack payloads and watch
whether Aegis's sensors fire with the right severity and attribution.

**Campaigns**:

### 3a — PHP Object Injection via REST

Fire a POST against a vulnerable REST endpoint with a serialized object in the
body:

```
POST /wp-json/some-plugin/v1/action
Content-Type: application/x-www-form-urlencoded

data=O:8:"stdClass":0:{}&more=a:1:{s:4:"test";s:5:"value";}
```

**Expected Aegis event**: `aegis.rest.poi_canary` at severity `critical`.
**Verify**: event present in JSONL log within 2 seconds of request.

### 3b — Admin account creation via auth chain

Reproduce the LiteSpeed CVE-2024-28000 chain:
1. Auth bypass via forged cookie
2. Admin account creation via `wp_create_user`
3. Login as new admin

**Expected Aegis events**:
- `aegis.auth.role_change` severity `high` or `aegis.auth.user_registered` (admin)
- `aegis.auth.login_success` severity `warn` for the new admin

**Verify**: all events present, correlated by request IP within 10 seconds.

### 3c — Webshell drop into uploads

Write a PHP file to `wp-content/uploads/2026/04/cachekeep.php` and request it
via HTTP.

**Expected Aegis events**: **NONE** with v0.1 sensors (FIM only watches
wp-config, not uploads). This is a gap; documenting it here makes the gap
explicit, and the Tier 3c result motivates FIM expansion.

### 3d — wp-config.php modification

```bash
echo "// injected at $(date)" >> /var/www/html/wp-config.php
curl http://lab.amoskys.com/ >/dev/null
```

**Expected Aegis event**: `aegis.fim.wpconfig_modified` severity `critical`,
within one HTTP request of the modification (FIM runs on `shutdown` hook).

### 3e — Ethereum-RPC beacon simulation

Inject a plugin that calls `wp_remote_post` to an attacker-controlled host
with a JSON body containing `{"jsonrpc":"2.0","method":"eth_call",...}`.

**Expected Aegis event**: `aegis.outbound.ethereum_rpc` severity `critical`
with `rpc_signals >= 2`.

## Tier 4 — Bug bounty training

**Purpose**: rehearse HackerOne WordPress Core submissions against our own
replicas before we submit anything real.

**Setup**: clone the upstream WordPress Meta repos
(`git clone git://meta.git.wordpress.org/` and individual project repos) into
`lab.amoskys.com/bounty/`. These are the test environments HackerOne explicitly
permits testing against.

**Operational rules**:
- Argos runs against our replicas only. Never against the actual
  `wordpress.org`, `*.wordpress.org`, or `wordpresscampus.org` subdomains
  unless we have a submit-ready finding and explicit authorization.
- Every rehearsal finding gets a reproducibility packet: the exact Argos
  command, the target commit hash of WordPress, the full response, and a
  human-readable reproduction steps document.

**Gate for real submission**: Argos v2 must be able to produce the
reproducibility packet autonomously. Until then, rehearsal only.

**Realistic year-1 expectations** (honest):
- Month 1-6: zero real submissions. Training only.
- Month 6-12: 1-5 accepted submissions on Patchstack or plugin-specific
  programs. WordPress Core program submissions later.
- Year 2: first WordPress Core acceptance is realistic.

## Arena operational checklist

Before any Argos run against the arena:

- [ ] Kali VM reachable (`ssh ghostops@192.168.237.132` responds)
- [ ] Lab WP responding (`curl -sSL -o /dev/null -w "%{http_code}\n" https://lab.amoskys.com/` returns 200)
- [ ] Aegis plugin active (`wp plugin list --status=active` shows `amoskys-aegis`)
- [ ] Baseline event count recorded (so we can diff after the run)
- [ ] Scope is lab-only (no external domains in the engagement's target list)

After every Argos run:

- [ ] Engagement JSON report written to `argos-reports/`
- [ ] Aegis event count delta recorded
- [ ] Any new findings triaged: real vuln / known plant / false positive
- [ ] AMRDR posteriors updated (once AMRDR exists)

## Running the arena — commands

Currently manual; automate once IGRIS-Web exists.

```bash
# From your Mac (Argos not yet installed on Kali):
cd /Volumes/Akash_Lab/Amoskys
PYTHONPATH=src /Volumes/Akash_Lab/Amoskys/.venv/bin/python -m amoskys.agents.Web.argos scan \
  lab.amoskys.com \
  --tools nuclei-cves,wpscan \
  --max-rps 5 \
  --max-duration 1800 \
  --report-dir ./argos-reports

# Once Argos is on Kali:
ssh ghostops@192.168.237.132 \
  'cd ~/amoskys && .venv/bin/python -m amoskys.agents.Web.argos scan lab.amoskys.com ...'
```

## Arena growth

Tier 1-3 go in first week. Tier 4 after Argos v2 (month 3-6). Future tiers to
consider:

- **Tier 5 — Grey-box fuzzing** against our own vulnerable replicas, with
  LLM-guided payload mutation.
- **Tier 6 — Third-party plugin audit** where Argos reads plugin source from
  the WordPress.org SVN mirror and looks for vulnerable patterns.
- **Tier 7 — Red-team-vs-red-team** where we install another security
  vendor's plugin (Wordfence, Sucuri) and measure whether Argos can bypass
  their detection while our own Aegis does catch it.
