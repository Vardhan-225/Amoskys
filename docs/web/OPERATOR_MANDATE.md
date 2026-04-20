# AMOSKYS Web — Operator Mandate v1

**Status:** binding. Every change to Argos tooling or Aegis enforcement
must be reconcilable with this document. Disagreements go to a
documented amendment, not a silent workaround.

**Audience:** (1) human operators running Argos, (2) agent/LLM
instances (e.g. Claude via MCP) driving the suite autonomously.

---

## Purpose

Argos exists to find and report security gaps in WordPress sites
**so we can offer to close them**. Two-stage engagement flow:

1. **Stage 1 — no consent.** Public-surface OSINT + pitch. Equivalent
   to what any visitor could see. Legal basis: CFAA §1030(a)(2)(C)
   "authorized access" — anything a webserver serves without auth
   bypass is, by definition, within authorization.

2. **Stage 2 — consent verified.** Full pentest. Signed DNS TXT
   consent token required. Scope + expiry baked into the token.

Every engagement converts to one of three business outcomes:
  - Bug-bounty submission (via the target's security.txt contact)
  - Customer-prospect pitch (Aegis blocks this class of gap)
  - No-action (target is well-hardened — log + revisit later)

---

## Rules of Engagement (binding)

### R1 — Stage 1 may NEVER cross these lines

- **No writes.** Zero POST, PUT, DELETE, PATCH. No form submissions.
- **No brute force.** Zero repeat submissions of the same endpoint
  with varying inputs.
- **No authz bypass.** If a path returns 401/403 we do not probe
  further on that path.
- **No signature-tripping payloads.** No `OR 1=1`, no `<script>`,
  no `../`, no `%00`, no `${jndi:`. If a check needs one of these,
  it belongs in Stage 2.
- **No enumeration depth >1.** We probe `?author=1` ONCE. We do not
  iterate 1→N. One probe is reconnaissance; iteration is attack.
- **No port scanning.** HTTPS (443) + HTTP redirect (80). Nothing else.
- **Respect `robots.txt`.** We read it to learn what the target wants
  hidden (that information is useful to the report). We do not
  request any path `Disallow`'d there.
- **Respect `/.well-known/security.txt`.** If `Contact:` is set and
  our findings warrant disclosure, we route to it before or in
  parallel with the sales pitch.
- **Abort on 5 consecutive 4xx/5xx.** If the target's WAF has made it
  clear we're unwelcome, we stop. Pushing through is counterproductive
  (reputational) and ethically indefensible.

### R2 — Traffic must look legitimate

- **UA pool:** current stable Chrome/Safari/Firefox UAs (no older
  than 180 days from the library's bundled "now"). Weighted by
  StatCounter Q1-2026 market share.
- **Sticky identity per engagement.** Within one Stage 1 run, we do
  not rotate UA. Rotating mid-session is itself a bot signal.
- **Pacing:** gaussian-jittered, median 3.0 s, stddev 1.5 s.
  Floor 0.8 s (anything faster is bot-y). 10% probability of long-
  tail "reader pause" in 15-45 s. (Basis: Liu & White 2013.)
- **Accept-Language + Sec-CH-UA hints** must match the UA. A
  Chrome/Windows UA with `Accept-Language: de-DE` from a US IP
  is a fingerprint mismatch — equivalent to a forged passport.
- **Honor `Retry-After`.** If the server asks us to wait, we wait.
  RFC 6585.
- **No known-bad UAs.** `curl/*`, `python-requests/*`, `sqlmap`,
  `nikto`, `wpscan/*` unless the target has explicitly opted into
  a scanner-class ROE in Stage 2.

### R3 — Legal ceiling

Argos operates under US law (CFAA, 18 USC §1030). Notably:

- **Van Buren v. United States (2021)** narrowed "exceeds authorized
  access" to explicit auth bypass. Public-surface reconnaissance is
  categorically outside that scope.
- **hiQ Labs v. LinkedIn (9th Cir. 2019 / 2022 on remand)** upheld
  that scraping publicly-accessible data does not violate CFAA.
- **GDPR / CCPA** — we do not collect PII beyond what the target
  publishes publicly (contact emails from security.txt, staff
  names from `<meta author>` tags). No PII is retained beyond
  the engagement + 90 days.

### R4 — Agent discipline

An LLM driving Argos must, BEFORE each action:

1. **Consult the playbook** via `web_operator_playbook()`.
2. **Verify preconditions** — all must be True per the state model.
3. **Log rationale** — what move, why now, what outcome expected.
4. **Update state** after the move and re-consult.

An agent that bypasses the playbook is out of compliance with this
mandate. The MCP server SHOULD eventually enforce playbook-driven
move-execution; until then the operator enforces via review.

---

## Research mandates cited throughout Argos

Each Argos module cites references in its `mandate` field. The
canonical list:

| Topic | Citation |
|---|---|
| Browsing dwell-time distribution | Liu & White (2013) "Mining browsing behavior for adaptive search" |
| Session pacing research | Chrome UX Report (CrUX) session traces, 2023+ |
| HTTP rate-limit semantics | RFC 6585 §4 (Retry-After) |
| Robots Exclusion Protocol | RFC 9309 (2022) |
| security.txt | RFC 9116 (2022) |
| Certificate Transparency | RFC 6962 (v1), RFC 9162 (v2) |
| CFAA scope narrowing | Van Buren v. US, 141 S. Ct. 1648 (2021) |
| Public-data scraping | hiQ Labs v. LinkedIn, 31 F.4th 1180 (9th Cir. 2022) |
| WP plugin CVE taxonomy | WPScan + Patchstack quarterly reports |
| Vuln classifier references | OWASP Top 10 (2021), CWE index |
| Browser fingerprint research | Tor Project browser fingerprinting (panopticlick lineage) |
| UA market-share data | StatCounter GlobalStats + caniuse.com |

**Every check in every Argos module ships with at least one
citation from this list** (enforced by
`test_every_finding_has_mandate_and_references`).

---

## Target acquisition — who we scan first

Priority order for Stage-1 sweeps (the first 5 customers):

1. **Sites with public security.txt** — they've said "we accept
   reports". Low ethical surface, high conversion potential.
2. **Sites with known-vulnerable plugin versions** — the plugin
   inventory leak from Stage 1 auto-reveals these via CVE cross-ref.
3. **Sites running abandoned plugins** — per our v0.4 supply-chain
   watcher: any plugin not updated in 18+ months is a prospect.
4. **Sites in industries with regulatory security obligations** —
   healthcare, fintech, legal. Tangible ROI on Aegis subscription.
5. **Referral-sourced leads** — a customer recommended them.

We do NOT target (hard lines):
  - Personal blogs unless the owner asked
  - Non-profits without an IT budget
  - Any target on a public harassment-watch list
  - Any domain we lack a bonafide business contact path to

---

## Amendment process

Change this document via PR. Changes require:
1. Written rationale (why the existing rule is insufficient).
2. A linked CVE, incident, or research citation.
3. Review by one human operator AND the auto-test suite passing
   `test_operator_mandate_compliance` (to-be-built).

We do not amend silently. The file's commit history is the authority.
