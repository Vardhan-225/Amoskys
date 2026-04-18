# Vision

## Why this product exists

Every device on every OS runs a browser. Every business depends on web-facing
applications they did not build themselves. The attackers who matter — the ones
who compromise plugin supply chains, abuse authentication flaws, deploy
credential-stealing JavaScript — all operate against HTTP and its adjacent
protocols, not against kernel syscalls or user-space processes.

The AMOSKYS macOS endpoint product pivoted into **AMOSKYS Web** in April 2026
because the right unit of security coverage is the web application, not the
host. Web is universal across OSes, universal across device form-factors, and
the surface area where 2025-era attacks actually land.

WordPress is where we begin — 43% of the web runs on it, the attack surface is
homogeneous, and the April 2026 EssentialPlugin supply-chain compromise proved
there is no credible defensive incumbent. Expansion to other CMS and then to
generic HTTP applications is a multi-year sequence.

## What AMOSKYS Web is

A platform that combines three capabilities no competitor today unifies:

1. **Autonomous offensive testing** against the customer's site, on a schedule,
   with findings that feed back into the defensive system as labeled training
   data (AMRDR).
2. **Inline defensive observation** from inside the customer's application
   runtime, emitting cryptographically chain-linked evidence events.
3. **A correlation brain** that fuses offensive and defensive telemetry,
   produces incidents, recommends virtual patches, and (with customer consent)
   pushes those patches back to the defensive agent.

No product on the market today holds all three. Wordfence holds only the second
(defense). Detectify, Acunetix, and Astra hold only the first (offense). Burp
Enterprise and XBOW hold the first and parts of the third. None holds all
three, and none publishes Proof-Spine-grade tamper-evident evidence for what
they see.

## What AMOSKYS Web is not

- Not a plug-and-play WAF. The real product extends from the plugin into a
  brain running on our infrastructure; the plugin alone is a sensor, not a
  shield.
- Not a pentest consultancy. Argos is an autonomous agent, not a human
  analyst — the economics depend on zero marginal cost per customer engagement.
- Not a CVE-assignment laboratory. We will find and disclose novel
  vulnerabilities via Argos v2+, but that's a side-effect of running the
  platform, not the business model.
- Not a compete-with-Cloudflare play. We sit on top of whatever edge the
  customer already uses; we do not operate an anycast network.

## Three pillars (locked naming, April 18 2026)

### Argos — offense
Named after the hundred-eyed Greek watchman. Autonomous pentester built on
Kali's toolchain (nuclei, wpscan, sqlmap, dalfox, subfinder, amass, nmap,
interactsh) with an LLM reasoning layer (Argos v2+, forking PentAGI).

### Aegis — defense
Named after Zeus's shield. WordPress plugin running inside PHP-FPM. Five
sensors today: auth, REST (with PHP object-injection canary), plugin
lifecycle, file integrity on wp-config, and outbound HTTP (with Ethereum
RPC beacon detection).

### IGRIS-Web — brain
Borrowed from Solo Leveling — the autonomous knight. Correlation engine with
a web-native signal vocabulary. Shares the kernel of the IGRIS brain that
already runs for the endpoint product, with its own signal types, its own
action vocabulary, and its own storage.

**Retired names — do not use in code, docs, or marketing**: Sentinel,
SentriWP, Sentri, CIA-WAF, Proving Plane.

## Redemption Agent — the GTM engine

"Redemption Agent" is the customer-facing productization of Argos. It is not
a separate technical component. The flow:

1. We reach out to a WordPress site owner (cold or inbound).
2. We offer a free external penetration test — no credit card.
3. They prove ownership via a DNS TXT record we tell them to add.
4. Argos runs. It produces a branded PDF pentest report.
5. The report lands in the prospect's inbox. Every finding is paired with the
   AMOSKYS Web defense capability that would have detected or prevented it.
6. The prospect converts to a paid subscription. Aegis gets installed. The
   loop closes.

This mechanism does three things in one:
- **Sales** — value-first, proof-of-capability, low-friction entry.
- **Training data for AMRDR** — every real customer's Argos run produces
  ground-truth labels that sharpen IGRIS-Web's reliability posteriors.
- **Marketing** — "we redeem your site" is brand language no competitor can
  steal without sounding derivative.

## Scope lock

Until we have 10 paying customers, **WordPress only** in every surface:
sensors, Argos tools, marketing, support, documentation. No Drupal detours.
No Shopify experiments. The whole company reads as a WordPress security
company externally, even while the codebase is architected for later CMS
expansion.

After customer 10, expansion order: Drupal → Joomla → Shopify → generic PHP →
any HTTP framework. This is roughly ordered by homogeneity of attack surface.

## Competitor reality

Direct competitors exist. **XBOW** (Y Combinator, 2024) is ahead of us on
autonomous AI pentesting — they've had HackerOne bounties accepted. We cannot
honestly position as "first AI pentester."

What we *can* defensibly claim:
> The first platform that combines autonomous offense, autonomous defense,
> and a self-calibrating brain that learns from both. Every finding Argos
> reports becomes a labeled observation that sharpens Aegis's rules; every
> exploitation attempt Aegis catches becomes evidence that trains Argos's
> attack planner.

That loop is the moat. Argos alone loses to XBOW over time. Aegis alone loses
to Wordfence on distribution. IGRIS alone is a SIEM. The combination has no
incumbent.

## Three-year shape (if this works)

- **Year 1**: 100 paid WordPress customers. $50–200/month ARPU. The
  Redemption Agent generates all sales; no sales team.
- **Year 2**: 1,000 customers. Expand to Drupal, Shopify. First managed-host
  partnership (Kinsta, Pressable, WP Engine — OEM Aegis as a built-in tier).
- **Year 3**: Any-HTTP coverage. Enterprise SKU with SOC 2, dedicated
  engagement teams, bug bounty submission workflow. Argos v4 (source-level
  static analysis) as a research lead.

## What could kill this product

- **Brain noise wins over detection.** If IGRIS-Web generates 50
  false-positive incidents per day per customer, we lose trust. The noise
  audit already flagged this risk in the endpoint brain; see
  [LESSONS_FROM_ENDPOINT.md](./LESSONS_FROM_ENDPOINT.md#lesson-1-noise-suppression-from-day-1).
- **Argos breaking something.** An uncapped scan that exhausts a customer's
  shared-hosting CPU kills the relationship. The engagement
  Scope is the safety boundary and must not be breakable.
- **Aegis becoming the vulnerability.** The v1 SentriWP prototype had a
  reflected XSS in its own denial page. A similar failure in Aegis —
  especially after we've marketed "we redeem your site" — would be ruinous.
- **Multi-tenant data leakage.** The endpoint product has no tenant
  isolation (single-org fleet). AMOSKYS Web *must* have tenant isolation
  from day one. See [LESSONS_FROM_ENDPOINT.md](./LESSONS_FROM_ENDPOINT.md#lesson-2-multi-tenant-first).
