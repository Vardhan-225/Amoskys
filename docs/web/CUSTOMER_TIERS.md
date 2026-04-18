# Customer Tiers

How customers buy AMOSKYS Web. Pricing is illustrative; exact numbers are
separate from this architecture doc.

## Tier matrix

| Tier | Argos | Aegis | IGRIS-Web | Dashboard | Virtual Patches | Price (illustrative) |
|---|---|---|---|---|---|---|
| **Lead / Free** | one-off scan | — | score only | PDF email | — | $0 |
| **Red-Team Only** | scheduled recurring | — | correlation + scoring | full | — | $X/month per site |
| **Defense Only** | — | installed | full | full | auto-approved | $Y/month per site |
| **AMOSKYS Web Full** | continuous | installed | full + AMRDR | full | pushed, approval flow | $Z/month per site |
| **Enterprise** | dedicated engagement | + PHP extension tier | + SLA | per-org | + custom rules | custom |

## Tier details

### Lead / Free

The Redemption Agent's entry point. Customer visits
`amoskys.com/free-pentest`, enters a domain, proves ownership via DNS TXT
record, clicks "Scan my site."

**What they get**:
- One Argos engagement (v1 — nuclei + wpscan, no LLM reasoning yet)
- PDF report emailed within ~30 minutes
- A secure link to view findings in their browser (no login yet — tokenized
  URL with 7-day expiry)

**What they don't get**:
- No ongoing monitoring
- No Aegis
- No brain correlation (findings are presented raw with severity)
- No dashboard access beyond the one-time token URL

**Cost structure**: compute cost of Argos run is real. We eat it because of
conversion rates. At scale we rate-limit to 1 free scan per domain per 30
days.

### Red-Team Only

For customers who want ongoing pentesting but can't or won't install a plugin.
Common case: site is on a managed host that forbids third-party plugins, or
the customer has their own WAF and wants complementary offensive coverage.

**What they get**:
- Weekly Argos engagement (configurable to daily/nightly for higher-tier
  pricing)
- Full dashboard access
- Monthly trend report
- Incident correlation when Argos finds multi-step vulnerability chains
- API access to results

**What they don't get**:
- No Aegis → no inline defense, no virtual patches, no authentication event
  visibility
- No AMRDR feedback loop (AMRDR needs Aegis to complete the calibration
  circle — Red-Team Only customers contribute to our industry-wide baseline
  but not to their own site's calibration)

**Competes with**: Astra, Detectify, Acunetix, Intruder. These are typically
priced at $3-10K/year for continuous. Our cost base is lower because Argos is
autonomous — we can undercut significantly.

### Defense Only

For customers who want in-site protection but don't want to pay for the
offensive side, typically because they already have a pentest provider.

**What they get**:
- Aegis installed on their site
- Full dashboard access
- Incident stream from IGRIS-Web
- Virtual patches auto-applied (not queued for approval — the customer has
  given blanket consent at subscription time)

**What they don't get**:
- No Argos runs → no Red-Team-Only dashboard view
- AMRDR runs but has no Argos labels for their site, so reliability
  posteriors rely on fleet-wide priors

**Competes with**: Wordfence Premium, Sucuri, MalCare. These tend to be
priced $10-30/month for basic, $40-100 for business. We enter at similar
pricing but distinguish on tamper-evident Proof Spine logs (compliance angle)
and on the correlation-based incident surface (rather than individual-alert
noise).

### AMOSKYS Web Full

The full thesis. Both sides running. AMRDR calibrating.

**What they get**: everything the previous tiers offer, plus:
- AMRDR per-site calibration (rules tune specifically for their traffic
  pattern)
- Virtual patches routed through approval flow (operator sees "we want to
  revoke this REST route, approve?" before it applies)
- Attack-chain replay capability (take an incident, replay the Argos probes
  that would have caught it earlier, see what we'd do differently)

**Pricing anchor**: probably 2-3× the Defense-Only tier. The value is the
closed-loop calibration that nobody else offers.

### Enterprise

Large customers (funds, governments, regulated industries) or managed-host
partnerships (Kinsta, Pressable, WP Engine).

**Differentiators vs Full**:
- PHP extension tier of Aegis (Tier 3 in the coverage ladder) for deeper
  runtime visibility
- Dedicated engagement rotation (Argos runs attuned to their specific threat
  model)
- Custom rule development
- SOC 2 report, signed DPAs, EU data residency
- Named point of contact, on-call SLA

**Pricing**: contract-based. Ballpark $50-500K/year per customer.

**Managed-host OEM variant**: instead of selling direct to 10,000 managed-
host customers, we sell a bundle to the managed host who pre-installs Aegis
on all their customers and markets "AMOSKYS-powered security" as a
differentiator. Revenue share or fixed-fee, whichever math works.

## Upgrade / downgrade paths

### Free → Red-Team Only
After the first free scan, the report CTA says "Schedule recurring scans,
$X/month." One-click signup. Stripe subscription. No new onboarding.

### Red-Team Only → Full
"Install Aegis to protect against the vulnerabilities we've been finding"
— the dashboard prominently shows this CTA on every engagement report.
Installing Aegis is a plugin ZIP, one click in WP admin, one field to paste
the tenant bearer token.

### Defense Only → Full
"Let us scan your site weekly. First scan is included." One-click upgrade.

### Enterprise from any tier
Manual, sales-assisted.

## Billing and metering

Per-site subscription. The `site_id` is the billing unit. Aegis reports its
site_id; Argos engagements are scoped by site_id. Multi-site tenants get
volume discounts.

Why not per-event? Because customers hate usage-based pricing for security
tools — "don't charge me more when I'm being attacked." Subscription is
industry-standard and aligns incentives (we lose money on heavily-attacked
sites, which motivates us to actually protect them).

## Free-trial mechanics

14-day free trial on Red-Team Only and Defense Only. Full tier: 7 days (it's
the flagship; we don't want to train customers to expect it free). No
Enterprise trial — pilot engagement instead.

## Self-serve vs sales-assisted

- Free, Red-Team Only, Defense Only, Full: fully self-serve via
  `amoskys.com` + Stripe.
- Enterprise: sales-assisted, custom contract, 30-90 day procurement cycle.

## Churn prevention

Two mechanisms baked into the product:
1. **Monthly "here's what we caught" report** auto-emailed to the primary
   contact. Makes the value visible between incidents.
2. **Annual security audit summary** suitable for customer's own compliance
   audits. Creates a sticky reason to renew (you already handed it to your
   auditor once).
