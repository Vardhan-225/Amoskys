# Outreach Playbook — Customer #1 Sprint

The goal of this document is singular: land the first paying AMOSKYS Web
customer. Everything else in `docs/web/` describes how the product works;
this file describes how we sell it before the infrastructure to run at
scale exists.

## The mechanic (end-to-end flow for customer #1)

```
Find prospect
     │
     ▼
Send outreach → "Free pentest, no credit card, 15 min of your time"
     │
     ▼
Prospect says yes
     │
     ▼
Ask for DNS TXT ownership proof (_amoskys-verify.<domain>)
     │
     ▼
Verify TXT is live
     │
     ▼
Run Argos from Kali  (python -m amoskys.agents.Web.argos scan <domain>)
     │
     ▼
Render branded report (argos report <json>)
     │
     ▼
Email PDF to prospect + offer subscription via Stripe Payment Link
     │
     ▼
Follow-up within 48h: "Here is how AMOSKYS protects against finding #N"
     │
     ▼
Sale
```

Every step is manual for customers 1–10. Automate once the flow is
proven.

## Who to target (in priority order)

1. **SMB WordPress sites with obvious attack surface**
   - Clinics, law firms, dental offices, accountants
   - Local service businesses ("Main Street" shops with WP marketing sites)
   - Small e-commerce on WooCommerce
   - Membership / subscription WP sites
   - Marketing agencies that host 5–50 client sites

2. **Secondary targets (bigger sales cycle, higher value)**
   - Non-profits with donor data
   - Educational institutions with WP course sites
   - Local government WP sites

3. **Deprioritized**
   - Pure hobby blogs (no budget)
   - Enterprise (too slow, not our ICP yet)
   - WordPress.com-hosted sites (can't install Aegis)

## How to find them

### Tools
- **BuiltWith** (builtwith.com) — search for "WordPress" + filter by country, industry
- **Wappalyzer** — Chrome extension; also has a lookup service
- **Shodan** — `http.html:"wp-content"` or `product:"WordPress"` filter
- **Censys** — similar scope
- **Google dorks** — `inurl:/wp-content/plugins/ site:*.example-industry.com`
- **SimilarWeb** / **Semrush** — competitor analysis of WP sites

### Direct tactics
- LinkedIn search for "marketing director" / "IT lead" at SMBs; check their company website for WP
- Local business directories (Yelp, Google Business) → check the linked website
- WooCommerce showcase — real stores running WP+Woo
- Reddit r/WordPress and r/ProWordPress for people posting questions suggesting pain

### Don'ts
- Don't scan without written permission (DNS TXT is our permission gate)
- Don't send the same email to 500 addresses (spam)
- Don't claim to have "found a vulnerability" as the opener — that's extortion pattern, illegal in several jurisdictions

## Email templates

### Template 1 — Cold, no prior relationship

Subject line options:
- `Free pentest for {{ company_name }}` — direct, might trigger spam
- `Quick WordPress security audit for {{ domain }}` — cleaner
- `Is {{ domain }} running an old WooCommerce?` — specific, relevant

```
Hi {{ first_name }},

I run AMOSKYS Web, a new kind of WordPress security platform. We're
inviting a small number of SMB site owners to claim a free external
penetration test — the same kind an attacker would run, but delivered
as a clean PDF report you can hand to your team or your auditor.

No credit card, no sales call, no obligation. The flow is:

  1. You add a single DNS TXT record to prove you own {{ domain }}
     (takes 2 minutes, I'll send exact instructions)
  2. Our autonomous agent runs a rate-limited, non-destructive scan
     (usually 10-20 minutes)
  3. You receive a branded PDF report with prioritized findings

If we find something, the report shows exactly how AMOSKYS Web's
defensive side would detect or contain each finding. If you want to
subscribe afterward, great. If not, you keep the report.

Interested?

— Akash
  amoskys.com
```

### Template 2 — Warmer, prospect posted about WP security

```
Hi {{ first_name }},

Saw your post about {{ specific_topic }} — I work on WordPress
security full-time and have a free offer that might save you a
weekend.

We run a project called AMOSKYS Web — autonomous external pentests
with a proper report deliverable. Takes 15 minutes of your time (one
DNS TXT record to prove ownership, then we scan and send the report).

Want to claim a scan? I can have the report in your inbox tomorrow.

— Akash
  amoskys.com
```

### Template 3 — Ownership verification (after they say yes)

```
Great — to run the scan, I need you to add one DNS TXT record so I
have written proof you own {{ domain }}. This is standard practice
for pentest authorization.

  Host:    _amoskys-verify
  Type:    TXT
  Value:   amoskys-verify={{ tokenuuid }}
  TTL:     300 (or default)

Once it's live (usually 30 seconds via Cloudflare, longer for legacy
DNS), reply "live" and I'll kick off the scan. You'll have the report
within 2 hours.

The scan is read-only, rate-limited to {{ max_rps }} requests/second,
and will complete in about 10-20 minutes. There is no risk to your
site's operation.

— Akash
```

### Template 4 — Report delivery (with CTA)

```
Hi {{ first_name }},

Attached is your AMOSKYS Web pentest report for {{ domain }}.

Quick summary:
  - {{ risk_rating }} risk
  - {{ total_findings }} findings ({{ critical }} critical, {{ high }} high, {{ rest }} lower)
  - Full details in the PDF

The report includes:
  1. An executive summary with severity breakdown
  2. Per-finding details with reproducible proof-of-concept
  3. How AMOSKYS Web's defensive side protects against each one

If you'd like ongoing protection — we continue running scans every
week, plus install a plugin that catches exploitation attempts in
real time — you can subscribe here:

  {{ stripe_payment_link }}

First 30 days are free. Cancel any time.

Happy to jump on a call to walk through any finding. Just hit reply.

— Akash
  amoskys.com
```

### Template 5 — 48h follow-up

```
Hi {{ first_name }},

Quick check-in on the pentest report I sent Thursday. A couple of the
findings I wanted to flag specifically:

  {{ finding_1_summary }} — this one ({{ finding_1_severity }}) is worth
  addressing within the week. It's the same class of issue that
  compromised 20,000 WordPress sites in the April 2026 EssentialPlugin
  supply-chain attack.

  {{ finding_2_summary }} — {{ finding_2_severity }}, slightly more
  patient but shouldn't sit for long.

If you want AMOSKYS Web to protect against these (and continue watching
for new ones), subscription is here:

  {{ stripe_payment_link }}

Either way, let me know if the report was useful.

— Akash
```

## Subscription mechanics (v0 — literally a Stripe Payment Link)

For customer #1-10, don't build a signup flow. Use a Stripe Payment Link:

1. Stripe dashboard → Products → create "AMOSKYS Web — Defense + Red Team" $X/month
2. Products → ... → Create payment link
3. Paste that URL into the report CTA (`product_url` template context)

When someone pays, Stripe emails you + the customer. You then:

1. Email them the AMOSKYS admin portal URL (for now: "I'll install Aegis on your site today, send me your WP admin creds" — or have them create an admin user for `amoskys_support@amoskys.com`)
2. SSH into their WP host, install Aegis plugin, configure the bearer token
3. Add their domain to the Argos scheduler (cron: weekly scan)
4. Send welcome email confirming they're on-boarded

For the first 3-5 customers, this is bespoke concierge onboarding. Use
that time to write down everything you do manually — that's the
automation roadmap for customer 10+.

## Pricing v0 (illustrative, tune based on conversion data)

- **Red-Team Only**: $99/mo per site → weekly Argos, no Aegis
- **Defense Only**:  $49/mo per site → Aegis, no Argos
- **Full**:          $129/mo per site → both + brain correlation
- **Free tier**:     1 Argos scan, one-off

Most SMBs will balk at $129/mo. Lead with Red-Team Only as the entry
tier; up-sell to Full once they see a finding they care about.

## What NOT to automate yet

- Fancy dashboard (nice-to-have — reports via email work for first 10)
- Per-tenant ingest (single ingest database, mental tenancy by site_id)
- Auto-onboarding via API (manual install is fine at scale 1-10)
- AMRDR (no data yet — wait for 5-10 customers)
- Multi-CMS (WordPress only until customer 10)

## Goals for the first 30 days

- 50 outreach emails sent (average 1-2% response → expect 1-3 replies)
- 5 free pentests delivered
- 1 paid subscription (ANY tier)

Hit that, AMOSKYS Web is a real business. Miss that, iterate on the
outreach message and/or target segment.
