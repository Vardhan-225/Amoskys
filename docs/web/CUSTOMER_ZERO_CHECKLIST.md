# Customer Zero Checklist — What's needed before we can take money

Single-page checklist tracking the concrete blockers between "product
scaffold exists" and "we can sell this to customer #1."

## What exists today (April 18, 2026)

- [x] Lab environment (lab.amoskys.com, live, Aegis active, 16 event types firing)
- [x] Argos v0.2 on Kali — 10 tool drivers, preset bundles
- [x] Argos report renderer — HTML + PDF, publisher-grade
- [x] Chain-linked evidence log (Proof Spine in PHP)
- [x] Git branch `amoskys-web/foundations` with 5,000+ lines, public on GitHub
- [x] Documentation (docs/web/, 12 files, ~2,000 lines)

## What's needed before we can take customer #1

### P0 — Must-have before first outreach

- [ ] **Stripe Payment Link set up**
  - amoskys.com Stripe account → Products → create "AMOSKYS Web Full $129/mo"
  - Copy payment link URL
  - Paste into `report.py`'s `customer_info.product_url` default
  - Test: click the link on a rendered PDF, confirms Stripe checkout page loads

- [x] **`_amoskys-verify.<domain>` DNS-TXT verification code path in Argos**
  - DONE (commit 388463d+1): dnspython-based TXT lookup against
    `_amoskys-verify.<target>`. Rejects engagement with clear error if
    record missing, empty, or token mismatch. Dev bypass via
    `--skip-dns-verify` flag (lab use only — never ship to customers).

- [ ] **Outbound email mechanism**
  - Option A: AWS SES (cheap, but needs domain verification + production access approval, 2-3 days)
  - Option B: Resend.com or Postmark (fastest, ~30 min to first send)
  - Used for: DNS-TXT instructions, report delivery, follow-up
  - Effort: 1 hour for Resend, 1 day for SES

- [ ] **Landing page live at amoskys.com/free-pentest**
  - Content: see `LANDING_PAGE_COPY.md` — ready to drop in
  - Form fields: email, domain, name, company (optional)
  - Form submits to: `/free-pentest/request` (POST handler that emails us)
  - Effort: 2-4 hours depending on existing Flask app structure

- [ ] **Outreach email drafts loaded + ready**
  - Templates in `OUTREACH_PLAYBOOK.md`
  - Load into your email client as snippets / canned responses
  - Effort: 30 min

- [ ] **Prospect list v1 — 20 targets**
  - Use BuiltWith + LinkedIn per playbook guidance
  - Tier by industry: clinics, law firms, Woo stores, agencies
  - Effort: 2-4 hours research

### P1 — Should-have before customer #5

- [ ] **Actual per-tenant API tokens for the ingest endpoint**
  - Current: single dev token
  - Needed: issue unique token per customer at subscription creation
  - Effort: 2 hours

- [ ] **Aegis install script for new customer sites**
  - Script: `scripts/web/install-aegis-for-customer.sh <domain> <tenant_token>`
  - Takes: customer's WP admin creds (or SSH access to their host)
  - Installs: Aegis plugin ZIP, configures `remote_url` + bearer token, activates
  - Effort: 2-3 hours

- [ ] **Engagement queue (cron-driven)**
  - systemd timer on the ops host: scan each active customer's domain weekly
  - Output: engagement JSON + PDF to each customer's inbox
  - Effort: 3-4 hours

### P2 — Nice-to-have before customer #10

- [ ] Dashboard (`/web/sites/<id>`)
- [ ] Multi-tenant isolation in the ingest DB
- [ ] Per-customer virtual-patch approval flow
- [ ] Daily digest emails vs weekly

## Concrete "we can run customer #1 manually" checklist

To take customer #1 TODAY with what we have, the minimum is:

1. **Get a Stripe Payment Link** — 5 min (user-driven)
2. **Update the report template** with the real Payment Link URL — 2 min
3. **Get one prospect to say yes** — unknown
4. **Verify their DNS TXT manually** — 1 min
5. **Run Argos manually from Kali** — 30 min wall-clock
6. **Render report** — 1 min (`argos report <json>`)
7. **Email them the PDF** — 2 min (any email client)
8. **If they want to subscribe, paste them the Payment Link** — 1 min

Total founder time per customer: ~45 min. At that rate, 10 customers =
~8 hours of direct customer work. Doable in a focused week.

## Red flags / stop-ship blockers

- [ ] **No scan until DNS TXT is verified by code (not manual).** The
      manual gate is fine for 1-5 customers; automate before customer 10.
- [ ] **No exploitation during the free scan.** Read-only probes ONLY.
      Argos's DENIED_PROBE_CLASSES enforces this but double-check per tool.
- [ ] **Don't oversell in the report.** The CTA should be honest:
      "subscribe for ongoing protection" NOT "this report saved your life."

## Definition of "done" for customer #1

All of these must be true:

- [ ] Prospect signed outreach agreement (email reply = sufficient for v0)
- [ ] DNS TXT verified (ownership proven)
- [ ] Scan completed, report delivered via email
- [ ] Prospect clicked the Stripe Payment Link
- [ ] Stripe webhook fired (payment received)
- [ ] Aegis installed on their WP site
- [ ] First event from their site hits our event log
- [ ] Scheduled weekly re-scan in place

If all eight are true, we have customer #1. If we hit this in the next
30 days, AMOSKYS Web is a real business.
