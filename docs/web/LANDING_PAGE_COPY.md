# Landing Page Copy — `amoskys.com/free-pentest`

Drop-in content for a single landing page that converts outreach replies
and warm traffic into free-pentest signups. Copy is tuned for WordPress
SMB owners who know they should worry about security but don't know where
to start.

## Hero section

```
WordPress gets hacked every day.
Find out what an attacker sees — free.

[ Get my free pentest → ]

15 minutes of your time. One DNS record for ownership. Branded PDF
report in your inbox within 2 hours. No credit card.
```

**Subhead**: "We'll run AMOSKYS Argos — our autonomous penetration
testing agent — against your WordPress site. You get a professional
report documenting exactly what an attacker would find."

## Social proof band (once we have it — leave placeholder for now)

```
Trusted by:    [logo]    [logo]    [logo]    [logo]
"I didn't know my xmlrpc was exposed. This took 15 minutes and saved
us from a breach I wouldn't have spotted for months."
   — Jane Doe, IT Director, Company
```

For v0, replace with an "As seen on" row pointing at our blog posts,
HackerNews threads, etc. Until there's genuine social proof, leave the
section out rather than fake it.

## Three-step explainer

### 1. Prove you own your site
A DNS TXT record at `_amoskys-verify.<your-domain>`. Takes 2 minutes to
add via Cloudflare, GoDaddy, or whatever DNS you use. This is standard
penetration-test authorization — we refuse to scan without it.

### 2. Argos scans
Our autonomous pentester runs a read-only, rate-limited probe against
your site. Most engagements complete in 10–20 minutes. No impact on
your site's operation, no downtime, no data touched.

### 3. You get a report
Branded PDF in your inbox, covering every finding with:
- Severity rating + CVSS score
- Exact reproduction steps (the same commands we used)
- How AMOSKYS Web would detect or prevent each one in production

## "What Argos actually does" section

```
Your external attack surface, inspected:

✓ WordPress version + plugin fingerprinting
✓ Exposed endpoints (xmlrpc, wp-cron, /wp-json/*)
✓ User enumeration via the REST API
✓ Known-CVE matching against every plugin version we detect
✓ Server + TLS configuration review
✓ Subdomain enumeration via passive sources
✓ Open-port assessment on web-relevant services
✓ Cross-referenced against 8,000+ public vulnerability signatures
```

## Why we do this

```
AMOSKYS Web is building the first platform that combines three things
no security vendor today offers together:

  OFFENSE — autonomous pentests that run continuously, not once a year
  DEFENSE — a plugin that watches your site from the inside, with
            cryptographic proof of every event
  BRAIN   — a correlation engine that fuses both streams, closes the
            loop, and protects you before attacks succeed

The free pentest is our first handshake with you. If you like what you
see in the report, subscribe for ongoing protection.
```

## CTA section

```
Ready?

[ Claim my free pentest → ]

One email. One DNS record. One scan. One report.
You decide what to do next.
```

## FAQ

### Is this legal?

Yes. We require a DNS TXT record at `_amoskys-verify.<your-domain>`
before any scan runs — that's your written authorization, which is the
standard legal basis for penetration testing. We refuse scans without it.

### Will this break my site?

No. Argos is rate-limited (configurable, typically 5–8 requests/second),
uses only non-destructive probes (the destructive probe classes are
permanently blacklisted at the engine level), and runs for a bounded
time window (default 30 minutes max).

### How long does it take?

The scan itself usually takes 10–20 minutes. We aim to deliver your
report within 2 hours of your DNS record going live.

### What's the catch?

No catch on the free scan. We'll include a CTA to subscribe to AMOSKYS
Web's ongoing protection ($49–$129/month depending on tier), but if you
keep the report and don't subscribe, we're not offended.

### Why is this free?

Because the best marketing for a security platform is showing exactly
what we'd catch. The report is the pitch.

### What happens if you find something critical?

We tell you immediately — don't wait for the full report. If we find a
critical vulnerability being actively exploited on your site, we reach
out within 15 minutes of detection. That's our commitment.

### How do I subscribe after the scan?

The report contains a Stripe Payment Link. One click, credit card,
done. We'll onboard you the same day.

### Do you store my site's data?

The scan result is stored in our system for 90 days, then deleted
unless you subscribe. The report PDF is yours to keep forever.

### Who are you?

Small team. WordPress-focused. Building something we think deserves
to exist. Happy to chat — akash@amoskys.com.

## Form fields (minimal)

```
Your email:       [                 ]
Domain to scan:   [                 ]
Your name:        [                 ]
Company (opt):    [                 ]

                  [ Submit → ]

By submitting you agree to our Terms (we promise they're short).
```

## Trust bar (bottom of page)

```
Your scan runs with:
  • Rate limits — max 5-8 req/sec, never a DDoS
  • Non-destructive probes only — engine-level block on dangerous tools
  • DNS TXT ownership verification — we won't scan without it
  • Cryptographic audit trail — every probe logged, chain-linked,
    available to you on request
```

## Footer

```
AMOSKYS Web
amoskys.com/free-pentest
akash@amoskys.com

Something secure belongs to everyone.
```

---

## Implementation notes

- This is COPY, not HTML. The copy should be dropped into whatever
  landing-page builder you're using — Webflow, Framer, Tailwind UI,
  or hand-rolled HTML on the existing amoskys.com Flask app.
- If hand-rolling: keep it to ONE page (no multi-page flows), use
  a single form that POSTs to `/free-pentest/request`, send the
  DNS TXT challenge via email auto-reply.
- Don't over-design. A functional single-column page with a clear
  CTA converts better than a fancy multi-section page that's hard
  to read on mobile.
- Measure CTR on the CTA button. If < 2% of visitors click it, the
  hero copy needs work. If > 10%, you're probably targeting the
  right audience.
