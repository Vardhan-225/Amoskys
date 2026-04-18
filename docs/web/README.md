# AMOSKYS Web

**Status**: Foundations phase · April 2026
**Branch**: `amoskys-web/foundations`

AMOSKYS Web is a web-application security platform built on three pillars: an
autonomous offensive agent (**Argos**), a defensive agent that lives inside the
customer's site (**Aegis**), and a correlation brain (**IGRIS-Web**) that fuses
both streams and decides actions. WordPress-first, then any HTTP application.

This is a sister product to the AMOSKYS macOS endpoint platform, sharing the
Proof Spine principle, the signal-engine kernel, and the scoring primitives —
but with a web-native signal vocabulary, multi-tenant isolation, and a
standalone deployment.

## Start here

| If you are… | Read first |
|---|---|
| New to AMOSKYS Web | [VISION.md](./VISION.md) |
| Setting up the lab for the first time | [QUICKSTART.md](./QUICKSTART.md) |
| Implementing a sensor or a signal | [ARCHITECTURE.md](./ARCHITECTURE.md) |
| Planning a red-team engagement | [RED_TEAM_ARENA.md](./RED_TEAM_ARENA.md) |
| Designing the sales motion | [CUSTOMER_TIERS.md](./CUSTOMER_TIERS.md) |
| Writing code in this monorepo | [MONOREPO_DISCIPLINE.md](./MONOREPO_DISCIPLINE.md) |
| Avoiding mistakes we already made on endpoint | [LESSONS_FROM_ENDPOINT.md](./LESSONS_FROM_ENDPOINT.md) |
| Understanding the Argos→IGRIS flow | [HANDOVER_PROTOCOL.md](./HANDOVER_PROTOCOL.md) |

## The three pillars

- **[Argos](../../src/amoskys/agents/Web/argos/)** — autonomous offensive agent.
  Runs on Kali. Takes a domain (authorized via DNS-TXT ownership proof), does
  recon + fingerprint + probe, produces a structured engagement report.
- **[Aegis](../../src/amoskys/agents/Web/wordpress/wp-content/plugins/amoskys-aegis/)**
  — defensive WordPress plugin. Five sensors (auth, REST, plugin lifecycle,
  FIM, outbound). Ships SHA-256 chain-linked events to IGRIS-Web.
- **IGRIS-Web** — web-native brain (not yet built). Reuses the IGRIS signal
  engine from the endpoint product with a web-specific signal vocabulary.

## The flow in one sentence

Argos attacks the customer site → findings and Aegis's observed-attack events
both stream into IGRIS-Web → IGRIS-Web correlates, creates incidents, queues
virtual patches → customer dashboard shows posture + pending actions.

## Current state (foundations phase)

| Component | State |
|---|---|
| Argos scaffold | ✅ Built, runs end-to-end on a test target |
| Aegis WP plugin | ✅ Live on `lab.amoskys.com`, 5 sensors verified |
| IGRIS-Web brain | ❌ Not yet — design documented, not coded |
| Event Ingest API | ❌ Not yet — the "missing link" between Aegis and IGRIS-Web |
| AMRDR-Web | ❌ Not yet — build before declaring the moat real |
| Customer Dashboard | ❌ Not yet |
| Action Queue / virtual patches | ❌ Not yet |
| Lab infrastructure | ✅ `lab.amoskys.com` live, TLS, WordPress 6.9.4 |

See [QUICKSTART.md](./QUICKSTART.md) for what to build next.

## Lab

The red-team arena lives at `lab.amoskys.com` — an EC2 Ubuntu 24.04 instance
running WordPress with the Aegis plugin active. This is where Argos trains,
where we test new sensors, and where every architectural assumption gets
validated before it leaves our hands.

Credentials and infrastructure coordinates for the lab are in
`docs/_local/` (gitignored) and in the user's `~/.claude/` memory.

## Tooling surfaces

- **CLI**: `python -m amoskys.agents.Web.argos scan <target>`
- **MCP**: three namespaces planned — `argos://`, `igris-web://`, `reports://`
- **Dashboard**: `web/app/` (shared Flask app; extended to render AMOSKYS Web
  views alongside the existing endpoint fleet views)

## Support

Owner: Akash (athanneeru). See repo root [README.md](../../README.md) for the
broader AMOSKYS context.
