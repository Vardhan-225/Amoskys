# AMOSKYS Web Changelog

## [foundations] — 2026-04-18

### Added
- **Branch**: `amoskys-web/foundations` from `main`.
- **Aegis WordPress plugin v0.1.0-alpha** — 5 sensors (auth, REST, plugin
  lifecycle, FIM, outbound), SHA-256 chain-linked event log, admin settings
  page, WP-CLI installable. Verified live on `lab.amoskys.com` with 23+
  events and 23/23 chain integrity.
- **Argos Python package v0.1.0-alpha** — 6-phase engagement driver with
  scope gate, denylist of destructive probe classes, nuclei + wpscan tool
  drivers. CLI verified end-to-end.
- **Lab infrastructure scripts** — `lab-up`, `lab-down`, `lab-status`,
  `lab-ssh`, `install-wordpress.sh` with LEMP + Aegis + Let's Encrypt.
- **IGRIS noise audit** — `src/amoskys/igris/NOISE_AUDIT.md` documenting
  the self-amplifying feedback loop (`THRESHOLD_INCIDENTS.CRITICAL`
  measuring its own output) and four proposed fixes.
- **Full documentation tree** under `docs/web/`:
  - `VISION.md`, `ARCHITECTURE.md`, `RED_TEAM_ARENA.md`,
    `HANDOVER_PROTOCOL.md`, `CUSTOMER_TIERS.md`,
    `MONOREPO_DISCIPLINE.md`, `LESSONS_FROM_ENDPOINT.md`, `QUICKSTART.md`

### Infrastructure
- **Lab EC2 instance** launched: `i-082fd9c71efc3638e`, Ubuntu 24.04,
  t3.micro, `us-east-1`, at `98.89.32.163`.
- **DNS**: `lab.amoskys.com` A record via Cloudflare (DNS-only, grey cloud).
- **TLS**: Let's Encrypt cert for `lab.amoskys.com`, auto-renewing via
  `certbot.timer`.
- **LEMP stack**: nginx 1.24.0, PHP-FPM 8.3.6, MariaDB 10.11.14,
  WordPress 6.9.4.

### Changed
- `.gitignore` — added rules for `docs/_local/`, `**/creds.env`,
  `**/*.secrets`, `.mcp.json`, `.claude/launch.json`.
- Final monorepo structure committed: `src/amoskys/agents/Web/` alongside
  existing `src/amoskys/agents/os/` and `agents/common/`.

### Not yet built (explicit gaps)
- `/v1/events` Event Ingest API on the ops server.
- `AMOSKYS Web DB` on Postgres (separate from endpoint `fleet.db`).
- `IGRIS-Web` cortex process with web-specific signal vocabulary.
- `AMRDR-Web` with real Beta-Binomial math (target: ship v1 non-stubbed).
- Customer Dashboard pages (`/web/sites/...` routes).
- Action Queue and virtual-patch push-back to Aegis.
- MCP servers for `argos://`, `igris-web://`, `reports://` namespaces.
- Multi-tenant isolation in database and middleware.
- Daily / monthly report generator.

### Naming / scope locked
- Three pillars: **Argos** (offense), **Aegis** (defense), **IGRIS-Web**
  (brain).
- Retired names: Sentinel, SentriWP, CIA-WAF, Proving Plane.
- Scope: WordPress only until customer #10.
