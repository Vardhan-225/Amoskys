# Architecture

## High-level picture

```
┌──────────────────┐   ┌─────────────┐   ┌───────────────────┐   ┌────────────────┐
│ OFFENSE          │   │ MCP PLANE   │   │ DEFENSE / BRAIN   │   │ CUSTOMER SITE  │
│ Kali VM          │   │ Claude ops  │   │ AWS Ubuntu        │   │ WordPress      │
├──────────────────┤   ├─────────────┤   ├───────────────────┤   ├────────────────┤
│ Argos core       │═══│ argos://    │   │ Event Ingest API  │═══│ nginx + TLS    │
│ Kali toolbelt    │   │ igris-web://│   │ AMOSKYS Web DB    │   │ PHP-FPM + WP   │
│ PentAGI reasoner │   │ reports://  │   │ IGRIS-Web cortex  │   │ Aegis plugin   │
│ OOB Collaborator │   │             │   │ AMRDR-Web         │   │ events.jsonl   │
└──────────────────┘   └─────────────┘   │ Action Queue      │   │ Remote POST    │
                                         │ Report Gen        │   │ Customer UI    │
                                         └───────────────────┘   └────────────────┘
```

Four swimlanes. Three physical locations (Kali VM, AWS host, customer site).
Claude agents drive everything through MCP.

## Data plane

The only data path that matters:

```
Argos engagement ends
   └─> Findings signed + POST /v1/events (origin="argos")
                             │
Aegis sensor fires           │
   └─> Event signed + POST /v1/events (origin="aegis")
                             │
                             ▼
              ┌──────────────────────────┐
              │    Event Ingest API      │  per-tenant auth
              │  FastAPI on AWS Ubuntu   │  per-IP rate cap
              └──────────────┬───────────┘  schema validation
                             │
                             ▼
              ┌──────────────────────────┐
              │    AMOSKYS Web DB        │  per-tenant rowset
              │  Postgres (new)          │  web_events table
              └──────────────┬───────────┘  incidents table
                             │              posture table
                             ▼
              ┌──────────────────────────┐
              │    IGRIS-Web cortex      │  reads new events every N sec
              │  signals + correlation   │  writes incidents on match
              └──────────────┬───────────┘  writes actions to queue
                             │
                ┌────────────┴─────────────┐
                ▼                          ▼
         ┌─────────────┐            ┌─────────────┐
         │ Dashboard   │            │Action Queue │
         │ Report Gen  │            │ → Aegis     │
         └─────────────┘            └─────────────┘
```

## Component specifications

### Argos
- **Location**: Kali VM (`ghostops@192.168.237.132` during development; a
  hardened Kali container on AWS for production)
- **Language**: Python 3.13+
- **Entry point**: `python -m amoskys.agents.Web.argos scan <target>`
- **Dependencies**: Kali-native tools (subprocess-invoked)
- **State**: stateless; each engagement writes its own report to disk and
  POSTs findings to the Event Ingest API
- **Module**: [`src/amoskys/agents/Web/argos/`](../../src/amoskys/agents/Web/argos/)

### Aegis
- **Location**: inside PHP-FPM on the customer's WordPress host
- **Language**: PHP 8.0+
- **Entry point**: WordPress plugin, bootstraps on `plugins_loaded` priority 1
- **Dependencies**: none beyond WordPress core
- **State**: SHA-chained local JSONL at
  `wp-content/uploads/amoskys-aegis/events.jsonl`, plus the
  `amoskys_aegis_prev_sig` WordPress option to link chains across restarts
- **Module**: [`src/amoskys/agents/Web/wordpress/wp-content/plugins/amoskys-aegis/`](../../src/amoskys/agents/Web/wordpress/wp-content/plugins/amoskys-aegis/)

### Event Ingest API (NOT YET BUILT)
- **Location**: AWS Ubuntu ops host
- **Language**: Python (FastAPI recommended)
- **Endpoint**: `POST /v1/events`
- **Auth**: per-tenant bearer token, issued at subscription creation
- **Rate cap**: per-token, per-IP, per-tenant (separate buckets)
- **Schema**: canonical JSON envelope matching Aegis's
  [`build_envelope()`](../../src/amoskys/agents/Web/wordpress/wp-content/plugins/amoskys-aegis/includes/class-aegis-emitter.php) output
- **Storage**: append to AMOSKYS Web DB + optional S3 cold archive

### AMOSKYS Web DB (NOT YET BUILT)
- **Location**: AWS Ubuntu ops host
- **Engine**: Postgres 15+ (deliberately not SQLite — multi-tenant concurrency
  demands row-level security and concurrent writers)
- **Key tables**:
  - `tenants` — customer organizations
  - `sites` — WordPress sites owned by a tenant (maps `site_id` from Aegis)
  - `web_events` — every event from Aegis or Argos
  - `engagements` — Argos engagement records
  - `findings` — individual Argos findings
  - `incidents` — IGRIS-Web-created incidents
  - `actions` — virtual patches queued for Aegis
  - `amrdr_posteriors` — reliability posteriors per (site, rule_id)
- **Tenant isolation**: every query joins on `tenant_id` via row-level
  security policy. No exceptions. See
  [LESSONS_FROM_ENDPOINT.md](./LESSONS_FROM_ENDPOINT.md#lesson-2-multi-tenant-first).

### IGRIS-Web (NOT YET BUILT)
- **Location**: AWS Ubuntu ops host, same process or sidecar as Ingest API
- **Design**: adapts the [existing IGRIS supervisor](../../src/amoskys/igris/supervisor.py)
  — swap the metric collectors for web-native ones, swap the signal
  vocabulary for web signal types.
- **Signal vocabulary (v0)**:
  - `WEB_AUTH_BRUTE_FORCE` — N failed logins from same IP in window
  - `WEB_PLUGIN_COMPROMISE_CHAIN` — plugin update → outbound anomaly → FIM
  - `WEB_UNAUTH_REST_ROUTE` — `__return_true` permission callback detected
  - `WEB_POI_ATTEMPT` — PHP object injection canary
  - `WEB_WPCONFIG_TAMPER` — FIM critical
  - `WEB_OUTBOUND_ANOMALY` — outbound to new host or Ethereum RPC
  - `WEB_ARGOS_FINDING_HIGH` — Argos reported a high-severity finding
  - `WEB_ARGOS_FINDING_CRITICAL` — Argos reported a critical finding
- **Feedback loop safety**: the self-amplifying bug from the endpoint brain
  (`THRESHOLD_INCIDENTS.CRITICAL` measuring its own output) must NOT happen
  here. See [LESSONS_FROM_ENDPOINT.md](./LESSONS_FROM_ENDPOINT.md#lesson-1-noise-suppression-from-day-1).

### AMRDR-Web (NOT YET BUILT)
- **Location**: library linked into IGRIS-Web
- **Design**: Beta-Binomial posterior per (site, rule_id, sensor). Updated on:
  - Argos finding confirmed by Aegis catching an exploit attempt → positive
  - Argos finding with no Aegis evidence over 30 days → negative
  - Aegis alert with no matching Argos finding → negative for Aegis
- **Not a stub**. The endpoint AMRDR is `NoOpReliabilityTracker`. Web AMRDR
  must actually compute posteriors from day one, even if the math is crude.

### Customer Dashboard (NOT YET BUILT)
- **Location**: AWS Ubuntu ops host — extends existing `web/app/` Flask
- **Pages**:
  - `/web/sites/<id>` — per-site posture + incident timeline
  - `/web/sites/<id>/engagements/<eid>` — Argos engagement detail
  - `/web/sites/<id>/actions` — pending virtual patches (approve/reject)
  - `/web/reports/daily` — daily roll-up
- **Auth**: per-tenant sessions

### Action Queue (NOT YET BUILT)
- **Location**: AMOSKYS Web DB table + poller
- **Flow**: IGRIS-Web writes an Action row → Aegis polls `/v1/actions?site_id=...`
  on a 60s interval → Aegis applies or returns "awaiting approval"
- **Action types** (v0):
  - `QUARANTINE_PLUGIN` — deactivate a named plugin
  - `FREEZE_WPCONFIG` — mark wp-config hash as baseline, refuse modifications
  - `REVOKE_REST_ROUTE` — hook `rest_pre_dispatch` to 403 a specific route
  - `FORCE_LOGOUT_ALL` — invalidate all sessions
  - `BLOCK_OUTBOUND_HOST` — blacklist outbound to a specific host
- **Operator approval**: every action marked `requires_approval=true` by
  default. Customer UI exposes approve/reject. Auto-approve only for reversible,
  low-blast-radius actions (configurable per tenant).

### MCP plane
Three independent MCP servers, three namespaces. One Claude client, three
conversations. Namespace separation matters because:
- offensive operations (Argos) and defensive operations (IGRIS-Web) are
  different trust domains
- audit trails stay cleaner when separated
- future product-embedded agents can be given access to only one namespace

| Namespace | Tools |
|---|---|
| `argos://` | `scan(target)`, `abort(engagement_id)`, `status(engagement_id)`, `report(engagement_id)`, `schedule(target, cron)` |
| `igris-web://` | `posture(site_id)`, `incidents(site_id, status)`, `approve(action_id)`, `reject(action_id)`, `trace(incident_id)` |
| `reports://` | `daily_summary(date)`, `engagement_pdf(engagement_id)`, `customer_monthly(tenant_id, month)` |

## The Proof Spine property

Every event emitted by Aegis and every phase event emitted by Argos carries a
SHA-256 signature computed over the event body and the previous event's
signature. This creates a tamper-evident chain: altering any historical event
invalidates every subsequent signature.

On the defensive side, chain integrity is checked by an operator tool that
iterates the log and verifies signatures. On the offensive side, the same
applies to engagement phase events.

This is the "Proof Spine" principle. It's what allows a customer to hand us
their log at incident-response time and trust that no internal-threat party
tampered with it. It's also a differentiator that no WordPress security vendor
publishes today.

## Multi-tenant isolation (hard requirement)

Unlike the endpoint product — which is single-tenant by design because it's an
internal org tool — AMOSKYS Web is multi-tenant from day one. Every row in the
database carries a `tenant_id`. Every query filters on `tenant_id`. Postgres
row-level security enforces it at the engine level, not just in application
code.

**Failing to enforce tenant isolation at the query layer is an existential bug
for this product.** A customer seeing another customer's events is SLA-breaking
on day one and reputationally terminal thereafter.

## Deployment units

| Unit | Where | How |
|---|---|---|
| Argos | Kali VM or Kali container | `pip install -e .` from repo, or prebuilt image |
| Aegis | Customer WordPress site | `.zip` install from WordPress admin, or managed-host pre-install |
| Event Ingest API | AWS Ubuntu ops host | systemd unit, gunicorn + FastAPI |
| IGRIS-Web | AWS Ubuntu ops host | systemd unit, Python daemon |
| Customer Dashboard | AWS Ubuntu ops host | extended existing Flask app |

Nothing here containers. Kubernetes is deliberately not in the v0 topology —
the fleet is small, the components are stateful, and operational simplicity
trumps portability at this stage.
