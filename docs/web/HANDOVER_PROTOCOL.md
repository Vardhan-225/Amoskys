# Argos → IGRIS-Web Handover Protocol

The protocol by which findings from the offensive side reach the brain and
become actionable. This is the load-bearing data contract of AMOSKYS Web.

## Shape of the pipe

```
[Argos engagement completes]
        │
        ▼
  for each Finding:
      POST /v1/events                      HTTPS + bearer token
        body = {                           JSON envelope
          schema_version: "1",
          origin: "argos",
          event_type: "argos.finding.{category}",
          engagement_id: <uuid>,
          site_id: <tenant-scoped site ref>,
          severity: "critical|high|medium|low|info",
          attributes: { ...finding fields... },
          event_timestamp_ns: <int>,
          prev_sig: <hex>,
          sig: <hex>
        }
        │
        ▼
[Event Ingest API on AWS]
   1. verify bearer token → resolve tenant_id
   2. verify chain sig matches expectations
   3. enforce per-site scope (site_id belongs to tenant_id)
   4. insert into web_events
        │
        ▼
[IGRIS-Web cortex (polls web_events)]
   1. compute amrdr_web weight for (site, rule_id)
   2. adjusted_severity = raw_severity × amrdr_weight
   3. if adjusted_severity >= HIGH:
        - create incidents row
        - lookup virtual_patch_library[rule_id]
        - if patch exists AND tenant has defense subscription:
            enqueue actions row (requires_approval=true)
   4. emit IGRIS-Web signal for dashboard
        │
        ▼
[Dashboard renders]
[Action Queue → Aegis (if subscription active)]
```

## Event schema — v1

### Envelope fields (all origins)

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | ✓ | `"1"` today |
| `event_id` | UUID | ✓ | unique across all events |
| `origin` | string | ✓ | `"argos"` or `"aegis"` |
| `event_type` | string | ✓ | dotted namespace, e.g. `argos.finding.cve`, `aegis.auth.login_failed` |
| `event_timestamp_ns` | int | ✓ | nanoseconds since epoch |
| `severity` | enum | ✓ | `critical \| high \| medium \| low \| info` |
| `tenant_id` | string | ✓ | resolved from bearer token, **server sets this** (don't trust client) |
| `site_id` | string | ✓ | per-tenant site identifier |
| `engagement_id` | UUID | optional | present for `origin=argos` |
| `attributes` | object | ✓ | event-specific payload |
| `prev_sig` | hex | ✓ | SHA-256 of previous event's envelope (chain) |
| `sig` | hex | ✓ | SHA-256 of this event's envelope (minus sig itself) |

### Argos-specific attributes

For `event_type = "argos.finding.*"`:

```json
{
  "template_id": "nuclei:cves/2024/CVE-2024-28000.yaml",
  "tool": "nuclei",
  "target": "https://lab.amoskys.com/vulnerable/wp-login.php",
  "cvss": 9.8,
  "cwe": "CWE-863",
  "references": ["CVE-2024-28000", "https://..."],
  "mitre_techniques": ["T1068"],
  "evidence": {
    "curl": "curl -X POST ...",
    "request": "POST ...",
    "response_excerpt": "...",
    "matcher_name": "priv-esc-indicator"
  }
}
```

### Aegis-specific attributes

For `event_type = "aegis.*"`, see the existing event types emitted by the
plugin. Documented in
[`class-aegis-sensors.php`](../../src/amoskys/agents/Web/wordpress/wp-content/plugins/amoskys-aegis/includes/class-aegis-sensors.php).

## Chain signature discipline

Every POSTed event must chain-link to the previous event from the same
origin+tenant+site combination. The ingest API verifies this:

```
expected_prev_sig = SELECT sig
                    FROM web_events
                    WHERE tenant_id=? AND site_id=? AND origin=?
                    ORDER BY event_timestamp_ns DESC
                    LIMIT 1;

if submitted.prev_sig != expected_prev_sig:
    reject(400, "chain break")
```

**Edge cases**:
- First event ever from a site: `prev_sig` = `null` (or empty string). Valid.
- Client-side crash that loses `prev_sig` state: client regenerates from their
  local log's last line. If their log is also gone, they submit with
  `prev_sig = null` and a field `chain_restart_reason` in attributes. The
  server accepts this but flags it as a chain-restart event (visible in
  dashboard as a suspicious reset).
- Multi-worker race (two PHP-FPM workers both submitting): serialize at the
  client side via the `amoskys_aegis_prev_sig` WordPress option, which is a
  row in the options table and thus DB-serialized.

## Authorization

### Bearer token issuance
- One token per tenant at subscription creation.
- Token scope: `sites=*` for that tenant. Future: per-site tokens.
- Rotation: manual UI button + automatic every 90 days.

### Scope verification
- Argos POSTs must include `site_id` matching a site the tenant owns.
- Aegis POSTs are implicitly scoped by the `site_id` tied to the token.
- Server rejects POSTs where `site_id` doesn't match tenant's sites: 403.

## Rate caps

| Dimension | Cap |
|---|---|
| Per-token | 100 req/sec (bursty; tune per tenant tier) |
| Per-IP | 50 req/sec (crude DDoS control) |
| Per-site per-event-type | 10 req/sec (stops a log flood from one sensor) |

A properly-instrumented busy site emits maybe 10-30 events/minute. 100/sec is
enormous headroom. If a tenant hits this cap, something is wrong (bug in
Aegis loop, or we're being attacked).

## Idempotency

Each event has a globally-unique `event_id` (UUID). The ingest API must be
idempotent on `event_id` — duplicate submissions (client retry after timeout)
result in 200 OK without duplicate insertion.

## Ordering

Events are processed in `event_timestamp_ns` order per (tenant, site, origin).
The chain signature enforces this implicitly: an out-of-order submission
breaks the chain and is rejected.

## Failure handling

### Aegis client side (PHP)
- POST is non-blocking with 2s timeout (`wp_remote_post(..., ['timeout'=>2, 'blocking'=>false])`).
- Every POST attempt is logged to a local retry queue regardless of success.
- A WP-Cron job every 5 minutes drains the retry queue.
- If retries exceed 24h, event expires from the queue (the local JSONL log
  retains it as forensic evidence).

### Argos client side (Python)
- Each POST retries up to 3 times with exponential backoff (1s, 3s, 10s).
- If all retries fail, the engagement record writes to disk anyway. Operator
  can re-post via `argos upload-report <engagement_id>`.

### Server side
- 5xx responses come with a `Retry-After` header when possible.
- 4xx responses (schema, chain, auth errors) are terminal — client should not
  retry without operator intervention.

## AMRDR feedback loop

Every event that passes through the protocol contributes to AMRDR posteriors:

### On Argos finding → Aegis evidence match
When Argos reports finding `F` on site `S`, and within 30 days Aegis emits an
event on site `S` with attributes matching the finding pattern (e.g., Argos
says "LiteSpeed auth-bypass vulnerable" and Aegis reports
`aegis.auth.role_change high` from external IP), AMRDR records a positive for
the Argos template.

### On Argos finding → no Aegis evidence
After 30 days with no matching Aegis event, AMRDR records a negative for the
Argos template.

### On Aegis event → no matching Argos finding
If Aegis emits a critical event on site `S` and Argos found nothing suggesting
this class of vulnerability, AMRDR records a negative for Argos's coverage of
this attack class. This is the hard one — it says "our offensive didn't spot
the thing our defensive caught live."

These three feedback paths are what make AMRDR different from "self-reported
confidence scores." We have ground truth from both sides.

## Schema versioning

`schema_version` is at the top of the envelope for a reason: when we change
anything, we bump the version and the server continues accepting both for a
transition window of at minimum 90 days.

Breaking-change deprecation path:
1. Ship v2 alongside v1 with `schema_version: "2"` newly accepted.
2. Update clients (Aegis plugin release, Argos release).
3. Set a `v1_sunset_date` in the tenant's dashboard.
4. Start returning warnings in v1 responses 30 days before sunset.
5. After sunset, return 410 Gone on v1 POSTs.

Non-breaking additions: just add optional fields and bump only if semantics
change.

## What is explicitly out of scope for v1

- Streaming ingest (SSE, WebSocket). POST is sufficient for current volume.
- Binary event payloads. If a sensor wants to ship a PCAP, it uploads to S3
  and includes the S3 key in attributes.
- Client-side event batching. One HTTP request per event keeps debugging
  tractable. Revisit at 10k events/minute scale.
