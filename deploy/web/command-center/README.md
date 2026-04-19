# Operator Command Center — deployed to lab.amoskys.com

These three files are the canonical source for the AMOSKYS Web Operator
Command Center — the real-live feed of what the Aegis plugin is
watching. The files are deployed to `/opt/amoskys-web/` on the lab;
this is the version-controlled copy.

## Files

| File | Deployed to | Purpose |
|---|---|---|
| `aegis_live.py` | `/opt/amoskys-web/src/app/web_product/aegis_live.py` | Reads `events.jsonl`, computes summary stats, verifies chain, returns a `LiveSnapshot` view-model |
| `command.html` | `/opt/amoskys-web/src/app/templates/web/command.html` | Jinja template rendering the Command Center page |
| `blueprint_command_patch.py` | N/A (reference) | Documents the exact patches applied to `blueprint.py` for import, template filters, and the `/web/command` route |

## Access

The Command Center is owner-only. Auth is via a secret token set in the
systemd environment:

```bash
# on the lab box
sudo systemctl edit amoskys-web.service
# (ensure Environment=AMOSKYS_COMMAND_TOKEN=<secret> is set)
sudo systemctl restart amoskys-web.service
```

First visit: `https://lab.amoskys.com/web/command?token=<secret>` — the
token is then persisted in a Secure HTTP-only cookie for 30 days.
Without a valid token, `/web/command` returns 404 (no hint the page
exists).

## What it shows

- Real-time event count, last-event-ago, chain integrity %
- Severity distribution (info / warn / high / critical)
- Per-sensor-family firing counts (full catalog of 16 families)
- Top external IPs observed (excludes localhost)
- User-agent breakdown
- Live event tail (last 200, severity-filterable)
- Proof Spine first/last sig

Reads are synchronous full-file scans of `events.jsonl`; acceptable for
current log volume (<10 MB typical). Switch to incremental tailing via
inotify when log grows past ~50 MB.

## Deployment

To re-deploy after changes in this directory:

```bash
# From the repo root (Mac)
scp -i ~/.ssh/amoskys-lab-key.pem \
  web_product/aegis_live/aegis_live.py \
  ubuntu@lab.amoskys.com:/tmp/
scp -i ~/.ssh/amoskys-lab-key.pem \
  web_product/aegis_live/command.html \
  ubuntu@lab.amoskys.com:/tmp/

ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com '
  sudo cp /tmp/aegis_live.py /opt/amoskys-web/src/app/web_product/aegis_live.py
  sudo cp /tmp/command.html /opt/amoskys-web/src/app/templates/web/command.html
  sudo systemctl restart amoskys-web.service
'
```

## Lessons (add to LESSONS_FROM_ENDPOINT.md)

1. The operator Command Center is distinct from the customer dashboard.
   Customer views are scoped by `tenant_id` and show fixtures during
   demo mode. The Command Center reads the real plugin log and is
   owner-only.

2. Event logs on the WP host are owned by `www-data`. Gunicorn runs as
   `ubuntu`. We granted `o+r` on `events.jsonl` + `o+x` on the ancestor
   directories so the web app can read it without running as www-data.
   A cleaner production setup: run gunicorn in a dedicated group that
   matches the log file's group.

3. Token auth is minimal-viable but NOT enterprise-grade. For
   production: wire to the tenant table + Argon2 password hashing +
   session management. For the lab / operator use case, a
   systemd-environment token is sufficient and leaks nothing at rest.
