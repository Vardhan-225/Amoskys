# Fleet Globe — /web/globe

Ported from the AMOSKYS OS overview globe (`web/app/templates/dashboard/overview.html`),
retargeted for WordPress-site protection: points = customer sites, arcs = attack
traffic from scanner IPs, rings = active engagements.

## Files

| File | Deployed to | Purpose |
|---|---|---|
| `globe.html`       | `/opt/amoskys-web/src/app/templates/web/globe.html` | Full Jinja template + globe.gl init |
| `fleet_globe.py`   | `/opt/amoskys-web/src/app/web_product/fleet_globe.py` | Seed data + arc builder |
| `blueprint_patch.py` | reference | Documents the route to add to blueprint.py |

## Route to add

```python
from .fleet_globe import (
    SEED_FLEET, build_sites_view, build_sites_json,
    build_arcs_json, build_stats,
)

@web_bp.route("/globe")
def globe():
    sites_view = build_sites_view()
    sites_json = build_sites_json(sites_view)
    arcs_json  = build_arcs_json(sites_view)
    # Pull the live aegis chain % so the top metric is honest
    snap = _aegis_tail.snapshot()
    chain_pct = (100 * snap.chain_ok / snap.total_events) if snap.total_events else 100.0
    stats = build_stats(sites_view, len(arcs_json), chain_pct)
    return render_template(
        "web/globe.html",
        sites_view=sites_view,
        sites_json=sites_json,
        arcs_json=arcs_json,
        stats=stats,
    )
```

## Dependencies

- `globe.gl@2` — pulled from jsdelivr CDN at template load; no bundler
- Earth textures — from `three-globe/example/img/` on jsdelivr

## Deploy

```bash
scp -i ~/.ssh/amoskys-lab-key.pem \
  deploy/web/globe/globe.html \
  ubuntu@lab.amoskys.com:/tmp/

scp -i ~/.ssh/amoskys-lab-key.pem \
  deploy/web/globe/fleet_globe.py \
  ubuntu@lab.amoskys.com:/tmp/

ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com '
  sudo cp /tmp/globe.html /opt/amoskys-web/src/app/templates/web/globe.html
  sudo cp /tmp/fleet_globe.py /opt/amoskys-web/src/app/web_product/fleet_globe.py
  # Add the /globe route to blueprint.py (see blueprint_patch.py)
  sudo systemctl restart amoskys-web.service
'
```

## Visual model

- **Point color** = site posture (green = healthy, amber = needs attention, red = critical)
- **Arc color** = attack severity (red = threat, amber = benign scan)
- **Arc animation speed** = attack intensity (fast = active threat, slow = probe)
- **Ring pulse** = active Argos engagement on that site
- **Auto-rotate** default on; toggle via "Rotate" button

## What this tells a prospect

"We protect WordPress sites in 16 countries. The amber/red arcs landing on our
sites are real scan traffic we see every day. The rings pulsing red are sites
we're actively pentesting right now. Your site would be a point on this globe."

## Next iterations (post-v0)

- Wire the seed fleet to actual tenant data (requires tenant → sites plumbing)
- Real-time WebSocket updates when a scan launches (ring appears live)
- Heatmap mode showing aggregate attack volume per region
- IP-geolocation of scanner sources via MaxMind DB (currently hardcoded)
