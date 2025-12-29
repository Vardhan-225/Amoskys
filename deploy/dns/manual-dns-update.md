# Manual DNS Update Guide

If you prefer to manually update Cloudflare DNS instead of using the automated script.

## Steps:

### 1. Log into Cloudflare Dashboard
- Go to [dash.cloudflare.com](https://dash.cloudflare.com)
- Select `amoskys.com` zone

### 2. Go to DNS Records
- Click **DNS** in left sidebar
- Click **Records**

### 3. Add/Update A Record for Root Domain

**Add new record:**
- Type: `A`
- Name: `@` (represents amoskys.com)
- IPv4 address: `YOUR_VPS_IP` (e.g., 203.0.113.57)
- Proxy status: **Proxied** (orange cloud)
- TTL: Auto
- Click **Save**

### 4. Add/Update A Record for www Subdomain

**Add new record:**
- Type: `A`
- Name: `www`
- IPv4 address: `YOUR_VPS_IP` (same as above)
- Proxy status: **Proxied** (orange cloud)
- TTL: Auto
- Click **Save**

### 5. Verify DNS Propagation

From your Mac:
```bash
# Check if DNS points to Cloudflare proxy
dig amoskys.com

# You should see Cloudflare IPs (not your VPS IP directly)
# This is correct - Cloudflare proxies traffic
```

### 6. Test HTTP Access (Before SSL)

```bash
# Should return Cloudflare response
curl -I http://amoskys.com

# May get 522 error (Connection timed out) - this is OK
# It means Cloudflare can't reach your VPS yet
# We'll fix this in the next step
```

## Next: Deploy AMOSKYS on VPS

See [VPS_DEPLOYMENT_STEPS.md](VPS_DEPLOYMENT_STEPS.md) for server setup.
