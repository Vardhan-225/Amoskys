# AMOSKYS - DNS Deployment Guide for amoskys.com
# Complete Cloudflare DNS Setup for Production

🧠🛡️ **AMOSKYS Neural Security Command Platform - DNS Deployment**

---

## Overview

This guide provides complete instructions for configuring DNS records in Cloudflare for the AMOSKYS platform deployed at **amoskys.com**. 

Your Cloudflare account is already set up with:
- **Zone ID**: `3f214ea5270b99e93c2a1460000e7a00`
- **Account ID**: `a65accb1674b8138917103c0c334a981`
- **DNS Setup**: Full (Cloudflare nameservers)
- **Registrar**: Cloudflare
- **Domain Expiry**: September 12, 2026

---

## Prerequisites

- ✅ Domain registered and managed by Cloudflare
- ✅ Cloudflare account access
- ✅ VPS/Server with static IP address
- ✅ NGINX configured on VPS (see `deploy/nginx/amoskys.conf`)
- ✅ SSL certificates (Cloudflare Origin Certificate recommended)

---

## Step 1: Configure DNS Records

### Using Cloudflare Dashboard

1. **Log in to Cloudflare Dashboard**
   - Navigate to: https://dash.cloudflare.com
   - Select domain: `amoskys.com`
   - Go to: **DNS** → **Records**

2. **Add Primary Records**

   Create the following DNS records (replace `YOUR_VPS_IP` with your actual server IP):

   | Type  | Name    | Content            | Proxy Status | TTL  | Comment                        |
   |-------|---------|-------------------|--------------|------|--------------------------------|
   | A     | @       | YOUR_VPS_IP       | Proxied ✅   | Auto | Main domain                    |
   | A     | www     | YOUR_VPS_IP       | Proxied ✅   | Auto | WWW subdomain                  |
   | CNAME | app     | amoskys.com       | Proxied ✅   | Auto | Application dashboard          |
   | CNAME | api     | amoskys.com       | Proxied ✅   | Auto | API endpoints                  |
   | CNAME | docs    | amoskys.com       | Proxied ✅   | Auto | Documentation                  |

3. **Add Future-Ready Records (Optional)**

   | Type  | Name    | Content            | Proxy Status | TTL  | Comment                        |
   |-------|---------|-------------------|--------------|------|--------------------------------|
   | CNAME | status  | amoskys.com       | Proxied ✅   | Auto | Status page (future)           |
   | CNAME | metrics | amoskys.com       | Proxied ✅   | Auto | Metrics dashboard (future)     |

4. **Save All Records**
   - Click "Save" for each record
   - Wait 1-2 minutes for propagation

### Using Cloudflare API (Advanced)

For automated deployment, you can use the Cloudflare API with the configuration in:
- `deploy/dns/cloudflare-dns-records.json` (template)
- `deploy/dns/setup-cloudflare-dns.sh` (automation script)

```bash
# Set your Cloudflare API token
export CLOUDFLARE_API_TOKEN="your_api_token_here"
export VPS_IP="your.vps.ip.address"

# Run DNS setup script
cd /path/to/Amoskys
chmod +x deploy/dns/setup-cloudflare-dns.sh
./deploy/dns/setup-cloudflare-dns.sh
```

---

## Step 2: SSL/TLS Configuration

### Set SSL Mode to Full (Strict)

1. **Navigate to SSL/TLS Settings**
   - Cloudflare Dashboard → SSL/TLS → Overview
   - Select: **Full (strict)**
   - This ensures end-to-end encryption

2. **Generate Origin Certificate**
   - Go to: SSL/TLS → Origin Server
   - Click: **Create Certificate**
   - Hostnames: `amoskys.com, *.amoskys.com`
   - Validity: 15 years
   - Download both certificate and private key

3. **Install Certificates on VPS**

   ```bash
   # Copy certificates to VPS
   scp origin-cert.pem user@your-vps:/tmp/amoskys.com.pem
   scp origin-key.pem user@your-vps:/tmp/amoskys.com.key

   # On VPS, install certificates
   sudo mkdir -p /opt/amoskys/certs
   sudo mv /tmp/amoskys.com.pem /opt/amoskys/certs/
   sudo mv /tmp/amoskys.com.key /opt/amoskys/certs/
   sudo chmod 644 /opt/amoskys/certs/amoskys.com.pem
   sudo chmod 600 /opt/amoskys/certs/amoskys.com.key
   ```

4. **Enable HSTS**
   - Go to: SSL/TLS → Edge Certificates
   - Enable **HSTS** with:
     - Max Age: 12 months
     - Include subdomains: ✅
     - No-Sniff header: ✅

5. **Set Minimum TLS Version**
   - SSL/TLS → Edge Certificates
   - Minimum TLS Version: **TLS 1.2**

---

## Step 3: Security Configuration

### Firewall Rules

1. **Navigate to Security**
   - Cloudflare Dashboard → Security → WAF

2. **Create Custom Firewall Rules**

   **Rule 1: Block Bad Bots**
   ```
   Name: Block Bad Bots
   Expression: (cf.bot_management.score lt 30) and not (cf.bot_management.verified_bot)
   Action: Block
   ```

   **Rule 2: Rate Limit API**
   ```
   Name: Rate Limit API Endpoints
   Expression: (http.request.uri.path contains "/api/") and (rate(1m) > 100)
   Action: Block
   ```

### Security Level

1. **Set Security Level**
   - Security → Settings
   - Security Level: **Medium** (or High for production)
   - Browser Integrity Check: **Enabled**

### Bot Protection

As shown in your dashboard, you have options to:
- **Block AI crawlers**: Control AI training bots
- **Manage robots.txt**: Configure via Cloudflare

Configure these based on your preferences:
- Go to: Security → Bots
- Configure bot management settings

---

## Step 4: Performance Optimization

### Speed Settings

1. **Navigate to Speed → Optimization**
   
2. **Enable Auto Minify**
   - HTML: ✅
   - CSS: ✅
   - JavaScript: ✅

3. **Enable Compression**
   - Brotli: ✅
   - Gzip: ✅ (automatic)

4. **Enable Enhanced Features**
   - HTTP/2: ✅
   - HTTP/3 (QUIC): ✅
   - Early Hints: ✅

### Caching Configuration

1. **Navigate to Caching → Configuration**

2. **Set Caching Level**
   - Caching Level: **Standard**
   - Browser Cache TTL: **4 hours**

3. **Create Page Rules for Caching**
   
   Go to: Rules → Page Rules

   **Rule 1: Cache Static Assets**
   ```
   URL: amoskys.com/static/*
   Settings:
   - Cache Level: Cache Everything
   - Edge Cache TTL: 1 month
   - Browser Cache TTL: 1 month
   ```

   **Rule 2: Bypass Cache for API**
   ```
   URL: api.amoskys.com/*
   Settings:
   - Cache Level: Bypass
   - Security Level: High
   ```

---

## Step 5: Verification & Testing

### DNS Propagation Check

```bash
# Check DNS resolution
dig amoskys.com
dig www.amoskys.com
dig app.amoskys.com

# Check if Cloudflare is proxying
dig amoskys.com +short
# Should return Cloudflare IPs (104.x.x.x or similar)

# Check DNS propagation globally
# Visit: https://www.whatsmydns.net/#A/amoskys.com
```

### SSL/TLS Testing

```bash
# Test SSL configuration
curl -I https://amoskys.com

# Detailed SSL check
openssl s_client -connect amoskys.com:443 -servername amoskys.com

# Test SSL rating
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=amoskys.com
```

### Application Testing

```bash
# Test main domain
curl https://amoskys.com/health
curl https://amoskys.com/status

# Test subdomains
curl https://www.amoskys.com/health
curl https://app.amoskys.com/health
curl https://api.amoskys.com/health

# Check security headers
curl -I https://amoskys.com | grep -i "strict-transport-security\|x-frame-options\|x-content-type"
```

### Performance Testing

```bash
# Test page load time with detailed timing
curl -w "@-" -o /dev/null -s https://amoskys.com/ <<'EOF'
     time_namelookup:  %{time_namelookup}s
        time_connect:  %{time_connect}s
     time_appconnect:  %{time_appconnect}s
    time_pretransfer:  %{time_pretransfer}s
       time_redirect:  %{time_redirect}s
  time_starttransfer:  %{time_starttransfer}s
                     ----------
          time_total:  %{time_total}s
EOF

# Test from multiple locations
# Visit: https://tools.pingdom.com/
# Visit: https://www.webpagetest.org/
```

---

## Step 6: Monitoring & Analytics

### Enable Analytics

Your dashboard already shows analytics. To enhance monitoring:

1. **Web Analytics**
   - Analytics & Logs → Web Analytics
   - Enable for visitor tracking

2. **Set Up Notifications**
   - Notifications → Add
   - Configure alerts for:
     - Origin unreachable
     - High error rate (4xx/5xx)
     - DDoS attacks
     - Certificate expiration

3. **View Real-Time Metrics**
   - Dashboard shows:
     - Unique Visitors
     - Total Requests  
     - Percent Cached (currently 97.62% ✅)
     - Data Served

---

## Step 7: VPS Server Configuration

### NGINX Configuration

Your NGINX config is already prepared at `deploy/nginx/amoskys.conf`. Ensure it's deployed:

```bash
# On VPS
sudo cp /opt/amoskys/deploy/nginx/amoskys.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Firewall Configuration

Allow Cloudflare IPs only (recommended for security):

```bash
# On VPS - Allow only Cloudflare IPs
# Create firewall rules for Cloudflare IP ranges
sudo ufw allow from 173.245.48.0/20
sudo ufw allow from 103.21.244.0/22
sudo ufw allow from 103.22.200.0/22
sudo ufw allow from 103.31.4.0/22
sudo ufw allow from 141.101.64.0/18
sudo ufw allow from 108.162.192.0/18
sudo ufw allow from 190.93.240.0/20
# ... (see full list in docs/CLOUDFLARE_SETUP.md)

# Or use the provided script
chmod +x /opt/amoskys/deploy/dns/configure-vps-firewall.sh
sudo /opt/amoskys/deploy/dns/configure-vps-firewall.sh
```

---

## Troubleshooting

### Common Issues

#### 1. DNS Not Resolving
```bash
# Check nameservers
dig amoskys.com NS

# Should return Cloudflare nameservers
# If not, update at your registrar

# Flush local DNS cache
# macOS:
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder

# Linux:
sudo systemd-resolve --flush-caches
```

#### 2. SSL Certificate Errors
```bash
# Verify certificate on VPS
sudo openssl x509 -in /opt/amoskys/certs/amoskys.com.pem -text -noout

# Check NGINX SSL config
sudo nginx -t

# Verify SSL mode in Cloudflare is "Full (strict)"
```

#### 3. 502/503 Bad Gateway
```bash
# Check if application is running on VPS
sudo systemctl status amoskys-web

# Check NGINX logs
sudo tail -f /var/log/nginx/amoskys.error.log

# Verify backend is accessible
curl http://localhost:8000/health
```

#### 4. Cloudflare Not Proxying
- Ensure orange cloud ☁️ icon is enabled (Proxied)
- Check that DNS record is not "DNS only" (gray cloud)
- Wait 1-2 minutes for changes to propagate

### Getting Help

1. **Cloudflare Status**: https://www.cloudflarestatus.com/
2. **Cloudflare Support**: https://dash.cloudflare.com/?to=/:account/support
3. **Community**: https://community.cloudflare.com/

---

## Quick Reference

### Essential Commands

```bash
# Check DNS
dig amoskys.com +short

# Test HTTPS
curl -I https://amoskys.com

# View Cloudflare Analytics
# Visit: https://dash.cloudflare.com → select amoskys.com

# Check VPS services
sudo systemctl status amoskys-web nginx

# View logs
sudo journalctl -u amoskys-web -f
sudo tail -f /var/log/nginx/amoskys.access.log
```

### DNS Record Summary

| Record Type | Name           | Points To          | Status   |
|-------------|----------------|--------------------|----------|
| A           | @              | YOUR_VPS_IP        | Proxied  |
| A           | www            | YOUR_VPS_IP        | Proxied  |
| CNAME       | app            | amoskys.com        | Proxied  |
| CNAME       | api            | amoskys.com        | Proxied  |
| CNAME       | docs           | amoskys.com        | Proxied  |

### Cloudflare Settings Checklist

- ✅ DNS Setup: **Full** (using Cloudflare nameservers)
- ✅ SSL/TLS Mode: **Full (strict)**
- ✅ HSTS: **Enabled**
- ✅ Minimum TLS: **1.2**
- ✅ Auto Minify: **HTML, CSS, JS**
- ✅ Brotli: **Enabled**
- ✅ Caching: **Standard**
- ✅ Firewall: **Custom rules configured**
- ✅ Bot Management: **Configured**

---

## Next Steps

1. ✅ Configure DNS records in Cloudflare (this guide)
2. ✅ Install SSL certificates on VPS
3. ✅ Deploy NGINX configuration
4. ✅ Start AMOSKYS services
5. ✅ Verify all endpoints
6. ⏳ Monitor analytics and performance
7. ⏳ Set up additional subdomains as needed
8. ⏳ Configure email (if required)

---

## Related Documentation

- **VPS Deployment**: `docs/VPS_DEPLOYMENT_GUIDE.md`
- **Cloudflare Setup**: `docs/CLOUDFLARE_SETUP.md`
- **NGINX Configuration**: `deploy/nginx/amoskys.conf`
- **Web Deployment**: `docs/WEB_DEPLOYMENT.md`
- **Docker Deployment**: `docs/DOCKER_DEPLOY.md`

---

🧠🛡️ **AMOSKYS Neural Security Command Platform**  
**DNS Deployment Complete - amoskys.com Ready for Production**

**Current Status**: 
- Domain: ✅ Active (expires Sep 12, 2026)
- DNS: ✅ Full setup with Cloudflare
- Analytics: ✅ Tracking (36 unique visitors, 1.48k requests, 97.62% cached)
- Security: ✅ Free plan active
