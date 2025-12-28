# AMOSKYS DNS Deployment Checklist

Quick checklist for deploying AMOSKYS to amoskys.com with Cloudflare DNS.

---

## Pre-Deployment Checklist

### Prerequisites
- [ ] Cloudflare account with amoskys.com domain
  - Zone ID: `3f214ea5270b99e93c2a1460000e7a00`
  - Account ID: `a65accb1674b8138917103c0c334a981`
- [ ] VPS with Ubuntu/Debian Linux
- [ ] Static IP address for VPS: `________________`
- [ ] SSH access to VPS
- [ ] Git installed on VPS
- [ ] Python 3.8+ on VPS
- [ ] NGINX installed on VPS

---

## Step 1: DNS Configuration (Choose One Method)

### Option A: Manual Configuration (Recommended for First Time)

**In Cloudflare Dashboard:**
- [ ] Go to https://dash.cloudflare.com
- [ ] Select domain: `amoskys.com`
- [ ] Navigate to: DNS → Records

**Add DNS Records:**
- [ ] A record: `@` → `YOUR_VPS_IP` (Proxied ✅)
- [ ] A record: `www` → `YOUR_VPS_IP` (Proxied ✅)
- [ ] CNAME: `app` → `amoskys.com` (Proxied ✅)
- [ ] CNAME: `api` → `amoskys.com` (Proxied ✅)
- [ ] CNAME: `docs` → `amoskys.com` (Proxied ✅)

**Verify DNS:**
```bash
dig amoskys.com +short
dig www.amoskys.com +short
```

### Option B: Automated Configuration (API)

**Setup:**
- [ ] Get Cloudflare API token from: https://dash.cloudflare.com/profile/api-tokens
- [ ] Set environment variables:
  ```bash
  export CLOUDFLARE_API_TOKEN="your_token"
  export VPS_IP="your.vps.ip.address"
  ```

**Run Script:**
```bash
cd deploy/dns
chmod +x setup-cloudflare-dns.sh
./setup-cloudflare-dns.sh
```

**Checklist:**
- [ ] Script completed successfully
- [ ] DNS records created/updated
- [ ] DNS propagation verified

---

## Step 2: SSL/TLS Configuration

### Generate Cloudflare Origin Certificate

**In Cloudflare Dashboard:**
- [ ] Go to: SSL/TLS → Origin Server
- [ ] Click: "Create Certificate"
- [ ] Hostnames: `amoskys.com, *.amoskys.com`
- [ ] Validity: 15 years
- [ ] Download certificate and private key
- [ ] Save as `amoskys.com.pem` and `amoskys.com.key`

### Set SSL Mode

- [ ] Go to: SSL/TLS → Overview
- [ ] Set mode to: **Full (strict)**

### Enable HSTS

- [ ] Go to: SSL/TLS → Edge Certificates
- [ ] Enable HSTS:
  - Max Age: 12 months
  - Include subdomains: ✅
  - No-Sniff: ✅

### Set Minimum TLS Version

- [ ] SSL/TLS → Edge Certificates
- [ ] Minimum TLS Version: **TLS 1.2**

---

## Step 3: VPS Server Setup

### Clone Repository

```bash
sudo mkdir -p /opt/amoskys
cd /opt/amoskys
sudo git clone https://github.com/Vardhan-225/Amoskys.git .
```

**Checklist:**
- [ ] Repository cloned to `/opt/amoskys`
- [ ] All files present

### Install SSL Certificates

**Transfer certificates to VPS:**
```bash
# On local machine
scp amoskys.com.pem user@your-vps:/tmp/
scp amoskys.com.key user@your-vps:/tmp/

# On VPS
sudo mkdir -p /opt/amoskys/certs
sudo mv /tmp/amoskys.com.pem /opt/amoskys/certs/
sudo mv /tmp/amoskys.com.key /opt/amoskys/certs/
sudo chmod 644 /opt/amoskys/certs/amoskys.com.pem
sudo chmod 600 /opt/amoskys/certs/amoskys.com.key
```

**Checklist:**
- [ ] Certificates copied to VPS
- [ ] Permissions set correctly
- [ ] Files located at `/opt/amoskys/certs/`

### Install Dependencies

```bash
cd /opt/amoskys
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[web]
```

**Checklist:**
- [ ] Virtual environment created
- [ ] Dependencies installed
- [ ] No installation errors

### Configure NGINX

```bash
# Copy NGINX configuration
sudo cp deploy/nginx/amoskys.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload NGINX
sudo systemctl reload nginx
```

**Checklist:**
- [ ] NGINX config copied
- [ ] Symlink created
- [ ] Config test passed
- [ ] NGINX reloaded

### Install Systemd Service

```bash
# Copy service file
sudo cp deploy/systemd/amoskys-web.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable amoskys-web
sudo systemctl start amoskys-web

# Check status
sudo systemctl status amoskys-web
```

**Checklist:**
- [ ] Service file installed
- [ ] Service enabled
- [ ] Service started
- [ ] Service running (active)

---

## Step 4: Firewall Configuration

### Configure VPS Firewall

```bash
cd /opt/amoskys/deploy/dns
sudo chmod +x configure-vps-firewall.sh
sudo ./configure-vps-firewall.sh
```

**Checklist:**
- [ ] Firewall script executed
- [ ] Cloudflare IPs allowed
- [ ] SSH access maintained (port 22)
- [ ] Direct IP access blocked

### Verify Firewall

```bash
# Check firewall status
sudo ufw status numbered  # For UFW

# Test Cloudflare access works
curl https://amoskys.com/health

# Test direct IP access is blocked (should fail/timeout)
curl http://YOUR_VPS_IP
```

**Checklist:**
- [ ] Firewall active
- [ ] Cloudflare access works
- [ ] Direct IP access blocked

---

## Step 5: Security & Performance

### Configure Cloudflare Security

**Firewall Rules:**
- [ ] Go to: Security → WAF
- [ ] Create rule: "Block Bad Bots"
  - Expression: `(cf.bot_management.score lt 30) and not (cf.bot_management.verified_bot)`
  - Action: Block
- [ ] Create rule: "Rate Limit API"
  - Expression: `(http.request.uri.path contains "/api/") and (rate(1m) > 100)`
  - Action: Block

**Security Settings:**
- [ ] Security → Settings
- [ ] Security Level: Medium (or High)
- [ ] Browser Integrity Check: Enabled

### Configure Performance

**Speed Settings:**
- [ ] Go to: Speed → Optimization
- [ ] Enable Auto Minify: HTML, CSS, JavaScript
- [ ] Enable Brotli compression

**Caching:**
- [ ] Go to: Caching → Configuration
- [ ] Caching Level: Standard
- [ ] Browser Cache TTL: 4 hours

**Page Rules:**
- [ ] Rules → Page Rules
- [ ] Create rule for `amoskys.com/static/*`:
  - Cache Level: Cache Everything
  - Edge Cache TTL: 1 month
- [ ] Create rule for `api.amoskys.com/*`:
  - Cache Level: Bypass
  - Security Level: High

---

## Step 6: Verification & Testing

### DNS Verification

```bash
# Check DNS resolution
dig amoskys.com +short
dig www.amoskys.com +short
dig app.amoskys.com +short
dig api.amoskys.com +short

# Check global propagation
# Visit: https://www.whatsmydns.net/#A/amoskys.com
```

**Checklist:**
- [ ] DNS resolving to Cloudflare IPs
- [ ] All subdomains resolving
- [ ] Global propagation complete

### SSL/TLS Testing

```bash
# Test HTTPS
curl -I https://amoskys.com

# Detailed SSL check
openssl s_client -connect amoskys.com:443 -servername amoskys.com < /dev/null

# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=amoskys.com
```

**Checklist:**
- [ ] HTTPS working
- [ ] Valid SSL certificate
- [ ] SSL Labs grade: A or A+
- [ ] HSTS header present

### Application Testing

```bash
# Test endpoints
curl https://amoskys.com/health
curl https://amoskys.com/status
curl https://www.amoskys.com/health
curl https://app.amoskys.com/health
curl https://api.amoskys.com/health
```

**Expected Response:**
```json
{"status": "healthy"}
```

**Checklist:**
- [ ] Main domain accessible
- [ ] WWW subdomain accessible
- [ ] App subdomain accessible
- [ ] API subdomain accessible
- [ ] All endpoints returning 200 OK

### Performance Testing

```bash
# Test page load time
curl -w "@-" -o /dev/null -s https://amoskys.com/ <<'EOF'
     time_namelookup:  %{time_namelookup}s
        time_connect:  %{time_connect}s
     time_appconnect:  %{time_appconnect}s
          time_total:  %{time_total}s
EOF
```

**Checklist:**
- [ ] Page load time < 2 seconds
- [ ] No SSL/TLS errors
- [ ] No redirect loops

### Security Headers Check

```bash
curl -I https://amoskys.com | grep -i "strict-transport-security\|x-frame-options\|x-content-type"
```

**Expected Headers:**
- [ ] Strict-Transport-Security
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff

---

## Step 7: Monitoring & Maintenance

### Enable Cloudflare Notifications

- [ ] Go to: Notifications
- [ ] Create alert: Origin unreachable
- [ ] Create alert: High error rate (4xx/5xx)
- [ ] Create alert: DDoS attack
- [ ] Create alert: Certificate expiration

### Monitor Logs

```bash
# Application logs
sudo journalctl -u amoskys-web -f

# NGINX access logs
sudo tail -f /var/log/nginx/amoskys.access.log

# NGINX error logs
sudo tail -f /var/log/nginx/amoskys.error.log
```

**Checklist:**
- [ ] No errors in application logs
- [ ] NGINX serving requests
- [ ] No SSL errors in logs

### Check Cloudflare Analytics

- [ ] Visit: https://dash.cloudflare.com
- [ ] Select: amoskys.com
- [ ] Review:
  - Unique visitors
  - Total requests
  - Percent cached (target: >90%)
  - Total data served
  - Security events

---

## Post-Deployment Checklist

### Documentation

- [ ] Document VPS IP address: `________________`
- [ ] Document DNS configuration date: `________________`
- [ ] Document SSL certificate expiry: `________________`
- [ ] Save Cloudflare API token securely
- [ ] Save server credentials securely

### Backups

- [ ] Backup SSL certificates
- [ ] Backup NGINX configuration
- [ ] Backup systemd service files
- [ ] Backup application code
- [ ] Document backup locations

### Team Access

- [ ] Share Cloudflare account access
- [ ] Share VPS SSH access
- [ ] Share deployment documentation
- [ ] Share monitoring credentials

---

## Troubleshooting

### DNS Issues
- **Problem**: DNS not resolving
- **Solution**: Check nameservers with `dig amoskys.com NS`
- **Docs**: See DNS_DEPLOYMENT_GUIDE.md → Troubleshooting

### SSL Issues
- **Problem**: SSL certificate errors
- **Solution**: Verify certificate installation and Cloudflare SSL mode
- **Docs**: See DNS_DEPLOYMENT_GUIDE.md → Step 2

### 502/503 Errors
- **Problem**: Bad Gateway errors
- **Solution**: Check application status: `sudo systemctl status amoskys-web`
- **Docs**: See VPS_DEPLOYMENT_GUIDE.md → Troubleshooting

### Firewall Issues
- **Problem**: Cannot access site
- **Solution**: Temporarily disable firewall to test: `sudo ufw disable`
- **Docs**: See deploy/dns/README.md → Troubleshooting

---

## Success Criteria

**Deployment is successful when:**
- ✅ All DNS records resolving correctly
- ✅ HTTPS working with valid certificate
- ✅ SSL Labs grade: A or better
- ✅ All subdomains accessible
- ✅ Health endpoints returning 200 OK
- ✅ Cloudflare caching > 90%
- ✅ No errors in logs
- ✅ Firewall properly configured
- ✅ Monitoring and alerts configured

---

## Support Resources

- **DNS Guide**: `docs/DNS_DEPLOYMENT_GUIDE.md`
- **VPS Guide**: `docs/VPS_DEPLOYMENT_GUIDE.md`
- **Cloudflare Guide**: `docs/CLOUDFLARE_SETUP.md`
- **DNS Scripts**: `deploy/dns/`
- **Cloudflare Dashboard**: https://dash.cloudflare.com

---

🧠🛡️ **AMOSKYS Neural Security Command Platform**  
DNS Deployment Checklist - Ready for Production

**Date Deployed**: ________________  
**Deployed By**: ________________  
**VPS IP**: ________________
