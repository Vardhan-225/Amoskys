# AMOSKYS DNS Deployment Resources

This directory contains DNS configuration files and automation scripts for deploying AMOSKYS to the `amoskys.com` domain via Cloudflare.

## Files

### Configuration Files

- **`cloudflare-dns-records.json`** - Complete DNS records configuration template
  - Contains all required DNS records (A, CNAME, TXT)
  - Includes SSL/TLS settings
  - Includes security and performance settings
  - Includes firewall and page rules

### Automation Scripts

- **`setup-cloudflare-dns.sh`** - Automated DNS record creation via Cloudflare API
  - Creates/updates all DNS records automatically
  - Requires Cloudflare API token
  - Verifies DNS propagation
  
- **`configure-vps-firewall.sh`** - VPS firewall configuration for Cloudflare
  - Restricts HTTP/HTTPS access to Cloudflare IPs only
  - Supports UFW, firewalld, and iptables
  - Maintains SSH access

## Quick Start

### 1. DNS Configuration (Cloudflare Dashboard)

The easiest way to configure DNS is through the Cloudflare dashboard:

1. Go to https://dash.cloudflare.com
2. Select `amoskys.com`
3. Navigate to DNS → Records
4. Add the following records (replace `YOUR_VPS_IP` with your server IP):

| Type  | Name | Content       | Proxy | TTL  |
|-------|------|---------------|-------|------|
| A     | @    | YOUR_VPS_IP   | ✅    | Auto |
| A     | www  | YOUR_VPS_IP   | ✅    | Auto |
| CNAME | app  | amoskys.com   | ✅    | Auto |
| CNAME | api  | amoskys.com   | ✅    | Auto |
| CNAME | docs | amoskys.com   | ✅    | Auto |

### 2. Automated DNS Setup (CLI)

For automated deployment using the Cloudflare API:

```bash
# Set environment variables
export CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
export VPS_IP="your.vps.ip.address"

# Run DNS setup script
cd deploy/dns
chmod +x setup-cloudflare-dns.sh
./setup-cloudflare-dns.sh
```

**Getting your Cloudflare API Token:**
1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Click "Create Token"
3. Use "Edit zone DNS" template
4. Select zone: `amoskys.com`
5. Create and copy the token

### 3. VPS Firewall Configuration

After DNS is configured, secure your VPS to only accept traffic from Cloudflare:

```bash
# On your VPS, run the firewall configuration script
cd /opt/amoskys/deploy/dns
sudo chmod +x configure-vps-firewall.sh
sudo ./configure-vps-firewall.sh
```

This will:
- Configure firewall to allow HTTP/HTTPS only from Cloudflare IPs
- Keep SSH access open (port 22)
- Support UFW, firewalld, or iptables

## Verification

### Check DNS Propagation

```bash
# Check if DNS is resolving
dig amoskys.com +short
dig www.amoskys.com +short

# Check global propagation
# Visit: https://www.whatsmydns.net/#A/amoskys.com
```

### Test SSL/TLS

```bash
# Test HTTPS access
curl -I https://amoskys.com

# Test health endpoint
curl https://amoskys.com/health

# Check SSL grade
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=amoskys.com
```

### Verify Firewall

```bash
# On VPS - check firewall status
sudo ufw status numbered  # For UFW
sudo firewall-cmd --list-all  # For firewalld
sudo iptables -L -n  # For iptables

# Test that direct IP access is blocked
curl http://YOUR_VPS_IP
# Should fail or timeout (traffic must go through Cloudflare)
```

## Configuration Details

### DNS Records Explained

- **A @ → VPS_IP** - Main domain `amoskys.com` points to your server
- **A www → VPS_IP** - WWW subdomain points to your server
- **CNAME app → amoskys.com** - Dashboard accessible at `app.amoskys.com`
- **CNAME api → amoskys.com** - API accessible at `api.amoskys.com`
- **CNAME docs → amoskys.com** - Documentation at `docs.amoskys.com`

All records are **Proxied** (orange cloud ☁️) which means:
- Traffic goes through Cloudflare's CDN
- DDoS protection enabled
- SSL/TLS encryption
- Caching and optimization
- Real IP hidden from public

### SSL/TLS Configuration

The configuration uses **Full (Strict)** SSL mode:
- Browser → Cloudflare: SSL/TLS (Cloudflare certificate)
- Cloudflare → Origin: SSL/TLS (Cloudflare Origin certificate)
- End-to-end encryption

**Required on VPS:**
- Cloudflare Origin Certificate installed at `/opt/amoskys/certs/amoskys.com.pem`
- Private key at `/opt/amoskys/certs/amoskys.com.key`

### Security Features

Configured security features:
- **HSTS**: Force HTTPS for 1 year
- **Minimum TLS**: 1.2
- **Bot Protection**: Block malicious bots
- **Rate Limiting**: 100 requests/min per IP for API
- **Firewall**: Only Cloudflare IPs can reach origin

### Performance Optimization

Configured performance features:
- **Caching**: Standard mode, 4-hour browser cache
- **Compression**: Brotli + Gzip
- **Minification**: HTML, CSS, JavaScript
- **HTTP/2 & HTTP/3**: Enabled
- **Early Hints**: Enabled

## Troubleshooting

### DNS Not Resolving

```bash
# Check nameservers
dig amoskys.com NS

# Should return Cloudflare nameservers
# If not, update at registrar

# Flush local DNS cache
sudo systemd-resolve --flush-caches  # Linux
sudo dscacheutil -flushcache  # macOS
```

### SSL Certificate Errors

```bash
# Verify certificate on VPS
sudo openssl x509 -in /opt/amoskys/certs/amoskys.com.pem -text -noout

# Check NGINX config
sudo nginx -t

# Ensure Cloudflare SSL mode is "Full (strict)"
```

### 502 Bad Gateway

```bash
# Check application is running
sudo systemctl status amoskys-web

# Check NGINX
sudo systemctl status nginx

# Check NGINX logs
sudo tail -f /var/log/nginx/amoskys.error.log

# Test backend directly
curl http://localhost:8000/health
```

### Firewall Issues

```bash
# Temporarily disable firewall to test
sudo ufw disable  # UFW
sudo systemctl stop firewalld  # firewalld

# Test access
curl https://amoskys.com/health

# Re-enable firewall
sudo ufw enable
sudo systemctl start firewalld
```

## Cloudflare Dashboard

Access your Cloudflare dashboard at:
- **Dashboard**: https://dash.cloudflare.com
- **Zone**: amoskys.com
- **Zone ID**: `3f214ea5270b99e93c2a1460000e7a00`
- **Account ID**: `a65accb1674b8138917103c0c334a981`

Current status visible in dashboard:
- Unique visitors
- Total requests
- Cache hit ratio (currently 97.62% 🎉)
- SSL/TLS status
- Security events
- Performance metrics

## Support & Documentation

- **Complete Guide**: `docs/DNS_DEPLOYMENT_GUIDE.md`
- **VPS Deployment**: `docs/VPS_DEPLOYMENT_GUIDE.md`
- **Cloudflare Setup**: `docs/CLOUDFLARE_SETUP.md`
- **NGINX Config**: `deploy/nginx/amoskys.conf`

## Security Notes

⚠️ **Important Security Considerations:**

1. **Keep API Token Secret**: Never commit your Cloudflare API token to git
2. **Firewall First**: Configure VPS firewall before going live
3. **Monitor Logs**: Regularly check Cloudflare security events
4. **Update IPs**: Cloudflare IP ranges may change; update firewall rules periodically
5. **SSH Access**: Always ensure SSH access (port 22) remains open

## Next Steps

After DNS deployment:

1. ✅ Configure DNS records
2. ✅ Install SSL certificates on VPS
3. ✅ Configure VPS firewall
4. ✅ Deploy NGINX configuration
5. ✅ Start AMOSKYS services
6. ⏳ Monitor Cloudflare analytics
7. ⏳ Set up alerts and notifications
8. ⏳ Configure additional security rules

---

🧠🛡️ **AMOSKYS Neural Security Command Platform**  
DNS Deployment Resources - Ready for Production
