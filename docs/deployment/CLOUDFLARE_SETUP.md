# AMOSKYS Neural Security Command Platform
# Cloudflare Configuration Guide for Production Deployment

## 🔒 SSL/TLS Configuration

### Step 1: Enable Full (Strict) SSL Mode
1. Go to Cloudflare Dashboard → SSL/TLS → Overview
2. Set SSL/TLS encryption mode to "Full (strict)"
3. This ensures end-to-end encryption between visitors and your origin server

### Step 2: Generate Origin Certificate
1. Navigate to SSL/TLS → Origin Server
2. Click "Create Certificate"
3. Choose "Let Cloudflare generate a private key and a CSR"
4. Set hostnames: `amoskys.com, *.amoskys.com`
5. Set certificate validity: 15 years (maximum)
6. Download and save both certificate and private key

### Step 3: Enable Security Features
1. **HSTS (HTTP Strict Transport Security)**
   - Go to SSL/TLS → Edge Certificates
   - Enable HSTS with these settings:
     - Max Age Header: 12 months
     - Include subdomains: Yes
     - No-sniff header: Yes

2. **Minimum TLS Version**
   - Set to TLS 1.2 or higher
   - Location: SSL/TLS → Edge Certificates

## 🌐 DNS Configuration

### Required DNS Records
```
Type    Name              Content           TTL    Proxy Status
A       amoskys.com       YOUR_VPS_IP       Auto   Proxied
A       www               YOUR_VPS_IP       Auto   Proxied
CNAME   app               amoskys.com       Auto   Proxied
CNAME   api               amoskys.com       Auto   Proxied
CNAME   docs              amoskys.com       Auto   Proxied
```

### Optional DNS Records (for future use)
```
Type    Name              Content           TTL    Proxy Status
CNAME   status            amoskys.com       Auto   Proxied
CNAME   metrics           amoskys.com       Auto   Proxied
CNAME   logs              amoskys.com       Auto   Proxied
MX      amoskys.com       mail.protonmail.ch  Auto   DNS only
TXT     amoskys.com       "v=spf1 include:_spf.protonmail.ch ~all"
```

## 🛡️ Security Configuration

### Firewall Rules
1. Go to Security → WAF
2. Create custom rules:

**Block Bad Bots**
```
(cf.bot_management.score lt 30) and not (cf.bot_management.verified_bot)
Action: Block
```

**Rate Limiting for API**
```
(http.request.uri.path contains "/api/") and (rate(1m) > 100)
Action: Block
```

**Geo-blocking (optional)**
```
(ip.geoip.country ne "US" and ip.geoip.country ne "CA")
Action: JS Challenge
```

### Page Rules
1. Go to Rules → Page Rules
2. Create these rules:

**API Security**
```
URL: api.amoskys.com/*
Settings:
- Security Level: High
- Cache Level: Bypass
- Disable Apps: On
```

**Static Assets Caching**
```
URL: amoskys.com/static/*
Settings:
- Cache Level: Cache Everything
- Edge Cache TTL: 1 month
- Browser Cache TTL: 1 month
```

## 📊 Performance Optimization

### Speed Settings
1. Go to Speed → Optimization
2. Enable these features:
   - Auto Minify: HTML, CSS, JavaScript
   - Brotli compression
   - Rocket Loader (test carefully)
   - Enhanced HTTP/2 Prioritization

### Caching Configuration
1. Go to Caching → Configuration
2. Set caching level: Standard
3. Browser Cache TTL: 4 hours
4. Always Online: On

## 📈 Analytics & Monitoring

### Enable Analytics
1. Go to Analytics & Logs → Web Analytics
2. Enable Web Analytics
3. Add tracking to your pages (optional)

### Set up Alerts
1. Go to Notifications
2. Create alerts for:
   - Origin unreachable
   - High error rate (4xx/5xx)
   - DDoS attacks
   - Certificate expiration

## 🔍 Testing & Validation

### SSL Testing
```bash
# Test SSL configuration
curl -I https://amoskys.com
openssl s_client -connect amoskys.com:443 -servername amoskys.com

# Check SSL rating
# Visit: https://www.ssllabs.com/ssltest/
```

### Performance Testing
```bash
# Test from multiple locations
curl -w "@-" -o /dev/null -s https://amoskys.com/ <<< '
     time_namelookup:  %{time_namelookup}s
        time_connect:  %{time_connect}s
     time_appconnect:  %{time_appconnect}s
    time_pretransfer:  %{time_pretransfer}s
       time_redirect:  %{time_redirect}s
  time_starttransfer:  %{time_starttransfer}s
                     ----------
          time_total:  %{time_total}s
'
```

### Security Testing
```bash
# Test security headers
curl -I https://amoskys.com

# Check for common vulnerabilities
# Use tools like: https://securityheaders.com/
```

## 🚨 Troubleshooting

### Common Issues

1. **SSL Errors**
   - Verify origin certificate is correctly installed
   - Check that SSL mode is "Full (strict)"
   - Ensure private key matches certificate

2. **502/503 Errors**
   - Check if origin server is running
   - Verify firewall allows Cloudflare IPs
   - Check NGINX configuration

3. **DNS Issues**
   - Verify DNS propagation: `dig amoskys.com`
   - Check TTL settings aren't too high
   - Ensure proxy status is correct

4. **Performance Issues**
   - Review caching settings
   - Check for large unoptimized images
   - Verify compression is enabled

### Cloudflare IP Ranges
Ensure your firewall allows these IP ranges:
```
# IPv4
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22

# IPv6
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
```

---

🧠🛡️ **AMOSKYS Neural Security Command Platform**  
**Cloudflare Configuration Complete - Ready for Global Deployment**
