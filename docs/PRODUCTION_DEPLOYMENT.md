# AMOSKYS Production Deployment Guide

**Domain**: amoskys.com (Cloudflare DNS)
**Status**: Ready for Production
**Date**: 2025-12-31

---

## 📋 Prerequisites Checklist

Before starting, ensure you have:

- [x] Domain: amoskys.com configured on Cloudflare
- [x] Cloudflare account with DNS access
- [ ] Production server (Ubuntu 22.04 LTS recommended)
- [ ] SSH access to server
- [ ] SSL certificates (Let's Encrypt - will set up)
- [ ] Email credentials (Zoho Mail - already configured)

---

## 🚀 DEPLOYMENT STEPS

### PHASE 1: Server Setup (30 minutes)

#### Step 1: Provision Production Server

**Option A: DigitalOcean (Recommended)**
```bash
# Create droplet:
# - Ubuntu 22.04 LTS
# - 4GB RAM minimum (8GB recommended)
# - 2 CPU cores minimum
# - 80GB SSD
# - Enable IPv6
# - Add SSH key

# Note the server IP address
SERVER_IP="your.server.ip.here"
```

**Option B: AWS EC2**
```bash
# Launch EC2 instance:
# - t3.medium or larger
# - Ubuntu 22.04 LTS AMI
# - Security group: Allow ports 22, 80, 443, 50051
```

**Option C: Any Ubuntu 22.04 VPS**

#### Step 2: Initial Server Configuration

SSH into your server:
```bash
ssh root@$SERVER_IP
```

Update system:
```bash
apt update && apt upgrade -y
```

Install required packages:
```bash
apt install -y \
    git \
    python3.11 \
    python3.11-venv \
    python3-pip \
    nginx \
    certbot \
    python3-certbot-nginx \
    ufw \
    fail2ban \
    htop
```

#### Step 3: Configure Firewall

```bash
# Enable firewall
ufw default deny incoming
ufw default allow outgoing

# Allow SSH, HTTP, HTTPS
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS
ufw allow 50051/tcp  # EventBus gRPC

# Enable firewall
ufw enable
```

#### Step 4: Create AMOSKYS User

```bash
# Create dedicated user
adduser amoskys --disabled-password --gecos ""

# Add to sudo group (optional)
usermod -aG sudo amoskys

# Switch to amoskys user
su - amoskys
```

---

### PHASE 2: Application Deployment (45 minutes)

#### Step 5: Clone Repository

```bash
cd /home/amoskys

# Clone repository
git clone https://github.com/YOUR_USERNAME/Amoskys.git
cd Amoskys

# Checkout main branch
git checkout main
```

#### Step 6: Set Up Python Environment

```bash
# Create virtual environment
python3.11 -m venv .venv

# Activate virtual environment
source .venv/bin/python

# Upgrade pip
.venv/bin/pip install --upgrade pip

# Install dependencies
.venv/bin/pip install -r requirements.txt

# Install production server (gunicorn)
.venv/bin/pip install gunicorn
```

#### Step 7: Configure Production Environment

```bash
# Copy environment template
cp .env.template .env

# Edit production environment
nano .env
```

**Production `.env` Configuration:**
```bash
# ==============================================================================
# CRITICAL: Production Email Configuration
# ==============================================================================
AMOSKYS_EMAIL_SMTP_HOST=smtppro.zoho.com
AMOSKYS_EMAIL_SMTP_PORT=587
AMOSKYS_EMAIL_USE_TLS=true
AMOSKYS_EMAIL_USERNAME=security@amoskys.com
AMOSKYS_EMAIL_PASSWORD=Jackiechan#7771$  # Your actual Zoho password
AMOSKYS_EMAIL_FROM_ADDRESS=security@amoskys.com
AMOSKYS_EMAIL_FROM_NAME=AMOSKYS Security

# CRITICAL: Disable dev mode for production
AMOSKYS_EMAIL_DEV_MODE=false

# ==============================================================================
# Flask Production Configuration
# ==============================================================================
FLASK_APP=wsgi.py
FLASK_ENV=production
FLASK_DEBUG=false  # CRITICAL: Must be false in production
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# CRITICAL: Enable secure cookies (requires HTTPS)
AMOSKYS_SECURE_COOKIES=true

# ==============================================================================
# Database Configuration
# ==============================================================================
DATABASE_URL=sqlite:///data/amoskys.db

# ==============================================================================
# EventBus Configuration
# ==============================================================================
BUS_HOST=0.0.0.0
BUS_SERVER_PORT=50051
BUS_OVERLOAD=false
BUS_MAX_INFLIGHT=100
BUS_HARD_MAX=500

# ==============================================================================
# Logging
# ==============================================================================
LOGLEVEL=INFO

# ==============================================================================
# Production Settings
# ==============================================================================
PYTHONPATH=src
```

#### Step 8: Initialize Production Database

```bash
# Create data directory
mkdir -p data

# Initialize database
.venv/bin/python scripts/init_database.py

# Verify database created
ls -lh data/amoskys.db
# Should show a file with size > 0
```

#### Step 9: Test Application Locally

```bash
# Test Flask app starts
cd web
FLASK_DEBUG=false AMOSKYS_EMAIL_DEV_MODE=false ../.venv/bin/python wsgi.py

# You should see:
# * Serving Flask app 'app'
# * Running on http://127.0.0.1:5001

# Press Ctrl+C to stop
```

---

### PHASE 3: Cloudflare DNS Configuration (10 minutes)

#### Step 10: Configure Cloudflare DNS

Log into Cloudflare dashboard → Select amoskys.com:

**Add DNS Records:**

| Type | Name | Content | Proxy | TTL |
|------|------|---------|-------|-----|
| A | @ | YOUR_SERVER_IP | ✅ Proxied | Auto |
| A | www | YOUR_SERVER_IP | ✅ Proxied | Auto |
| AAAA | @ | YOUR_IPv6 (if available) | ✅ Proxied | Auto |

**Cloudflare SSL/TLS Settings:**
- SSL/TLS encryption mode: **Full (strict)**
- Always Use HTTPS: **On**
- Minimum TLS Version: **TLS 1.2**
- Opportunistic Encryption: **On**
- TLS 1.3: **On**

**Cloudflare Security Settings:**
- Security Level: **Medium**
- Challenge Passage: **30 minutes**
- Browser Integrity Check: **On**
- Bot Fight Mode: **On** (optional)

**Wait 2-5 minutes for DNS propagation**

Verify DNS:
```bash
# From your local machine
dig amoskys.com +short
# Should show Cloudflare proxy IP (not your server IP directly)
```

---

### PHASE 4: SSL/TLS Certificate Setup (15 minutes)

#### Step 11: Obtain SSL Certificate (Let's Encrypt)

**IMPORTANT**: Since you're using Cloudflare proxy, you have two options:

**Option A: Cloudflare Origin Certificate (Recommended - Easier)**

1. Cloudflare Dashboard → SSL/TLS → Origin Server
2. Click "Create Certificate"
3. Select:
   - Private key type: RSA (2048)
   - Hostnames: amoskys.com, *.amoskys.com
   - Certificate Validity: 15 years
4. Click "Create"
5. Copy both certificate and private key

On server:
```bash
sudo mkdir -p /etc/ssl/cloudflare
sudo nano /etc/ssl/cloudflare/cert.pem
# Paste certificate

sudo nano /etc/ssl/cloudflare/key.pem
# Paste private key

sudo chmod 600 /etc/ssl/cloudflare/key.pem
sudo chmod 644 /etc/ssl/cloudflare/cert.pem
```

**Option B: Let's Encrypt (Alternative)**

If you prefer Let's Encrypt:
```bash
# Temporarily disable Cloudflare proxy (make DNS record DNS-only, not proxied)
# Wait 5 minutes for DNS to propagate

sudo certbot --nginx -d amoskys.com -d www.amoskys.com

# Follow prompts
# Then re-enable Cloudflare proxy
```

---

### PHASE 5: Nginx Configuration (20 minutes)

#### Step 12: Configure Nginx as Reverse Proxy

Create Nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/amoskys
```

**Nginx Configuration (copy this exactly):**
```nginx
# AMOSKYS Production Configuration

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name amoskys.com www.amoskys.com;

    # Let's Encrypt validation
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Redirect all HTTP to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name amoskys.com www.amoskys.com;

    # SSL Certificate (Cloudflare Origin or Let's Encrypt)
    ssl_certificate /etc/ssl/cloudflare/cert.pem;  # Change if using Let's Encrypt
    ssl_certificate_key /etc/ssl/cloudflare/key.pem;

    # SSL Configuration (Modern)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/amoskys_access.log;
    error_log /var/log/nginx/amoskys_error.log;

    # Max upload size
    client_max_body_size 10M;

    # Proxy to Flask application
    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_http_version 1.1;

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files (if you add them later)
    location /static {
        alias /home/amoskys/Amoskys/web/app/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable site:
```bash
# Create symlink
sudo ln -s /etc/nginx/sites-available/amoskys /etc/nginx/sites-enabled/

# Remove default site
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

---

### PHASE 6: Systemd Service Setup (15 minutes)

#### Step 13: Create Systemd Service for Flask App

```bash
sudo nano /etc/systemd/system/amoskys-web.service
```

**Service Configuration:**
```ini
[Unit]
Description=AMOSKYS Web Application
After=network.target

[Service]
Type=simple
User=amoskys
Group=amoskys
WorkingDirectory=/home/amoskys/Amoskys/web
Environment="PATH=/home/amoskys/Amoskys/.venv/bin"
Environment="PYTHONPATH=/home/amoskys/Amoskys/src"
EnvironmentFile=/home/amoskys/Amoskys/.env

ExecStart=/home/amoskys/Amoskys/.venv/bin/gunicorn \
    --bind 127.0.0.1:5001 \
    --workers 4 \
    --timeout 120 \
    --access-logfile /var/log/amoskys/access.log \
    --error-logfile /var/log/amoskys/error.log \
    --log-level info \
    wsgi:app

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Create log directory:
```bash
sudo mkdir -p /var/log/amoskys
sudo chown amoskys:amoskys /var/log/amoskys
```

Enable and start service:
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable amoskys-web

# Start service
sudo systemctl start amoskys-web

# Check status
sudo systemctl status amoskys-web

# You should see "active (running)" in green
```

---

### PHASE 7: Verification & Testing (15 minutes)

#### Step 14: Verify Deployment

**Test local access:**
```bash
# From server
curl http://localhost:5001

# Should return HTML
```

**Test external access:**
```bash
# From your local machine
curl https://amoskys.com

# Should return homepage HTML
```

**Test in browser:**
1. Open https://amoskys.com
2. Should see homepage with "🧠 Intelligence-First Security, Built to Understand Threats"
3. Click "Access Dashboard" → Should load dashboard
4. Test signup: Create account → Check email for verification
5. Test login with verified account

**Check SSL:**
```bash
# From local machine
openssl s_client -connect amoskys.com:443 -servername amoskys.com

# Look for:
# - "Verify return code: 0 (ok)"
# - TLS 1.3 or TLS 1.2
```

**Monitor logs:**
```bash
# Flask app logs
sudo journalctl -u amoskys-web -f

# Nginx access log
sudo tail -f /var/log/nginx/amoskys_access.log

# Nginx error log
sudo tail -f /var/log/nginx/amoskys_error.log
```

---

### PHASE 8: Post-Deployment Security (10 minutes)

#### Step 15: Harden Security

**Configure fail2ban for SSH:**
```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

**Disable password authentication (SSH keys only):**
```bash
sudo nano /etc/ssh/sshd_config

# Set these values:
PasswordAuthentication no
PermitRootLogin no

# Restart SSH
sudo systemctl restart sshd
```

**Set up automatic security updates:**
```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

**Configure log rotation:**
```bash
sudo nano /etc/logrotate.d/amoskys
```

Add:
```
/var/log/amoskys/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 amoskys amoskys
    sharedscripts
    postrotate
        systemctl reload amoskys-web > /dev/null 2>&1 || true
    endscript
}
```

---

## ✅ DEPLOYMENT COMPLETE!

Your AMOSKYS platform is now live at **https://amoskys.com**

### Quick Reference Commands

**View application logs:**
```bash
sudo journalctl -u amoskys-web -f
```

**Restart application:**
```bash
sudo systemctl restart amoskys-web
```

**Update application:**
```bash
cd /home/amoskys/Amoskys
git pull origin main
sudo systemctl restart amoskys-web
```

**Check application status:**
```bash
sudo systemctl status amoskys-web
```

**Nginx commands:**
```bash
sudo systemctl reload nginx    # Reload config
sudo systemctl restart nginx   # Full restart
sudo nginx -t                  # Test config
```

---

## 🔧 Troubleshooting

### Application won't start

**Check logs:**
```bash
sudo journalctl -u amoskys-web -n 100
```

**Common issues:**
- Database not initialized: Run `scripts/init_database.py`
- Port 5001 in use: `sudo lsof -i :5001` (kill conflicting process)
- Permission issues: `sudo chown -R amoskys:amoskys /home/amoskys/Amoskys`

### 502 Bad Gateway

**Check if Flask app is running:**
```bash
sudo systemctl status amoskys-web
```

**Check if port 5001 is listening:**
```bash
sudo netstat -tulpn | grep 5001
```

**Check Nginx error log:**
```bash
sudo tail -f /var/log/nginx/amoskys_error.log
```

### SSL Certificate Issues

**Test SSL:**
```bash
openssl s_client -connect amoskys.com:443 -servername amoskys.com
```

**Cloudflare SSL mode:**
- Must be "Full (strict)" in Cloudflare dashboard
- Certificate on server must be valid

### Email not sending

**Check .env:**
```bash
cat /home/amoskys/Amoskys/.env | grep EMAIL_DEV_MODE
# Must be: AMOSKYS_EMAIL_DEV_MODE=false
```

**Test email manually:**
```bash
cd /home/amoskys/Amoskys
AMOSKYS_EMAIL_DEV_MODE=false .venv/bin/python scripts/test_email_config.py --send --to your-email@example.com
```

---

## 📊 Monitoring & Maintenance

### Set up monitoring (Optional but recommended)

**Install monitoring tools:**
```bash
sudo apt install prometheus-node-exporter
```

**Monitor disk space:**
```bash
df -h
# Keep /var/log and /home/amoskys below 80%
```

**Monitor memory:**
```bash
free -h
htop
```

**Database backup:**
```bash
# Create backup script
cat > /home/amoskys/backup_db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/home/amoskys/backups"
mkdir -p $BACKUP_DIR
cp /home/amoskys/Amoskys/data/amoskys.db \
   $BACKUP_DIR/amoskys_$(date +%Y%m%d_%H%M%S).db
# Keep only last 30 backups
ls -t $BACKUP_DIR/amoskys_*.db | tail -n +31 | xargs -r rm
EOF

chmod +x /home/amoskys/backup_db.sh

# Add to crontab (daily backup at 3 AM)
crontab -e
# Add: 0 3 * * * /home/amoskys/backup_db.sh
```

---

## 🚀 Next Steps

1. **Test all authentication flows**
   - Signup → Email verification → Login
   - Password reset flow
   - Logout

2. **Deploy agents** (see Agent Deployment Guide)
   - Download agent package
   - Deploy to endpoints
   - Verify telemetry collection

3. **Monitor for 24 hours**
   - Watch logs for errors
   - Test from different networks
   - Verify email delivery

4. **Set up monitoring/alerting**
   - UptimeRobot for uptime monitoring
   - Email alerts for application errors

---

## 📞 Support

**Logs Location:**
- Application: `/var/log/amoskys/`
- Nginx: `/var/log/nginx/`
- Systemd: `journalctl -u amoskys-web`

**Configuration Files:**
- Environment: `/home/amoskys/Amoskys/.env`
- Nginx: `/etc/nginx/sites-available/amoskys`
- Systemd: `/etc/systemd/system/amoskys-web.service`

**Status**: ✅ Production Ready
**Deployment Time**: ~2-3 hours
**Difficulty**: Intermediate

---

**AMOSKYS Production Deployment Guide v1.0**
Last Updated: 2025-12-31
