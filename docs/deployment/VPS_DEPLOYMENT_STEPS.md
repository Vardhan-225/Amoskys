# AMOSKYS VPS Deployment - Step by Step

**Prerequisites:**
- ✅ Cloudflare Origin Certificate saved at `~/amoskys-tls/`
- ✅ VPS created (Ubuntu 24.04 LTS)
- ✅ VPS IP address known (e.g., `203.0.113.57`)
- ✅ SSH access to VPS

---

## Quick Deployment (30 minutes)

### Step 1: Connect to Your VPS

From your Mac:
```bash
# Replace with your VPS IP
ssh root@YOUR_VPS_IP

# Or if using ubuntu user:
ssh ubuntu@YOUR_VPS_IP
```

**First time?** You may need to accept the fingerprint (type `yes`).

---

### Step 2: Initial Server Setup (5 min)

On the VPS, run:

```bash
# Update system packages
apt update && apt upgrade -y

# Install required packages
apt install -y git nginx python3 python3-pip python3-venv sqlite3 ufw curl

# Enable firewall with SSH, HTTP, HTTPS
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ufw status
```

---

### Step 3: Clone AMOSKYS Repository (2 min)

```bash
# Clone to /opt/amoskys
cd /opt
git clone https://github.com/YOUR_USERNAME/Amoskys.git amoskys
cd /opt/amoskys

# Or if repo is private, use HTTPS with token:
# git clone https://YOUR_TOKEN@github.com/YOUR_USERNAME/Amoskys.git amoskys
```

---

### Step 4: Copy TLS Certificates to VPS (2 min)

**On your Mac** (in a new terminal, NOT SSH):

```bash
# Copy certificates from your Mac to VPS
scp ~/amoskys-tls/amoskys_origin.crt root@YOUR_VPS_IP:/tmp/
scp ~/amoskys-tls/amoskys_origin.key root@YOUR_VPS_IP:/tmp/

# If using ubuntu user:
# scp ~/amoskys-tls/amoskys_origin.crt ubuntu@YOUR_VPS_IP:/tmp/
# scp ~/amoskys-tls/amoskys_origin.key ubuntu@YOUR_VPS_IP:/tmp/
```

**Back on the VPS SSH session:**

```bash
# Move certificates to secure location
mkdir -p /etc/ssl/amoskys
mv /tmp/amoskys_origin.crt /etc/ssl/amoskys/
mv /tmp/amoskys_origin.key /etc/ssl/amoskys/

# Set proper permissions
chmod 644 /etc/ssl/amoskys/amoskys_origin.crt
chmod 600 /etc/ssl/amoskys/amoskys_origin.key

# Verify
ls -lh /etc/ssl/amoskys/
```

You should see:
```
-rw-r--r-- 1 root root 1.8K Dec 28 01:09 amoskys_origin.crt
-rw------- 1 root root 1.7K Dec 28 01:09 amoskys_origin.key
```

---

### Step 5: Install Python Dependencies (3 min)

```bash
cd /opt/amoskys

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python -c "from amoskys.intel import FusionEngine; print('✅ AMOSKYS modules loaded')"
```

---

### Step 6: Configure Nginx with Cloudflare SSL (5 min)

Create Nginx configuration:

```bash
nano /etc/nginx/sites-available/amoskys
```

Paste this configuration:

```nginx
# AMOSKYS Production Configuration
# Cloudflare → Nginx (Origin) → Flask App

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name amoskys.com www.amoskys.com;

    # Cloudflare forwarded protocol
    if ($http_x_forwarded_proto != 'https') {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS Server with Cloudflare Origin Certificate
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name amoskys.com www.amoskys.com;

    # Cloudflare Origin Certificate
    ssl_certificate /etc/ssl/amoskys/amoskys_origin.crt;
    ssl_certificate_key /etc/ssl/amoskys/amoskys_origin.key;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Max upload size
    client_max_body_size 10M;

    # Root directory (static files)
    root /opt/amoskys/web/app/static;
    index index.html;

    # Proxy to Flask app
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        # WebSocket support (for future real-time features)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Static files (CSS, JS, images)
    location /static/ {
        alias /opt/amoskys/web/app/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
}
```

Save and exit (Ctrl+O, Enter, Ctrl+X).

**Enable the site:**

```bash
# Create symlink to enable site
ln -s /etc/nginx/sites-available/amoskys /etc/nginx/sites-enabled/

# Remove default site
rm /etc/nginx/sites-enabled/default

# Test configuration
nginx -t

# Should output:
# nginx: configuration file /etc/nginx/nginx.conf test is successful

# Reload Nginx
systemctl reload nginx
systemctl status nginx
```

---

### Step 7: Start AMOSKYS Flask Dashboard (5 min)

```bash
cd /opt/amoskys
source .venv/bin/activate

# Create data directories
mkdir -p data/intel data/queue data/wal logs

# Start Flask app in background
nohup python -m web.app.main --host 127.0.0.1 --port 8000 > logs/dashboard.log 2>&1 &

# Verify it's running
ps aux | grep "web.app.main"

# Check logs
tail -f logs/dashboard.log
```

You should see:
```
 * Running on http://127.0.0.1:8000
```

Press Ctrl+C to exit log tail.

---

### Step 8: Test Deployment (2 min)

**From your Mac:**

```bash
# Test HTTP (should redirect to HTTPS via Cloudflare)
curl -I http://amoskys.com

# Test HTTPS
curl -I https://amoskys.com

# Expected output:
# HTTP/2 200
# server: cloudflare
# ...
```

**In browser:**
- Open: https://amoskys.com
- You should see the AMOSKYS dashboard
- Check browser padlock: Should show "Secure" (Cloudflare certificate)

---

### Step 9: Start Agents (5 min)

```bash
cd /opt/amoskys
source .venv/bin/activate

# Start EventBus (central message broker)
nohup python -m amoskys.eventbus.server \
    --cert certs/server.crt \
    --key certs/server.key \
    > logs/eventbus.log 2>&1 &

# Start FlowAgent (network monitoring)
nohup python -m amoskys.agents.flowagent.main \
    --device-id "$(hostname)" \
    > logs/flowagent.log 2>&1 &

# Start ProcAgent (process monitoring)
nohup python -m amoskys.agents.proc.proc_agent \
    --device-id "$(hostname)" \
    > logs/procagent.log 2>&1 &

# Start PersistenceGuard (persistence detection)
nohup python -m amoskys.agents.persistence.persistence_agent \
    --device-id "$(hostname)" \
    --queue-db data/queue/persistence_agent.db \
    > logs/persistence.log 2>&1 &

# Start TelemetryIngestor + FusionEngine
nohup python -m amoskys.intel.ingest \
    --poll-interval 5 \
    --fusion-db data/intel/fusion_live.db \
    --fusion-window 30 \
    > logs/ingest.log 2>&1 &

# Verify all processes
ps aux | grep amoskys | grep -v grep
```

---

### Step 10: Verify Data Collection (3 min)

```bash
# Wait 60 seconds for first collection cycle
sleep 60

# Check event queues
sqlite3 data/queue/persistence_agent.db "SELECT COUNT(*) FROM queue"

# Check incidents
PYTHONPATH=/opt/amoskys/src python -m amoskys.intel.fusion_engine \
    --db data/intel/fusion_live.db \
    --list-incidents --limit 5

# Check device risk
PYTHONPATH=/opt/amoskys/src python -m amoskys.intel.fusion_engine \
    --db data/intel/fusion_live.db \
    --risk "$(hostname)"
```

---

## ✅ Deployment Complete!

Your AMOSKYS deployment is now live at **https://amoskys.com**

### What's Running:

| Service | Port | Log File |
|---------|------|----------|
| Nginx (reverse proxy) | 443 (HTTPS) | `/var/log/nginx/access.log` |
| Flask Dashboard | 8000 (internal) | `logs/dashboard.log` |
| EventBus | 50051 (gRPC) | `logs/eventbus.log` |
| FlowAgent | - | `logs/flowagent.log` |
| ProcAgent | - | `logs/procagent.log` |
| PersistenceGuard | - | `logs/persistence.log` |
| TelemetryIngestor | - | `logs/ingest.log` |

### Monitoring Commands:

```bash
# Check all AMOSKYS processes
ps aux | grep amoskys | grep -v grep

# Check Nginx status
systemctl status nginx

# Tail all logs
tail -f logs/*.log

# Check firewall
ufw status

# Check disk usage
df -h
```

### Troubleshooting:

**Dashboard not loading?**
```bash
# Check Flask app
ps aux | grep "web.app.main"
tail logs/dashboard.log

# Restart Flask
pkill -f "web.app.main"
cd /opt/amoskys && source .venv/bin/activate
nohup python -m web.app.main --host 127.0.0.1 --port 8000 > logs/dashboard.log 2>&1 &
```

**502 Bad Gateway?**
```bash
# Check Nginx can reach Flask
curl http://127.0.0.1:8000

# If timeout, Flask isn't running
# Restart Flask (command above)
```

**No telemetry data?**
```bash
# Check if agents are running
ps aux | grep amoskys

# Check agent logs
tail -f logs/flowagent.log logs/procagent.log

# Manually trigger test event
./scripts/run_e2e_validation.sh
```

---

## Next Steps:

1. **Enable Systemd Services** - Make services auto-start on reboot
2. **Set up Monitoring** - Sentry for error tracking, Prometheus for metrics
3. **Configure Backups** - Database backups to S3/Backblaze
4. **Add More Devices** - Install agents on your Mac, other servers
5. **Mobile UI** - Implement Step 2 from Strategic Roadmap (mobile dashboard)

See [STRATEGIC_ROADMAP_2025.md](../STRATEGIC_ROADMAP_2025.md) for complete roadmap.

---

**Deployment Date:** 2025-12-28
**Status:** ✅ PRODUCTION ALPHA
**Next Review:** 2025-01-15
