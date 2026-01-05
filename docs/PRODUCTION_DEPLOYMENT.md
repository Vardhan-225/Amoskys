# AMOSKYS Production Deployment Guide

## 📋 Overview

This guide covers deploying AMOSKYS to a production environment with proper security, monitoring, and reliability.

## ✅ Pre-Deployment Checklist

Before deploying to production, verify:

- [ ] All unit tests pass (`pytest tests/`)
- [ ] Code quality checks pass (`flake8`, `black`, `mypy`)
- [ ] Security scan completed (no critical vulnerabilities)
- [ ] SSL/TLS certificates obtained
- [ ] Production environment variables configured
- [ ] Database migrations tested
- [ ] Backup strategy in place
- [ ] Monitoring alerts configured

## 🚀 Quick Production Deployment

### Prerequisites

- **OS**: Ubuntu 20.04+ or CentOS 8+
- **Python**: 3.9+
- **RAM**: 4GB minimum, 8GB+ recommended
- **CPU**: 2+ cores
- **Disk**: 20GB+ for application and logs
- **Network**: Ports 80, 443, 50051 accessible

### 1. System Setup

```bash
# Create amoskys user and directories
sudo useradd -r -s /bin/bash -m -d /opt/amoskys amoskys
sudo mkdir -p /var/log/amoskys /var/run/amoskys /etc/amoskys/certs
sudo chown -R amoskys:amoskys /opt/amoskys /var/log/amoskys /var/run/amoskys /etc/amoskys
```

### 2. Install Dependencies

```bash
# System packages
sudo apt update && sudo apt install -y \
    python3.9 python3.9-venv python3-pip \
    nginx redis-server postgresql-13 \
    build-essential libssl-dev libffi-dev

# Clone repository
sudo -u amoskys git clone https://github.com/your-org/amoskys.git /opt/amoskys
cd /opt/amoskys

# Python environment
sudo -u amoskys python3.9 -m venv .venv
sudo -u amoskys .venv/bin/pip install --upgrade pip
sudo -u amoskys .venv/bin/pip install -r requirements.txt
sudo -u amoskys .venv/bin/pip install gunicorn[eventlet]
```

### 3. Database Configuration

#### PostgreSQL (Recommended)

```bash
# Create database
sudo -u postgres psql <<EOF
CREATE DATABASE amoskys;
CREATE USER amoskys WITH ENCRYPTED PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE amoskys TO amoskys;
\q
EOF

# Run migrations
sudo -u amoskys /opt/amoskys/.venv/bin/python -c "
from web.app import create_app
app, _ = create_app()
with app.app_context():
    from amoskys.db import init_db
    init_db()
"
```

### 4. SSL/TLS Certificates

#### Let's Encrypt (Production)

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Generate certificates
sudo certbot certonly --nginx -d yourdomain.com -d www.yourdomain.com

# Link to AMOSKYS
sudo ln -s /etc/letsencrypt/live/yourdomain.com/privkey.pem /etc/amoskys/certs/server.key
sudo ln -s /etc/letsencrypt/live/yourdomain.com/fullchain.pem /etc/amoskys/certs/server.crt
sudo ln -s /etc/letsencrypt/live/yourdomain.com/chain.pem /etc/amoskys/certs/ca.crt
sudo chown -h amoskys:amoskys /etc/amoskys/certs/*
```

#### Self-Signed (Testing Only)

```bash
cd /etc/amoskys/certs
sudo openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout server.key -out server.crt \
    -days 365 -subj "/CN=amoskys.local"
sudo cp server.crt ca.crt
sudo chown amoskys:amoskys *
sudo chmod 600 server.key
```

### 5. Production Configuration

```bash
# Copy and edit production config
sudo cp /opt/amoskys/config/production.env.example /etc/amoskys/production.env
sudo chown amoskys:amoskys /etc/amoskys/production.env
sudo chmod 600 /etc/amoskys/production.env

# Generate secret key
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Edit configuration
sudo nano /etc/amoskys/production.env
```

**Required Settings:**
```bash
# Application
FLASK_ENV=production
SECRET_KEY=<generated-secret-key>

# Database
DATABASE_URL=postgresql://amoskys:<password>@localhost/amoskys

# SSL
SSL_KEYFILE=/etc/amoskys/certs/server.key
SSL_CERTFILE=/etc/amoskys/certs/server.crt
SSL_CA_CERTS=/etc/amoskys/certs/ca.crt

# Email (for notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-specific-password
```

### 6. Systemd Services

```bash
# Copy service files
sudo cp /opt/amoskys/systemd/*.service /etc/systemd/system/

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable amoskys-eventbus amoskys-web amoskys-agents

# Start services
sudo systemctl start amoskys-eventbus
sleep 3
sudo systemctl start amoskys-web
sleep 2
sudo systemctl start amoskys-agents

# Verify status
sudo systemctl status amoskys-*
```

### 7. Nginx Reverse Proxy

```bash
# Create nginx config
sudo tee /etc/nginx/sites-available/amoskys > /dev/null <<'EOF'
upstream amoskys_web {
    server 127.0.0.1:8000 fail_timeout=0;
}

# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name yourdomain.com;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/amoskys-access.log;
    error_log /var/log/nginx/amoskys-error.log;

    # Max upload size
    client_max_body_size 10M;

    # Proxy settings
    location / {
        proxy_pass http://amoskys_web;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for SocketIO
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files
    location /static/ {
        alias /opt/amoskys/web/app/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/amoskys /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 8. Firewall Configuration

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow gRPC for agents (restrict to agent subnets)
sudo ufw allow from 10.0.0.0/8 to any port 50051 proto tcp

# Enable firewall
sudo ufw --force enable
sudo ufw status
```

## 🔒 Security Hardening

### Fail2Ban (Brute Force Protection)

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create AMOSKYS jail
sudo tee /etc/fail2ban/jail.d/amoskys.conf > /dev/null <<'EOF'
[amoskys-auth]
enabled = true
port = http,https
filter = amoskys-auth
logpath = /var/log/amoskys/web-access.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Create filter
sudo tee /etc/fail2ban/filter.d/amoskys-auth.conf > /dev/null <<'EOF'
[Definition]
failregex = ^<HOST> .* "POST /auth/login HTTP.*" 401
ignoreregex =
EOF

sudo systemctl restart fail2ban
```

### Regular Security Updates

```bash
# Enable unattended upgrades
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

## 📊 Monitoring & Observability

### Prometheus (Metrics)

```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
sudo tar -xzf prometheus-*.tar.gz -C /opt/
sudo mv /opt/prometheus-* /opt/prometheus

# Configure
sudo tee /opt/prometheus/prometheus.yml > /dev/null <<'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'amoskys-eventbus'
    static_configs:
      - targets: ['localhost:9000', 'localhost:9100']

  - job_name: 'amoskys-web'
    static_configs:
      - targets: ['localhost:9200']
EOF

# Create service
sudo tee /etc/systemd/system/prometheus.service > /dev/null <<'EOF'
[Unit]
Description=Prometheus
After=network.target

[Service]
Type=simple
User=prometheus
ExecStart=/opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo useradd -r -s /bin/false prometheus
sudo chown -R prometheus:prometheus /opt/prometheus
sudo systemctl daemon-reload
sudo systemctl enable --now prometheus
```

### Log Management

```bash
# Configure log rotation
sudo tee /etc/logrotate.d/amoskys > /dev/null <<'EOF'
/var/log/amoskys/*.log {
    daily
    missingok
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
EOF
```

## 💾 Backup Strategy

### Database Backups

```bash
# Create backup script
sudo tee /opt/amoskys/scripts/backup_db.sh > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR=/opt/amoskys/backups
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
pg_dump -U amoskys amoskys | gzip > "$BACKUP_DIR/amoskys_db_$DATE.sql.gz"

# Keep only last 30 days
find "$BACKUP_DIR" -name "amoskys_db_*.sql.gz" -mtime +30 -delete
EOF

sudo chmod +x /opt/amoskys/scripts/backup_db.sh

# Add to crontab (daily at 2 AM)
sudo crontab -u amoskys -l 2>/dev/null | { cat; echo "0 2 * * * /opt/amoskys/scripts/backup_db.sh"; } | sudo crontab -u amoskys -
```

### Configuration Backups

```bash
# Backup configs
sudo tar -czf /opt/amoskys/backups/config_$(date +%Y%m%d).tar.gz \
    /etc/amoskys/ \
    /opt/amoskys/config/
```

## 🔍 Health Checks

### Automated Health Monitoring

```bash
# Create health check script
sudo tee /opt/amoskys/scripts/healthcheck.sh > /dev/null <<'EOF'
#!/bin/bash
set -e

# Check web application
curl -f -s http://localhost:8000/api/v1/health/ping > /dev/null || exit 1

# Check EventBus
netstat -tuln | grep :50051 > /dev/null || exit 2

# Check database
PGPASSWORD=<db-password> psql -U amoskys -h localhost -c "SELECT 1" > /dev/null 2>&1 || exit 3

echo "All health checks passed"
EOF

sudo chmod +x /opt/amoskys/scripts/healthcheck.sh
```

## 🚨 Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u amoskys-web -n 100 --no-pager
sudo journalctl -u amoskys-eventbus -n 100 --no-pager

# Check permissions
sudo ls -la /opt/amoskys /var/log/amoskys /var/run/amoskys

# Verify configuration
sudo -u amoskys /opt/amoskys/.venv/bin/python -c "from web.app import create_app; create_app()"
```

### Database Connection Issues

```bash
# Test connection
PGPASSWORD=<password> psql -U amoskys -h localhost amoskys -c "SELECT version();"

# Check PostgreSQL status
sudo systemctl status postgresql
sudo tail -n 50 /var/log/postgresql/postgresql-13-main.log
```

### SSL Certificate Issues

```bash
# Verify certificates
sudo openssl x509 -in /etc/amoskys/certs/server.crt -text -noout | grep -E "Subject:|Issuer:|Not"

# Test SSL
echo | openssl s_client -connect localhost:443 -servername yourdomain.com 2>/dev/null | grep -E "subject=|issuer="
```

## 🔄 Updates & Maintenance

### Application Updates

```bash
cd /opt/amoskys
sudo -u amoskys git pull
sudo -u amoskys .venv/bin/pip install -r requirements.txt --upgrade

# Run migrations if needed
sudo -u amoskys .venv/bin/python scripts/migrate_db.py

# Restart services
sudo systemctl restart amoskys-web amoskys-agents
```

### Certificate Renewal (Let's Encrypt)

```bash
# Auto-renewal is enabled by default
# Test renewal
sudo certbot renew --dry-run

# Manual renewal
sudo certbot renew
sudo systemctl reload nginx
```

## 📈 Performance Tuning

### PostgreSQL Optimization

```bash
# Edit /etc/postgresql/13/main/postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
work_mem = 8MB
min_wal_size = 1GB
max_wal_size = 4GB
```

### Gunicorn Workers

```bash
# Adjust workers based on CPU cores
# Formula: (2 x CPU cores) + 1
# Edit /opt/amoskys/web/gunicorn_config.py or set env var:
export GUNICORN_WORKERS=9  # For 4-core system
```

## 🎯 Deployment Checklist

Final verification before going live:

- [ ] All services running (`systemctl status amoskys-*`)
- [ ] HTTPS working (`curl -I https://yourdomain.com`)
- [ ] EventBus receiving telemetry (check logs)
- [ ] Database accessible and backed up
- [ ] Monitoring alerts configured
- [ ] Firewall rules verified
- [ ] SSL certificates valid (`openssl x509 -in cert -text`)
- [ ] Log rotation configured
- [ ] Backups tested (restore test)
- [ ] Health checks passing
- [ ] Documentation updated

## 📞 Support

- **Documentation**: [https://docs.amoskys.com](https://docs.amoskys.com)
- **Issues**: [https://github.com/your-org/amoskys/issues](https://github.com/your-org/amoskys/issues)
- **Email**: support@amoskys.com

## 📄 License

Copyright © 2026 AMOSKYS Security Platform
