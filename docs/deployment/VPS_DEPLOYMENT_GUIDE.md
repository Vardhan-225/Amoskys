# AMOSKYS Neural Security Command Platform
## VPS Deployment Guide - Complete Production Setup

🧠🛡️ **DEPLOYMENT STATUS: READY FOR PRODUCTION**

### Overview
This document provides complete instructions for deploying the AMOSKYS Neural Security Command Platform on a VPS with NGINX, Flask, and Gunicorn.

### ✅ **DEPLOYMENT CHECKLIST**

#### Prerequisites
- [ ] VPS with Ubuntu 20.04+ or Debian 11+
- [ ] Domain name pointed to VPS IP (amoskys.com)
- [ ] Cloudflare account configured
- [ ] SSL certificates (Cloudflare Origin Certificate)
- [ ] SSH access to VPS with sudo privileges

#### Components Ready
- [x] Flask Web Application
- [x] Gunicorn WSGI Configuration
- [x] NGINX Reverse Proxy Configuration
- [x] Systemd Service Definition
- [x] SSL/TLS Security Configuration
- [x] Health & Status Endpoints
- [x] Neural-themed Landing Page
- [x] Production Logging Setup
- [x] Automated Deployment Script

### 🚀 **QUICK DEPLOYMENT**

#### 1. Repository Setup on VPS
```bash
# Clone repository
sudo mkdir -p /opt/amoskys
cd /opt/amoskys
sudo git clone https://github.com/your-org/amoskys.git .

# Or upload files via SCP
# scp -r ./Amoskys/* user@your-vps:/opt/amoskys/
```

#### 2. Run Automated Deployment
```bash
cd /opt/amoskys
sudo chmod +x scripts/deploy_web.sh
sudo ./scripts/deploy_web.sh
```

#### 3. SSL Certificate Installation
```bash
# Place your Cloudflare Origin certificates
sudo cp amoskys.com.pem /opt/amoskys/certs/
sudo cp amoskys.com.key /opt/amoskys/certs/
sudo chmod 644 /opt/amoskys/certs/amoskys.com.pem
sudo chmod 600 /opt/amoskys/certs/amoskys.com.key
```

#### 4. Start Services
```bash
# Start AMOSKYS web service
sudo systemctl start amoskys-web
sudo systemctl status amoskys-web

# Reload NGINX
sudo systemctl reload nginx
```

### 🔍 **VERIFICATION COMMANDS**

```bash
# Test local endpoints
curl http://localhost:8000/health
curl http://localhost:8000/status

# Test external access
curl -k https://amoskys.com/health
curl -k https://amoskys.com/status

# Check service status
sudo systemctl status amoskys-web nginx

# Monitor logs
sudo journalctl -u amoskys-web -f
sudo tail -f /var/log/nginx/amoskys.access.log
```

### 📁 **DIRECTORY STRUCTURE ON VPS**

```
/opt/amoskys/
├── .venv/                   # Python virtual environment
├── web/                     # Flask application
│   ├── app/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── templates/
│   │       └── index.html
│   ├── gunicorn_config.py
│   ├── wsgi.py
│   └── requirements.txt
├── nginx/
│   └── amoskys.conf         # NGINX configuration
├── certs/                   # SSL certificates
│   ├── amoskys.com.pem
│   └── amoskys.com.key
├── deploy/
│   └── systemd/
│       └── amoskys-web.service
└── scripts/
    └── deploy_web.sh        # Deployment automation
```

### ⚙️ **MANUAL SETUP STEPS**

If you prefer manual setup over the automated script:

#### 1. System Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx curl
```

#### 2. Python Environment
```bash
cd /opt/amoskys
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements/requirements-amoskys-web.txt
```

#### 3. NGINX Configuration
```bash
sudo cp nginx/amoskys.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### 4. Systemd Service
```bash
sudo cp deploy/systemd/amoskys-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-web
sudo systemctl start amoskys-web
```

### 🔒 **SECURITY CONFIGURATION**

#### SSL/TLS Settings
- TLS 1.2 and 1.3 only
- Strong cipher suites
- HSTS headers
- Security headers (XSS, CSRF protection)

#### Service Security
- Non-root user execution (www-data)
- Restricted file system access
- Memory limits
- Process isolation

### 📊 **MONITORING & OBSERVABILITY**

#### Health Endpoints
- `/health` - Basic health check (200 OK)
- `/status` - Detailed system status with components

#### Logging
- Application logs: `/var/log/amoskys/web-*.log`
- NGINX logs: `/var/log/nginx/amoskys.*.log`
- System logs: `journalctl -u amoskys-web`

#### Metrics
- Prometheus client integrated
- Gunicorn worker metrics
- Custom application metrics

### 🔧 **MAINTENANCE COMMANDS**

```bash
# Service management
sudo systemctl {start|stop|restart|reload} amoskys-web
sudo systemctl {start|stop|restart|reload} nginx

# View logs
sudo journalctl -u amoskys-web --since "1 hour ago"
sudo tail -f /var/log/nginx/amoskys.error.log

# Update application
cd /opt/amoskys
git pull
sudo systemctl restart amoskys-web

# Check configuration
sudo nginx -t
python -m py_compile web/wsgi.py
```

### 🚨 **TROUBLESHOOTING**

#### Common Issues

1. **Service won't start**
   ```bash
   sudo journalctl -u amoskys-web --no-pager -n 20
   sudo systemctl status amoskys-web
   ```

2. **NGINX errors**
   ```bash
   sudo nginx -t
   sudo tail /var/log/nginx/error.log
   ```

3. **SSL certificate issues**
   ```bash
   sudo openssl x509 -in /opt/amoskys/certs/amoskys.com.pem -text -noout
   ```

4. **Port conflicts**
   ```bash
   sudo netstat -tulpn | grep :8000
   sudo lsof -i :8000
   ```

### 📈 **SCALING CONSIDERATIONS**

#### Horizontal Scaling
- Multiple Gunicorn workers (CPU cores × 2 + 1)
- Load balancer configuration
- Shared session storage

#### Vertical Scaling
- Memory optimization
- CPU resource allocation
- Disk I/O optimization

### 🔄 **BACKUP & RECOVERY**

#### Important Files to Backup
- SSL certificates: `/opt/amoskys/certs/`
- Configuration: `/opt/amoskys/nginx/amoskys.conf`
- Application code: `/opt/amoskys/web/`
- Service definitions: `/etc/systemd/system/amoskys-web.service`

#### Recovery Process
1. Restore files from backup
2. Recreate virtual environment
3. Reinstall dependencies
4. Restart services

### 📞 **SUPPORT & NEXT STEPS**

#### Current Capabilities
- ✅ Neural-themed landing page
- ✅ Health monitoring endpoints
- ✅ Production-ready WSGI deployment
- ✅ SSL/TLS termination
- ✅ Security headers
- ✅ Logging and monitoring

#### Phase 2 Roadmap
- [ ] Dashboard interface (app.amoskys.com)
- [ ] API endpoints (api.amoskys.com)
- [ ] Real-time monitoring
- [ ] Agent management interface
- [ ] Neural analytics dashboard

---

🧠🛡️ **AMOSKYS Neural Security Command Platform v1.0.0-alpha**  
**Deployment Guide Complete - Ready for Production**
