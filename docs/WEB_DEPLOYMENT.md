# AMOSKYS Web Interface Deployment Guide

🧠🛡️ **AMOSKYS Neural Security Command Platform - Production Deployment**

This guide covers the complete deployment of the AMOSKYS web interface using NGINX, Flask, and Gunicorn on a VPS with SSL/TLS security.

## 🏗️ Architecture Overview

```
Internet → Cloudflare → VPS (NGINX) → Gunicorn → Flask App
              ↓
          SSL/TLS (Full Strict)
```

**Components:**
- **Frontend**: Neural-themed landing page with matrix animations
- **Web Framework**: Flask with Blueprint architecture
- **WSGI Server**: Gunicorn with multi-worker configuration
- **Reverse Proxy**: NGINX with SSL termination
- **SSL/TLS**: Cloudflare Origin Certificate (Full Strict mode)
- **Process Management**: systemd service
- **Security**: Headers, HSTS, secure ciphers

## 📁 Directory Structure

```
/opt/amoskys/
├── web/                     # Flask application
│   ├── app/
│   │   ├── __init__.py     # Flask factory
│   │   ├── routes.py       # Routes and views
│   │   └── templates/
│   │       └── index.html  # Neural landing page
│   ├── venv/               # Python virtual environment
│   ├── wsgi.py             # WSGI entry point
│   ├── gunicorn_config.py  # Gunicorn configuration
│   └── requirements.txt    # Python dependencies
├── certs/                   # SSL certificates
│   ├── amoskys.com.pem     # Cloudflare Origin Certificate
│   └── amoskys.com.key     # Private key
└── backups/                # Configuration backups
```

## 🚀 Quick Deployment

### Prerequisites

1. **VPS Requirements:**
   - Ubuntu 20.04+ or Debian 11+
   - 1GB+ RAM
   - Python 3.8+
   - NGINX
   - Root/sudo access

2. **Domain Setup:**
   - Domain pointing to VPS IP
   - Cloudflare DNS management
   - Cloudflare Origin Certificate generated

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url> /opt/amoskys-src
cd /opt/amoskys-src

# Run local tests first
./scripts/test_web_local.sh
```

### 2. Install SSL Certificates

```bash
# Place your Cloudflare Origin Certificate files in the project directory
# Then install them:
sudo ./scripts/manage_ssl.sh install amoskys.com.pem amoskys.com.key
```

### 3. Deploy to Production

```bash
# Run the automated deployment script
sudo ./scripts/deploy_web.sh
```

### 4. Verify Deployment

```bash
# Check service status
sudo systemctl status amoskys-web

# Test endpoints
curl -k https://amoskys.com/health
curl -k https://amoskys.com/status

# View logs
sudo journalctl -u amoskys-web -f
```

## 🔧 Manual Configuration

### NGINX Setup

1. **Install NGINX:**
```bash
sudo apt update
sudo apt install nginx
```

2. **Configure Site:**
```bash
sudo cp nginx/amoskys.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/amoskys.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Flask Application Setup

1. **Create Directory Structure:**
```bash
sudo mkdir -p /opt/amoskys/{web,certs,backups}
sudo mkdir -p /var/log/amoskys
```

2. **Copy Application Files:**
```bash
sudo cp -r web/* /opt/amoskys/web/
sudo chown -R www-data:www-data /opt/amoskys/web
```

3. **Setup Python Environment:**
```bash
cd /opt/amoskys/web
sudo -u www-data python3 -m venv venv
sudo -u www-data venv/bin/pip install -r requirements.txt
```

### Systemd Service Setup

1. **Install Service:**
```bash
sudo cp deploy/systemd/amoskys-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable amoskys-web
sudo systemctl start amoskys-web
```

## 🔒 SSL/TLS Configuration

### Cloudflare Setup

1. **DNS Configuration:**
   - A record: `amoskys.com` → VPS IP
   - A record: `www.amoskys.com` → VPS IP
   - Proxy status: Proxied (orange cloud)

2. **SSL/TLS Mode:**
   - Go to SSL/TLS tab
   - Set to "Full (strict)"

3. **Origin Certificate:**
   - SSL/TLS → Origin Server
   - Create Certificate
   - Download `.pem` and `.key` files

### Certificate Management

```bash
# Install certificates
sudo ./scripts/manage_ssl.sh install amoskys.com.pem amoskys.com.key

# Check certificate status
sudo ./scripts/manage_ssl.sh status

# Check expiry
sudo ./scripts/manage_ssl.sh check
```

## 📊 Monitoring and Logs

### Service Management

```bash
# Control the service
sudo systemctl {start|stop|restart|reload} amoskys-web

# View status
sudo systemctl status amoskys-web

# Enable/disable auto-start
sudo systemctl {enable|disable} amoskys-web
```

### Log Files

```bash
# Application logs
sudo journalctl -u amoskys-web -f

# NGINX access logs
sudo tail -f /var/log/nginx/amoskys.access.log

# NGINX error logs
sudo tail -f /var/log/nginx/amoskys.error.log

# Gunicorn logs
sudo tail -f /var/log/amoskys/web-access.log
sudo tail -f /var/log/amoskys/web-error.log
```

### Health Checks

```bash
# Application health
curl https://amoskys.com/health

# Detailed status
curl https://amoskys.com/status

# SSL certificate check
openssl s_client -connect amoskys.com:443 -servername amoskys.com
```

## 🔧 Troubleshooting

### Common Issues

1. **Service Won't Start:**
```bash
# Check logs
sudo journalctl -u amoskys-web --no-pager -n 50

# Check Python environment
sudo -u www-data /opt/amoskys/web/venv/bin/python -c "from app import create_app; print('OK')"

# Check permissions
ls -la /opt/amoskys/web/
```

2. **NGINX Issues:**
```bash
# Test configuration
sudo nginx -t

# Check if port 8000 is listening
sudo netstat -tulpn | grep :8000

# Check NGINX error logs
sudo tail -f /var/log/nginx/error.log
```

3. **SSL Issues:**
```bash
# Check certificate files
sudo ./scripts/manage_ssl.sh check

# Test SSL connection
openssl s_client -connect amoskys.com:443 -servername amoskys.com
```

### Performance Tuning

1. **Gunicorn Workers:**
   - Edit `gunicorn_config.py`
   - Adjust `workers` based on CPU cores
   - Monitor with `htop`

2. **NGINX Optimization:**
   - Enable gzip compression (already configured)
   - Adjust worker connections
   - Enable caching for static files

## 🔄 Updates and Maintenance

### Application Updates

```bash
# 1. Backup current version
sudo cp -r /opt/amoskys/web /opt/amoskys/backups/web_$(date +%Y%m%d_%H%M%S)

# 2. Update code
cd /opt/amoskys-src
git pull

# 3. Copy new files
sudo cp -r web/* /opt/amoskys/web/
sudo chown -R www-data:www-data /opt/amoskys/web

# 4. Restart service
sudo systemctl restart amoskys-web
```

### Certificate Renewal

```bash
# 1. Generate new certificate in Cloudflare Dashboard
# 2. Download new files
# 3. Install new certificate
sudo ./scripts/manage_ssl.sh install new_amoskys.com.pem new_amoskys.com.key
```

## 🎯 Next Steps

Once the web interface is deployed:

1. **Dashboard Development** (`app.amoskys.com`)
2. **API Endpoints** (`api.amoskys.com`)
3. **Monitoring Integration** (Prometheus/Grafana)
4. **Event Bus Connection**
5. **Agent Management Interface**

## 📞 Support

For deployment issues:
1. Check logs with `sudo journalctl -u amoskys-web -f`
2. Validate configuration with `./scripts/test_web_local.sh`
3. Review NGINX config with `sudo nginx -t`

🧠🛡️ **AMOSKYS Neural Security Command Platform - Ready for Operation**
