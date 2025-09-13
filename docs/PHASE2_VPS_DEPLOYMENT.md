# AMOSKYS Neural Security Command Platform
# Phase 2.2 - Production VPS Deployment Guide
# Domain: amoskys.com | SSL: Cloudflare Origin Certificate

## 🚀 DEPLOYMENT EXECUTION SEQUENCE

### Step 1: VPS Preparation
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-venv python3-pip nginx curl git

# Create deployment user (optional but recommended)
sudo useradd -m -s /bin/bash amoskys
sudo usermod -aG sudo amoskys
```

### Step 2: Repository Deployment
```bash
# Clone AMOSKYS repository
sudo git clone https://github.com/your-username/amoskys.git /opt/amoskys
cd /opt/amoskys

# Set ownership
sudo chown -R www-data:www-data /opt/amoskys
sudo chmod +x scripts/deploy_web.sh
```

### Step 3: SSL Certificate Installation
```bash
# Create certificate directory
sudo mkdir -p /opt/amoskys/certs

# Copy Cloudflare Origin certificates (replace with your actual certificates)
sudo cp /path/to/amoskys.com.pem /opt/amoskys/certs/
sudo cp /path/to/amoskys.com.key /opt/amoskys/certs/

# Set certificate permissions
sudo chown root:root /opt/amoskys/certs/*
sudo chmod 644 /opt/amoskys/certs/amoskys.com.pem
sudo chmod 600 /opt/amoskys/certs/amoskys.com.key
```

### Step 4: Automated Deployment
```bash
# Run the automated deployment script
cd /opt/amoskys
sudo ./scripts/deploy_web.sh
```

### Step 5: DNS Configuration
```bash
# Set up DNS records in Cloudflare:
# A record: amoskys.com → Your VPS IP
# A record: www.amoskys.com → Your VPS IP
# CNAME record: app.amoskys.com → amoskys.com (for future dashboard)
# CNAME record: api.amoskys.com → amoskys.com (for future API)
```

### Step 6: Service Management
```bash
# Check service status
sudo systemctl status amoskys-web nginx

# View logs
sudo journalctl -u amoskys-web -f
sudo tail -f /var/log/nginx/amoskys.access.log

# Restart services
sudo systemctl restart amoskys-web
sudo systemctl reload nginx
```

## 🔍 VERIFICATION COMMANDS

### Health Checks
```bash
# Local health check
curl http://localhost:8000/health

# External health check (replace with your domain)
curl https://amoskys.com/health
curl https://amoskys.com/status

# SSL verification
openssl s_client -connect amoskys.com:443 -servername amoskys.com
```

### Performance Testing
```bash
# Basic load test (install apache2-utils first)
sudo apt install apache2-utils
ab -n 1000 -c 10 https://amoskys.com/health

# Check response times
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

## 🔧 TROUBLESHOOTING

### Common Issues

1. **Service won't start**
   ```bash
   sudo journalctl -u amoskys-web --no-pager -n 20
   sudo systemctl status amoskys-web
   ```

2. **NGINX configuration errors**
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

## 🎯 SUCCESS INDICATORS

✅ AMOSKYS landing page loads at https://amoskys.com
✅ Neural command center accessible at https://amoskys.com/command
✅ API endpoints respond: /status, /health
✅ SSL certificate valid and trusted
✅ NGINX access logs show incoming requests
✅ Gunicorn workers running and healthy
✅ Systemd service auto-starts on boot

## 🚀 POST-DEPLOYMENT NEXT STEPS

After successful deployment:

1. **Email Configuration**: Set up admin@amoskys.com
2. **Monitoring**: Configure Prometheus/Grafana
3. **Backup Strategy**: Implement automated backups
4. **Phase 2.3**: Begin API Gateway development
5. **Phase 2.4**: Start Dashboard development

---

🧠🛡️ **AMOSKYS Neural Security Command Platform**  
**Phase 2.2 Production Deployment - Ready for Global Access**
