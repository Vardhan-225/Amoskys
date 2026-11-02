# AWS final state before teardown (2026-11-02)

AMOSKYS was shut down on 2026-11-02. This records the live setup so it can be rebuilt from `deploy/` and `docs/deployment/`. No data was kept.

| Name | Instance | Type | Region | Disk |
|---|---|---|---|---|
| amoskys-command (ops / fleet server) | i-0faf42459f5b05452 | t3.small | us-east-2c | 32 GiB gp3 |
| amoskys-vps | i-0fc095537d0f4ef6f | t3.micro | us-east-2c | 8 GiB gp3 |

Elastic IPs released: 3.147.175.238 (us-east-2), 32.195.33.133 (us-east-1, unattached). Lab instance i-082fd9c71efc3638e was already gone. October 2026 bill: $37.61.

## amoskys-command (18.223.110.15)

### OS
Ubuntu 24.04.4 LTS
6.17.0-1007-aws

### Enabled amoskys/web services
amoskys-mcp.service                            enabled enabled
amoskys-ops.service                            enabled enabled
nginx.service                                  enabled enabled
amoskys-analyzer-rescore.timer                 enabled enabled
amoskys-intel-refresh.timer                    enabled enabled
amoskys-retention.timer                        enabled enabled

### Listening ports
0.0.0.0:22 sshd
0.0.0.0:443 nginx
0.0.0.0:80 nginx
0.0.0.0:8443 python3
0.0.0.0:8444 python3
127.0.0.1:5432 postgres
127.0.0.53%lo:53 systemd-resolve
127.0.0.54:53 systemd-resolve
[::]:22 sshd
[::]:443 nginx

### nginx sites
ops-amoskys

### Python
Python 3.12.3

### /opt/amoskys git rev
4852d577c8e140cb1980f473dfad728bd8965fec Tue Jun 30 19:44:01 2026 -0700 feat(brain): make the brain's verdict real — visibility, calibration, flow, intel

### Custom systemd units
#### /etc/systemd/system/amoskys-analyzer-rescore.service
```ini
[Unit]
Description=AMOSKYS brain — fleet.db re-scoring (one batch)
After=network-online.target amoskys-ops.service
Wants=amoskys-ops.service
[Service]
Type=oneshot
User=ubuntu
WorkingDirectory=/opt/amoskys-brain
Environment=PYTHONPATH=/opt/amoskys-brain/src
Environment=AMOSKYS_DATA_DIR=/var/lib/amoskys
Environment=AMOSKYS_TELEMETRY_DB=/var/lib/amoskys/analyzer.db
Environment=AMOSKYS_FLEET_DB=/var/lib/amoskys/fleet.db
Environment=AMOSKYS_FUSION_DB=/var/lib/amoskys/intel/fusion.db
Environment=AMOSKYS_THREAT_INTEL_DB=/var/lib/amoskys/threat_intel.db
Environment=AMOSKYS_FLEET_RESCORE=1
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/amoskys/venv/bin/python -m amoskys.analyzer_main --once
MemoryAccounting=yes
MemoryMax=420M
MemoryHigh=360M
Nice=10
SyslogIdentifier=amoskys-analyzer
```
#### /etc/systemd/system/amoskys-intel-refresh.service
```ini
[Unit]
Description=AMOSKYS threat-intel feed refresh (abuse.ch/ET)
After=network-online.target

[Service]
Type=oneshot
User=ubuntu
Environment=AMOSKYS_THREAT_INTEL_DB=/var/lib/amoskys/threat_intel.db
WorkingDirectory=/opt/amoskys-brain
ExecStart=/opt/amoskys/venv/bin/python /opt/amoskys-brain/scripts/update_threat_intel.py
MemoryMax=256M
Nice=10
```
#### /etc/systemd/system/amoskys-mcp.service
```ini
[Unit]
Description=AMOSKYS MCP Server — IGRIS Fleet Command & Control
After=network.target amoskys-ops.service
Wants=amoskys-ops.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/amoskys
Environment="PYTHONPATH=/opt/amoskys/src"
Environment="PATH=/opt/amoskys/venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=/opt/amoskys/config/mcp.env
ExecStart=/opt/amoskys/venv/bin/python3 -m amoskys.mcp.server
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=amoskys-mcp

[Install]
WantedBy=multi-user.target
```
#### /etc/systemd/system/amoskys-ops.service
```ini
[Unit]
Description=AMOSKYS Operations Server — Command Center
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/amoskys
Environment=PYTHONPATH=/opt/amoskys/src
Environment=CC_PORT=8443
Environment=CC_DB_PATH=/var/lib/amoskys/fleet.db
Environment=CC_HOST=0.0.0.0
ExecStart=/opt/amoskys/venv/bin/python3 server/command_center.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=amoskys-ops

[Install]
WantedBy=multi-user.target
```
#### /etc/systemd/system/amoskys-retention.service
```ini
[Unit]
Description=AMOSKYS fleet.db retention (prune resolved incidents + cap event tables)
After=network-online.target
[Service]
Type=oneshot
User=ubuntu
WorkingDirectory=/opt/amoskys-brain
Environment=PYTHONPATH=/opt/amoskys-brain/src
ExecStart=/opt/amoskys/venv/bin/python /opt/amoskys-brain/scripts/fleet_retention.py --db /var/lib/amoskys/fleet.db --incident-days 7
MemoryMax=256M
Nice=15
SyslogIdentifier=amoskys-retention
```

## amoskys-vps (3.147.175.238)

### OS
Ubuntu 24.04.3 LTS
6.14.0-1018-aws

### Enabled amoskys/web services
amoskys-web.service                            enabled enabled
nginx.service                                  enabled enabled

### Listening ports
0.0.0.0:22 sshd
0.0.0.0:443 nginx
0.0.0.0:80 nginx
127.0.0.1:5001 gunicorn
127.0.0.53%lo:53 systemd-resolve
127.0.0.54:53 systemd-resolve
[::]:22 sshd
[::]:443 nginx
[::]:80 nginx

### nginx sites
amoskys

### Python
Python 3.12.3

### /opt/amoskys git rev
2af9ded9915477229db902897a71b7252d6f785b Sat Aug 29 12:40:42 2026 -0700 feat(ledger): surface the kernel's allow/deny decision — the signal triage was burying

### Custom systemd units
#### /etc/systemd/system/amoskys-web.service
```ini
# AMOSKYS Web Interface Systemd Service
# Location: /etc/systemd/system/amoskys-web.service

[Unit]
Description=AMOSKYS Neural Security Command Platform - Web Interface
Documentation=https://github.com/amoskys/platform
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
RuntimeDirectory=amoskys-web
RuntimeDirectoryMode=755

# Working directory and environment
WorkingDirectory=/opt/amoskys
Environment=FLASK_ENV=production
# Without this the app boots with no SECRET_KEY, no API keys and no DB paths.
# The live unit has carried it since the first deploy; the repo copy did not,
# and deploy_remote.sh copies this file over /etc/systemd/system on every run —
# so shipping the repo version as it stood would have silently stripped
# production of its entire environment.
EnvironmentFile=/opt/amoskys/.env
Environment=PYTHONPATH=/opt/amoskys
Environment=PYTHONUNBUFFERED=1

# Service execution - use gevent worker (eventlet hangs on VPS)
ExecStart=/opt/amoskys/venv/bin/gunicorn \
    --worker-class gevent \
    -w 1 \
    --bind 127.0.0.1:5001 \
    --timeout 120 \
    --access-logfile /var/log/amoskys/access.log \
    --error-logfile /var/log/amoskys/error.log \
    --chdir /opt/amoskys/web \
    wsgi:app

ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/amoskys/web
# ProtectSystem=strict makes the filesystem read-only except for these paths.
# The live unit permits logs/; the repo copy did not, so log writes would have
# started failing the moment this file replaced it.
ReadWritePaths=/opt/amoskys/logs
ReadWritePaths=/opt/amoskys/data
ReadWritePaths=/var/log/amoskys
ReadWritePaths=/tmp

# Resource limits
LimitNOFILE=65536
MemoryAccounting=yes
MemoryMax=1G

# Restart policy
Restart=always
RestartSec=10
StartLimitIntervalSec=60
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=amoskys-web

[Install]
WantedBy=multi-user.target
```
#### /etc/systemd/system/amoskys.service
```ini
[Unit]
Description=AMOSKYS Neural Security Platform
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=ubuntu
WorkingDirectory=/opt/amoskys
Environment="PATH=/opt/amoskys/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ExecStart=/bin/bash -lc 'cd /opt/amoskys && source venv/bin/activate && ./start_amoskys.sh'
ExecStop=/bin/bash -lc 'cd /opt/amoskys && source venv/bin/activate && ./stop_amoskys.sh'

# If something fails during ExecStart, don’t spam reboot loop
Restart=no

[Install]
WantedBy=multi-user.target
```
