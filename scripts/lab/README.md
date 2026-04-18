# AMOSKYS Lab Scripts

Management scripts for the lab WordPress target at `lab.amoskys.com`.

The lab is an EC2 t3.micro running Ubuntu 24.04 with three WordPress
installations:

| Path | Purpose |
|------|---------|
| `/clean` | Vanilla WP, no custom plugins — baseline |
| `/vulnerable` | Hosts deliberately-old plugins for Argos to find |
| `/prod-like` | Modern realistic stack for false-positive measurement |

All three have the **Aegis** plugin installed so we can measure defense
coverage identically across baselines.

## Prerequisites

```bash
# AWS CLI with credentials for the AMOSKYS account
brew install awscli
aws configure

# SSH key (download from the EC2 console during launch)
mv ~/Downloads/amoskys-lab-key.pem ~/.ssh/
chmod 400 ~/.ssh/amoskys-lab-key.pem
```

## Scripts

| Script | What it does |
|--------|-------------|
| `lab-config.sh` | Shared config — `source` but don't exec |
| `lab-up.sh` | Start the instance (idempotent) |
| `lab-down.sh` | Stop the instance (saves money when idle) |
| `lab-status.sh` | Show state, IP, SSH command |
| `lab-ssh.sh` | SSH in; with args runs one-shot commands |
| `install-wordpress.sh` | Run ON the instance to install LEMP + 3 WP variants |

## Typical workflow

```bash
# start the lab
./scripts/lab/lab-up.sh

# check state
./scripts/lab/lab-status.sh

# ssh in for interactive work
./scripts/lab/lab-ssh.sh

# one-shot commands
./scripts/lab/lab-ssh.sh 'tail -f /var/log/nginx/access.log'

# stop when done testing (save ~$7/month)
./scripts/lab/lab-down.sh
```

## First-time bootstrap

```bash
# 1. Launch the instance via AWS console (see handoff from architect)
# 2. Associate Elastic IP, point lab.amoskys.com at it
# 3. Copy the Aegis plugin to /tmp on the lab box
rsync -avz \
  -e "ssh -i ~/.ssh/amoskys-lab-key.pem" \
  src/amoskys/agents/Web/wordpress/wp-content/plugins/amoskys-aegis \
  ubuntu@lab.amoskys.com:/tmp/

# 4. Copy + run the installer
scp -i ~/.ssh/amoskys-lab-key.pem \
  scripts/lab/install-wordpress.sh \
  ubuntu@lab.amoskys.com:/tmp/

./scripts/lab/lab-ssh.sh \
  "sudo MYSQL_ROOT_PASS='$(openssl rand -hex 16)' \
        WP_DB_PASS='$(openssl rand -hex 16)' \
        bash /tmp/install-wordpress.sh"
```

## Cost

| State | Hourly | Monthly |
|-------|--------|---------|
| t3.micro running 24/7 | \$0.0104 | ~\$7.50 |
| t3.micro stopped | \$0 compute, \$0.80 EBS | ~\$0.80 |
| Running 4 hours/day | — | ~\$1.25 |

Stop the instance when not actively testing. Script + cron can automate
this — see `deploy/scheduled-tasks/` (future work).
