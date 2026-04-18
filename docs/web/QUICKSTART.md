# Quickstart

Operator guide — from repo checkout to running the first Argos engagement
against `lab.amoskys.com`.

## Prerequisites

- macOS workstation with AWS CLI (or you can skip lab provisioning if already done)
- SSH key at `~/.ssh/amoskys-lab-key.pem` (chmod 400)
- SSH key at `~/.ssh/kali_lab` for the Kali VM
- Python 3.11+ with a venv at `/Volumes/Akash_Lab/Amoskys/.venv/`
- Kali VM running at `192.168.237.132` (VMware Fusion)

## 1. Verify lab is up

```bash
# DNS + HTTPS reach
dig +short lab.amoskys.com
curl -sS -o /dev/null -w "lab HTTPS: %{http_code}\n" https://lab.amoskys.com/

# SSH into the lab
ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com 'uptime && wp --version'
```

If lab is down:
```bash
cd /Volumes/Akash_Lab/Amoskys
./scripts/lab/lab-up.sh
./scripts/lab/lab-status.sh
```

## 2. Verify Aegis is emitting

```bash
ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com \
  'wc -l /var/www/html/wp-content/uploads/amoskys-aegis/events.jsonl'
```

Expect a number > 0. Trigger a manual event to confirm:

```bash
curl -sS -o /dev/null -d "log=attacker&pwd=wrong" https://lab.amoskys.com/wp-login.php
ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com \
  'tail -1 /var/www/html/wp-content/uploads/amoskys-aegis/events.jsonl | jq .event_type'
```

Expect: `"aegis.auth.login_failed"`.

## 3. Verify Kali is reachable

```bash
ssh -i ~/.ssh/kali_lab ghostops@192.168.237.132 'uname -a && whoami'
```

If it times out, boot the Kali VM in VMware Fusion, then retry.

## 4. Install Argos on Kali (first time)

```bash
# Sync the repo to Kali (adjust the paths once the split is cleaner)
rsync -avz --exclude='.venv' --exclude='__pycache__' --exclude='.git' \
  -e "ssh -i ~/.ssh/kali_lab" \
  /Volumes/Akash_Lab/Amoskys/ \
  ghostops@192.168.237.132:~/amoskys/

ssh -i ~/.ssh/kali_lab ghostops@192.168.237.132 '
  cd ~/amoskys
  python3 -m venv .venv
  .venv/bin/pip install -e .
  .venv/bin/python -m amoskys.agents.Web.argos --help
'
```

Install missing Kali tools:

```bash
ssh -i ~/.ssh/kali_lab ghostops@192.168.237.132 '
  sudo apt update
  sudo apt install -y nuclei dalfox subfinder
  # interactsh-client:
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
'
```

## 5. Run the first Argos engagement

```bash
ssh -i ~/.ssh/kali_lab ghostops@192.168.237.132 '
  cd ~/amoskys
  .venv/bin/python -m amoskys.agents.Web.argos scan \
    lab.amoskys.com \
    --tools nuclei-cves,wpscan \
    --max-rps 5 \
    --max-duration 1800 \
    --report-dir ~/argos-reports
'
```

Report lands in `~/argos-reports/argos-<uuid>.json` on the Kali VM.

## 6. Fetch the report

```bash
scp -i ~/.ssh/kali_lab \
  ghostops@192.168.237.132:~/argos-reports/argos-*.json \
  /Volumes/Akash_Lab/Amoskys/docs/_local/argos-runs/
```

Analyze findings:

```bash
cat /Volumes/Akash_Lab/Amoskys/docs/_local/argos-runs/argos-*.json | \
  jq '.findings | group_by(.severity) | map({sev: .[0].severity, count: length})'
```

## 7. Check what Aegis saw during the scan

```bash
ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com '
  cd /var/www/html/wp-content/uploads/amoskys-aegis
  # events from the last 30 minutes
  python3 -c "
import json, time
cutoff = time.time_ns() - 30 * 60 * 10**9
with open(\"events.jsonl\") as f:
    from collections import Counter
    c = Counter()
    for line in f:
        if not line.strip(): continue
        e = json.loads(line)
        if e[\"event_timestamp_ns\"] >= cutoff:
            c[e[\"event_type\"]] += 1
    for t, n in c.most_common():
        print(f\"  {n:>3}  {t}\")
"
'
```

## 8. Tear down when done

```bash
./scripts/lab/lab-down.sh
```

This stops the EC2 instance. Re-run `./scripts/lab/lab-up.sh` next time.
State persists across stop/start.

## Common failure modes

### "Connection timed out" when SSH'ing to Kali
The VM is off. Boot in VMware Fusion. Verify with `ip a` on the VM — IP
should be 192.168.237.132.

### Argos scan completes instantly with zero findings
Check that `nuclei` is actually installed on Kali (`which nuclei`). A
missing binary causes the tool driver to report "failed" but the engagement
still completes.

### Aegis log shows no events despite traffic
Check the file permissions on
`/var/www/html/wp-content/uploads/amoskys-aegis/`. Must be writable by
`www-data`. If not:
```bash
ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com \
  'sudo chown -R www-data:www-data /var/www/html/wp-content/uploads/amoskys-aegis/'
```

### HTTPS cert expired
```bash
ssh -i ~/.ssh/amoskys-lab-key.pem ubuntu@lab.amoskys.com \
  'sudo certbot renew && sudo systemctl reload nginx'
```

Should not happen — `certbot.timer` auto-renews 30 days before expiry — but
if it does, this is the fix.

## Next steps

Once you can run `steps 1-7` end-to-end without manual intervention, the
next operator task is:

1. **Build the `/v1/events` ingest API** on the AWS ops host so Aegis
   doesn't just write locally but also ships to the brain.
2. **Apply IGRIS Fix 1** (see
   [../../src/amoskys/igris/NOISE_AUDIT.md](../../src/amoskys/igris/NOISE_AUDIT.md))
   before enabling the web event flow.
3. **Wire Argos findings into the same ingest**, closing the offensive →
   defensive loop.

Each is independently ~1 day of work. Together they unlock AMOSKYS Web as a
functional platform.
