# AMOSKYS Dismantle Record

**Date:** 2026-11-02
**Decision by:** Akash Thanneeru
**Status:** Project ended. All cloud infrastructure destroyed, all local services stopped. Code and docs kept on GitHub.

This file records what was running, what was removed, how to verify it, and how to rebuild it.

---

## 1. Why

AMOSKYS cost about $37/month on AWS ($37.61 for October 2026) with no users. The project had grown past what one person could finish and ship (endpoint agents, ESF sensor, fleet server, IGRIS brain, dashboard, WordPress lab). The decision was to stop paying for it and keep the work as a reference.

No runtime data was kept. `fleet.db` (2.5 GB), `analyzer.db` and `threat_intel.db` were destroyed with the server on purpose.

---

## 2. What was running

### AWS (account `168064691729`)

| Resource | ID | Region | Notes |
|---|---|---|---|
| EC2 `amoskys-command-center` | `i-0faf42459f5b05452` | us-east-2c | t3.small, ops/fleet server, public IP `18.223.110.15` |
| EC2 `amoskys-vps` | `i-0fc095537d0f4ef6f` | us-east-2c | t3.micro |
| EBS volume | `vol-0409eb69d91a791b3` | us-east-2 | 32 GiB gp3 |
| EBS volume | `vol-01934872f22cc376b` | us-east-2 | 8 GiB gp3 |
| Elastic IP | `3.147.175.238` (`eipalloc-09430aa71f932febd`) | us-east-2 | attached to `amoskys-vps` |
| Elastic IP | `32.195.33.133` (`eipalloc-0d0e364819b853068`) | us-east-1 | unattached leftover from the lab instance |

Already gone before teardown: lab instance `i-082fd9c71efc3638e` (us-east-1). No snapshots, AMIs, RDS, or S3 data in use.

The live software setup of both servers (services, ports, nginx site, systemd units, deployed commit `4852d577`) is captured in [`deployment/AWS_FINAL_STATE_2026-11-02.md`](deployment/AWS_FINAL_STATE_2026-11-02.md).

### Local Mac

| Component | How it ran |
|---|---|
| `amoskys.collector_main`, `amoskys.analyzer_main`, `amoskys.igris.cli --daemon` | user processes |
| `scripts/collect_and_store.py` (6 copies) | user processes |
| `com.amoskys.live` | LaunchAgent, `~/Library/LaunchAgents` |
| `AmoskysSentinel.app` (ESF shim, root) | LaunchDaemon `com.amoskys.sentinel`, `/Library/LaunchDaemons` |

---

## 3. What was done (2026-11-02, US Pacific)

1. Stopped all local AMOSKYS processes. Unloaded `com.amoskys.live` and moved its plist to `~/Library/LaunchAgents/disabled-amoskys/`.
2. Booted out and deleted the root LaunchDaemon `com.amoskys.sentinel` (run by the owner with `sudo`).
3. Captured the live server configuration into `deployment/AWS_FINAL_STATE_2026-11-02.md`.
4. ~14:10: terminated `i-0faf42459f5b05452` and `i-0fc095537d0f4ef6f` from the EC2 console. Both EBS root volumes were deleted with them (delete-on-termination).
5. Released Elastic IPs `3.147.175.238` (us-east-2) and `32.195.33.133` (us-east-1).
6. Checked afterward: both instances `terminated`, no volumes, snapshots, or Elastic IPs remaining in either region.

Expected billing: a final partial bill for Nov 1–2 2026 (about $2–3), then $0.

---

## 4. How to prove it

Anyone with access to the AWS account can confirm the teardown:

```bash
# Instances show "terminated" (visible for about an hour after termination, then gone from the list)
aws ec2 describe-instances --region us-east-2 \
  --instance-ids i-0faf42459f5b05452 i-0fc095537d0f4ef6f \
  --query 'Reservations[].Instances[].[InstanceId,State.Name]'

# Nothing billable left
aws ec2 describe-volumes   --region us-east-2 --query 'Volumes[].VolumeId'
aws ec2 describe-addresses --region us-east-2 --query 'Addresses[].PublicIp'
aws ec2 describe-addresses --region us-east-1 --query 'Addresses[].PublicIp'

# The audit trail: CloudTrail keeps these events for 90 days (until about 2027-01-31)
aws cloudtrail lookup-events --region us-east-2 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=TerminateInstances
aws cloudtrail lookup-events --region us-east-2 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ReleaseAddress
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ReleaseAddress
```

The monthly bills are the long-term proof: October 2026 = $37.61, November 2026 = only the first two days, December 2026 onward = $0.

On the Mac:

```bash
ps aux | grep -i amoskys | grep -v grep          # no output
launchctl list | grep -i amoskys                 # no output
ls /Library/LaunchDaemons | grep -i amoskys      # no output
```

---

## 5. How to bring it back

Everything needed to rebuild is in this repo. Nothing depends on the destroyed servers.

| Need | Where |
|---|---|
| Exact live server setup | [`deployment/AWS_FINAL_STATE_2026-11-02.md`](deployment/AWS_FINAL_STATE_2026-11-02.md) |
| Server deploy guides | [`deployment/`](deployment/) (`VPS_DEPLOYMENT_GUIDE.md`, `PRODUCTION_DEPLOYMENT.md`, `CLOUDFLARE_SETUP.md`) |
| nginx, systemd, Docker configs | [`../deploy/`](../deploy/) |
| Local agent install | [`../install.sh`](../install.sh), [`../install_daemon.sh`](../install_daemon.sh) |
| ESF sentinel build and signing | [`../macos-esf-shim/`](../macos-esf-shim/) (`sign.sh`, `install_sentinel.sh`) |
| Architecture and known issues | [`architecture/AMOSKYS_ARCHITECTURE_AUDIT_2026-06-17.md`](architecture/AMOSKYS_ARCHITECTURE_AUDIT_2026-06-17.md) |

Rough path: launch an Ubuntu 24.04 instance (t3.small was enough), clone this repo to `/opt/amoskys`, follow the deploy guide and recreate the systemd units from the final-state doc, point DNS at the new IP, then reinstall the Mac agents and sentinel. Secrets (TLS certs, `SECRET_KEY`, API keys, DB passwords) were never committed and have to be regenerated.

Before reviving it, read the architecture audit first. It lists the known problems that were never fixed (IGRIS incident feedback loop, no integrity at rest in `fleet.db`, single ops node).
