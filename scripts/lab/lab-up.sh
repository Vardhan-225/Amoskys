#!/usr/bin/env bash
# AMOSKYS Lab — start the lab EC2 instance.
#
# Usage: ./scripts/lab/lab-up.sh
#
# Idempotent: no-op if already running.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./lab-config.sh
source "$HERE/lab-config.sh"
lab_require_aws

iid="$(lab_instance_id)"
if [ -z "$iid" ]; then
  echo "error: no instance found with tag Name=$LAB_INSTANCE_NAME in $LAB_AWS_REGION" >&2
  exit 1
fi

state="$(lab_instance_state)"
echo "[lab-up] instance $iid state: $state"

case "$state" in
  running)
    echo "[lab-up] already running — no action"
    ;;
  stopped)
    echo "[lab-up] starting..."
    aws ec2 start-instances \
      --region "$LAB_AWS_REGION" \
      --profile "$LAB_AWS_PROFILE" \
      --instance-ids "$iid" >/dev/null
    echo "[lab-up] waiting for running..."
    aws ec2 wait instance-running \
      --region "$LAB_AWS_REGION" \
      --profile "$LAB_AWS_PROFILE" \
      --instance-ids "$iid"
    ;;
  pending)
    echo "[lab-up] already starting — waiting..."
    aws ec2 wait instance-running \
      --region "$LAB_AWS_REGION" \
      --profile "$LAB_AWS_PROFILE" \
      --instance-ids "$iid"
    ;;
  stopping)
    echo "[lab-up] instance is stopping. wait a minute then rerun." >&2
    exit 1
    ;;
  *)
    echo "[lab-up] unexpected state: $state" >&2
    exit 1
    ;;
esac

ip="$(lab_public_ip)"
echo "[lab-up] public IP: $ip"
echo "[lab-up] hostname: $LAB_HOSTNAME"
echo "[lab-up] SSH:      ssh -i $LAB_SSH_KEY $LAB_SSH_USER@$LAB_HOSTNAME"
