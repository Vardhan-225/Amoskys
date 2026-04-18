#!/usr/bin/env bash
# AMOSKYS Lab — stop the lab EC2 instance.
#
# Usage: ./scripts/lab/lab-down.sh
#
# Stops (not terminates) the instance. EBS volume + Elastic IP persist.
# Next lab-up restores identical state.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./lab-config.sh
source "$HERE/lab-config.sh"
lab_require_aws

iid="$(lab_instance_id)"
if [ -z "$iid" ]; then
  echo "error: no instance found with tag Name=$LAB_INSTANCE_NAME" >&2
  exit 1
fi

state="$(lab_instance_state)"
echo "[lab-down] instance $iid state: $state"

case "$state" in
  stopped)
    echo "[lab-down] already stopped"
    ;;
  running|pending)
    echo "[lab-down] stopping..."
    aws ec2 stop-instances \
      --region "$LAB_AWS_REGION" \
      --profile "$LAB_AWS_PROFILE" \
      --instance-ids "$iid" >/dev/null
    echo "[lab-down] waiting for stopped..."
    aws ec2 wait instance-stopped \
      --region "$LAB_AWS_REGION" \
      --profile "$LAB_AWS_PROFILE" \
      --instance-ids "$iid"
    echo "[lab-down] stopped."
    ;;
  stopping)
    echo "[lab-down] already stopping — waiting..."
    aws ec2 wait instance-stopped \
      --region "$LAB_AWS_REGION" \
      --profile "$LAB_AWS_PROFILE" \
      --instance-ids "$iid"
    ;;
  *)
    echo "[lab-down] unexpected state: $state" >&2
    exit 1
    ;;
esac
