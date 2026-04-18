#!/usr/bin/env bash
# AMOSKYS Lab — show current lab instance status.
#
# Usage: ./scripts/lab/lab-status.sh

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./lab-config.sh
source "$HERE/lab-config.sh"
lab_require_aws

iid="$(lab_instance_id)"
if [ -z "$iid" ]; then
  echo "[lab-status] no instance found with tag Name=$LAB_INSTANCE_NAME"
  exit 0
fi

state="$(lab_instance_state)"
ip="$(lab_public_ip || echo '(not assigned)')"

cat <<EOF
[lab-status]
  instance:   $iid
  name:       $LAB_INSTANCE_NAME
  region:     $LAB_AWS_REGION
  state:      $state
  public IP:  $ip
  hostname:   $LAB_HOSTNAME
  ssh:        ssh -i $LAB_SSH_KEY $LAB_SSH_USER@$LAB_HOSTNAME
EOF

# Cost hint
if [ "$state" = "running" ]; then
  echo "  running cost: ~\$0.0104/hr (t3.micro on-demand) = ~\$7.50/month always-on"
fi
