#!/usr/bin/env bash
# AMOSKYS Lab — shared configuration for lab-* scripts.
# Edit this file to change the lab instance name, region, or SSH key.
#
# Source, don't execute: all lab-* scripts do `source lab-config.sh`.

set -euo pipefail

# AWS identification
export LAB_INSTANCE_NAME="${LAB_INSTANCE_NAME:-amoskys-lab-wp}"
export LAB_AWS_REGION="${LAB_AWS_REGION:-us-east-1}"
export LAB_AWS_PROFILE="${LAB_AWS_PROFILE:-default}"

# SSH
export LAB_SSH_KEY="${LAB_SSH_KEY:-$HOME/.ssh/amoskys-lab-key.pem}"
export LAB_SSH_USER="${LAB_SSH_USER:-ubuntu}"
export LAB_HOSTNAME="${LAB_HOSTNAME:-lab.amoskys.com}"

# Resolve instance id by name tag
lab_instance_id() {
  aws ec2 describe-instances \
    --region "$LAB_AWS_REGION" \
    --profile "$LAB_AWS_PROFILE" \
    --filters "Name=tag:Name,Values=$LAB_INSTANCE_NAME" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text
}

lab_instance_state() {
  aws ec2 describe-instances \
    --region "$LAB_AWS_REGION" \
    --profile "$LAB_AWS_PROFILE" \
    --filters "Name=tag:Name,Values=$LAB_INSTANCE_NAME" \
    --query 'Reservations[].Instances[].State.Name' \
    --output text
}

lab_public_ip() {
  aws ec2 describe-instances \
    --region "$LAB_AWS_REGION" \
    --profile "$LAB_AWS_PROFILE" \
    --filters "Name=tag:Name,Values=$LAB_INSTANCE_NAME" \
              "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].PublicIpAddress' \
    --output text
}

lab_require_aws() {
  if ! command -v aws >/dev/null 2>&1; then
    echo "error: aws cli not found. Install: brew install awscli" >&2
    exit 2
  fi
}
