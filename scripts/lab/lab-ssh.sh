#!/usr/bin/env bash
# AMOSKYS Lab — SSH into the lab instance.
#
# Usage: ./scripts/lab/lab-ssh.sh [command ...]
#
# With no args: interactive shell.
# With args: runs command(s) on the box and returns.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./lab-config.sh
source "$HERE/lab-config.sh"

if [ ! -f "$LAB_SSH_KEY" ]; then
  echo "error: SSH key not found at $LAB_SSH_KEY" >&2
  echo "       did you download amoskys-lab-key.pem and move it to ~/.ssh/?" >&2
  exit 2
fi

# Ensure correct key permissions (SSH refuses keys with 0644)
chmod 400 "$LAB_SSH_KEY" 2>/dev/null || true

if [ "$#" -eq 0 ]; then
  exec ssh -i "$LAB_SSH_KEY" \
    -o ServerAliveInterval=30 \
    -o ConnectTimeout=10 \
    "$LAB_SSH_USER@$LAB_HOSTNAME"
else
  exec ssh -i "$LAB_SSH_KEY" \
    -o ServerAliveInterval=30 \
    -o ConnectTimeout=10 \
    "$LAB_SSH_USER@$LAB_HOSTNAME" "$@"
fi
