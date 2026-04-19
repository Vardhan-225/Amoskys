#!/usr/bin/env bash
#
# inject-ses-creds.sh — Inject SES SMTP credentials onto lab.amoskys.com
#
# Reads an SES SMTP-user credentials CSV (downloaded from the AWS SES
# console via "Create SMTP credentials") and pipes user+password over
# SSH to the server-side injector /usr/local/sbin/amoskys-smtp-inject.py.
#
# Credentials never appear in argv or in a shell variable — they flow
# from the CSV through a Python pipe directly into SSH stdin.
#
# Usage:
#   scripts/lab/inject-ses-creds.sh                         # auto-finds CSV in ~/Downloads
#   scripts/lab/inject-ses-creds.sh path/to/credentials.csv # explicit path
#
# Safe to rerun for rotations. Reloads php-fpm on the server on success.

set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/amoskys-lab-key.pem}"
SSH_HOST="${SSH_HOST:-ubuntu@lab.amoskys.com}"

if [[ ! -r "$SSH_KEY" ]]; then
    echo "ERROR: SSH key not readable: $SSH_KEY" >&2
    exit 1
fi

# Locate CSV
if [[ $# -ge 1 ]]; then
    CSV="$1"
else
    CSV="$(ls -t "$HOME/Downloads"/*credentials*.csv "$HOME/Downloads"/*smtp*.csv "$HOME/Downloads"/*SES*.csv 2>/dev/null | head -n1 || true)"
fi

if [[ -z "${CSV:-}" || ! -r "$CSV" ]]; then
    echo "ERROR: No readable SES credentials CSV found." >&2
    echo "       Pass the path explicitly, e.g.:" >&2
    echo "       $0 ~/Downloads/security_credentials.csv" >&2
    exit 1
fi

echo "[inject-ses-creds] Using CSV: $CSV"
echo "[inject-ses-creds] Piping credentials to ${SSH_HOST}..."

python3 "$(dirname "$0")/_parse_ses_csv.py" "$CSV" \
  | ssh -i "$SSH_KEY" -o BatchMode=yes "$SSH_HOST" \
        'sudo /usr/local/sbin/amoskys-smtp-inject.py'

echo "[inject-ses-creds] Done. To rotate in future: rerun this script with a new CSV."
