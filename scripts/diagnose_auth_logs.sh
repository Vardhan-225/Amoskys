#!/usr/bin/env bash
#
# Diagnostic script to check macOS unified log format for sudo events
#
# Usage: ./scripts/diagnose_auth_logs.sh
#

set -euo pipefail

echo "========================================="
echo "macOS Auth Log Format Diagnostic"
echo "========================================="
echo ""

# Check for sudo events in the last 10 minutes
echo "Checking for sudo events in last 10 minutes..."
echo ""

log show --last 10m --predicate 'process == "sudo"' --style syslog 2>&1 | head -50

echo ""
echo "========================================="
echo "Analysis:"
echo "========================================="
echo ""
echo "Look for lines containing your username and recent commands."
echo "We need to update the regex pattern in auth_agent.py to match this format."
echo ""
echo "Expected pattern in code:"
echo "  r'sudo.*USER=(\S+).*COMMAND=(.*)'"
echo ""
echo "If you see a different format (e.g., 'TTY=', 'PWD=', etc.),"
echo "we'll need to update the regex to match it."
echo ""
