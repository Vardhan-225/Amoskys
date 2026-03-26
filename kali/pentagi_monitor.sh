#!/bin/bash
# PentAGI Flow Monitor — polls flow status from terminal
# Usage: ./pentagi_monitor.sh [flow_id]

KALI="ghostops@192.168.237.132"
KEY="$HOME/.ssh/id_ed25519"
FLOW_ID="${1:-2}"

# Login
ssh -o ServerAliveInterval=5 -i "$KEY" "$KALI" "
curl -sk -c /tmp/pagi_mon.txt 'https://localhost:8443/api/v1/auth/login' \
  -X POST -H 'Content-Type: application/json' \
  -d '{\"mail\":\"admin@pentagi.com\",\"password\":\"Theweekndlove22059\\\$#\"}' 2>/dev/null >/dev/null
" 2>/dev/null

echo "=== PentAGI Monitor — Flow $FLOW_ID ==="
echo ""

while true; do
    OUTPUT=$(ssh -o ServerAliveInterval=5 -o ConnectTimeout=5 -i "$KEY" "$KALI" "
    # Flow status
    echo '=== FLOW ==='
    curl -sk -b /tmp/pagi_mon.txt 'https://localhost:8443/api/v1/graphql' \
      -H 'Content-Type: application/json' \
      -d '{\"query\":\"{ flow(flowId: $FLOW_ID) { id title status } }\"}' 2>/dev/null

    echo ''
    echo '=== TASKS ==='
    curl -sk -b /tmp/pagi_mon.txt 'https://localhost:8443/api/v1/graphql' \
      -H 'Content-Type: application/json' \
      -d '{\"query\":\"{ tasks(flowId: $FLOW_ID) { id title status result } }\"}' 2>/dev/null

    echo ''
    echo '=== TERMINAL (last 5) ==='
    curl -sk -b /tmp/pagi_mon.txt 'https://localhost:8443/api/v1/graphql' \
      -H 'Content-Type: application/json' \
      -d '{\"query\":\"{ terminalLogs(flowId: $FLOW_ID) { type text createdAt } }\"}' 2>/dev/null

    echo ''
    echo '=== MESSAGES (last 5) ==='
    curl -sk -b /tmp/pagi_mon.txt 'https://localhost:8443/api/v1/graphql' \
      -H 'Content-Type: application/json' \
      -d '{\"query\":\"{ messageLogs(flowId: $FLOW_ID) { type message result createdAt } }\"}' 2>/dev/null
    " 2>/dev/null)

    clear
    echo "=== PentAGI Monitor — Flow $FLOW_ID === $(date '+%H:%M:%S')"
    echo ""
    echo "$OUTPUT" | python3 -m json.tool 2>/dev/null || echo "$OUTPUT"
    echo ""
    echo "--- Refreshing in 15s (Ctrl+C to stop) ---"
    sleep 15
done
