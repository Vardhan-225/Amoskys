#!/bin/bash
# Stop all AMOSKYS E2E validation processes

echo "🛑 Stopping AMOSKYS validation processes..."

if [ -f /tmp/amoskys_pids.txt ]; then
    while read pid; do
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "  Killing PID $pid..."
            kill "$pid" 2>/dev/null || true
        fi
    done < /tmp/amoskys_pids.txt
    rm /tmp/amoskys_pids.txt
else
    # Fallback: kill by process name
    pkill -f "amoskys-authguard" 2>/dev/null || true
    pkill -f "amoskys-persistguard" 2>/dev/null || true
    pkill -f "amoskys-ingest" 2>/dev/null || true
    pkill -f "amoskys-fusion" 2>/dev/null || true
fi

sleep 2
echo "✅ All processes stopped"
