#!/bin/bash
#
# AMOSKYS Flask Dashboard Stop Script
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/logs/flask.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Stopping AMOSKYS Dashboard Server...${NC}"

# Stop by PID file
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo -e "  → Stopping Flask process (PID: $PID)"
        kill "$PID"
        sleep 2

        # Force kill if still running
        if kill -0 "$PID" 2>/dev/null; then
            echo -e "  → Force stopping..."
            kill -9 "$PID"
        fi

        echo -e "${GREEN}  ✓ Server stopped${NC}"
    else
        echo -e "${YELLOW}  → Process not running${NC}"
    fi
    rm -f "$PID_FILE"
else
    echo -e "${YELLOW}  → No PID file found${NC}"
fi

# Kill any stray processes
pkill -f "flask run" 2>/dev/null && echo -e "  → Cleaned up stray Flask processes"
lsof -ti :5000 | xargs kill -9 2>/dev/null && echo -e "  → Freed port 5000"

echo -e "${GREEN}Done.${NC}"
