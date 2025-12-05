#!/bin/bash
#
# AMOSKYS Flask Dashboard Startup Script
# Ensures single-instance operation on port 5000
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT=5000
LOG_DIR="$SCRIPT_DIR/logs"
FLASK_LOG="$LOG_DIR/flask.log"
PID_FILE="$LOG_DIR/flask.pid"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   AMOSKYS Neural Security Platform v2.4   ║${NC}"
echo -e "${GREEN}║        Starting Dashboard Server...        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Function to check if port is in use
port_in_use() {
    lsof -i :$PORT >/dev/null 2>&1
}

# Function to kill existing Flask processes
kill_existing_flask() {
    echo -e "${YELLOW}[1/5] Checking for existing Flask instances...${NC}"

    # Kill by PID file if it exists
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo -e "  → Stopping Flask process (PID: $OLD_PID)"
            kill "$OLD_PID" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$PID_FILE"
    fi

    # Kill any Flask processes on our port
    if port_in_use; then
        echo -e "  → Port $PORT is in use, terminating existing process"
        lsof -ti :$PORT | xargs kill -9 2>/dev/null || true
        sleep 2
    fi

    # Kill any stray Flask processes
    pkill -f "flask run" 2>/dev/null || true
    sleep 1

    echo -e "  ✓ Cleanup complete"
}

# Function to verify Python environment
check_environment() {
    echo -e "${YELLOW}[2/5] Verifying Python environment...${NC}"

    if [ ! -d ".venv" ]; then
        echo -e "${RED}  ✗ Virtual environment not found at .venv${NC}"
        exit 1
    fi

    # Activate virtual environment
    source .venv/bin/activate

    # Check required packages
    if ! python -c "import flask" 2>/dev/null; then
        echo -e "${RED}  ✗ Flask not installed${NC}"
        exit 1
    fi

    echo -e "  ✓ Python environment ready"
}

# Function to verify application structure
check_app_structure() {
    echo -e "${YELLOW}[3/5] Verifying application structure...${NC}"

    if [ ! -f "web/wsgi.py" ]; then
        echo -e "${RED}  ✗ web/wsgi.py not found${NC}"
        exit 1
    fi

    if [ ! -d "web/app" ]; then
        echo -e "${RED}  ✗ web/app directory not found${NC}"
        exit 1
    fi

    echo -e "  ✓ Application structure valid"
}

# Function to start Flask
start_flask() {
    echo -e "${YELLOW}[4/5] Starting Flask development server...${NC}"

    # Set environment variables
    export PYTHONPATH="$SCRIPT_DIR/src"
    export FLASK_APP="wsgi:app"
    export FLASK_DEBUG="True"

    # Start Flask in background
    cd web
    nohup ../.venv/bin/python -m flask run --host=127.0.0.1 --port=$PORT > "$FLASK_LOG" 2>&1 &
    FLASK_PID=$!
    cd ..

    # Save PID
    echo "$FLASK_PID" > "$PID_FILE"

    # Wait for Flask to start
    echo -e "  → Waiting for server to initialize..."
    sleep 3

    # Check if process is still running
    if ! kill -0 "$FLASK_PID" 2>/dev/null; then
        echo -e "${RED}  ✗ Flask failed to start. Check logs: $FLASK_LOG${NC}"
        exit 1
    fi

    echo -e "  ✓ Flask started (PID: $FLASK_PID)"
}

# Function to verify server is responding
verify_server() {
    echo -e "${YELLOW}[5/5] Verifying server health...${NC}"

    MAX_RETRIES=10
    RETRY_COUNT=0

    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if curl -s http://127.0.0.1:$PORT/ >/dev/null 2>&1; then
            echo -e "  ✓ Server is responding"
            return 0
        fi
        RETRY_COUNT=$((RETRY_COUNT + 1))
        sleep 1
    done

    echo -e "${RED}  ✗ Server not responding after $MAX_RETRIES attempts${NC}"
    echo -e "${RED}  Check logs: $FLASK_LOG${NC}"
    exit 1
}

# Function to display server info
show_server_info() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         Server Started Successfully!       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "📍 Dashboard URL:  ${GREEN}http://127.0.0.1:$PORT/${NC}"
    echo -e "🧠 Cortex Center:  ${GREEN}http://127.0.0.1:$PORT/dashboard/cortex${NC}"
    echo -e "📊 System Monitor: ${GREEN}http://127.0.0.1:$PORT/dashboard/system${NC}"
    echo -e "🔬 Processes:      ${GREEN}http://127.0.0.1:$PORT/dashboard/processes${NC}"
    echo -e "🤖 Agents:         ${GREEN}http://127.0.0.1:$PORT/dashboard/agents${NC}"
    echo -e "📖 API Docs:       ${GREEN}http://127.0.0.1:$PORT/api/docs${NC}"
    echo ""
    echo -e "📝 Logs:           $FLASK_LOG"
    echo -e "🔢 PID:            $(cat $PID_FILE)"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to view logs, or use:${NC}"
    echo -e "  tail -f $FLASK_LOG"
    echo ""
}

# Main execution
main() {
    kill_existing_flask
    check_environment
    check_app_structure
    start_flask
    verify_server
    show_server_info
}

# Run main function
main

# Keep script running to show it's active
echo -e "${GREEN}Server is running. Press Ctrl+C to stop monitoring.${NC}"
echo ""

# Trap Ctrl+C to show cleanup message
trap 'echo -e "\n${YELLOW}Server is still running in background (PID: $(cat $PID_FILE))${NC}\nTo stop: kill $(cat $PID_FILE)"; exit 0' INT

# Monitor logs in real-time
tail -f "$FLASK_LOG" 2>/dev/null || sleep infinity
