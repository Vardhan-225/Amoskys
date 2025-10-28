#!/bin/bash
# AMOSKYS ML Pipeline - Quick Reference Commands
# Source: TOMORROW_MORNING_PLAN.md

set -e  # Exit on error

AMOSKYS_ROOT="/Users/athanneeru/Downloads/GitHub/Amoskys"
cd "$AMOSKYS_ROOT"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}    AMOSKYS ML Pipeline - Quick Commands${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

# Activate venv
source .venv/bin/activate

echo -e "${GREEN}✓${NC} Virtual environment activated"
echo ""

# Show menu
echo "Select an action:"
echo ""
echo "  1) Start EventBus + SNMP Agent"
echo "  2) Stop all agents"
echo "  3) Check system status"
echo "  4) View database stats"
echo "  5) Run ML pipeline (full)"
echo "  6) Train Isolation Forest"
echo "  7) Test inference"
echo "  8) View visualizations"
echo "  9) Clean up old data"
echo "  0) Show logs"
echo ""
echo -n "Enter choice [1-9, 0 for logs]: "
read choice

case $choice in
    1)
        echo -e "${YELLOW}Starting EventBus...${NC}"
        mkdir -p logs
        python -m amoskys.eventbus.server > logs/eventbus.log 2>&1 &
        echo $! > .eventbus.pid
        sleep 2
        
        echo -e "${YELLOW}Starting SNMP Agent...${NC}"
        python -m amoskys.agents.snmpagent.monitor > logs/snmp_agent.log 2>&1 &
        echo $! > .snmp_agent.pid
        sleep 2
        
        echo -e "${GREEN}✓${NC} Both services started"
        echo ""
        echo "Monitor with: tail -f logs/eventbus.log"
        echo "              tail -f logs/snmp_agent.log"
        ;;
        
    2)
        echo -e "${YELLOW}Stopping all agents...${NC}"
        if [ -f .eventbus.pid ]; then
            kill $(cat .eventbus.pid) 2>/dev/null || true
            rm .eventbus.pid
        fi
        if [ -f .snmp_agent.pid ]; then
            kill $(cat .snmp_agent.pid) 2>/dev/null || true
            rm .snmp_agent.pid
        fi
        pkill -f "amoskys.eventbus.server" 2>/dev/null || true
        pkill -f "amoskys.agents.snmpagent" 2>/dev/null || true
        echo -e "${GREEN}✓${NC} All agents stopped"
        ;;
        
    3)
        echo -e "${YELLOW}System Status:${NC}"
        echo ""
        echo "EventBus:"
        ps aux | grep "amoskys.eventbus.server" | grep -v grep || echo "  Not running"
        echo ""
        echo "SNMP Agent:"
        ps aux | grep "amoskys.agents.snmpagent" | grep -v grep || echo "  Not running"
        echo ""
        if [ -f data/wal/flowagent.db ]; then
            echo "Database:"
            sqlite3 data/wal/flowagent.db "SELECT COUNT(*) FROM events" | xargs echo "  Events:"
        else
            echo "Database: Not found"
        fi
        ;;
        
    4)
        echo -e "${YELLOW}Database Statistics:${NC}"
        if [ -f data/wal/flowagent.db ]; then
            sqlite3 data/wal/flowagent.db <<EOF
SELECT 
    COUNT(*) as total_events,
    MIN(datetime(ts_ns/1000000000, 'unixepoch')) as first_event,
    MAX(datetime(ts_ns/1000000000, 'unixepoch')) as last_event
FROM events;
EOF
        else
            echo "  Database not found: data/wal/flowagent.db"
        fi
        ;;
        
    5)
        echo -e "${YELLOW}Running full ML pipeline...${NC}"
        python scripts/run_ml_pipeline_full.py
        echo ""
        echo -e "${GREEN}✓${NC} Pipeline complete"
        echo "Output: data/ml_pipeline/"
        ;;
        
    6)
        echo -e "${YELLOW}Training Isolation Forest...${NC}"
        python scripts/train_models.py --model isolation_forest
        echo ""
        echo -e "${GREEN}✓${NC} Model trained"
        echo "Model saved: models/anomaly_detection/isolation_forest.pkl"
        ;;
        
    7)
        echo -e "${YELLOW}Running inference test...${NC}"
        python scripts/quick_inference.py
        ;;
        
    8)
        echo -e "${YELLOW}Opening visualizations...${NC}"
        open data/ml_pipeline/*.png 2>/dev/null || echo "No visualizations found"
        ;;
        
    9)
        echo -e "${YELLOW}Cleaning up old data...${NC}"
        echo -n "This will delete all ML pipeline outputs. Continue? [y/N]: "
        read confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            rm -rf data/ml_pipeline/*.csv
            rm -rf data/ml_pipeline/*.parquet
            rm -rf data/ml_pipeline/*.png
            rm -rf data/ml_pipeline/*.json
            echo -e "${GREEN}✓${NC} Cleaned up"
        else
            echo "Cancelled"
        fi
        ;;
        
    0)
        echo -e "${YELLOW}Available logs:${NC}"
        echo ""
        ls -lh logs/ 2>/dev/null || echo "No logs directory"
        echo ""
        echo "View with:"
        echo "  tail -f logs/eventbus.log"
        echo "  tail -f logs/snmp_agent.log"
        ;;
        
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
