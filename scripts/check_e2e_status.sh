#!/bin/bash
# Check status of AMOSKYS E2E validation

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONPATH="$PROJECT_ROOT/src"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "🔍 AMOSKYS E2E Validation Status"
echo "================================="
echo ""

# Check processes
echo -e "${BLUE}Running Processes:${NC}"
AUTH_RUNNING=$(pgrep -f "amoskys.agents.auth.auth_agent" | wc -l)
PERSIST_RUNNING=$(pgrep -f "amoskys.agents.persistence.persistence_agent" | wc -l)
INGEST_RUNNING=$(pgrep -f "amoskys.intel.ingest" | wc -l)
FUSION_RUNNING=$(pgrep -f "amoskys.intel.fusion_engine" | wc -l)

if [ "$AUTH_RUNNING" -gt 0 ]; then
    echo -e "  ${GREEN}✓${NC} AuthGuardAgent ($(pgrep -f amoskys.agents.auth.auth_agent))"
else
    echo -e "  ${RED}✗${NC} AuthGuardAgent (not running)"
fi

if [ "$PERSIST_RUNNING" -gt 0 ]; then
    echo -e "  ${GREEN}✓${NC} PersistenceGuardAgent ($(pgrep -f amoskys.agents.persistence.persistence_agent))"
else
    echo -e "  ${RED}✗${NC} PersistenceGuardAgent (not running)"
fi

if [ "$INGEST_RUNNING" -gt 0 ]; then
    echo -e "  ${GREEN}✓${NC} TelemetryIngestor ($(pgrep -f amoskys.intel.ingest))"
else
    echo -e "  ${RED}✗${NC} TelemetryIngestor (not running)"
fi

if [ "$FUSION_RUNNING" -gt 0 ]; then
    echo -e "  ${GREEN}✓${NC} FusionEngine ($(pgrep -f amoskys.intel.fusion_engine))"
else
    echo -e "  ${RED}✗${NC} FusionEngine (not running)"
fi

echo ""

# Check databases
echo -e "${BLUE}Agent Databases:${NC}"
for db in data/queue/auth_agent.db data/queue/persistence_agent.db data/wal/flowagent.db; do
    if [ -f "$db" ]; then
        size=$(du -h "$db" | cut -f1)
        events=$(sqlite3 "$db" "SELECT COUNT(*) FROM queue" 2>/dev/null || echo "N/A")
        echo -e "  ${GREEN}✓${NC} $db ($size, $events events)"
    else
        echo -e "  ${YELLOW}○${NC} $db (not created yet)"
    fi
done

echo ""

# Check fusion database
echo -e "${BLUE}Intelligence Layer:${NC}"
if [ -f data/intel/fusion_live.db ]; then
    size=$(du -h data/intel/fusion_live.db | cut -f1)
    incidents=$(sqlite3 data/intel/fusion_live.db "SELECT COUNT(*) FROM incidents" 2>/dev/null || echo "0")
    devices=$(sqlite3 data/intel/fusion_live.db "SELECT COUNT(DISTINCT device_id) FROM device_risk" 2>/dev/null || echo "0")
    echo -e "  ${GREEN}✓${NC} Fusion DB ($size)"
    echo -e "      Incidents: $incidents"
    echo -e "      Devices tracked: $devices"

    if [ "$incidents" -gt 0 ]; then
        echo ""
        echo -e "${GREEN}🎯 Recent Incidents:${NC}"
        PYTHONPATH=src python -m amoskys.intel.fusion_engine \
            --db data/intel/fusion_live.db \
            --list-incidents --limit 3
    fi
else
    echo -e "  ${YELLOW}○${NC} Fusion DB (not created yet)"
fi

echo ""

# Check logs
echo -e "${BLUE}Recent Log Activity:${NC}"
if [ -d logs ]; then
    for log in logs/*.log; do
        if [ -f "$log" ]; then
            lines=$(wc -l < "$log" | tr -d ' ')
            last_update=$(stat -f "%Sm" -t "%H:%M:%S" "$log" 2>/dev/null || stat -c "%y" "$log" 2>/dev/null | cut -d' ' -f2)
            echo -e "  ${BLUE}$(basename $log):${NC} $lines lines (updated: $last_update)"
        fi
    done
else
    echo -e "  ${YELLOW}No logs directory${NC}"
fi

echo ""
echo -e "${BLUE}Tail logs:${NC} tail -f logs/fusion_engine.log"
echo -e "${BLUE}List incidents:${NC} PYTHONPATH=src python -m amoskys.intel.fusion_engine --db data/intel/fusion_live.db --list-incidents"
echo -e "${BLUE}Check risk:${NC} PYTHONPATH=src python -m amoskys.intel.fusion_engine --db data/intel/fusion_live.db --risk \"\$(hostname)\""
