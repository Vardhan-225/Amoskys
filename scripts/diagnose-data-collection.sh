#!/bin/zsh
# AMOSKYS Data Collection Diagnostic & Fix Script
# Purpose: Verify agents are running, collecting data, and pushing to database
# Date: December 5, 2025

set -e

AMOSKYS_ROOT="/Users/athanneeru/Downloads/GitHub/Amoskys"
DB_PATH="$AMOSKYS_ROOT/data/wal/flowagent.db"
LOG_DIR="$AMOSKYS_ROOT/logs"

echo "🔍 AMOSKYS Data Collection Diagnostic"
echo "======================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 1. Check running agents
echo "${BLUE}1. CHECKING RUNNING AGENTS${NC}"
echo "Expected: 6 agents (proc_agent, snmp_agent, flowagent, device_scanner, mac_telemetry, eventbus)"
echo ""

RUNNING_AGENTS=$(ps aux | grep -E "python.*amoskys" | grep -v grep | wc -l)
echo "Running AMOSKYS processes: $RUNNING_AGENTS"
echo ""

ps aux | grep -E "python.*amoskys" | grep -v grep | while read line; do
    echo "  ✓ $line" | head -c 100
    echo ""
done

echo ""

# 2. Check EventBus
echo "${BLUE}2. CHECKING EVENTBUS (gRPC)${NC}"
if lsof -i :50051 > /dev/null 2>&1; then
    echo "${GREEN}✓ EventBus listening on port 50051${NC}"
else
    echo "${RED}✗ EventBus NOT listening on port 50051${NC}"
fi
echo ""

# 3. Check Dashboard
echo "${BLUE}3. CHECKING DASHBOARD (Flask)${NC}"
if lsof -i :5000 > /dev/null 2>&1; then
    echo "${GREEN}✓ Dashboard listening on port 5000${NC}"
else
    echo "${RED}✗ Dashboard NOT listening on port 5000${NC}"
fi
echo ""

# 4. Check Database
echo "${BLUE}4. CHECKING DATABASE${NC}"
if [ -f "$DB_PATH" ]; then
    DB_SIZE=$(du -h "$DB_PATH" | awk '{print $1}')
    echo "${GREEN}✓ Database exists${NC}: $DB_PATH ($DB_SIZE)"
    
    # Check tables
    echo ""
    echo "Database tables:"
    sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table';" 2>/dev/null | while read table; do
        if [ ! -z "$table" ]; then
            COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM $table;" 2>/dev/null || echo "ERROR")
            echo "  • $table: $COUNT rows"
        fi
    done
else
    echo "${RED}✗ Database NOT found${NC}: $DB_PATH"
fi
echo ""

# 5. Check for data in database
echo "${BLUE}5. DATA COLLECTION STATUS${NC}"

# Check if tables have data
TABLES=$(sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table';" 2>/dev/null | grep -v sqlite_sequence)

if [ -z "$TABLES" ]; then
    echo "${RED}✗ No tables found in database${NC}"
    echo "   Database needs initialization!"
else
    for TABLE in $TABLES; do
        COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM $TABLE;" 2>/dev/null || echo "0")
        if [ "$COUNT" -gt 0 ]; then
            echo "${GREEN}✓ $TABLE: $COUNT records${NC}"
        else
            echo "${YELLOW}⚠ $TABLE: 0 records (empty)${NC}"
        fi
    done
fi
echo ""

# 6. Check logs
echo "${BLUE}6. CHECKING LOGS${NC}"
if [ -d "$LOG_DIR" ]; then
    echo "Recent logs:"
    ls -lht "$LOG_DIR" | head -10
else
    echo "${YELLOW}⚠ Log directory not found${NC}"
fi
echo ""

# 7. Check configuration
echo "${BLUE}7. CHECKING CONFIGURATION${NC}"
if [ -f "$AMOSKYS_ROOT/.env" ]; then
    echo "${GREEN}✓ .env file exists${NC}"
    echo "  EventBus endpoint: $(grep -i 'EVENTBUS\|GRPC' "$AMOSKYS_ROOT/.env" || echo 'Not set')"
else
    echo "${YELLOW}⚠ .env file not found${NC}"
fi
echo ""

# 8. Summary
echo "${BLUE}SUMMARY${NC}"
echo "========"
if [ "$RUNNING_AGENTS" -lt 6 ]; then
    echo "${YELLOW}⚠ WARNING: Only $RUNNING_AGENTS/6 agents running${NC}"
    echo "   Missing agents need to be started"
else
    echo "${GREEN}✓ All 6+ agents are running${NC}"
fi

TOTAL_RECORDS=0
for TABLE in $TABLES; do
    COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM $TABLE;" 2>/dev/null || echo "0")
    TOTAL_RECORDS=$((TOTAL_RECORDS + COUNT))
done

if [ "$TOTAL_RECORDS" -eq 0 ]; then
    echo "${RED}✗ Database is empty - no data being collected${NC}"
else
    echo "${GREEN}✓ Database has $TOTAL_RECORDS total records${NC}"
fi

echo ""
echo "Next steps:"
echo "  1. If agents < 6: Run 'make dev-up' to start all services"
echo "  2. If database is empty: Check agent logs for errors"
echo "  3. If dashboard shows no data: Restart dashboard with 'make restart-dashboard'"
