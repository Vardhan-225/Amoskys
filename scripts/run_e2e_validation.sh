#!/bin/bash
# End-to-End Intelligence Validation Script
# Runs the complete AMOSKYS pipeline on Mac for detection testing

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

export PYTHONPATH="$PROJECT_ROOT/src"

echo "🧠 AMOSKYS End-to-End Validation"
echo "================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "${BLUE}[1/6]${NC} Checking prerequisites..."
if ! python -c "from amoskys.intel import TelemetryIngestor, FusionEngine" 2>/dev/null; then
    echo -e "${RED}✗${NC} Failed to import intelligence modules"
    exit 1
fi
echo -e "${GREEN}✓${NC} Intelligence modules ready"

# Ensure directories exist
echo -e "${BLUE}[2/6]${NC} Setting up directories..."
mkdir -p data/queue data/wal data/intel logs
echo -e "${GREEN}✓${NC} Directories ready"

# Clean up old state (CRITICAL for repeatable testing)
echo -e "${BLUE}[3/6]${NC} Cleaning up previous test state..."

# Stop old processes
pkill -f "amoskys.agents.auth.auth_agent" 2>/dev/null || true
pkill -f "amoskys.agents.persistence.persistence_agent" 2>/dev/null || true
pkill -f "amoskys.intel.ingest" 2>/dev/null || true
pkill -f "amoskys.intel.fusion_engine" 2>/dev/null || true
sleep 2

# Remove test LaunchAgent if exists
if [ -f "$HOME/Library/LaunchAgents/com.amoskys.test.plist" ]; then
    echo "  • Removing old test LaunchAgent"
    rm "$HOME/Library/LaunchAgents/com.amoskys.test.plist"
fi

# Reset persistence snapshot (forces fresh baseline)
if [ -f "data/persistence_snapshot.json" ]; then
    echo "  • Resetting persistence snapshot for fresh baseline"
    rm "data/persistence_snapshot.json"
fi

# Clear queue databases
for db in data/queue/auth_agent.db data/queue/persistence_agent.db; do
    if [ -f "$db" ]; then
        echo "  • Clearing queue: $db"
        sqlite3 "$db" "DELETE FROM queue" 2>/dev/null || true
    fi
done

# Clear fusion database (fresh start)
if [ -f "data/intel/fusion_live.db" ]; then
    echo "  • Clearing fusion database"
    rm "data/intel/fusion_live.db"
fi

echo -e "${GREEN}✓${NC} Cleanup complete"

# Start agents
echo -e "${BLUE}[4/6]${NC} Starting agents..."

# AuthGuard Agent
echo "  Starting AuthGuardAgent..."
PYTHONPATH=src python -m amoskys.agents.auth.auth_agent \
    --device-id "$(hostname)" \
    --queue-db data/queue/auth_agent.db \
    > logs/auth_agent.log 2>&1 &
AUTH_PID=$!
echo -e "  ${GREEN}✓${NC} AuthGuardAgent (PID: $AUTH_PID)"

# PersistenceGuard Agent
echo "  Starting PersistenceGuardAgent..."
PYTHONPATH=src python -m amoskys.agents.persistence.persistence_agent \
    --device-id "$(hostname)" \
    --queue-db data/queue/persistence_agent.db \
    > logs/persistence_agent.log 2>&1 &
PERSIST_PID=$!
echo -e "  ${GREEN}✓${NC} PersistenceGuardAgent (PID: $PERSIST_PID)"

# CRITICAL: Wait for persistence baseline snapshot
echo ""
echo "  Waiting for PersistenceGuard to create initial baseline..."
echo "  (This is required before it can detect changes)"
sleep 10

if [ -f "data/persistence_snapshot.json" ]; then
    SNAPSHOT_SIZE=$(wc -l < "data/persistence_snapshot.json")
    echo -e "  ${GREEN}✓${NC} Baseline snapshot created ($SNAPSHOT_SIZE lines)"
else
    echo -e "  ${RED}✗${NC} WARNING: Baseline snapshot not created yet"
    echo "  PersistenceGuard may not detect changes on first scan"
fi

sleep 3

# Start TelemetryIngestor (includes FusionEngine internally)
echo -e "${BLUE}[5/6]${NC} Starting TelemetryIngestor + FusionEngine..."
PYTHONPATH=src python -m amoskys.intel.ingest \
    --poll-interval 5 \
    --fusion-db data/intel/fusion_live.db \
    --fusion-window 30 \
    > logs/ingest.log 2>&1 &
INGEST_PID=$!
echo -e "${GREEN}✓${NC} TelemetryIngestor (PID: $INGEST_PID)"
echo "  • TelemetryIngestor includes built-in FusionEngine"
echo "  • No separate FusionEngine process needed"

FUSION_PID=""  # No standalone FusionEngine

echo ""
echo -e "${GREEN}✅ All components running!${NC}"
echo ""
echo "Process IDs:"
echo "  AuthGuard:       $AUTH_PID"
echo "  PersistenceGuard: $PERSIST_PID"
echo "  Ingest+Fusion:   $INGEST_PID"
echo ""
echo "Logs:"
echo "  tail -f logs/auth_agent.log"
echo "  tail -f logs/persistence_agent.log"
echo "  tail -f logs/ingest.log  # Includes FusionEngine correlation"
echo ""
echo -e "${YELLOW}══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SAFE SCENARIO: Trigger persistence_after_auth${NC}"
echo -e "${YELLOW}══════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}IMPORTANT:${NC} Perform these steps NOW while baseline is fresh!"
echo ""
echo "Step 1: Generate sudo event (triggers AuthGuard)"
echo -e "${BLUE}  sudo ls /tmp${NC}"
echo ""
echo "Step 2: Immediately create test LaunchAgent (triggers PersistenceGuard)"
cat << 'SCENARIO'
  cat << 'EOF' > ~/Library/LaunchAgents/com.amoskys.test.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.amoskys.test</string>
    <key>ProgramArguments</key>
    <array>
      <string>/bin/echo</string>
      <string>amoskys-test</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
  </dict>
</plist>
EOF
SCENARIO
echo ""
echo "Step 3: Wait 10-15 seconds for correlation..."
echo ""
echo "Step 4: Check for incidents:"
cat << 'CHECKCMD'
# List latest incidents
PYTHONPATH=src python -m amoskys.intel.fusion_engine \
  --db data/intel/fusion_live.db \
  --list-incidents --limit 5
CHECKCMD
echo ""
echo "Step 5: Check device risk:"
cat << 'CHECKCMD'
# Check device risk for this Mac
PYTHONPATH=src python -m amoskys.intel.fusion_engine \
  --db data/intel/fusion_live.db \
  --risk "$(hostname)"
CHECKCMD
echo ""
echo -e "${YELLOW}══════════════════════════════════════════════${NC}"
echo ""
echo "To stop all components:"
echo -e "${RED}  kill $AUTH_PID $PERSIST_PID $INGEST_PID${NC}"
echo ""
echo "Or run:"
echo -e "${RED}  scripts/stop_e2e_validation.sh${NC}"
echo ""

# Save PIDs for cleanup script
cat > /tmp/amoskys_pids.txt << EOF
$AUTH_PID
$PERSIST_PID
$INGEST_PID
EOF

echo -e "${GREEN}Ready for validation! Follow the safe scenario steps above.${NC}"
