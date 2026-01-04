#!/bin/bash

# AMOSKYS System Startup Script
# Platform: macOS/Linux
# Purpose: Start all agents and dashboard in proper order

set -e

echo "🧠⚡ AMOSKYS Neural Security Platform - Startup"
echo "=============================================="
echo ""

# Change to project root
cd "$(dirname "$0")"
PROJECT_ROOT=$(pwd)

# Export PYTHONPATH
export PYTHONPATH="$PROJECT_ROOT/src:$PYTHONPATH"

# Create logs directory
mkdir -p logs

echo "📋 Checking existing services..."
echo ""

# Check EventBus
if pgrep -f "eventbus/server.py" > /dev/null; then
    echo "✅ EventBus already running (PID: $(pgrep -f 'eventbus/server.py'))"
else
    echo "⚠️  EventBus not running - starting..."
    cd "$PROJECT_ROOT"
    nohup python src/amoskys/eventbus/server.py > logs/eventbus.log 2>&1 &
    echo "✅ EventBus started (PID: $!)"
    sleep 2
fi

# Check WAL Processor
if pgrep -f "wal_processor" > /dev/null; then
    echo "✅ WAL Processor already running (PID: $(pgrep -f 'wal_processor'))"
else
    echo "⚠️  WAL Processor not running - starting..."
    cd "$PROJECT_ROOT"
    nohup python -m amoskys.storage.wal_processor > logs/wal_processor.log 2>&1 &
    echo "✅ WAL Processor started (PID: $!)"
    sleep 2
fi

echo ""
echo "📡 Starting Agents..."
echo ""

# Start Proc Agent
if pgrep -f "proc_agent.py" > /dev/null; then
    echo "✅ Proc Agent already running (PID: $(pgrep -f 'proc_agent.py'))"
else
    echo "🔄 Starting Proc Agent..."
    cd "$PROJECT_ROOT"
    nohup python -m amoskys.agents.proc.proc_agent > logs/proc_agent.log 2>&1 &
    PROC_PID=$!
    echo "✅ Proc Agent started (PID: $PROC_PID)"
    sleep 1
fi

# Start Peripheral Agent
if pgrep -f "peripheral_agent.py" > /dev/null; then
    echo "✅ Peripheral Agent already running (PID: $(pgrep -f 'peripheral_agent.py'))"
else
    echo "🔄 Starting Peripheral Agent..."
    cd "$PROJECT_ROOT"
    nohup python -m amoskys.agents.peripheral.peripheral_agent > logs/peripheral_agent.log 2>&1 &
    PERIPH_PID=$!
    echo "✅ Peripheral Agent started (PID: $PERIPH_PID)"
    sleep 1
fi

# Start SNMP Agent (newly fixed)
if pgrep -f "snmp_agent.py" > /dev/null; then
    echo "✅ SNMP Agent already running (PID: $(pgrep -f 'snmp_agent.py'))"
else
    echo "🔄 Starting SNMP Agent (NEWLY FIXED)..."
    cd "$PROJECT_ROOT"
    nohup python -m amoskys.agents.snmp.snmp_agent > logs/snmp_agent.log 2>&1 &
    SNMP_PID=$!
    echo "✅ SNMP Agent started (PID: $SNMP_PID)"
    sleep 1
fi

echo ""
echo "🌐 Starting Dashboard..."
echo ""

# Start Flask Dashboard with gunicorn for production
if pgrep -f "gunicorn.*wsgi:app" > /dev/null; then
    echo "✅ Dashboard already running (PID: $(pgrep -f 'gunicorn.*wsgi:app'))"
elif pgrep -f "wsgi.py" > /dev/null; then
    echo "✅ Dashboard already running (PID: $(pgrep -f 'wsgi.py'))"
else
    echo "🔄 Starting Gunicorn Dashboard (Production)..."
    cd "$PROJECT_ROOT"
    nohup gunicorn \
        --bind 127.0.0.1:5001 \
        --workers 1 \
        --worker-class gevent \
        --timeout 120 \
        --access-logfile /var/log/amoskys/access.log \
        --error-logfile /var/log/amoskys/error.log \
        --chdir "$PROJECT_ROOT/web" \
        "wsgi:app" > logs/dashboard.log 2>&1 &
    DASH_PID=$!
    echo "✅ Dashboard started (PID: $DASH_PID)"
    sleep 2
fi

echo ""
echo "=============================================="
echo "✅ AMOSKYS System Startup Complete"
echo "=============================================="
echo ""

# Display running services
echo "📊 Running Services:"
echo ""
ps aux | grep -E "(eventbus|wal_processor|proc_agent|peripheral_agent|snmp_agent|flask)" | grep -v grep | awk '{print "   " $2 "\t" $11 " " $12 " " $13}'

echo ""
echo "🔗 Dashboard URL: http://localhost:5001/dashboard/cortex"
echo ""
echo "📝 Logs location: $PROJECT_ROOT/logs/"
echo "   - EventBus:       logs/eventbus.log"
echo "   - WAL Processor:  logs/wal_processor.log"
echo "   - Proc Agent:     logs/proc_agent.log"
echo "   - Peripheral:     logs/peripheral_agent.log"
echo "   - SNMP Agent:     logs/snmp_agent.log"
echo "   - Dashboard:      logs/dashboard.log"
echo ""
echo "🔍 Validate data flow:"
echo "   sqlite3 data/telemetry.db \"SELECT COUNT(*), MAX(timestamp_dt) FROM process_events;\""
echo ""
echo "🛑 To stop all services:"
echo "   ./stop_amoskys.sh"
echo ""
