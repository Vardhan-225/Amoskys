#!/bin/bash

# AMOSKYS System Shutdown Script
# Platform: macOS/Linux
# Purpose: Gracefully stop all AMOSKYS services

echo "🛑 AMOSKYS Neural Security Platform - Shutdown"
echo "=============================================="
echo ""

echo "Stopping services..."
echo ""

# Stop Dashboard
if pgrep -f "flask.*run.py" > /dev/null; then
    echo "🔄 Stopping Flask Dashboard..."
    pkill -f "flask.*run.py"
    sleep 1
    echo "✅ Dashboard stopped"
else
    echo "⚠️  Dashboard not running"
fi

# Stop SNMP Agent
if pgrep -f "snmp_agent.py" > /dev/null; then
    echo "🔄 Stopping SNMP Agent..."
    pkill -f "snmp_agent.py"
    sleep 1
    echo "✅ SNMP Agent stopped"
else
    echo "⚠️  SNMP Agent not running"
fi

# Stop Peripheral Agent
if pgrep -f "peripheral_agent.py" > /dev/null; then
    echo "🔄 Stopping Peripheral Agent..."
    pkill -f "peripheral_agent.py"
    sleep 1
    echo "✅ Peripheral Agent stopped"
else
    echo "⚠️  Peripheral Agent not running"
fi

# Stop Proc Agent
if pgrep -f "proc_agent.py" > /dev/null; then
    echo "🔄 Stopping Proc Agent..."
    pkill -f "proc_agent.py"
    sleep 1
    echo "✅ Proc Agent stopped"
else
    echo "⚠️  Proc Agent not running"
fi

# Stop WAL Processor
if pgrep -f "wal_processor" > /dev/null; then
    echo "🔄 Stopping WAL Processor..."
    pkill -f "wal_processor"
    sleep 2
    echo "✅ WAL Processor stopped"
else
    echo "⚠️  WAL Processor not running"
fi

# Stop EventBus
if pgrep -f "eventbus/server.py" > /dev/null; then
    echo "🔄 Stopping EventBus..."
    pkill -f "eventbus/server.py"
    sleep 2
    echo "✅ EventBus stopped"
else
    echo "⚠️  EventBus not running"
fi

echo ""
echo "=============================================="
echo "✅ AMOSKYS System Shutdown Complete"
echo "=============================================="
echo ""

# Verify all stopped
REMAINING=$(ps aux | grep -E "(eventbus|wal_processor|proc_agent|peripheral_agent|snmp_agent|flask)" | grep -v grep | wc -l)
if [ "$REMAINING" -eq 0 ]; then
    echo "✅ All AMOSKYS services stopped successfully"
else
    echo "⚠️  Warning: $REMAINING process(es) still running"
    ps aux | grep -E "(eventbus|wal_processor|proc_agent|peripheral_agent|snmp_agent|flask)" | grep -v grep
fi
echo ""
