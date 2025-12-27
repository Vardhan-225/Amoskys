#!/bin/bash

echo "🧠 AMOSKYS Quick Status Check"
echo "======================================================"
echo ""

check_process() {
    local name="$1"
    local pattern="$2"
    local pid=$(pgrep -f "$pattern" 2>/dev/null | head -1)
    
    if [ -n "$pid" ]; then
        local uptime=$(ps -o etime= -p "$pid" 2>/dev/null | xargs)
        printf "%-25s ✅ RUNNING   PID: %-8s Uptime: %s\n" "$name" "$pid" "$uptime"
        return 0
    else
        printf "%-25s ❌ STOPPED\n" "$name"
        return 1
    fi
}

# Check all AMOSKYS services
running=0
total=0

echo "CORE INFRASTRUCTURE:"
echo "------------------------------------------------------"
check_process "EventBus" "eventbus/server.py" && ((running++)); ((total++))
check_process "WAL Processor" "wal_processor" && ((running++)); ((total++))

echo ""
echo "AGENTS:"
echo "------------------------------------------------------"
check_process "Proc Agent" "amoskys.agents.proc.proc_agent" && ((running++)); ((total++))
check_process "Mac Telemetry" "generate_mac_telemetry" && ((running++)); ((total++))
check_process "Peripheral Agent" "amoskys.agents.peripheral.peripheral_agent" && ((running++)); ((total++))
check_process "SNMP Agent" "amoskys.agents.snmp.snmp_agent" && ((running++)); ((total++))

echo ""
echo "DASHBOARD:"
echo "------------------------------------------------------"
check_process "Flask Dashboard" "wsgi.py" && ((running++)); ((total++))

echo ""
echo "======================================================"
echo "SUMMARY: $running / $total services running"
echo "Health: $(( running * 100 / total ))%"
echo "======================================================"
echo ""

if [ $running -lt $total ]; then
    echo "⚠️  Some services are not running. Start them with:"
    echo "   ./start_amoskys.sh"
fi

echo ""
