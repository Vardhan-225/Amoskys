#!/bin/bash

# AMOSKYS Agent Status Checker
# Shows real-time agent status from both system and API

echo "🧠 AMOSKYS Agent Status Check"
echo "======================================"
echo ""

echo "1️⃣  System Process Check (psutil equivalent):"
echo "--------------------------------------"
echo ""

# Check each agent by process pattern
declare -A agents=(
    ["EventBus"]="eventbus/server.py"
    ["Proc Agent"]="proc_agent.py"
    ["Mac Telemetry"]="generate_mac_telemetry.py"
    ["Peripheral Agent"]="peripheral_agent.py"
    ["SNMP Agent"]="snmp_agent.py"
    ["Flow Agent"]="flowagent"
    ["WAL Processor"]="wal_processor"
)

for agent_name in "${!agents[@]}"; do
    pattern="${agents[$agent_name]}"
    pid=$(pgrep -f "$pattern" 2>/dev/null | head -1)

    if [ -n "$pid" ]; then
        uptime=$(ps -o etime= -p "$pid" 2>/dev/null | xargs)
        printf "%-20s ✅ RUNNING (PID: %-8s Uptime: %s)\n" "$agent_name" "$pid" "$uptime"
    else
        printf "%-20s ❌ STOPPED\n" "$agent_name"
    fi
done

echo ""
echo "2️⃣  Dashboard API Check:"
echo "--------------------------------------"
echo ""

# Check if dashboard is running
if ! curl -s http://localhost:5001/dashboard/api/live/agents >/dev/null 2>&1; then
    echo "❌ Dashboard not responding on http://localhost:5001"
    echo "   Run: cd web && python run.py"
    exit 1
fi

# Fetch and parse agent status from API
curl -s http://localhost:5001/dashboard/api/live/agents | python3 << 'PYTHON'
import json, sys

try:
    data = json.load(sys.stdin)

    if data.get('status') == 'success':
        agents = data.get('agents', [])

        for agent in agents:
            name = agent['hostname']
            status = agent['status']
            running = agent['running']
            instances = agent['instances']

            # Status emoji
            if status == 'online':
                emoji = '✅'
                status_text = 'RUNNING'
            elif status == 'stopped':
                emoji = '❌'
                status_text = 'STOPPED'
            elif status == 'incompatible':
                emoji = '⚠️'
                status_text = 'INCOMPATIBLE'
            else:
                emoji = '❓'
                status_text = status.upper()

            # Format output
            instances_text = f"({instances} instance{'s' if instances != 1 else ''})" if instances > 0 else ""
            print(f"{name:30} {emoji} {status_text:12} {instances_text}")

            # Show warnings if any
            if agent.get('warnings'):
                for warning in agent['warnings']:
                    print(f"   ⚠️  {warning}")
    else:
        print(f"❌ API error: {data}")

except Exception as e:
    print(f"❌ Failed to parse API response: {e}")
    sys.exit(1)
PYTHON

echo ""
echo "3️⃣  Summary:"
echo "--------------------------------------"
curl -s http://localhost:5001/dashboard/api/live/agents | python3 << 'PYTHON'
import json, sys

try:
    data = json.load(sys.stdin)
    summary = data.get('summary', {})

    total = summary.get('total', 0)
    online = summary.get('online', 0)
    stopped = summary.get('stopped', 0)
    health = summary.get('health_percentage', 0)

    print(f"Total Agents:    {total}")
    print(f"Online:          {online}")
    print(f"Stopped:         {stopped}")
    print(f"Health:          {health}%")

    if health < 50:
        print("\n⚠️  WARNING: Less than 50% of agents are online")
    elif health < 100:
        print(f"\n⚠️  {stopped} agent(s) need to be started")
    else:
        print("\n✅ All agents operational")

except Exception as e:
    print(f"❌ Failed to parse summary: {e}")
PYTHON

echo ""
echo "======================================"
echo ""
echo "🔄 To start all agents, run:"
echo "   ./start_amoskys.sh"
echo ""
