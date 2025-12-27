#!/bin/bash

echo "========================================="
echo "AMOSKYS Dashboard Execution Test Suite"
echo "========================================="
echo ""

# Test 1: API Endpoints
echo "Test 1: API Endpoints"
echo "--------------------"
echo "✓ Testing /dashboard/api/live/metrics..."
curl -s http://127.0.0.1:5000/dashboard/api/live/metrics | python -m json.tool > /dev/null && echo "  ✅ Live metrics OK" || echo "  ❌ Live metrics FAILED"

echo "✓ Testing /dashboard/api/live/agents..."
curl -s http://127.0.0.1:5000/dashboard/api/live/agents | python -m json.tool > /dev/null && echo "  ✅ Live agents OK" || echo "  ❌ Live agents FAILED"

echo "✓ Testing /dashboard/api/agents/status..."
curl -s http://127.0.0.1:5000/dashboard/api/agents/status | python -m json.tool > /dev/null && echo "  ✅ Agents status OK" || echo "  ❌ Agents status FAILED"

echo "✓ Testing /dashboard/api/available-agents..."
curl -s http://127.0.0.1:5000/dashboard/api/available-agents | python -m json.tool > /dev/null && echo "  ✅ Available agents OK" || echo "  ❌ Available agents FAILED"

echo ""
echo "Test 2: Dashboard Pages"
echo "----------------------"
for page in cortex soc agents system neural processes; do
  echo "✓ Testing /dashboard/$page..."
  curl -s "http://127.0.0.1:5000/dashboard/$page" | grep -q "<title>" && echo "  ✅ $page OK" || echo "  ❌ $page FAILED"
done

echo ""
echo "Test 3: Python Imports"
echo "---------------------"
source .venv/bin/activate
echo "✓ Testing agent_control import..."
python -c "from web.app.dashboard.agent_control import start_agent; print('  ✅ agent_control OK')" 2>/dev/null || echo "  ❌ agent_control FAILED"

echo "✓ Testing agent_discovery import..."
python -c "from web.app.dashboard.agent_discovery import get_all_agents_status; print('  ✅ agent_discovery OK')" 2>/dev/null || echo "  ❌ agent_discovery FAILED"

echo ""
echo "Test 4: Agent Status"
echo "-------------------"
echo "✓ Checking agent health..."
curl -s http://127.0.0.1:5000/dashboard/api/agents/proc_agent/health | python -c "import sys, json; data = json.load(sys.stdin); print('  ✅ Health check OK' if data.get('status') == 'success' else '  ❌ Health check FAILED')" 2>/dev/null || echo "  ❌ Health check FAILED"

echo ""
echo "========================================="
echo "Test Suite Complete"
echo "========================================="
