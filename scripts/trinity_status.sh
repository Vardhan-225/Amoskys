#!/bin/bash
# filepath: /scripts/trinity_status.sh
# AMOSKYS Trinity Status Dashboard
# Run on any node to verify AMOSKYS Trinity health
#
# Usage:
#   ./trinity_status.sh          # Basic status
#   ./trinity_status.sh --full   # Include queue event samples

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
AGENTS=("amoskys-kernel-audit" "amoskys-protocol_collectors" "amoskys-device_discovery")
AGENT_NAMES=("KernelAuditGuardV2" "ProtocolCollectorsV2" "DeviceDiscoveryV2")
PROBE_COUNTS=(7 10 6)
QUEUE_BASE="/var/lib/amoskys/queues"

# Header
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}${BOLD}         AMOSKYS NEURAL SECURITY COMMAND - TRINITY STATUS            ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Get hostname
HOSTNAME=$(hostname)
echo -e "${BOLD}Node:${NC} $HOSTNAME"
echo -e "${BOLD}Time:${NC} $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# Agent Status
echo -e "${BOLD}═══ AGENT STATUS ═══${NC}"
echo ""

total_probes=0
running_count=0

for i in "${!AGENTS[@]}"; do
    svc="${AGENTS[$i]}"
    name="${AGENT_NAMES[$i]}"
    probes="${PROBE_COUNTS[$i]}"
    
    # Get service status
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        status="${GREEN}✅ ACTIVE${NC}"
        running_count=$((running_count + 1))
        
        # Get memory and uptime
        mem=$(systemctl show "$svc" --property=MemoryCurrent 2>/dev/null | cut -d= -f2)
        if [[ "$mem" =~ ^[0-9]+$ ]]; then
            mem_mb=$((mem / 1024 / 1024))
            mem_str="${mem_mb}MB"
        else
            mem_str="N/A"
        fi
        
        since=$(systemctl show "$svc" --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2)
        
        echo -e "  $status ${BOLD}$name${NC}"
        echo -e "         Probes: $probes | Memory: $mem_str"
        echo -e "         Since:  $since"
    else
        status="${RED}❌ STOPPED${NC}"
        echo -e "  $status ${BOLD}$name${NC} ($probes probes)"
    fi
    
    total_probes=$((total_probes + probes))
    echo ""
done

echo -e "${BOLD}Total:${NC} $running_count/3 agents running, $total_probes micro-probes"
echo ""

# Queue Status
echo -e "${BOLD}═══ QUEUE STATUS ═══${NC}"
echo ""

# Map service names to queue directory names
declare -A QUEUE_DIRS
QUEUE_DIRS["amoskys-kernel-audit"]="kernel_audit"
QUEUE_DIRS["amoskys-protocol_collectors"]="protocol_collectors"
QUEUE_DIRS["amoskys-device_discovery"]="device_discovery"

for i in "${!AGENTS[@]}"; do
    svc="${AGENTS[$i]}"
    name="${AGENT_NAMES[$i]}"
    
    # Get queue directory name from map
    queue_name="${QUEUE_DIRS[$svc]}"
    db_path="$QUEUE_BASE/$queue_name/${queue_name}_queue.db"
    
    if [[ -f "$db_path" ]]; then
        # Get count and size
        count=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM queue;" 2>/dev/null || echo "0")
        size=$(du -h "$db_path" 2>/dev/null | cut -f1)
        
        echo -e "  📦 ${BOLD}$queue_name${NC}: $count events ($size)"
    else
        echo -e "  📦 ${BOLD}$queue_name${NC}: ${YELLOW}No queue file${NC}"
    fi
done

echo ""

# Drain Status
if [[ -f "/var/log/amoskys-drain.log" ]]; then
    last_drain=$(tail -1 /var/log/amoskys-drain.log 2>/dev/null | head -c 50)
    echo -e "${BOLD}Last Drain:${NC} $last_drain..."
    echo ""
fi

# System Resources
echo -e "${BOLD}═══ SYSTEM RESOURCES ═══${NC}"
echo ""

# Disk
disk_info=$(df -h / | tail -1)
disk_used=$(echo "$disk_info" | awk '{print $5}')
disk_avail=$(echo "$disk_info" | awk '{print $4}')
disk_pct=${disk_used%\%}

if [[ $disk_pct -ge 90 ]]; then
    disk_color=$RED
elif [[ $disk_pct -ge 80 ]]; then
    disk_color=$YELLOW
else
    disk_color=$GREEN
fi

echo -e "  💾 Disk: ${disk_color}${disk_used}${NC} used (${disk_avail} free)"

# Memory
mem_info=$(free -m | grep Mem)
mem_used=$(echo "$mem_info" | awk '{print $3}')
mem_total=$(echo "$mem_info" | awk '{print $2}')
mem_pct=$((mem_used * 100 / mem_total))

if [[ $mem_pct -ge 90 ]]; then
    mem_color=$RED
elif [[ $mem_pct -ge 80 ]]; then
    mem_color=$YELLOW
else
    mem_color=$GREEN
fi

echo -e "  🧠 Memory: ${mem_color}${mem_used}MB${NC} / ${mem_total}MB (${mem_pct}%)"

# CPU (1 min load average)
load=$(cat /proc/loadavg | awk '{print $1}')
echo -e "  ⚡ Load: $load"

echo ""

# Footer
echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"

# Optional: Detailed queue sample
if [[ "$1" == "--full" ]]; then
    echo ""
    echo -e "${BOLD}═══ RECENT EVENTS (last 3 per queue) ═══${NC}"
    echo ""
    
    for i in "${!AGENTS[@]}"; do
        svc="${AGENTS[$i]}"
        queue_name="${QUEUE_DIRS[$svc]}"
        db_path="$QUEUE_BASE/$queue_name/${queue_name}_queue.db"
        
        if [[ -f "$db_path" ]]; then
            echo -e "  ${BOLD}$queue_name:${NC}"
            sqlite3 "$db_path" "SELECT id, datetime(ts_ns/1000000000, 'unixepoch'), length(bytes) FROM queue ORDER BY id DESC LIMIT 3;" 2>/dev/null | while read line; do
                echo "    $line"
            done
            echo ""
        fi
    done
fi
