#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# AMOSKYS MCP Server — Deploy to ops EC2 (18.223.110.15)
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────
OPS_HOST="18.223.110.15"
OPS_USER="ubuntu"
SSH_KEY="$HOME/.ssh/amoskys-ops.pem"
REMOTE_DIR="/opt/amoskys"
SERVICE="amoskys-mcp"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ssh_cmd() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$OPS_USER@$OPS_HOST" "$@"
}

scp_cmd() {
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$@"
}

echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  AMOSKYS MCP Server Deployment${NC}"
echo -e "${CYAN}  Target: ${OPS_USER}@${OPS_HOST}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"

# ── Step 1: Sync code ─────────────────────────────────────────────
echo -e "\n${YELLOW}[1/5] Syncing MCP server code...${NC}"
ssh_cmd "cd ${REMOTE_DIR} && git pull origin main"

# ── Step 2: Install MCP SDK ───────────────────────────────────────
echo -e "\n${YELLOW}[2/5] Installing Python MCP SDK...${NC}"
ssh_cmd "pip3 install --quiet 'mcp[cli]>=1.0.0'"

# ── Step 3: Create MCP config ────────────────────────────────────
echo -e "\n${YELLOW}[3/5] Creating MCP config...${NC}"
ssh_cmd "mkdir -p ${REMOTE_DIR}/config"

# Generate API key if not exists
ssh_cmd "
if [ ! -f ${REMOTE_DIR}/config/mcp.env ]; then
    MCP_KEY=\$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    cat > ${REMOTE_DIR}/config/mcp.env << EOF
MCP_API_KEYS=\${MCP_KEY}
MCP_AUTH_ENABLED=true
MCP_BRAIN_ENABLED=true
MCP_BRAIN_INTERVAL=60
MCP_LOG_LEVEL=INFO
EOF
    echo 'Generated new MCP API key'
    echo \"MCP_API_KEY: \${MCP_KEY}\"
else
    echo 'MCP config already exists'
fi
"

# ── Step 4: Install systemd service ──────────────────────────────
echo -e "\n${YELLOW}[4/5] Installing systemd service...${NC}"
ssh_cmd "
    sudo cp ${REMOTE_DIR}/deploy/systemd/amoskys-mcp.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE}
"

# ── Step 5: Start/restart service ─────────────────────────────────
echo -e "\n${YELLOW}[5/5] Starting MCP server...${NC}"
ssh_cmd "
    sudo systemctl restart ${SERVICE}
    sleep 2
    sudo systemctl status ${SERVICE} --no-pager -l
"

# ── Done ──────────────────────────────────────────────────────────
echo -e "\n${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  MCP Server deployed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}SSE Endpoint:${NC} https://ops.amoskys.com:8444/sse"
echo -e "  ${CYAN}Service:${NC}      sudo systemctl status ${SERVICE}"
echo -e "  ${CYAN}Logs:${NC}         sudo journalctl -u ${SERVICE} -f"
echo ""
echo -e "  ${YELLOW}Claude Code config (~/.claude/settings.json):${NC}"
echo '  {'
echo '    "mcpServers": {'
echo '      "amoskys": {'
echo '        "type": "sse",'
echo '        "url": "https://ops.amoskys.com:8444/sse"'
echo '      }'
echo '    }'
echo '  }'
echo ""

# Print API key for reference
echo -e "  ${YELLOW}API Key (save this):${NC}"
ssh_cmd "grep MCP_API_KEYS ${REMOTE_DIR}/config/mcp.env 2>/dev/null || echo '  (check config/mcp.env on server)'"
