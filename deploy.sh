#!/bin/bash
#
# AMOSKYS Deploy — One command to rule them all.
#
# Usage:
#   ./deploy.sh              Deploy everything (local + servers)
#   ./deploy.sh local        Only update local Mac agent
#   ./deploy.sh servers      Only deploy to ops + web servers
#   ./deploy.sh status       Check health of all systems
#
# Works from ANY directory — worktree, main repo, wherever.
# Handles the worktree→main repo→install sync automatically.
#
set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────
REPO="/Volumes/Akash_Lab/Amoskys"
INSTALL="/Library/Amoskys/src/amoskys"
SSH_KEY="$HOME/.ssh/amoskys-deploy"
OPS_IP="18.223.110.15"
WEB_IP="3.147.175.238"
SSH="ssh -i $SSH_KEY -o ConnectTimeout=5 -o StrictHostKeyChecking=no"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${CYAN}[..]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!!]${NC} $1"; }

# ── Step 1: Git — push to GitHub ───────────────────────────────────
push_to_github() {
    echo -e "\n${CYAN}── STEP 1: Push to GitHub ──${NC}"

    # Detect if we're in a worktree or main repo
    local git_dir
    git_dir=$(git rev-parse --git-dir 2>/dev/null)
    local current_branch
    current_branch=$(git branch --show-current 2>/dev/null)

    # Check for uncommitted changes
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
        warn "Uncommitted changes detected — commit first or they won't deploy"
    fi

    # Push current branch to main
    if [ "$current_branch" != "main" ]; then
        info "Pushing $current_branch → origin/main"
        git fetch origin main 2>/dev/null
        if ! git rebase origin/main 2>/dev/null; then
            fail "Rebase failed — resolve conflicts first"
            return 1
        fi
        git push origin "$current_branch:main" 2>/dev/null && ok "Pushed to main" || fail "Push failed"
    else
        git push origin main 2>/dev/null && ok "Pushed to main" || fail "Push failed"
    fi
}

# ── Step 2: Sync main repo ─────────────────────────────────────────
sync_main_repo() {
    echo -e "\n${CYAN}── STEP 2: Sync main repo ──${NC}"
    cd "$REPO"
    git fetch origin main 2>/dev/null
    git reset --hard origin/main 2>/dev/null
    ok "Main repo synced to $(git log --oneline -1)"
    cd - >/dev/null 2>&1
}

# ── Step 3: Update local Mac agent ─────────────────────────────────
deploy_local() {
    echo -e "\n${CYAN}── STEP 3: Update local Mac agent ──${NC}"

    # rsync from main repo to installed location
    sudo rsync -a "$REPO/src/amoskys/" "$INSTALL/" --exclude=__pycache__ --delete
    ok "Code synced to $INSTALL"

    # Kill ALL amoskys processes (children survive launchctl unload)
    sudo pkill -9 -f "amoskys" 2>/dev/null || true
    sleep 1
    # Restart via launchd
    sudo launchctl load /Library/LaunchDaemons/com.amoskys.watchdog.plist 2>/dev/null

    # Verify it's running
    sleep 2
    if pgrep -f "amoskys.watchdog" >/dev/null 2>&1; then
        ok "Local agent running ($(pgrep -fc 'amoskys.watchdog') processes)"
    else
        fail "Local agent not running"
    fi
}

# ── Step 4: Deploy to servers ──────────────────────────────────────
deploy_ops() {
    echo -e "\n${CYAN}── STEP 4a: Deploy to ops server ($OPS_IP) ──${NC}"
    $SSH ubuntu@$OPS_IP "cd /opt/amoskys && git fetch origin main && git reset --hard origin/main >/dev/null && sudo systemctl restart amoskys-ops" 2>/dev/null
    sleep 2
    local status
    status=$($SSH ubuntu@$OPS_IP "systemctl is-active amoskys-ops" 2>/dev/null)
    if [ "$status" = "active" ]; then
        ok "Ops server: active"
    else
        fail "Ops server: $status"
    fi
}

deploy_web() {
    echo -e "\n${CYAN}── STEP 4b: Deploy to web server ($WEB_IP) ──${NC}"
    $SSH ubuntu@$WEB_IP "cd /opt/amoskys && git fetch origin main && git reset --hard origin/main >/dev/null && sudo systemctl restart amoskys-web" 2>/dev/null
    sleep 2
    local status
    status=$($SSH ubuntu@$WEB_IP "systemctl is-active amoskys-web" 2>/dev/null)
    if [ "$status" = "active" ]; then
        ok "Web server: active"
    else
        fail "Web server: $status"
    fi
}

# ── Step 5: Health check ──────────────────────────────────────────
health_check() {
    echo -e "\n${CYAN}── STEP 5: Health check ──${NC}"

    # Local agent
    if pgrep -f "amoskys.watchdog" >/dev/null 2>&1; then
        ok "Local agent: running"
    else
        fail "Local agent: NOT running"
    fi

    # Ops server
    local ops_status
    ops_status=$($SSH ubuntu@$OPS_IP "systemctl is-active amoskys-ops" 2>/dev/null || echo "unreachable")
    if [ "$ops_status" = "active" ]; then
        ok "Ops server: active"
    else
        fail "Ops server: $ops_status"
    fi

    # Web server
    local web_code
    web_code=$(curl -sk -o /dev/null -w "%{http_code}" https://amoskys.com/auth/login 2>/dev/null || echo "000")
    if [ "$web_code" = "200" ]; then
        ok "Dashboard: https://amoskys.com (200)"
    else
        fail "Dashboard: HTTP $web_code"
    fi

    # Data flow check
    local latest
    latest=$($SSH ubuntu@$OPS_IP "cd /opt/amoskys && /opt/amoskys/venv/bin/python3 -c \"
import sqlite3, time
db = sqlite3.connect('/var/lib/amoskys/fleet.db')
r = db.execute('SELECT COUNT(*) FROM security_events WHERE timestamp_ns > cast((strftime(\\\"%s\\\",\\\"now\\\") - 300) * 1e9 as integer)').fetchone()[0]
print(r)
\"" 2>/dev/null || echo "0")
    if [ "$latest" -gt 0 ] 2>/dev/null; then
        ok "Data flow: $latest events in last 5 min"
    else
        warn "Data flow: no events in last 5 min (agent may be starting)"
    fi

    # Git commit
    local commit
    commit=$(cd "$REPO" && git log --oneline -1 2>/dev/null)
    info "Deployed: $commit"
}

# ── Main ──────────────────────────────────────────────────────────
main() {
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         AMOSKYS Deploy Pipeline              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"

    local target="${1:-all}"

    case "$target" in
        all)
            push_to_github
            sync_main_repo
            deploy_local
            deploy_ops
            deploy_web
            health_check
            ;;
        local)
            sync_main_repo
            deploy_local
            ;;
        servers)
            push_to_github
            sync_main_repo
            deploy_ops
            deploy_web
            ;;
        status)
            health_check
            ;;
        *)
            echo "Usage: $0 [all|local|servers|status]"
            exit 1
            ;;
    esac

    echo -e "\n${GREEN}Done.${NC}"
}

main "$@"
