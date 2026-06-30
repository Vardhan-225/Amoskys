#!/bin/bash
# Check AMOSKYS deployment status and verify CI/CD pipeline

set -e

echo "🔍 AMOSKYS Deployment Status Check"
echo "===================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="amoskys.com"
EC2_IP="18.219.40.205"
DEPLOY_USER="ubuntu"

echo -e "${BLUE}[1/5]${NC} Checking domain DNS..."
if dig +short $DOMAIN | grep -q .; then
    DNS_IP=$(dig +short $DOMAIN | head -1)
    echo -e "  ${GREEN}✓${NC} DNS resolves to: $DNS_IP"
else
    echo -e "  ${RED}✗${NC} DNS not resolving"
fi
echo ""

echo -e "${BLUE}[2/5]${NC} Checking HTTPS accessibility..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" https://$DOMAIN 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "  ${GREEN}✓${NC} HTTPS accessible (HTTP $HTTP_CODE)"
else
    echo -e "  ${YELLOW}⚠${NC} HTTP status: $HTTP_CODE (may be redirecting or starting up)"
fi
echo ""

echo -e "${BLUE}[3/5]${NC} Checking for deployment marker..."
if curl -s https://$DOMAIN 2>/dev/null | grep -q "CI/CD Pipeline Active"; then
    echo -e "  ${GREEN}✓${NC} CI/CD deployment marker found!"
    echo -e "  ${GREEN}✓${NC} New version is LIVE on https://$DOMAIN"
else
    echo -e "  ${YELLOW}⚠${NC} Deployment marker not found (may still be deploying)"
    echo -e "  ${YELLOW}→${NC} Check GitHub Actions: https://github.com/Vardhan-225/Amoskys/actions"
fi
echo ""

echo -e "${BLUE}[4/5]${NC} Checking latest commit on server..."
echo -e "  ${YELLOW}→${NC} SSHing to EC2 to check git log..."
REMOTE_COMMIT=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
    ${DEPLOY_USER}@${EC2_IP} \
    "cd /opt/amoskys 2>/dev/null && git log -1 --oneline 2>/dev/null || echo 'not deployed'" 2>/dev/null || echo "ssh failed")

if [ "$REMOTE_COMMIT" != "ssh failed" ] && [ "$REMOTE_COMMIT" != "not deployed" ]; then
    echo -e "  ${GREEN}✓${NC} Latest commit on server:"
    echo -e "  ${GREEN}  $REMOTE_COMMIT${NC}"
else
    echo -e "  ${YELLOW}⚠${NC} Could not verify server commit (may need SSH key)"
fi
echo ""

echo -e "${BLUE}[5/5]${NC} GitHub Actions workflow status..."
echo -e "  ${BLUE}→${NC} Check workflow run at:"
echo -e "  ${BLUE}  https://github.com/Vardhan-225/Amoskys/actions${NC}"
echo ""

echo "===================================="
echo -e "${GREEN}Deployment Check Complete!${NC}"
echo ""
echo "Quick verification commands:"
echo ""
echo "  # View landing page in browser:"
echo "  open https://$DOMAIN"
echo ""
echo "  # Check HTML source for marker:"
echo "  curl -s https://$DOMAIN | grep 'CI/CD Pipeline Active'"
echo ""
echo "  # Force refresh in browser:"
echo "  Cmd+Shift+R (Mac) or Ctrl+F5 (Windows)"
echo ""
