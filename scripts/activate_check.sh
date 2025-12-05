#!/bin/bash
#
# Quick activation check script
# Source this or run it to check if venv is active
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${RED}✗ Virtual environment not activated!${NC}"
    echo -e "${YELLOW}  Activate with: source .venv/bin/activate${NC}"
    echo -e "${YELLOW}  Or run: make env && source .venv/bin/activate${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Virtual environment active: $VIRTUAL_ENV${NC}"
    exit 0
fi
