#!/bin/bash
#
# AMOSKYS Environment Validation Script
# Comprehensive environment checking
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AMOSKYS Environment Validation Utility   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

# Check if virtual environment is activated
check_venv() {
    echo -e "${YELLOW}[1] Virtual Environment${NC}"

    if [ -z "$VIRTUAL_ENV" ]; then
        echo -e "  ${RED}✗ Virtual environment not activated${NC}"
        echo -e "  ${YELLOW}  Run: source .venv/bin/activate${NC}"
        ERRORS=$((ERRORS + 1))
        return 1
    else
        echo -e "  ${GREEN}✓ Active: $VIRTUAL_ENV${NC}"
        return 0
    fi
}

# Check Python version
check_python() {
    echo -e "${YELLOW}[2] Python Version${NC}"

    PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
    MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 9 ]; then
        echo -e "  ${GREEN}✓ Python $PYTHON_VERSION${NC}"
    else
        echo -e "  ${RED}✗ Python 3.9+ required, found $PYTHON_VERSION${NC}"
        ERRORS=$((ERRORS + 1))
    fi
}

# Check critical packages
check_packages() {
    echo -e "${YELLOW}[3] Critical Packages${NC}"

    PACKAGES=("flask" "psutil" "flask_socketio" "protobuf" "grpc")

    for pkg in "${PACKAGES[@]}"; do
        if python -c "import $pkg" 2>/dev/null; then
            VERSION=$(python -c "import $pkg; print($pkg.__version__)" 2>/dev/null || echo "unknown")
            echo -e "  ${GREEN}✓${NC} $pkg ($VERSION)"
        else
            echo -e "  ${RED}✗ $pkg missing${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    done
}

# Check file structure
check_structure() {
    echo -e "${YELLOW}[4] Project Structure${NC}"

    REQUIRED_FILES=(
        "web/wsgi.py"
        "web/app/__init__.py"
        "src/amoskys/__init__.py"
        "requirements.txt"
        "Makefile"
    )

    for file in "${REQUIRED_FILES[@]}"; do
        if [ -f "$file" ]; then
            echo -e "  ${GREEN}✓${NC} $file"
        else
            echo -e "  ${RED}✗ $file missing${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    done

    REQUIRED_DIRS=(
        "logs"
        "data"
        "web/app/templates"
        "web/app/api"
    )

    for dir in "${REQUIRED_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            echo -e "  ${GREEN}✓${NC} $dir/"
        else
            echo -e "  ${YELLOW}⚠${NC} $dir/ missing (will be created)"
            mkdir -p "$dir"
            WARNINGS=$((WARNINGS + 1))
        fi
    done
}

# Check environment variables
check_env_vars() {
    echo -e "${YELLOW}[5] Environment Variables${NC}"

    if [ -n "$FLASK_APP" ]; then
        echo -e "  ${GREEN}✓${NC} FLASK_APP=$FLASK_APP"
    else
        echo -e "  ${YELLOW}⚠${NC} FLASK_APP not set (will use default)"
        WARNINGS=$((WARNINGS + 1))
    fi

    if [ -n "$PYTHONPATH" ]; then
        echo -e "  ${GREEN}✓${NC} PYTHONPATH=$PYTHONPATH"
    else
        echo -e "  ${YELLOW}⚠${NC} PYTHONPATH not set"
        WARNINGS=$((WARNINGS + 1))
    fi
}

# Check database
check_database() {
    echo -e "${YELLOW}[6] Database${NC}"

    if [ -f "data/wal/flowagent.db" ]; then
        SIZE=$(du -h data/wal/flowagent.db | cut -f1)
        ROWS=$(sqlite3 data/wal/flowagent.db "SELECT COUNT(*) FROM wal;" 2>/dev/null || echo "0")
        echo -e "  ${GREEN}✓${NC} flowagent.db ($SIZE, $ROWS rows)"
    else
        echo -e "  ${YELLOW}⚠${NC} flowagent.db not found (will be created on first run)"
        mkdir -p data/wal
        WARNINGS=$((WARNINGS + 1))
    fi
}

# Check ports
check_ports() {
    echo -e "${YELLOW}[7] Port Availability${NC}"

    if lsof -i :5000 >/dev/null 2>&1; then
        PID=$(lsof -ti :5000)
        echo -e "  ${YELLOW}⚠${NC} Port 5000 in use (PID: $PID)"
        WARNINGS=$((WARNINGS + 1))
    else
        echo -e "  ${GREEN}✓${NC} Port 5000 available"
    fi
}

# Main execution
main() {
    check_venv || true
    check_python
    check_packages
    check_structure
    check_env_vars
    check_database
    check_ports

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║            Validation Summary              ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo ""

    if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}✓ All checks passed!${NC}"
        echo ""
        echo -e "${YELLOW}Ready to run:${NC}"
        echo -e "  make run"
        exit 0
    elif [ $ERRORS -eq 0 ]; then
        echo -e "${YELLOW}⚠ $WARNINGS warnings${NC}"
        echo ""
        echo -e "${YELLOW}You can proceed, but consider fixing warnings${NC}"
        exit 0
    else
        echo -e "${RED}✗ $ERRORS errors, $WARNINGS warnings${NC}"
        echo ""
        echo -e "${YELLOW}Fix errors before proceeding:${NC}"

        if [ -z "$VIRTUAL_ENV" ]; then
            echo -e "  ${BLUE}source .venv/bin/activate${NC}"
        fi

        if [ $ERRORS -gt 1 ]; then
            echo -e "  ${BLUE}make env${NC}"
        fi

        exit 1
    fi
}

main
