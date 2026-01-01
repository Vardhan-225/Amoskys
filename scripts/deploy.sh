#!/bin/bash
# AMOSKYS Production Deployment Script
# Usage: ./scripts/deploy.sh [start|stop|restart|status]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="amoskys"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="$PROJECT_ROOT/.venv"
WEB_DIR="$PROJECT_ROOT/web"
PID_DIR="/var/run/amoskys"
LOG_DIR="/var/log/amoskys"

# Service configurations
GUNICORN_BIND="0.0.0.0:8000"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-4}"
EVENTBUS_PORT="${BUS_SERVER_PORT:-50051}"

# Ensure directories exist
mkdir -p "$PID_DIR" 2>/dev/null || true
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."

    if [ ! -d "$VENV_PATH" ]; then
        log_error "Virtual environment not found at $VENV_PATH"
        log_info "Run: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
        exit 1
    fi

    if [ ! -f "$PROJECT_ROOT/config/production.env" ] && [ ! -f "$PROJECT_ROOT/.env" ]; then
        log_warn "No production environment file found"
        log_info "Copy config/production.env.example to config/production.env and configure"
    fi

    log_info "✓ Requirements check passed"
}

start_eventbus() {
    log_info "Starting EventBus gRPC server..."

    cd "$PROJECT_ROOT"

    # Load environment if exists
    [ -f "config/production.env" ] && export $(cat config/production.env | grep -v '^#' | xargs)
    [ -f ".env" ] && export $(cat .env | grep -v '^#' | xargs)

    if [ -f "$PID_DIR/eventbus.pid" ] && kill -0 $(cat "$PID_DIR/eventbus.pid") 2>/dev/null; then
        log_warn "EventBus already running (PID: $(cat $PID_DIR/eventbus.pid))"
        return 0
    fi

    nohup "$VENV_PATH/bin/python" src/amoskys/eventbus/server.py \
        --overload off \
        > "$LOG_DIR/eventbus.log" 2>&1 &

    echo $! > "$PID_DIR/eventbus.pid"
    log_info "✓ EventBus started (PID: $!)"
}

start_web() {
    log_info "Starting Web application..."

    cd "$WEB_DIR"

    # Load environment
    [ -f "../config/production.env" ] && export $(cat ../config/production.env | grep -v '^#' | xargs)
    [ -f "../.env" ] && export $(cat ../.env | grep -v '^#' | xargs)

    if [ -f "$PID_DIR/gunicorn.pid" ] && kill -0 $(cat "$PID_DIR/gunicorn.pid") 2>/dev/null; then
        log_warn "Web application already running (PID: $(cat $PID_DIR/gunicorn.pid))"
        return 0
    fi

    "$VENV_PATH/bin/gunicorn" \
        --config gunicorn_config.py \
        --pid "$PID_DIR/gunicorn.pid" \
        --daemon \
        wsgi:app

    log_info "✓ Web application started"
}

start_agents() {
    log_info "Starting monitoring agents..."

    cd "$PROJECT_ROOT"

    # Start proc_agent
    if [ ! -f "$PID_DIR/proc_agent.pid" ] || ! kill -0 $(cat "$PID_DIR/proc_agent.pid") 2>/dev/null; then
        nohup "$VENV_PATH/bin/python" -m amoskys.agents.proc_agent > "$LOG_DIR/proc_agent.log" 2>&1 &
        echo $! > "$PID_DIR/proc_agent.pid"
        log_info "✓ proc_agent started (PID: $!)"
    fi

    # Start flowagent
    if [ ! -f "$PID_DIR/flowagent.pid" ] || ! kill -0 $(cat "$PID_DIR/flowagent.pid") 2>/dev/null; then
        nohup "$VENV_PATH/bin/python" -m amoskys.agents.flowagent > "$LOG_DIR/flowagent.log" 2>&1 &
        echo $! > "$PID_DIR/flowagent.pid"
        log_info "✓ flowagent started (PID: $!)"
    fi

    # Start auth_agent
    if [ ! -f "$PID_DIR/auth_agent.pid" ] || ! kill -0 $(cat "$PID_DIR/auth_agent.pid") 2>/dev/null; then
        nohup "$VENV_PATH/bin/python" src/amoskys/agents/auth/auth_agent.py > "$LOG_DIR/auth_agent.log" 2>&1 &
        echo $! > "$PID_DIR/auth_agent.pid"
        log_info "✓ auth_agent started (PID: $!)"
    fi

    # Start device_scanner
    if [ ! -f "$PID_DIR/device_scanner.pid" ] || ! kill -0 $(cat "$PID_DIR/device_scanner.pid") 2>/dev/null; then
        nohup "$VENV_PATH/bin/python" src/amoskys/agents/discovery/device_scanner.py > "$LOG_DIR/device_scanner.log" 2>&1 &
        echo $! > "$PID_DIR/device_scanner.pid"
        log_info "✓ device_scanner started (PID: $!)"
    fi
}

stop_service() {
    local service=$1
    local pidfile="$PID_DIR/${service}.pid"

    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping $service (PID: $pid)..."
            kill -TERM "$pid"

            # Wait up to 10 seconds for graceful shutdown
            for i in {1..10}; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    rm -f "$pidfile"
                    log_info "✓ $service stopped"
                    return 0
                fi
                sleep 1
            done

            # Force kill if still running
            log_warn "Force killing $service..."
            kill -9 "$pid" 2>/dev/null || true
            rm -f "$pidfile"
        else
            rm -f "$pidfile"
        fi
    fi
}

stop_all() {
    log_info "Stopping all AMOSKYS services..."

    stop_service "gunicorn"
    stop_service "eventbus"
    stop_service "proc_agent"
    stop_service "flowagent"
    stop_service "auth_agent"
    stop_service "device_scanner"

    log_info "✓ All services stopped"
}

show_status() {
    echo "════════════════════════════════════════════════════════════"
    echo "  AMOSKYS Production Status"
    echo "════════════════════════════════════════════════════════════"
    echo ""

    check_service_status() {
        local service=$1
        local pidfile="$PID_DIR/${service}.pid"

        if [ -f "$pidfile" ] && kill -0 $(cat "$pidfile") 2>/dev/null; then
            echo -e "  ${GREEN}●${NC} $service (PID: $(cat $pidfile))"
        else
            echo -e "  ${RED}●${NC} $service (not running)"
        fi
    }

    echo "Services:"
    check_service_status "gunicorn"
    check_service_status "eventbus"
    check_service_status "proc_agent"
    check_service_status "flowagent"
    check_service_status "auth_agent"
    check_service_status "device_scanner"

    echo ""
    echo "Ports:"
    echo "  Web:      :8000"
    echo "  EventBus: :50051"
    echo "  Metrics:  :9000, :9100"
    echo ""
    echo "════════════════════════════════════════════════════════════"
}

# Main command handling
case "${1:-help}" in
    start)
        check_requirements
        log_info "Starting AMOSKYS services..."
        start_eventbus
        sleep 2
        start_web
        sleep 2
        start_agents
        echo ""
        show_status
        ;;

    stop)
        stop_all
        ;;

    restart)
        stop_all
        sleep 2
        "$0" start
        ;;

    status)
        show_status
        ;;

    logs)
        service="${2:-gunicorn}"
        if [ -f "$LOG_DIR/${service}.log" ]; then
            tail -f "$LOG_DIR/${service}.log"
        else
            log_error "Log file not found: $LOG_DIR/${service}.log"
            exit 1
        fi
        ;;

    *)
        echo "AMOSKYS Deployment Script"
        echo ""
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all AMOSKYS services"
        echo "  stop     - Stop all AMOSKYS services"
        echo "  restart  - Restart all services"
        echo "  status   - Show service status"
        echo "  logs     - Tail service logs (default: gunicorn)"
        echo ""
        exit 1
        ;;
esac
