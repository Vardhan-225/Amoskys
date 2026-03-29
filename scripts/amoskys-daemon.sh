#!/bin/bash
# AMOSKYS Daemon — production-ready launcher
# Usage: amoskys-daemon.sh {start|stop|restart|status|web-only|collect-once}

PROJECT_DIR="/Volumes/Akash_Lab/Amoskys"
VENV="$PROJECT_DIR/.venv/bin/python3"
WEB_PID_FILE="/tmp/amoskys_web.pid"
COLLECT_PID_FILE="/tmp/amoskys_collect.pid"
COLLECT_INTERVAL=60

# Persistent secret key — survives restarts, sessions stay valid
SECRET_KEY_FILE="$PROJECT_DIR/data/.secret_key"
if [ ! -f "$SECRET_KEY_FILE" ]; then
    python3 -c 'import secrets; print(secrets.token_hex(32))' > "$SECRET_KEY_FILE"
    chmod 600 "$SECRET_KEY_FILE"
fi

export PYTHONPATH="$PROJECT_DIR/src"
export SECRET_KEY="$(cat "$SECRET_KEY_FILE")"
export FLASK_PORT=5002
export LOGIN_DISABLED=true
export FORCE_HTTPS=false

cd "$PROJECT_DIR"

start_web() {
    if [ -f "$WEB_PID_FILE" ] && kill -0 "$(cat "$WEB_PID_FILE")" 2>/dev/null; then
        echo "  Web server already running (PID $(cat "$WEB_PID_FILE"))"
        return 0
    fi
    $VENV -m web.app > /tmp/amoskys_web.log 2>&1 &
    echo $! > "$WEB_PID_FILE"
    for i in $(seq 1 30); do
        if grep -q "Serving Flask" /tmp/amoskys_web.log 2>/dev/null; then
            echo "  Web server started (PID $!)"
            return 0
        fi
        sleep 1
    done
    echo "  Web server failed — check /tmp/amoskys_web.log"
    return 1
}

start_collector() {
    if [ -f "$COLLECT_PID_FILE" ] && kill -0 "$(cat "$COLLECT_PID_FILE")" 2>/dev/null; then
        echo "  Collector already running (PID $(cat "$COLLECT_PID_FILE"))"
        return 0
    fi
    nohup bash -c "
        while true; do
            \"$VENV\" \"$PROJECT_DIR/scripts/collect_and_store.py\" >> /tmp/amoskys_collect.log 2>&1
            sleep $COLLECT_INTERVAL
        done
    " > /dev/null 2>&1 &
    echo $! > "$COLLECT_PID_FILE"
    echo "  Collector started (PID $!, every ${COLLECT_INTERVAL}s)"
}

stop_all() {
    if [ -f "$WEB_PID_FILE" ]; then
        kill "$(cat "$WEB_PID_FILE")" 2>/dev/null
        rm -f "$WEB_PID_FILE"
        echo "  Web server stopped"
    fi
    if [ -f "$COLLECT_PID_FILE" ]; then
        kill "$(cat "$COLLECT_PID_FILE")" 2>/dev/null
        rm -f "$COLLECT_PID_FILE"
    fi
    pkill -f "collect_and_store" 2>/dev/null
    echo "  Collector stopped"
}

status() {
    echo "═══ AMOSKYS Status ═══"
    if [ -f "$WEB_PID_FILE" ] && kill -0 "$(cat "$WEB_PID_FILE")" 2>/dev/null; then
        echo "  Web:       RUNNING (PID $(cat "$WEB_PID_FILE")) → http://127.0.0.1:5002/dashboard/"
    else
        echo "  Web:       STOPPED"
    fi
    if [ -f "$COLLECT_PID_FILE" ] && kill -0 "$(cat "$COLLECT_PID_FILE")" 2>/dev/null; then
        echo "  Collector: RUNNING (PID $(cat "$COLLECT_PID_FILE"), every ${COLLECT_INTERVAL}s)"
    else
        echo "  Collector: STOPPED"
    fi
    if grep -q "IGRIS cycle" /tmp/amoskys_web.log 2>/dev/null; then
        LAST_CYCLE=$(grep "IGRIS cycle" /tmp/amoskys_web.log | tail -1 | grep -o 'cycle #[0-9]*')
        echo "  IGRIS:     ACTIVE ($LAST_CYCLE)"
    else
        echo "  IGRIS:     INACTIVE"
    fi
    if [ -f /tmp/amoskys_collect.log ]; then
        LAST=$(grep "STEP 3" /tmp/amoskys_collect.log 2>/dev/null | tail -1 | cut -d' ' -f1-2)
        [ -n "$LAST" ] && echo "  Last scan: $LAST"
    fi
}

case "${1:-status}" in
    start)
        echo "Starting AMOSKYS..."
        start_web && start_collector
        echo ""
        status
        ;;
    stop)
        echo "Stopping AMOSKYS..."
        stop_all
        ;;
    restart)
        echo "Restarting AMOSKYS..."
        stop_all
        sleep 2
        start_web && start_collector
        echo ""
        status
        ;;
    status)
        status
        ;;
    web-only)
        start_web
        ;;
    collect-once)
        echo "Running single collection..."
        $VENV scripts/collect_and_store.py 2>&1 | grep -E "STEP|collected|INCIDENT|Evaluated" | tail -10
        ;;
    *)
        echo "AMOSKYS Daemon"
        echo "Usage: $0 {start|stop|restart|status|web-only|collect-once}"
        ;;
esac
