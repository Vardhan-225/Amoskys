#!/usr/bin/env bash
set -euo pipefail
X="${1:-10}"
while true; do
  echo "[chaos] overload ON"; BUS_OVERLOAD=1 python InfraSpectre/common/eventbus/server.py &
  PID=$!
  sleep "$X"
  echo "[chaos] kill bus"
  kill -TERM "$PID" || true
  sleep 2
  echo "[chaos] overload OFF"; python InfraSpectre/common/eventbus/server.py &
  PID=$!
  sleep "$X"
  echo "[chaos] kill bus"
  kill -TERM "$PID" || true
  sleep 2
done
