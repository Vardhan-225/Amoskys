#!/bin/bash
# AMOSKYS launchd wrapper — waits for external volume before launching
# Usage: launchd_wrapper.sh <working_dir> <python> <module_args...>
set -euo pipefail

WORKDIR="$1"
shift
PYTHON="$1"
shift

# Wait up to 120s for the volume to mount
TIMEOUT=120
ELAPSED=0
while [ ! -d "$WORKDIR" ]; do
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "ERROR: $WORKDIR not available after ${TIMEOUT}s" >&2
        exit 1
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

cd "$WORKDIR"
export PYTHONPATH="${WORKDIR}/src:${WORKDIR}"
exec "$PYTHON" "$@"
