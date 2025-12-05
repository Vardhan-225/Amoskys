#!/usr/bin/env bash
set -euo pipefail
make proto
make certs
# terminal 1:
#   make run-bus
# terminal 2:
#   make run-agent
