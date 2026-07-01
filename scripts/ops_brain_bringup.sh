#!/usr/bin/env bash
#
# ops_brain_bringup.sh — prepare the AMOSKYS "brain" (analyzer daemon) on the
# low-memory ops box (~1.9 GB RAM, ~900 MB free, NO swap).
#
# This is a RUNBOOK you run MANUALLY on the box (as ubuntu, via sudo). It is
# safe to read and safe to re-run: every step is IDEMPOTENT — it checks for the
# desired end state before acting, so a second run is a no-op.
#
# It deliberately does NOT start the service. The final `systemctl enable --now`
# is left to a human so a human decides the moment the brain goes live.
#
#   Usage:   sudo bash /opt/amoskys/scripts/ops_brain_bringup.sh
#
# Why these steps (memory math):
#   * 2G swapfile  — the box has no swap; without it a transient allocation
#                    spike OOM-kills a random process (often the web UI). Swap
#                    is a safety net, not the working set — the analyzer's hot
#                    path stays in RAM under the 384M cgroup cap.
#   * numpy only   — numpy is needed by scoring/vector math; sklearn is heavy
#                    (~120 MB+ RSS) and is GUARDED by scoring/SOMA (they degrade
#                    gracefully when it is missing). Installing numpy-only keeps
#                    the resident set well under the 320M soft / 384M hard cap.
#   * 384M cap     — see amoskys-analyzer.service. Fits comfortably in ~900 MB
#                    free alongside ops + web + mcp, with swap as the cushion.
#
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
APP_DIR="/opt/amoskys"
VENV_PY="${APP_DIR}/venv/bin/python3"
VENV_PIP="${APP_DIR}/venv/bin/pip"
DATA_DIR="/var/lib/amoskys"
SWAPFILE="/swapfile"
SWAP_SIZE="2G"
SERVICE_NAME="amoskys-analyzer.service"
# Source unit ships in the repo; adjust if you cloned elsewhere.
UNIT_SRC="${APP_DIR}/deploy/systemd/${SERVICE_NAME}"
UNIT_DST="/etc/systemd/system/${SERVICE_NAME}"
SERVICE_USER="ubuntu"

log()  { printf '\033[1;32m[bringup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bringup]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bringup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash $0)"

# ── 1. Swap: add a 2G swapfile ONLY if the box has no swap at all ─────────────
# Idempotent: if any swap is already active we leave it untouched.
if [ "$(swapon --show --noheadings | wc -l)" -gt 0 ]; then
    log "swap already present — skipping swapfile creation:"
    swapon --show
else
    log "no swap detected — creating ${SWAP_SIZE} swapfile at ${SWAPFILE}"
    if [ ! -f "${SWAPFILE}" ]; then
        # fallocate is instant; fall back to dd if the fs (e.g. some overlay/xfs
        # configs) rejects fallocate for swap.
        if ! fallocate -l "${SWAP_SIZE}" "${SWAPFILE}" 2>/dev/null; then
            warn "fallocate failed — falling back to dd (slower)"
            dd if=/dev/zero of="${SWAPFILE}" bs=1M count=2048 status=progress
        fi
    else
        log "${SWAPFILE} already exists — reusing it"
    fi
    chmod 600 "${SWAPFILE}"
    # mkswap is safe to re-run on an already-formatted file.
    mkswap "${SWAPFILE}" >/dev/null
    swapon "${SWAPFILE}"
    log "swap enabled:"
    swapon --show
fi

# Persist across reboots — only add the fstab line if it is not already there.
if ! grep -qE "^\s*${SWAPFILE}\s+none\s+swap" /etc/fstab; then
    log "adding swapfile to /etc/fstab"
    printf '%s none swap sw 0 0\n' "${SWAPFILE}" >> /etc/fstab
else
    log "swapfile already in /etc/fstab — skipping"
fi

# ── 2. numpy into the venv (numpy ONLY — deliberately NOT sklearn) ────────────
# Idempotent: pip install is a no-op if numpy is already satisfied.
[ -x "${VENV_PY}" ] || die "venv python not found at ${VENV_PY}"
if "${VENV_PY}" -c 'import numpy' 2>/dev/null; then
    log "numpy already installed in venv: $("${VENV_PY}" -c 'import numpy; print(numpy.__version__)')"
else
    log "installing numpy into ${APP_DIR}/venv (numpy only — sklearn stays out)"
    # --no-cache-dir keeps peak disk/RAM low on the constrained box.
    "${VENV_PIP}" install --no-cache-dir numpy
    log "numpy installed: $("${VENV_PY}" -c 'import numpy; print(numpy.__version__)')"
fi

# ── 3. Data directories under /var/lib/amoskys, owned by ubuntu ───────────────
# Idempotent: mkdir -p + chown are safe to repeat.
log "ensuring data directories exist and are owned by ${SERVICE_USER}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
    "${DATA_DIR}" \
    "${DATA_DIR}/intel" \
    "${DATA_DIR}/igris"
log "data directories ready:"
ls -ld "${DATA_DIR}" "${DATA_DIR}/intel" "${DATA_DIR}/igris"

# ── 4. Install the systemd unit + daemon-reload ───────────────────────────────
# Idempotent: cmp avoids a needless copy/reload when the unit is unchanged.
[ -f "${UNIT_SRC}" ] || die "unit file not found at ${UNIT_SRC}"
if [ -f "${UNIT_DST}" ] && cmp -s "${UNIT_SRC}" "${UNIT_DST}"; then
    log "systemd unit already up to date at ${UNIT_DST}"
else
    log "installing systemd unit → ${UNIT_DST}"
    install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"
    systemctl daemon-reload
    log "systemd daemon reloaded"
fi

# ── 5. Done — hand the trigger to a human ─────────────────────────────────────
# We intentionally DO NOT enable/start the service here.
cat <<EOF

────────────────────────────────────────────────────────────────────────────
  Bring-up complete. The brain is staged but NOT running.

  Before you enable it, sanity-check that the threat-intel DB is populated
  (an empty DB makes every threat_intel_match False — the daemon logs a LOUD
  WARNING on startup, but better to load it first):

      AMOSKYS_THREAT_INTEL_DB=${DATA_DIR}/threat_intel.db \\
        ${VENV_PY} ${APP_DIR}/scripts/update_threat_intel.py

  Then start the brain (human decision):

      sudo systemctl enable --now ${SERVICE_NAME}

  Watch it come up:

      journalctl -u ${SERVICE_NAME} -f
      systemctl status ${SERVICE_NAME}
      # confirm the memory cap is being accounted:
      systemctl show ${SERVICE_NAME} -p MemoryCurrent -p MemoryMax -p MemoryHigh
────────────────────────────────────────────────────────────────────────────
EOF

# ══════════════════════════════════════════════════════════════════════════════
# TEARDOWN (manual — copy/paste; NOT executed by this script)
# ══════════════════════════════════════════════════════════════════════════════
# To fully reverse this runbook:
#
#   # 1. Stop + disable the brain and remove the unit.
#   sudo systemctl disable --now amoskys-analyzer.service
#   sudo rm -f /etc/systemd/system/amoskys-analyzer.service
#   sudo systemctl daemon-reload
#
#   # 2. Turn off and remove the swapfile.
#   sudo swapoff /swapfile
#   sudo sed -i '\#^/swapfile none swap#d' /etc/fstab
#   sudo rm -f /swapfile
#
#   # 3. (Optional) uninstall numpy — usually left in place, it is harmless.
#   #    /opt/amoskys/venv/bin/pip uninstall -y numpy
#
#   # 4. (Optional) data dirs are left in place on purpose (they hold the DBs).
#   #    Only remove them if you intend to wipe the brain's state:
#   #    sudo rm -rf /var/lib/amoskys/intel /var/lib/amoskys/igris
# ══════════════════════════════════════════════════════════════════════════════
