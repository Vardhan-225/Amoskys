#!/bin/bash
# AMOSKYS Sentinel (Endpoint Security) setup + verification.
#
# Run:   bash scripts/esf_setup.sh          full guided setup
#        bash scripts/esf_setup.sh --verify report state only, no changes, no sudo
#
# WHY A SCRIPT AND NOT JUST COMMANDS: the Sentinel needs FOUR independent
# conditions to be true at once, and es_new_client() collapses all of them into
# a single ERR_NOT_PERMITTED. Checking them one at a time, by hand, after each
# failed launch, is how this stayed broken from 2026-07-06 to 2026-08-22. This
# checks all four up front and names the one that is actually wrong.
#
# This script NEVER writes to TCC.db (SIP forbids it — see the FDA note below),
# never deletes anything, and asks for sudo only where the OS genuinely
# requires it. You type your own password into sudo's prompt.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
APP="$PWD/macos-esf-shim/AmoskysSentinel.app"
BIN="$APP/Contents/MacOS/amoskys-sentinel"
BUNDLE_ID="com.amoskys.agent"
TCC_DB="/Library/Application Support/com.apple.TCC/TCC.db"
VERIFY_ONLY=0
[ "${1:-}" = "--verify" ] && VERIFY_ONLY=1

bold=$(tput bold 2>/dev/null || true); dim=$(tput dim 2>/dev/null || true)
red=$(tput setaf 1 2>/dev/null || true); grn=$(tput setaf 2 2>/dev/null || true)
ylw=$(tput setaf 3 2>/dev/null || true); rst=$(tput sgr0 2>/dev/null || true)
ok(){ echo "  ${grn}PASS${rst}  $*"; }
bad(){ echo "  ${red}FAIL${rst}  $*"; }
warn(){ echo "  ${ylw}WARN${rst}  $*"; }
hdr(){ echo; echo "${bold}$*${rst}"; }

# ── TCC inspection (read-only) ──────────────────────────────────────────────
# Reads the SYSTEM TCC.db directly rather than trusting System Settings' UI,
# because the UI is exactly what lied here: it renders a path-form grant whose
# target file has been deleted as an enabled checkbox.
tcc_rows() {
  python3 - "$TCC_DB" "$BIN" "$BUNDLE_ID" <<'PY' 2>/dev/null
import sqlite3, sys, os
db, binpath, bundle = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    rows = c.execute(
        "SELECT service, client, client_type, auth_value FROM access "
        "WHERE service IN ('kTCCServiceEndpointSecurityClient',"
        "'kTCCServiceSystemPolicyAllFiles')").fetchall()
except Exception:
    print("UNREADABLE"); raise SystemExit(0)
base = os.path.basename(binpath)
for svc, client, ctype, auth in rows:
    if bundle not in client and base not in client and "AmoskysSentinel" not in client:
        continue
    ghost = "GHOST" if (ctype == 1 and not os.path.exists(client)) else "LIVE"
    # ctype 0 = bundle identifier, 1 = absolute path. This binary is a SIGNED
    # BUNDLE (Identifier com.amoskys.agent), so macOS resolves it by bundle id
    # and the bundle row is authoritative; a path row for the same executable
    # is inert. Getting this backwards is what made the probe report an ESF
    # denial as an allow.
    if ctype == 0 and client == bundle:
        kind = "BUNDLE"
    elif ctype == 1 and client in (binpath, os.path.dirname(os.path.dirname(binpath))):
        kind = "PATH"
    else:
        kind = "OTHER"
    print("%s|%s|%s|%s|%s" % (svc.replace("kTCCService", ""), auth, ghost, kind, client))
PY
}

state_of() {  # $1 = service short name; echoes ALLOW / DENY / MISSING for the RUNTIME binary
  # Precedence is explicit, not incidental: a BUNDLE row always beats a PATH
  # row, because that is how macOS itself resolves a signed bundle. Relying on
  # row order would make the verdict depend on TCC.db insertion sequence.
  local svc="$1" bundle_state="" path_state=""
  while IFS='|' read -r s auth ghost kind client; do
    [ "$s" = "$svc" ] || continue
    [ "$ghost" = "GHOST" ] && continue
    local v="DENY"; [ "$auth" = "2" ] && v="ALLOW"
    case "$kind" in
      BUNDLE) bundle_state="$v" ;;
      PATH)   path_state="$v" ;;
    esac
  done <<< "$(tcc_rows)"
  if [ -n "$bundle_state" ]; then echo "$bundle_state"
  elif [ -n "$path_state" ]; then echo "$path_state"
  else echo "MISSING"; fi
}

# ── 1. Preflight ────────────────────────────────────────────────────────────
hdr "1. Preflight — the four conditions es_new_client() requires"

[ -x "$BIN" ] && ok "binary present    $BIN" || { bad "binary MISSING at $BIN"; exit 1; }

if codesign --verify --deep --strict "$APP" 2>/dev/null; then
  ok "signature valid   $(codesign -dv "$APP" 2>&1 | awk -F= '/^TeamIdentifier/{print "Team " $2}')"
else
  bad "signature INVALID — rebuild with macos-esf-shim/build_bundle.sh"; exit 1
fi

if codesign -d --entitlements - "$APP" 2>/dev/null | grep -q "endpoint-security.client"; then
  ok "entitlement       com.apple.developer.endpoint-security.client"
else
  bad "entitlement MISSING — ES clients cannot be created without it"; exit 1
fi

EXP=$(security cms -D -i "$APP/Contents/embedded.provisionprofile" 2>/dev/null \
      | plutil -extract ExpirationDate raw - 2>/dev/null)
[ -n "$EXP" ] && ok "profile valid to  $EXP" || warn "provisioning profile unreadable"

# ── 2. Grant state ──────────────────────────────────────────────────────────
hdr "2. TCC grant state (read from the system TCC.db, not the Settings UI)"

ROWS="$(tcc_rows)"
if [ "$ROWS" = "UNREADABLE" ]; then
  warn "TCC.db not readable from this shell — grant this terminal Full Disk Access"
  warn "to let the script self-verify, or continue and verify by launching."
  ROWS=""
fi

GHOSTS=0
while IFS='|' read -r s auth ghost exact client; do
  [ -z "${s:-}" ] && continue
  lbl="deny "; [ "$auth" = "2" ] && lbl="ALLOW"
  tag=""
  [ "$ghost" = "GHOST" ] && { tag="  ${red}<- GHOST: this file no longer exists${rst}"; GHOSTS=$((GHOSTS+1)); }
  if [ "$ghost" != "GHOST" ]; then
    case "$exact" in
      BUNDLE) tag="  ${grn}<- AUTHORITATIVE (macOS resolves this bundle by id)${rst}" ;;
      PATH)   tag="  ${dim}<- path row; inert for a signed bundle${rst}" ;;
    esac
  fi
  printf "  %-22s %s  %s%s\n" "$s" "$lbl" "$client" "$tag"
done <<< "$ROWS"

FDA=$(state_of SystemPolicyAllFiles)
ESF=$(state_of EndpointSecurityClient)
echo
echo "  ${bold}Full Disk Access for the running binary : $FDA${rst}"
echo "  ${bold}Endpoint Security for the running binary: $ESF${rst}"

if [ "$VERIFY_ONLY" = "1" ]; then
  echo
  [ "$FDA" = "ALLOW" ] && [ "$ESF" != "DENY" ] && echo "  ${grn}Grants look correct.${rst}" \
    || echo "  ${ylw}Grants incomplete — run without --verify for the guided fix.${rst}"
  exit 0
fi

# ── 3. Full Disk Access (GUI ONLY — this is not a limitation of this script) ─
if [ "$FDA" != "ALLOW" ]; then
  hdr "3. Grant Full Disk Access  ${dim}(GUI required)${rst}"
  cat <<EOF
  Full Disk Access CANNOT be granted from a shell. TCC.db is protected by SIP,
  so writes are rejected even as root — sudo does not help here. System
  Settings is the only path. This is macOS policy, not a missing feature.

  Opening the pane now. In it:
EOF
  if [ "$GHOSTS" -gt 0 ]; then
    echo "    a) REMOVE the existing 'amoskys-sentinel' entry (select it, click -)."
    echo "       It points at a deleted file, so it shows a checkmark while"
    echo "       protecting nothing. Leaving it there is what hid this."
  fi
  echo "    b) Click +, press Cmd+Shift+G, paste this path, and add it:"
  echo
  echo "         ${bold}$APP${rst}"
  echo
  echo "       Add the .app itself, NOT the binary inside it — macOS resolves a"
  echo "       signed bundle by its bundle id ($BUNDLE_ID)."
  echo
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null
  read -r -p "  Press Return when done (or Ctrl-C to stop)... " _
  FDA=$(state_of SystemPolicyAllFiles)
  [ "$FDA" = "ALLOW" ] && ok "Full Disk Access now granted to the running binary" \
                       || warn "still reads $FDA — if you just added it, macOS may need a moment"
else
  hdr "3. Full Disk Access"; ok "already granted"
fi

# ── 4. Clear the stale Endpoint Security denial ─────────────────────────────
hdr "4. Endpoint Security grant"
if [ "$ESF" = "DENY" ]; then
  echo "  A DENY row exists for $BUNDLE_ID. Resetting it lets macOS re-evaluate"
  echo "  instead of serving the cached refusal. This needs sudo — you will be"
  echo "  prompted by sudo itself; the password is not read by this script."
  echo
  sudo tccutil reset EndpointSecurityClient "$BUNDLE_ID" 2>&1 | sed 's/^/  /'
  ESF=$(state_of EndpointSecurityClient)
  [ "$ESF" = "DENY" ] && warn "still DENY — a profile or policy may be pinning it" \
                      || ok "denial cleared (now: $ESF)"
else
  ok "no blocking denial (state: $ESF)"
fi

# ── 5. Prove it ─────────────────────────────────────────────────────────────
hdr "5. Proof — launch in MONITOR mode and read the kernel's answer"
cat <<EOF
  The only authoritative test is es_new_client() itself. Running the Sentinel
  in the FOREGROUND for 15s, in MONITOR mode — it logs WOULD-DENY and denies
  nothing. Mode is controlled solely by the AMOSKYS_ENFORCE env var (see
  main.swift:24); it is pinned to 0 below rather than left to sudo's env
  handling, so this run cannot block a process on your machine.

  NOT installing a LaunchDaemon. Persistence is deliberately a separate step:
  unbounded telemetry from this agent filled the SSD to 99% and panicked the
  kernel six times in 2026-08. Retention is fixed now, but persistence should
  follow a false-positive measurement, not precede it.

EOF
read -r -p "  Press Return to run it (sudo required — it must be root)... " _
LOG=$(mktemp)
# No CLI flags: this binary parses none (main.swift has no argument handling).
# MONITOR is the default and AMOSKYS_ENFORCE=0 pins it.
sudo AMOSKYS_ENFORCE=0 "$BIN" >"$LOG" 2>&1 &
SPID=$!
sleep 15
sudo kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null
echo
if grep -qiE "guarding exec|es_subscribe ok|monitoring" "$LOG"; then
  ok "SENTINEL IS LIVE AT THE KERNEL"
  grep -iE "guarding|subscribe|monitoring" "$LOG" | head -3 | sed 's/^/       /'
elif grep -q "needs Full Disk Access" "$LOG"; then
  bad "still ERR_NOT_PERMITTED — Full Disk Access did not take"
  echo "       Re-open the pane and confirm '$(basename "$APP")' is listed AND checked."
elif grep -q "must run as root" "$LOG"; then
  bad "not root — rerun with sudo"
elif grep -q "entitlement" "$LOG"; then
  bad "entitlement rejected — the signature may not match the profile"
else
  warn "inconclusive; raw output:"; sed 's/^/       /' "$LOG" | head -10
fi
rm -f "$LOG"

hdr "Summary"
echo "  Full Disk Access : $(state_of SystemPolicyAllFiles)"
echo "  Endpoint Security: $(state_of EndpointSecurityClient)"
echo "  Re-check anytime : bash scripts/esf_setup.sh --verify"
