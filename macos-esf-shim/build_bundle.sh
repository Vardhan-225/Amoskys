#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# AMOSKYS Sentinel — bundle + embed profile + sign + verify.
#
# Why a bundle at all: com.apple.developer.endpoint-security.client is a
# RESTRICTED entitlement. Under SIP, AMFI only honors it when an Apple-issued
# provisioning profile authorizes it — and a profile can ONLY be delivered at a
# bundle path (Contents/embedded.provisionprofile). A bare Mach-O has nowhere to
# put it, so the kernel SIGKILLs it at exec (the exit-137 we saw).
# Ref: Apple TN3125 + "Signing a Daemon with a Restricted Entitlement".
#
# This wraps our existing signed Mach-O in AmoskysSentinel.app, embeds the
# granted profile, and re-signs the bundle so the entitlement is authorized.
# SIP stays ON. No reboot. This is the exact artifact that ships to customers.
#
# Usage:
#   ./build_bundle.sh                 # auto-find the .provisionprofile, local test sign
#   ./build_bundle.sh path/to.profile # explicit profile
#   ./build_bundle.sh --dist [prof]   # add secure timestamp (for notarization)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

IDENTITY="Developer ID Application: Akash Thanneeru (4Z5335ZWBH)"
BUNDLE="AmoskysSentinel.app"
BIN="amoskys-sentinel"
ENTS="AmoskysAgent.entitlements"
DIST=0

args=()
for a in "$@"; do
  case "$a" in
    --dist) DIST=1 ;;
    *) args+=("$a") ;;
  esac
done

# ── 1. locate the provisioning profile ───────────────────────────────────────
PROFILE="${args[0]:-}"
if [[ -z "$PROFILE" ]]; then
  # search the signing vault and here for the newest .provisionprofile
  PROFILE="$(ls -t ../signing/*.provisionprofile ./*.provisionprofile 2>/dev/null | head -1 || true)"
fi
if [[ -z "$PROFILE" || ! -f "$PROFILE" ]]; then
  cat >&2 <<EOF
✖ No .provisionprofile found.

  Create one (needs your Apple Developer login — only you can do this):
    developer.apple.com → Certificates, IDs & Profiles → Profiles → ➕
      Profile type : Developer ID  (macOS, distribution)
      App ID       : com.amoskys.agent   (has Endpoint Security enabled)
      Certificate  : Developer ID Application: Akash Thanneeru (4Z5335ZWBH)
    → Generate → Download → drop the .provisionprofile into:
       $(cd ../signing && pwd)/
  Then re-run:  ./build_bundle.sh
EOF
  exit 2
fi
echo "▸ profile: $PROFILE"

# ── 2. sanity-check the profile actually authorizes the ES entitlement ────────
PROF_PLIST="$(security cms -D -i "$PROFILE" 2>/dev/null || true)"
if ! grep -q "com.apple.developer.endpoint-security.client" <<<"$PROF_PLIST"; then
  echo "✖ This profile does NOT whitelist com.apple.developer.endpoint-security.client." >&2
  echo "  Regenerate it against App ID com.amoskys.agent (the one with ESF enabled)." >&2
  exit 3
fi
PROF_TEAM="$(plutil -extract Entitlements.com\\.apple\\.developer\\.team-identifier raw -o - - <<<"$PROF_PLIST" 2>/dev/null || true)"
echo "  ✓ profile whitelists the ESF entitlement${PROF_TEAM:+ (team $PROF_TEAM)}"

# ── 2.5 (re)compile against the REAL SDK EndpointSecurity stub ────────────────
# Link the SDK's libEndpointSecurity.tbd so the binary embeds the correct runtime
# install-name /usr/lib/libEndpointSecurity.dylib. A hand-written framework-path
# stub links fine but dyld can't resolve it at load time (Library not loaded).
SDK="$(xcrun --show-sdk-path)"
swiftc -O main.swift -o "$BIN" -L"$SDK/usr/lib" -lEndpointSecurity
echo "▸ compiled $BIN ($(stat -f%z "$BIN") bytes), links $(otool -L "$BIN" | grep -o '/usr/lib/libEndpointSecurity.dylib')"

# ── 3. (re)assemble the bundle ────────────────────────────────────────────────
mkdir -p "$BUNDLE/Contents/MacOS"
cp -f "$BIN" "$BUNDLE/Contents/MacOS/$BIN"
cp -f "$PROFILE" "$BUNDLE/Contents/embedded.provisionprofile"   # .provisionprofile, NOT .mobileprovision
echo "▸ bundle assembled ($(find "$BUNDLE" -type f | wc -l | tr -d ' ') files)"

# ── 4. sign the bundle (seals Info.plist + embedded profile + Mach-O) ─────────
# Entitlements claimed here MUST be a subset of the profile allowlist.
TS=(); [[ $DIST -eq 1 ]] && TS=(--timestamp) || TS=(--timestamp=none)
codesign --force --options runtime "${TS[@]}" \
  --entitlements "$ENTS" \
  --sign "$IDENTITY" \
  "$BUNDLE"
echo "▸ signed (${DIST:+dist }$([[ $DIST -eq 1 ]] && echo 'with secure timestamp' || echo 'local, no timestamp'))"

# ── 5. verify ────────────────────────────────────────────────────────────────
echo "── verification ─────────────────────────────────────────────"
codesign --verify --strict --verbose=2 "$BUNDLE" 2>&1 | sed 's/^/  /'
echo "  entitlements embedded:"
codesign -d --entitlements :- "$BUNDLE" 2>/dev/null | grep -o 'endpoint-security[^<]*' | sed 's/^/    /'
echo "  team + authority:"
codesign -dv --verbose=2 "$BUNDLE" 2>&1 | grep -iE 'TeamIdentifier|Authority=Developer' | sed 's/^/    /'
echo "─────────────────────────────────────────────────────────────"
cat <<EOF
✓ Bundle ready: $BUNDLE

Next (you, once):
  1. Grant the Endpoint Security client. macOS surfaces ES clients under
     System Settings → Privacy & Security → Full Disk Access, so that is where
     the toggle lives — but add the .app BUNDLE, never the inner binary:
       $(pwd)/$BUNDLE
     Then verify:  bash scripts/esf_setup.sh --verify
     (CORRECTED 2026-08-22: this step used to say "grant FDA to the INNER
      binary". macOS resolves a signed bundle by its BUNDLE ID, so a path-form
      row for the inner binary is inert — and following that advice produced a
      grant that outlived the file it named. System Settings kept showing it
      ENABLED while it protected a deleted binary, so the Sentinel looked
      authorized for weeks while es_new_client() returned ERR_NOT_PERMITTED.
      Verified at the moment it finally attached: the entire TCC state was one
      kTCCServiceEndpointSecurityClient=allow row for com.amoskys.agent, with
      NO kTCCServiceSystemPolicyAllFiles row at all — FDA is not a second
      grant, the pane name just makes it look like one.)
  2. Run it as root:
       sudo "$(pwd)/$BUNDLE/Contents/MacOS/$BIN"
     Expect:  "amoskys-sentinel: guarding exec (mode=MONITOR, fail-open)."
     (that line = es_new_client SUCCEEDED — the Sentinel is live.)
EOF
