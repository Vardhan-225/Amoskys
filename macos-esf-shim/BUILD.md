# AMOSKYS ESF sensor — build & sign (Phase 1)

State (verified 2026-07-01):
- ✅ **ESF entitlement APPROVED** — App ID `com.amoskys.agent`, Team `4Z5335ZWBH`,
  "Endpoint Security" capability enabled. The multi-week Apple approval is DONE.
- ✅ **Developer ID Installer** cert present (signs the `.pkg`).
- ❌ **No Developer ID *Application*** cert (signs the `.app`/`.systemextension` binary).
- ❌ **No provisioning profile** for `com.amoskys.agent` with the ESF entitlement.
- ⚠️ **Command-Line-Tools only** (no full Xcode). Full Xcode (~40 GB) exceeds the
  ~9 GB free, so the *System Extension bundle* path is blocked on THIS machine
  until disk + Xcode. A **command-line ESF daemon** (below) needs neither.

There are two ways to ship a native ESF client. Pick by constraints:

| | System Extension (Phase 1b) | Command-line root daemon (Phase 1a) |
|---|---|---|
| Needs full Xcode | **yes** | no (swiftc + codesign) |
| SIP tamper-protection, early-boot | yes | no |
| Distribution / MDM pre-approval | yes | manual |
| Buildable on this machine today | no (Xcode/disk) | **yes, once cert+profile exist** |

Recommended now: **Phase 1a** (daemon) to get real native ESF + the AUTH/blocking
path working; move to **Phase 1b** (sysext) for hardening/distribution once Xcode
+ disk are available.

---

## Step 1 — Create a Developer ID Application certificate (self-service, ~3 min)

The private key should live in your keychain, so use Apple's CSR flow:

1. **Keychain Access → Certificate Assistant → Request a Certificate From a
   Certificate Authority…**
   - User Email: `iamakash225@gmail.com`
   - Common Name: `Akash Thanneeru`
   - **Saved to disk** (not "emailed"); check *Let me specify key pair information*
     → 2048-bit RSA. Save `CertificateSigningRequest.certSigningRequest`.
2. developer.apple.com → **Certificates → ➕ → Developer ID → Developer ID
   Application** → upload the CSR → **Download** the `.cer`.
3. Double-click the `.cer` to install it into the login keychain. Verify:
   ```sh
   security find-identity -v -p codesigning
   # should now list: "Developer ID Application: Akash Thanneeru (4Z5335ZWBH)"
   ```

## Step 2 — Create the provisioning profile carrying the ESF entitlement

developer.apple.com → **Profiles → ➕**:
- Type: **Developer ID** → *(for a System Extension choose the System-Extension
  variant; for a bare daemon a Developer ID profile bound to the App ID works)*.
- App ID: **com.amoskys.agent** (the one with Endpoint Security enabled).
- Certificate: the Developer ID Application cert from Step 1.
- **Download** `AMOSKYS.provisionprofile` into `macos-esf-shim/`.

## Step 3 — Build (Phase 1a, command-line daemon — no Xcode)

```sh
cd macos-esf-shim
swiftc -O -framework EndpointSecurity main.swift -o amoskys-esf
# embed the profile + entitlements and sign with the Developer ID Application cert:
cp AMOSKYS.provisionprofile amoskys-esf.provisionprofile   # embedded at sign time for bundles;
                                                            # for a bare Mach-O see note below
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: Akash Thanneeru (4Z5335ZWBH)" \
  --entitlements AmoskysAgent.entitlements \
  amoskys-esf
codesign -d --entitlements - amoskys-esf   # verify the ESF entitlement is present
```

> Note: a restricted entitlement on a **bare Mach-O** needs the provisioning
> profile embedded in a `__TEXT,__info_plist`/profile section — this is the one
> fiddly part of the daemon path. If it fights you, the clean route is the
> app-bundle/System-Extension packaging (Phase 1b, needs Xcode). For **local dev**
> you can instead sign with an **Apple Development** identity and
> `systemextensionsctl developer on` (SIP stays on) — the sysext subsystem skips
> notarization for Apple-Development-signed builds.

## Step 4 — Run (root + Full Disk Access)

```sh
sudo ./amoskys-esf            # es_new_client requires root + the entitlement + FDA
# grant Full Disk Access: System Settings → Privacy & Security → Full Disk Access
```
`es_new_client` returns `ERR_NOT_ENTITLED` / `ERR_NOT_PRIVILEGED` / `ERR_NOT_PERMITTED`
if any of {entitlement, root, Full Disk Access} is missing.

## Step 5 — Notarize (for distribution only)

```sh
xcrun notarytool store-credentials amoskys \
  --apple-id iamakash225@gmail.com --team-id 4Z5335ZWBH   # app-specific password
xcrun notarytool submit AMOSKYS.pkg --keychain-profile amoskys --wait
xcrun stapler staple AMOSKYS.pkg
```

---

### What runs TODAY with none of the above
Phase 0 — `sudo eslogger exec | ../sensor/target/release/amoskys-sensor` — uses
Apple's own entitled `eslogger`, so it needs no cert, no profile, no Xcode. It is
a legitimate production source for the *observe* path (exec/fork/file NOTIFY with
full code-signing identity). Native ESF (this doc) adds the *block* (AUTH) path
and tamper-resistance.
