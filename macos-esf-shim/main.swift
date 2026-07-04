// AMOSKYS Sentinel — native ESF blocking daemon (Phase 1, front #4).
//
// Division of labor (per the research):
//   • WITNESS  = eslogger → amoskys-sensor → Brain   (observe; already live)
//   • BLOCKER  = THIS daemon                          (AUTH deny; stop mid-exec)
//
// It subscribes ONLY to ES_EVENT_TYPE_AUTH_EXEC and makes one decision per exec:
// deny a narrow, high-confidence set (unsigned/ad-hoc binaries launching from
// quarantine/Downloads, or a cdhash on the blocklist); ALLOW everything else.
// It FAILS OPEN — a slow/buggy/dead sentinel must never brick the machine
// (Santa's default; the CrowdStrike lesson). A deadline watchdog guarantees a
// response before the kernel SIGKILLs us.
//
// Requires: root + Full Disk Access + the (already-approved) entitlement
//   com.apple.developer.endpoint-security.client   on App ID com.amoskys.agent.
// Build/sign/run: see BUILD.md.  swiftc -parse verifies this compiles vs the SDK.

import EndpointSecurity
import Foundation

// ── Policy knobs ──────────────────────────────────────────────────────────────
// MONITOR (default): never deny, only log would-blocks — measure FP≈0 first.
// ENFORCE: actually deny the narrow high-confidence set.
let ENFORCE = ProcessInfo.processInfo.environment["AMOSKYS_ENFORCE"] == "1"

// cdhashes known-bad (hex, lowercase). Wire to threat-intel later.
let BLOCKED_CDHASHES: Set<String> = []

// Launch locations that are suspicious for an UNSIGNED binary.
let RISKY_PREFIXES = ["/Users/", "/private/tmp/", "/tmp/", "/Volumes/"]
let RISKY_SUBPATHS = ["/Downloads/", "/Library/Caches/"]

// CS_* (xnu cs_blobs.h)
let CS_VALID: UInt32 = 0x0000_0001
let CS_ADHOC: UInt32 = 0x0000_0002
let CS_PLATFORM_BINARY: UInt32 = 0x0400_0000
let CS_SIGNED: UInt32 = 0x2000_0000

let decisionQueue = DispatchQueue(label: "com.amoskys.sentinel.decision", qos: .userInitiated)

@inline(__always)
func tok(_ t: es_string_token_t) -> String {
    guard t.length > 0, let d = t.data else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: d, count: t.length), as: UTF8.self)
}

func cdhashHex(_ proc: UnsafePointer<es_process_t>) -> String {
    withUnsafeBytes(of: proc.pointee.cdhash) { raw in
        raw.map { String(format: "%02x", $0) }.joined()
    }
}

/// The block decision for one exec. Returns true to DENY.
func shouldDeny(path: String, csFlags: UInt32, isPlatform: Bool, cdhash: String) -> (deny: Bool, why: String) {
    if isPlatform || (csFlags & CS_PLATFORM_BINARY) != 0 { return (false, "platform") }
    if BLOCKED_CDHASHES.contains(cdhash) { return (true, "blocklisted cdhash") }

    let signed = (csFlags & CS_SIGNED) != 0
    let valid = (csFlags & CS_VALID) != 0
    let adhoc = (csFlags & CS_ADHOC) != 0
    let untrusted = !signed || adhoc || (signed && !valid)

    if untrusted {
        let risky =
            RISKY_SUBPATHS.contains(where: { path.contains($0) })
            || RISKY_PREFIXES.contains(where: { path.hasPrefix($0) }) && path.contains("/Downloads/")
        if risky { return (true, "unsigned binary from a download/temp location") }
    }
    return (false, "allow")
}

func handle(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>) {
    let m = msg.pointee
    guard m.event_type == ES_EVENT_TYPE_AUTH_EXEC, let target = m.event.exec.target else {
        // Not ours (or malformed) — allow immediately, never hold the kernel.
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let path = tok(target.pointee.executable.pointee.path)
    let csFlags = target.pointee.codesigning_flags
    let isPlatform = target.pointee.is_platform_binary
    let cdhash = cdhashHex(target)

    // Retain; decide async; guarantee a response before the deadline (fail-open).
    es_retain_message(msg)
    let deadlineNs = machToNanos(m.deadline)
    let nowNs = machToNanos(mach_absolute_time())
    let budget = deadlineNs > nowNs ? Int(min(deadlineNs - nowNs, 20_000_000)) : 0 // cap 20ms
    let watchdog = DispatchWorkItem {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false) // FAIL OPEN
        es_release_message(msg)
    }
    decisionQueue.asyncAfter(deadline: .now() + .nanoseconds(max(0, budget * 4 / 5)), execute: watchdog)

    decisionQueue.async {
        let (deny, why) = shouldDeny(path: path, csFlags: csFlags, isPlatform: isPlatform, cdhash: cdhash)
        if watchdog.isCancelled { return }
        watchdog.cancel()
        let result: es_auth_result_t = (deny && ENFORCE) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW
        if deny {
            FileHandle.standardError.write(Data(
                "\(ENFORCE ? "DENIED" : "WOULD-DENY") exec \(path) — \(why)\n".utf8))
        }
        es_respond_auth_result(client, msg, result, true /*cache identical decisions*/)
        es_release_message(msg)
    }
}

func machToNanos(_ mach: UInt64) -> UInt64 {
    var tb = mach_timebase_info_data_t()
    mach_timebase_info(&tb)
    return mach * UInt64(tb.numer) / UInt64(tb.denom)
}

func run() {
    var client: OpaquePointer?
    let res = es_new_client(&client) { c, msg in handle(c, msg) }
    guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
        let msg: String
        switch res {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: msg = "missing com.apple.developer.endpoint-security.client entitlement"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: msg = "must run as root"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: msg = "needs Full Disk Access (TCC)"
        default: msg = "es_new_client failed: \(res)"
        }
        FileHandle.standardError.write(Data("amoskys-sentinel: \(msg)\n".utf8))
        exit(1)
    }
    var events = [ES_EVENT_TYPE_AUTH_EXEC]
    guard es_subscribe(client, &events, events.count) == ES_RETURN_SUCCESS else {
        FileHandle.standardError.write(Data("es_subscribe failed\n".utf8)); exit(1)
    }
    FileHandle.standardError.write(Data(
        "amoskys-sentinel: guarding exec (mode=\(ENFORCE ? "ENFORCE" : "MONITOR"), fail-open).\n".utf8))
    dispatchMain()
}

run()
