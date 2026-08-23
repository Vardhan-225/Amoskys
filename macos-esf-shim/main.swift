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
        // PRECEDENCE FIX. This previously read:
        //
        //   SUBPATHS.contains(...) || PREFIXES.hasPrefix(...) && path.contains("/Downloads/")
        //
        // and Swift binds && tighter than ||, so it evaluated as
        //   SUBPATHS.contains(...) || (PREFIXES.hasPrefix(...) && contains("/Downloads/"))
        // The second disjunct required "/Downloads/", which the FIRST disjunct
        // already matched — so RISKY_PREFIXES contributed nothing at all and
        // the whole rule collapsed to "/Downloads/ or /Library/Caches/".
        // The constant read like coverage while being dead code.
        let matchedSubpath = RISKY_SUBPATHS.first(where: { path.contains($0) })
        let matchedPrefix = RISKY_PREFIXES.first(where: { path.hasPrefix($0) })
        if let where_ = matchedSubpath ?? matchedPrefix {
            // Name WHICH form of untrust and WHERE, so a MONITOR run can be
            // tuned on evidence. "untrusted" lumps together three very
            // different populations: genuinely unsigned binaries (rare, and
            // interesting), ad-hoc signed ones (ubiquitous on a developer
            // machine — every local build and most homebrew bottles), and
            // signed-but-invalid ones (rare, and the most alarming). Emitting
            // one undifferentiated string made it impossible to tell a flood
            // of benign local builds from a real finding.
            let kind = !signed ? "unsigned" : (adhoc ? "adhoc-signed" : "signature-invalid")
            return (true, "\(kind) binary from \(where_)")
        }
    }
    return (false, "allow")
}


// ── Forensic event emission ───────────────────────────────────────────────────
// Every AUTH_EXEC is emitted as one NDJSON line on stdout. The Sentinel is the
// only sensor on this machine that observes a process BEFORE it runs, and the
// only one that can read cdhash and code-signing state as the kernel sees them
// at exec time. A polling sensor cannot reconstruct either after the fact — by
// the time it samples, a short-lived process is gone and a replaced binary
// reports its NEW signature. That is what this stream exists to capture.
//
// THREE HARD RULES, in priority order:
//
//  1. NEVER STALL THE KERNEL. Emission happens strictly AFTER
//     es_respond_auth_result(). Writes go to a dedicated queue with a bounded
//     buffer; if that buffer is full the event is dropped rather than blocking.
//     A blocked writer (a full pipe, a stopped `tee`, a wedged disk) must
//     never turn into a hung exec on this machine.
//
//  2. NEVER DROP SILENTLY. Dropping is acceptable; hiding it is not. Every
//     drop increments a counter that is emitted as its own record, so a gap in
//     the forensic timeline is always visible AS a gap. An analyst who cannot
//     tell "nothing happened" from "we stopped looking" has no timeline at
//     all — they have a guess.
//
//  3. IDENTITY IS THE CDHASH, NOT THE PATH. Paths are attacker-controlled and
//     get reused; the code directory hash is what actually identifies a
//     binary. It is emitted on every record so a binary can be tracked across
//     renames, moves, and reinstalls.
let emitQueue = DispatchQueue(label: "com.amoskys.sentinel.emit", qos: .utility)
let emitSem = DispatchSemaphore(value: EMIT_BUFFER_MAX)
let EMIT_BUFFER_MAX = 4096
let dropCounter = ManagedAtomicCounter()

final class ManagedAtomicCounter {
    private var value: UInt64 = 0
    private let lock = NSLock()
    func increment() -> UInt64 { lock.lock(); value += 1; let v = value; lock.unlock(); return v }
    func snapshotAndReset() -> UInt64 { lock.lock(); let v = value; value = 0; lock.unlock(); return v }
}

@inline(__always)
func jsonEscape(_ s: String) -> String {
    var out = ""
    out.reserveCapacity(s.count + 8)
    for ch in s.unicodeScalars {
        switch ch {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if ch.value < 0x20 { out += String(format: "\\u%04x", ch.value) }
            else { out.unicodeScalars.append(ch) }
        }
    }
    return out
}

func emit(_ line: String) {
    // Non-blocking admission. .now() means "give up immediately if full" —
    // this is the rule-1 guarantee, in one call.
    guard emitSem.wait(timeout: .now()) == .success else {
        _ = dropCounter.increment()
        return
    }
    emitQueue.async {
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
        emitSem.signal()
    }
}

func emitExec(path: String, argv: [String], pid: Int32, ppid: Int32,
              uid: UInt32, cdhash: String, csFlags: UInt32, isPlatform: Bool,
              signingID: String, teamID: String, decision: String,
              reason: String, tsNs: UInt64) {
    var argvJSON = "["
    for (i, a) in argv.enumerated() {
        if i > 0 { argvJSON += "," }
        argvJSON += "\"\(jsonEscape(a))\""
    }
    argvJSON += "]"
    let signed = (csFlags & CS_SIGNED) != 0
    let valid = (csFlags & CS_VALID) != 0
    let adhoc = (csFlags & CS_ADHOC) != 0
    let line = """
    {"v":1,"t":\(tsNs),"pid":\(pid),"ppid":\(ppid),"uid":\(uid),\
    "exe":"\(jsonEscape(path))","argv":\(argvJSON),"cdhash":"\(cdhash)",\
    "cs_flags":\(csFlags),"signed":\(signed),"valid":\(valid),"adhoc":\(adhoc),\
    "platform":\(isPlatform),"signing_id":"\(jsonEscape(signingID))",\
    "team_id":"\(jsonEscape(teamID))","decision":"\(decision)","reason":"\(jsonEscape(reason))"}
    """.replacingOccurrences(of: "\n", with: "")
    emit(line)
}

// Heartbeat: proves the stream is ALIVE even when nothing executes, and
// reports any drops. Without it, a silent stream and a dead Sentinel look
// identical to whatever is reading this.
func startHeartbeat() {
    let timer = DispatchSource.makeTimerSource(queue: emitQueue)
    timer.schedule(deadline: .now() + 30, repeating: 30)
    timer.setEventHandler {
        let dropped = dropCounter.snapshotAndReset()
        let ts = machToNanos(mach_absolute_time())
        emit("{\"v\":1,\"t\":\(ts),\"type\":\"heartbeat\",\"dropped\":\(dropped),\"enforce\":\(ENFORCE)}")
    }
    timer.resume()
    heartbeatTimer = timer
}
var heartbeatTimer: DispatchSourceTimer?


func argvOf(_ msg: UnsafePointer<es_message_t>) -> [String] {
    var out: [String] = []
    // es_exec_arg{,_count} take an inout es_event_exec_t, and msg.pointee is
    // get-only, so work from a local copy. The copy is a small struct of
    // pointers into the kernel-owned message; it stays valid for exactly as
    // long as the message does, which is why this runs on the callback thread.
    var exec = msg.pointee.event.exec
    let count = es_exec_arg_count(&exec)
    // Bounded: a pathological argv must not turn one exec into megabytes of
    // log. 64 args and 4KB total is far beyond anything legitimate while
    // staying enough to reconstruct a command line.
    var budget = 4096
    for i in 0..<min(count, 64) {
        let a = tok(es_exec_arg(&exec, i))
        if budget <= 0 { out.append("<truncated>"); break }
        budget -= a.utf8.count
        out.append(a)
    }
    if count > 64 { out.append("<+\(count - 64) more>") }
    return out
}

func signingIDOf(_ proc: UnsafePointer<es_process_t>) -> String {
    return tok(proc.pointee.signing_id)
}

func teamIDOf(_ proc: UnsafePointer<es_process_t>) -> String {
    return tok(proc.pointee.team_id)
}

func handle(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>) {
    let m = msg.pointee
    guard m.event_type == ES_EVENT_TYPE_AUTH_EXEC else {
        // Not ours — allow immediately, never hold the kernel.
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false)
        return
    }
    let target = m.event.exec.target // non-optional in the ESF C API
    let path = tok(target.pointee.executable.pointee.path)
    let csFlags = target.pointee.codesigning_flags
    let isPlatform = target.pointee.is_platform_binary
    let cdhash = cdhashHex(target)
    // Read every forensic field HERE, on the ES callback thread, while the
    // message is still valid. Reading them later on the decision queue is a
    // use-after-free waiting to happen.
    let argv = argvOf(msg)
    let signingID = signingIDOf(target)
    let teamID = teamIDOf(target)
    // audit_token_to_pid/_euid are MACROS in <bsm/libbsm.h>, not linkable
    // symbols, so Swift cannot call them. audit_token_t is a val[8] array that
    // imports as a tuple; the layout is fixed and documented:
    //   val.0 auid  val.1 euid  val.2 egid  val.3 ruid
    //   val.4 rgid  val.5 pid   val.6 asid  val.7 pidversion
    let atok = target.pointee.audit_token
    let epid = Int32(bitPattern: atok.val.5)
    let euid = atok.val.1
    let parentPid = target.pointee.ppid
    let eventTs = machToNanos(m.mach_time)

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

        // KERNEL FIRST. The auth response is the only latency-critical thing
        // in this function; everything below is bookkeeping and must not come
        // before it.
        es_respond_auth_result(client, msg, result, true /*cache identical decisions*/)

        if deny {
            FileHandle.standardError.write(Data(
                "\(ENFORCE ? "DENIED" : "WOULD-DENY") exec \(path) — \(why)\n".utf8))
        }
        // EVERY exec, not just denials. A forensic timeline built only from
        // things the policy disliked cannot answer the question that actually
        // matters after an incident — "what else ran?" — and a rule that has
        // not been written yet catches nothing retroactively. Recording the
        // allows is what makes reconstruction possible later.
        let decision = deny ? (ENFORCE ? "denied" : "would_deny") : "allow"
        emitExec(path: path, argv: argv, pid: epid, ppid: parentPid, uid: euid,
                 cdhash: cdhash, csFlags: csFlags, isPlatform: isPlatform,
                 signingID: signingID, teamID: teamID, decision: decision,
                 reason: why, tsNs: eventTs)
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
    guard es_subscribe(client, &events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
        FileHandle.standardError.write(Data("es_subscribe failed\n".utf8)); exit(1)
    }
    startHeartbeat()
    FileHandle.standardError.write(Data(
        "amoskys-sentinel: guarding exec (mode=\(ENFORCE ? "ENFORCE" : "MONITOR"), fail-open).\n".utf8))
    dispatchMain()
}

run()
