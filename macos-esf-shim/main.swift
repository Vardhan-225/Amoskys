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
// ORDER IS LOAD-BEARING. In main.swift — and ONLY in main.swift — top-level
// globals are initialised SEQUENTIALLY as statements, not lazily on first use
// as they are in every other Swift file. EMIT_BUFFER_MAX was declared AFTER
// the semaphore that consumes it, so it read as 0, the semaphore was created
// with zero permits, and wait(timeout: .now()) failed for every event. The
// Sentinel attached to the kernel, decided correctly, and emitted absolutely
// nothing.
let EMIT_BUFFER_MAX = 4096
// Reported in sentinel_start so a reader can tell which subscription set is
// live without correlating against a build.
var SUBSCRIBED_COUNT = 0
let emitQueue = DispatchQueue(label: "com.amoskys.sentinel.emit", qos: .utility)
let emitSem = DispatchSemaphore(value: EMIT_BUFFER_MAX)
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

/// Write bypassing the admission gate.
///
/// Reserved for STREAM-HEALTH records. The first version of this file routed
/// heartbeats through emit(), which meant the drop counter travelled through
/// the very buffer whose exhaustion it existed to report: when the semaphore
/// was starved, every event was dropped AND so was every notice that events
/// were being dropped. The whole "never drop silently" guarantee evaporated
/// precisely when it was needed.
///
/// A health signal must never depend on the mechanism it reports on. This
/// path can block, which is acceptable ONLY because it is called from the
/// heartbeat timer and at startup — never from the ES callback, and never
/// from the exec decision path.
func emitDirect(_ line: String) {
    emitQueue.async {
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }
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
        let ts = machToEpochNanos(mach_absolute_time())
        // Two drop counters, deliberately separate. `dropped` is what OUR buffer
        // discarded; `kernel_dropped` is what the KERNEL discarded before we ever
        // saw it. Summing them would hide which half is failing, and they have
        // completely different fixes — a bigger buffer versus a lighter
        // subscription.
        let kdrop = kernelDropCounter.snapshotAndReset()
        emitDirect("{\"v\":1,\"t\":\(ts),\"type\":\"heartbeat\",\"dropped\":\(dropped),"
            + "\"kernel_dropped\":\(kdrop),\"enforce\":\(ENFORCE)}")
    }
    timer.resume()
    heartbeatTimer = timer
    // Emitted at once, not after the first 30s interval. A reader must be able
    // to tell "the stream is alive and quiet" from "the stream is dead" within
    // seconds of startup, and an empty file says nothing at all. This record
    // also carries the buffer size, which is what would have made the
    // zero-permit semaphore bug obvious on sight instead of invisible.
    emitDirect("{\"v\":1,\"t\":\(machToEpochNanos(mach_absolute_time())),\"type\":\"sentinel_start\",\"enforce\":\(ENFORCE),\"buffer\":\(EMIT_BUFFER_MAX),\"subscriptions\":\(SUBSCRIBED_COUNT)}")
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


// ── Phase 1: sequence tracking ────────────────────────────────────────────────
// Every ES message carries seq_num, a PER-CLIENT PER-EVENT-TYPE counter. When
// the kernel drops events for this client, the sequence skips — so a gap is
// authoritative proof of loss, from the kernel itself.
//
// This is strictly better than the drop counter already in this file, which can
// only report events OUR OWN buffer discarded. A kernel-side drop was, until
// now, completely invisible: the stream would simply be missing events with
// nothing anywhere saying so. That is the exact failure this whole subsystem
// exists to prevent, and it was sitting one layer below where anyone was
// looking.
//
// Tracked per event type because the counters are per type: comparing a
// NOTIFY_EXEC seq against a NOTIFY_SETUID seq would manufacture gaps out of
// nothing and train the reader to ignore them.
final class SequenceTracker {
    private var last: [UInt32: UInt64] = [:]
    private let lock = NSLock()

    /// Returns how many events the KERNEL dropped before this one, or 0.
    func check(eventType: UInt32, seq: UInt64) -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        defer { last[eventType] = seq }
        guard let prev = last[eventType] else { return 0 }   // first sighting
        if seq <= prev { return 0 }                          // reorder or repeat
        return seq - prev - 1
    }
}
let seqTracker = SequenceTracker()
let kernelDropCounter = ManagedAtomicCounter()

// ── Phase 1: kernel-side muting ───────────────────────────────────────────────
// Paths muted here are filtered INSIDE THE KERNEL: their events never cross
// into userspace and cost nothing. That distinction is what makes high-volume
// event types survivable at all — the alternative is sampling, which would
// reintroduce exactly the shutter this migration exists to remove.
//
// Muted deliberately narrow for now. The events subscribed in Phase 2 are all
// low-volume, so this is establishing the MECHANISM before the volume arrives,
// not throttling anything today. Mute broadly first, unmute deliberately.
let MUTE_PREFIXES = [
    "/System/Volumes/Data/private/var/folders/",  // per-boot scratch
    "/private/var/folders/",                       // ditto
    "/System/Library/Caches/",
]

func applyMuting(_ client: OpaquePointer) -> Int {
    var muted = 0
    for prefix in MUTE_PREFIXES {
        let ok = prefix.withCString { cstr in
            es_mute_path(client, cstr, ES_MUTE_PATH_TYPE_TARGET_PREFIX) == ES_RETURN_SUCCESS
        }
        if ok { muted += 1 }
        else {
            FileHandle.standardError.write(Data(
                "amoskys-sentinel: WARNING failed to mute \(prefix)\n".utf8))
        }
    }
    return muted
}


// ── Phase 2: NOTIFY observers ─────────────────────────────────────────────────
// These are TRANSITIONS, not states. No polling sensor produces them at any
// interval, because there is nothing to sample: a signature going invalid, a
// uid changing, a volume attaching are instants, and an instant either has a
// witness or it does not.
//
// All NOTIFY, deliberately. Every AUTH subscription adds latency to the
// operation it inspects and a slow handler stalls the machine; observation
// costs nothing and is what these are for. Blocking is a later decision that
// must be paid for with measured evidence.
func handleNotify(_ msg: UnsafePointer<es_message_t>) {
    let m = msg.pointee
    let proc = m.process
    let path = tok(proc.pointee.executable.pointee.path)
    let atok = proc.pointee.audit_token
    let pid = Int32(bitPattern: atok.val.5)
    let euid = atok.val.1
    let ts = machToEpochNanos(m.mach_time)
    let cdhash = cdhashHex(proc)

    var kind = ""
    var detail = ""

    switch m.event_type {
    case ES_EVENT_TYPE_NOTIFY_SETUID:
        kind = "setuid"
        detail = "\"new_uid\":\(m.event.setuid.uid)"
    case ES_EVENT_TYPE_NOTIFY_SETGID:
        kind = "setgid"
        detail = "\"new_gid\":\(m.event.setgid.gid)"
    case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
        kind = "kextload"
        detail = "\"identifier\":\"\(jsonEscape(tok(m.event.kextload.identifier)))\""
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
        // The most alarming event in this set: a process that was validly
        // signed when it started is no longer. Something modified running code.
        kind = "cs_invalidated"
        detail = "\"was_platform\":\(proc.pointee.is_platform_binary)"
    case ES_EVENT_TYPE_NOTIFY_MOUNT:
        kind = "mount"
        let sf = m.event.mount.statfs.pointee
        let onName = withUnsafePointer(to: sf.f_mntonname) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
        }
        let fromName = withUnsafePointer(to: sf.f_mntfromname) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
        }
        detail = "\"on\":\"\(jsonEscape(onName))\",\"from\":\"\(jsonEscape(fromName))\""
    case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
        kind = "unmount"
        let sf = m.event.unmount.statfs.pointee
        let onName = withUnsafePointer(to: sf.f_mntonname) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
        }
        detail = "\"on\":\"\(jsonEscape(onName))\""
    default:
        kind = "notify_\(m.event_type.rawValue)"
        detail = "\"unmapped\":true"
    }

    let line = "{\"v\":1,\"t\":\(ts),\"type\":\"\(kind)\","
        + "\"pid\":\(pid),\"uid\":\(euid),"
        + "\"exe\":\"\(jsonEscape(path))\",\"cdhash\":\"\(cdhash)\","
        + "\"platform\":\(proc.pointee.is_platform_binary),\(detail)}"
    emit(line)
}

func handle(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>) {
    let m = msg.pointee

    // Kernel-side loss check, BEFORE anything else and for every event type.
    // A gap here means the kernel discarded events for this client; nothing
    // downstream can recover them, so the only correct response is to say so
    // loudly and immediately.
    let dropped = seqTracker.check(eventType: m.event_type.rawValue, seq: m.seq_num)
    if dropped > 0 {
        for _ in 0..<min(dropped, 1000) { _ = kernelDropCounter.increment() }
        emitDirect("{\"v\":1,\"t\":\(machToEpochNanos(m.mach_time)),"
            + "\"type\":\"kernel_drop\",\"event_type\":\(m.event_type.rawValue),"
            + "\"dropped\":\(dropped),\"seq\":\(m.seq_num)}")
    }

    // NOTIFY events are observation only. They must NOT be answered with
    // es_respond_auth_result — that call is for AUTH events, and the ES client
    // is torn down for misuse. Routed here, emitted, done.
    if m.action_type == ES_ACTION_TYPE_NOTIFY {
        handleNotify(msg)
        return
    }

    guard m.event_type == ES_EVENT_TYPE_AUTH_EXEC else {
        // An AUTH event we did not subscribe for — allow immediately, never
        // hold the kernel.
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
    let eventTs = machToEpochNanos(m.mach_time)

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

/// Nanoseconds between the UNIX epoch and this machine's boot.
///
/// mach_absolute_time() counts from BOOT, not from the epoch, so a raw mach
/// value is ~2.7 days on a machine that has been up 2.7 days. Emitting that as
/// a timestamp silently corrupts everything downstream: time-window queries
/// match nothing, correlation with other telemetry is impossible, and — worst
/// — retention compares a boot-relative value against an epoch cutoff, finds
/// every row "older" than the window, and deletes the entire evidence table on
/// its first pass.
///
/// Captured once at startup: the offset is fixed for the life of the process,
/// and sampling it per event would add jitter for no benefit.
/// REFRESHED, not captured once — and this cost 17.5 hours of correct timestamps.
///
/// mach_absolute_time() is SUSPENDED while the Mac sleeps. An offset computed
/// at startup is therefore wrong by the full sleep duration the moment the
/// machine wakes, and stays wrong forever after. Measured on this machine after
/// one overnight sleep: every event was stamped exactly 17.46 hours in the
/// past — still a perfectly plausible epoch value, which is why the collector's
/// range check (2020 < t < 2100) did not catch it and could not have.
///
/// The damage is not cosmetic. Misdated events break correlation with every
/// other sensor, fall outside "last N minutes" queries entirely, and sit in the
/// retention window far longer than they should.
///
/// Refreshed when older than REFRESH_S, so drift is bounded by that interval
/// rather than by uptime. The cost is one clock read every few seconds.
private let OFFSET_REFRESH_S: Double = 5.0
private var _offsetNs: UInt64 = 0
private var _offsetAt: Double = -1e9
private let offsetLock = NSLock()

func currentEpochOffsetNs() -> UInt64 {
    offsetLock.lock(); defer { offsetLock.unlock() }
    let now = Date().timeIntervalSince1970
    if now - _offsetAt > OFFSET_REFRESH_S {
        let nowEpochNs = UInt64(now * 1_000_000_000)
        let uptimeNs = machToNanos(mach_absolute_time())
        _offsetNs = nowEpochNs > uptimeNs ? nowEpochNs - uptimeNs : 0
        _offsetAt = now
    }
    return _offsetNs
}

@inline(__always)
func machToEpochNanos(_ mach: UInt64) -> UInt64 {
    return currentEpochOffsetNs() + machToNanos(mach)
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
    // Muting BEFORE subscribing. If a high-volume type were subscribed first,
    // the window between the two calls is unfiltered — small today because
    // everything here is low-volume, but the ordering is the habit that keeps
    // Phase 4's file events survivable.
    let mutedCount = applyMuting(client)

    // PHASE 2 SUBSCRIPTION SET.
    //
    // AUTH_EXEC stays first and unchanged: it is the only blocking decision
    // this Sentinel makes, it is already validated, and nothing below is
    // allowed to disturb it.
    //
    // Everything after it is NOTIFY — pure observation, no kernel latency, no
    // possibility of stalling the machine. Each one is a TRANSITION that no
    // polling sensor can produce at any interval, because there is no state to
    // sample: a signature going invalid, a uid changing, a kext loading, a
    // volume attaching are instants. They either have a witness or they did
    // not happen as far as the record is concerned.
    //
    // Chosen for being rare AND unambiguous: these fire tens of times a day,
    // not thousands a second, so Phase 2 adds real coverage without adding the
    // volume risk that filled this SSD to 99% in August.
    var events: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_EXEC,            // existing, blocking, unchanged
        ES_EVENT_TYPE_NOTIFY_SETUID,        // privilege change, at the instant
        ES_EVENT_TYPE_NOTIFY_SETGID,
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD,      // kernel extension load
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,// running code modified in place
        ES_EVENT_TYPE_NOTIFY_MOUNT,         // volume / disk image attach
        ES_EVENT_TYPE_NOTIFY_UNMOUNT,
    ]
    SUBSCRIBED_COUNT = events.count
    guard es_subscribe(client, &events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
        FileHandle.standardError.write(Data("es_subscribe failed\n".utf8)); exit(1)
    }
    FileHandle.standardError.write(Data(
        ("amoskys-sentinel: subscribed to \(events.count) event types, "
         + "\(mutedCount)/\(MUTE_PREFIXES.count) mute prefixes applied\n").utf8))
    // Refuse to run blind. A zero-permit semaphore silently discards 100% of
    // events while the Sentinel looks perfectly healthy — attached to the
    // kernel, deciding correctly, emitting nothing. That is the exact failure
    // this whole subsystem exists to make impossible, so it is checked rather
    // than assumed.
    guard EMIT_BUFFER_MAX > 0 else {
        FileHandle.standardError.write(Data(
            ("amoskys-sentinel: FATAL — emit buffer is 0, every event would "
             + "be dropped silently. Refusing to run blind.\n").utf8))
        exit(2)
    }
    startHeartbeat()
    FileHandle.standardError.write(Data(
        "amoskys-sentinel: guarding exec (mode=\(ENFORCE ? "ENFORCE" : "MONITOR"), fail-open).\n".utf8))
    dispatchMain()
}

run()
