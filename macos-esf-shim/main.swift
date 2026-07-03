// AMOSKYS macOS ESF shim — Phase 1 production sensor source (SKELETON).
//
// This is the thin, Apple-native layer the research says is mandatory: it owns
// the System Extension lifecycle and the Endpoint Security client, and does
// NOTHING but marshal each es_message into the Rust core (../sensor) and, for
// AUTH events, ship the Rust core's verdict back with es_respond_auth_result.
//
// It replaces the Phase-0 `eslogger` source with the real kernel event stream.
// It CANNOT run without the restricted entitlement
//   com.apple.developer.endpoint-security.client
// plus root + Full Disk Access. For local dev: sign with an Apple Development
// identity and `systemextensionsctl developer on` (SIP stays on). See
// ../docs/_local/amoskys_redesign/ARCHITECTURE_2.0.md §9.
//
// Build (once entitled):  swiftc -framework EndpointSecurity main.swift -o amoskys-esf
//
// The deadline discipline below is the load-bearing correctness pattern
// (WWDC20 + Santa): never work in the handler; retain; offload; arm a watchdog
// that fires a DEFAULT response just before es_message.deadline so the kernel
// never SIGKILLs the client (Namespace ENDPOINTSECURITY, Code 2).

import EndpointSecurity
import Foundation

// FFI into the Rust core. In production, cbindgen exposes:
//   amoskys_classify_exec(path, team_id, is_platform, cs_flags) -> u8 (Trust)
//   amoskys_emit(json)  // hand normalized event to the shipping pipeline
// Here we sketch the boundary; the Rust side already exists in ../sensor.
@_silgen_name("amoskys_classify_exec")
func amoskys_classify_exec(_ path: UnsafePointer<CChar>,
                           _ teamId: UnsafePointer<CChar>,
                           _ isPlatform: Bool,
                           _ csFlags: UInt64) -> UInt8

let AMOSKYS_ALLOW: UInt8 = 0   // Trust::Platform / KnownVendor / Signed
let AMOSKYS_FLAG: UInt8  = 1   // Untrusted (observe, don't block by default)
let AMOSKYS_DENY: UInt8  = 2   // known-bad (only in an explicit block policy)

// A dedicated serial queue for slow decision work — NEVER decide in the handler.
let decisionQueue = DispatchQueue(label: "com.amoskys.sensor.decision", qos: .userInitiated)

func machToNanos(_ mach: UInt64) -> UInt64 {
    var tb = mach_timebase_info_data_t()
    mach_timebase_info(&tb)
    return mach * UInt64(tb.numer) / UInt64(tb.denom)
}

func tokenString(_ t: es_string_token_t) -> String {
    guard t.length > 0, let p = t.data else { return "" }
    return String(bytes: UnsafeBufferPointer(start: UnsafeRawPointer(p).assumingMemoryBound(to: UInt8.self),
                                             count: t.length), encoding: .utf8) ?? ""
}

func path(of proc: UnsafePointer<es_process_t>) -> String {
    tokenString(proc.pointee.executable.pointee.path)
}

// ── The event handler ─────────────────────────────────────────────────────────
// Fast, allocation-light. AUTH => retain + offload + deadline watchdog.
func handle(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>) {
    let m = msg.pointee
    guard let target = m.event.exec.target else { // exec target es_process_t
        return
    }
    let p = path(of: target)
    let teamId = tokenString(target.pointee.team_id)
    let isPlatform = target.pointee.is_platform_binary
    let csFlags = UInt64(target.pointee.codesigning_flags)

    switch m.action_type {
    case ES_ACTION_TYPE_NOTIFY:
        // Observe-only: classify + emit off the hot path. No response needed.
        decisionQueue.async {
            _ = p.withCString { pc in teamId.withCString { tc in
                amoskys_classify_exec(pc, tc, isPlatform, csFlags)
            }}
            // amoskys_emit(normalizedJson)  // → DeviceTelemetry protobuf → Brain
        }

    case ES_ACTION_TYPE_AUTH:
        // Blocking path. Retain the message, decide async, and guarantee a
        // response before the kernel deadline via a watchdog.
        es_retain_message(msg)
        let deadlineNs = machToNanos(m.deadline)
        let nowNs = machToNanos(mach_absolute_time())
        // Fire the default (fail-OPEN) just before the deadline if we're slow.
        let safety = deadlineNs > nowNs ? (deadlineNs - nowNs) : 0
        let watchdog = DispatchWorkItem {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false) // fail-open
            es_release_message(msg)
        }
        decisionQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(safety * 4 / 5)), execute: watchdog)

        decisionQueue.async {
            let verdict = p.withCString { pc in teamId.withCString { tc in
                amoskys_classify_exec(pc, tc, isPlatform, csFlags)
            }}
            if watchdog.isCancelled { return }
            watchdog.cancel()
            // Default policy = MONITOR: always ALLOW (log would-blocks). Only an
            // explicit high-confidence block policy returns DENY.
            let result = (verdict == AMOSKYS_DENY) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW
            es_respond_auth_result(client, msg, result, true /*cache*/)
            es_release_message(msg)
        }

    default:
        break
    }
}

// ── Client bring-up ───────────────────────────────────────────────────────────
func run() {
    var client: OpaquePointer?
    let res = es_new_client(&client) { c, msg in handle(c, msg) }
    guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
        switch res {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            FileHandle.standardError.write(Data("missing com.apple.developer.endpoint-security.client entitlement\n".utf8))
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            FileHandle.standardError.write(Data("must run as root\n".utf8))
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            FileHandle.standardError.write(Data("needs Full Disk Access (TCC)\n".utf8))
        default:
            FileHandle.standardError.write(Data("es_new_client failed: \(res)\n".utf8))
        }
        exit(1)
    }

    // Subscribe in ONE call (early-boot correctness). Start with the process
    // tree; expand to file/injection/persistence per ARCHITECTURE_2.0 §7.
    var events: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        // ES_EVENT_TYPE_AUTH_EXEC,   // enable for the sentinel (blocking) phase
    ]
    guard es_subscribe(client, &events, events.count) == ES_RETURN_SUCCESS else {
        FileHandle.standardError.write(Data("es_subscribe failed\n".utf8))
        exit(1)
    }

    // Mute the noisiest known-benign instigators by audit token (cheap) — e.g.
    // Spotlight — to cut event volume before it reaches us.
    FileHandle.standardError.write(Data("amoskys-esf: witnessing the kernel.\n".utf8))
    dispatchMain()
}

run()
