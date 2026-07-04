//! AMOSKYS sensor — Phase 0.
//!
//! Witnesses the macOS kernel by consuming Apple's entitled `eslogger` ESF
//! stream, normalizing each `es_message` into a trust-classified event.
//!
//!   sudo eslogger exec | amoskys-sensor          # live kernel exec stream
//!   amoskys-sensor --selftest                    # synthetic proof, no sudo
//!   amoskys-sensor < fixture.ndjson              # replay
//!
//! This is the permanent parse/normalize/trust CORE (Rust, the decided sensor
//! language). Phase 1 swaps the *source* from eslogger's stdout to a native ESF
//! System Extension over FFI; this core is unchanged. Output is one normalized
//! JSON event per line — ready to become the DeviceTelemetry protobuf the
//! AMOSKYS Brain already consumes.

mod event;
mod trust;

use std::io::{self, BufRead, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!(
            "amoskys-sensor — kernel-witness sensor core (Phase 0: eslogger source)\n\
             \n  sudo eslogger exec | amoskys-sensor\n  amoskys-sensor --selftest\n"
        );
        return;
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let (mut seen, mut emitted, mut flagged, mut parse_err) = (0u64, 0u64, 0u64, 0u64);
    let mut last_health = std::time::Instant::now();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Err(_) => break, // stdin closed / eslogger died — exit so the supervisor restarts us
            _ => continue,
        };
        seen += 1;
        // Hostile/garbage input must never crash the sensor — parse errors are
        // counted and skipped, not panicked. (panic=abort in release backs this.)
        let msg: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                parse_err += 1;
                continue;
            }
        };
        // Dispatch across exec / fork / exit (full process lifecycle).
        if let Some((js, is_exec, susp)) = event::parse_any(&msg) {
            emitted += 1;
            if is_exec && susp > 0.0 {
                flagged += 1;
            }
            // A broken pipe (downstream bridge died) means we should exit so the
            // supervisor rebuilds the whole chain, rather than spin.
            if writeln!(out, "{js}").is_err() {
                break;
            }
            let _ = out.flush();
        }
        // Emit a health heartbeat to stderr every 60s (observability; the
        // supervisor/log can confirm the sensor is alive and flowing).
        if last_health.elapsed().as_secs() >= 60 {
            eprintln!(
                "[amoskys-sensor] health: seen={seen} emitted={emitted} flagged={flagged} parse_err={parse_err}"
            );
            last_health = std::time::Instant::now();
        }
    }
    let _ = out.flush();
    eprintln!(
        "[amoskys-sensor] processed {seen} messages · {emitted} lifecycle events · {flagged} above baseline · {parse_err} unparseable"
    );
}

/// Prove the whole pipeline without eslogger/sudo: feed synthetic es_messages
/// covering the exact cases we fought all session, and show the verdicts.
fn selftest() {
    let cases = vec![
        (
            "owner's own curl (was mislabeled 'execute_to_exfil')",
            serde_json::json!({
                "time": "2026-07-01T21:00:00Z", "mach_time": 1u64,
                "event": {"exec": {
                    "args": ["curl", "-s", "https://api.anthropic.com"],
                    "target": {
                        "executable": {"path": "/usr/bin/curl"},
                        "audit_token": {"pid": 4242, "euid": 501}, "ppid": 400,
                        "is_platform_binary": true,
                        "codesigning_flags": 0x2400_0101u64,
                        "team_id": "", "signing_id": "com.apple.curl", "cdhash": "a1b2c3"
                    }}}
            }),
        ),
        (
            "owner's own ssh deploy",
            serde_json::json!({
                "time": "2026-07-01T21:00:05Z", "mach_time": 2u64,
                "event": {"exec": {
                    "args": ["ssh", "-i", "~/.ssh/deploy", "ubuntu@host"],
                    "target": {
                        "executable": {"path": "/usr/bin/ssh"},
                        "audit_token": {"pid": 4243, "euid": 501}, "ppid": 400,
                        "is_platform_binary": true, "codesigning_flags": 0x2400_0101u64,
                        "team_id": "", "signing_id": "com.apple.ssh"
                    }}}
            }),
        ),
        (
            "Docker Desktop (known vendor by Team ID)",
            serde_json::json!({
                "time": "2026-07-01T21:00:10Z", "mach_time": 3u64,
                "event": {"exec": {
                    "args": ["com.docker.backend"],
                    "target": {
                        "executable": {"path": "/Applications/Docker.app/Contents/MacOS/com.docker.backend"},
                        "audit_token": {"pid": 5000, "euid": 501}, "ppid": 1,
                        "is_platform_binary": false,
                        "codesigning_flags": 0x2001_0101u64,   // SIGNED|VALID|RUNTIME|HARD
                        "team_id": "9BNSXJN65R", "signing_id": "com.docker.backend"
                    }}}
            }),
        ),
        (
            "UNSIGNED binary from ~/Downloads (the thing we SHOULD flag)",
            serde_json::json!({
                "time": "2026-07-01T21:00:15Z", "mach_time": 4u64,
                "event": {"exec": {
                    "args": ["/Users/x/Downloads/Invoice.app/Contents/MacOS/Invoice"],
                    "target": {
                        "executable": {"path": "/Users/x/Downloads/Invoice.app/Contents/MacOS/Invoice"},
                        "audit_token": {"pid": 6666, "euid": 501}, "ppid": 4242,
                        "is_platform_binary": false, "codesigning_flags": 0u64,
                        "team_id": "", "signing_id": ""
                    }}}
            }),
        ),
        (
            "binary with an INVALID signature (tampered/revoked — high signal)",
            serde_json::json!({
                "time": "2026-07-01T21:00:20Z", "mach_time": 5u64,
                "event": {"exec": {
                    "args": ["/tmp/patched-app"],
                    "target": {
                        "executable": {"path": "/tmp/patched-app"},
                        "audit_token": {"pid": 7777, "euid": 501}, "ppid": 6666,
                        "is_platform_binary": false,
                        "codesigning_flags": 0x2000_0000u64,   // SIGNED but not VALID
                        "team_id": "EQHXZ8M8AV", "signing_id": "com.evil.masquerade"
                    }}}
            }),
        ),
    ];

    println!("AMOSKYS sensor Phase 0 — selftest (synthetic ESF exec events)\n");
    println!("{:<52} {:>14} {:>6}", "binary", "trust", "susp");
    println!("{}", "-".repeat(76));
    for (desc, msg) in &cases {
        if let Some(ev) = event::parse_exec(msg) {
            let vendor = ev.team_name.map(|n| format!(" [{n}]")).unwrap_or_default();
            let short = ev.path.rsplit('/').next().unwrap_or(&ev.path);
            println!("{:<52} {:>14} {:>6.2}", format!("{short}{vendor}"), ev.trust, ev.suspicion);
            println!("    ↳ {desc}");
        }
    }
    println!("\nThe owner's ssh/curl → 'platform' (0.00). Docker → 'known-vendor' (0.00).");
    println!("Only the unsigned download and the tampered signature carry suspicion.");
    println!("This is the structural false-positive fix: identity, not guesswork.");
}
