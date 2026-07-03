//! Parse Apple `eslogger` ESF JSON (`es_message_t`) into a normalized event.
//!
//! Phase 0 source = `eslogger`; Phase 1 source = a native ESF System Extension.
//! Either way the downstream shape is identical, so the Brain never sees the
//! difference. We navigate defensively with `serde_json::Value` because the
//! eslogger schema is explicitly "not API" and shifts between OS releases.

use serde::Serialize;
use serde_json::Value;

use crate::trust::{self, Trust};

/// A normalized process-exec observation — kernel-witnessed, trust-classified.
#[derive(Debug, Serialize)]
pub struct ExecEvent {
    pub kind: &'static str, // "process_exec"
    pub path: String,
    pub argv: Vec<String>,
    pub pid: i64,
    pub ppid: i64,
    pub uid: i64,
    pub signing_id: String,
    pub team_id: String,
    pub team_name: Option<&'static str>,
    pub is_platform_binary: bool,
    pub codesigning_flags: u64,
    pub cdhash: String,
    pub trust: &'static str,
    pub cdhash_durable: bool,
    pub suspicion: f32,
    pub mach_time: u64,
    pub time: String,
}

fn s(v: &Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str().map(|x| x.to_string())
}

fn i(v: &Value, path: &[&str]) -> Option<i64> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_i64()
}

fn u(v: &Value, path: &[&str]) -> Option<u64> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_u64()
}

fn b(v: &Value, path: &[&str]) -> Option<bool> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_bool()
}

/// cdhash may serialize as a hex string or as an array of byte ints — handle both.
fn cdhash(v: &Value) -> String {
    match v {
        Value::String(hx) => hx.clone(),
        Value::Array(bytes) => bytes
            .iter()
            .filter_map(|b| b.as_u64())
            .map(|b| format!("{:02x}", b as u8))
            .collect(),
        _ => String::new(),
    }
}

/// Try to parse an ESF exec message. Returns None for other event types.
pub fn parse_exec(msg: &Value) -> Option<ExecEvent> {
    // The exec payload lives under event.exec (eslogger) — with the target
    // es_process_t typically at event.exec.target.
    let exec = msg.get("event").and_then(|e| e.get("exec"))?;
    let target = exec.get("target").unwrap_or(exec);

    let path = s(target, &["executable", "path"])
        .or_else(|| s(target, &["executable", "stat", "path"]))
        .or_else(|| s(exec, &["executable", "path"]))?;

    // args may be at event.exec.args or event.exec.target.args
    let argv = exec
        .get("args")
        .or_else(|| target.get("args"))
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let is_platform = b(target, &["is_platform_binary"]).unwrap_or(false);
    let cs_flags = u(target, &["codesigning_flags"]).unwrap_or(0);
    let team_id = s(target, &["team_id"]).unwrap_or_default();
    let signing_id = s(target, &["signing_id"]).unwrap_or_default();
    let cdh = target.get("cdhash").map(cdhash).unwrap_or_default();

    let pid = i(target, &["audit_token", "pid"])
        .or_else(|| i(target, &["ppid"]))
        .unwrap_or(0);
    let ppid = i(target, &["ppid"]).or_else(|| i(target, &["original_ppid"])).unwrap_or(0);
    let uid = i(target, &["audit_token", "euid"])
        .or_else(|| i(target, &["audit_token", "ruid"]))
        .unwrap_or(-1);

    let t: Trust = trust::classify(is_platform, cs_flags, &team_id);

    Some(ExecEvent {
        kind: "process_exec",
        path,
        argv,
        pid,
        ppid,
        uid,
        team_name: trust::team_name(&team_id),
        signing_id,
        team_id,
        is_platform_binary: is_platform,
        codesigning_flags: cs_flags,
        cdhash: cdh,
        trust: t.label(),
        cdhash_durable: trust::cdhash_is_durable(cs_flags),
        suspicion: t.suspicion(),
        mach_time: u(msg, &["mach_time"]).unwrap_or(0),
        time: s(msg, &["time"]).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_curl() -> Value {
        // A synthetic es_message for /usr/bin/curl (Apple platform binary) — the
        // exact event the polling agent kept mislabeling "execute_to_exfil".
        serde_json::json!({
            "time": "2026-07-01T21:00:00Z",
            "mach_time": 123456789u64,
            "event": { "exec": {
                "args": ["curl", "-s", "https://api.example.com"],
                "target": {
                    "executable": { "path": "/usr/bin/curl" },
                    "audit_token": { "pid": 4242, "euid": 501 },
                    "ppid": 400,
                    "is_platform_binary": true,
                    "codesigning_flags": 0x2400_0101u64,   // SIGNED|VALID|PLATFORM|HARD
                    "team_id": "",
                    "signing_id": "com.apple.curl",
                    "cdhash": "a1b2c3"
                }
            }}
        })
    }

    fn sample_unsigned_malware() -> Value {
        serde_json::json!({
            "time": "2026-07-01T21:01:00Z",
            "mach_time": 123456999u64,
            "event": { "exec": {
                "args": ["/Users/x/Downloads/invoice.app"],
                "target": {
                    "executable": { "path": "/Users/x/Downloads/invoice.app" },
                    "audit_token": { "pid": 6666, "euid": 501 },
                    "ppid": 4242,
                    "is_platform_binary": false,
                    "codesigning_flags": 0u64,       // unsigned
                    "team_id": "",
                    "signing_id": ""
                }
            }}
        })
    }

    #[test]
    fn parses_platform_binary_as_trusted() {
        let e = parse_exec(&sample_curl()).expect("should parse exec");
        assert_eq!(e.path, "/usr/bin/curl");
        assert_eq!(e.trust, "platform");
        assert_eq!(e.suspicion, 0.0); // curl is no longer suspicious — by construction
        assert_eq!(e.argv.len(), 3);
    }

    #[test]
    fn parses_unsigned_download_as_untrusted() {
        let e = parse_exec(&sample_unsigned_malware()).expect("should parse exec");
        assert_eq!(e.trust, "unsigned");
        assert!(e.suspicion > 0.0);
        assert!(!e.is_platform_binary);
    }

    #[test]
    fn non_exec_returns_none() {
        let m = serde_json::json!({ "event": { "open": { "file": {} } } });
        assert!(parse_exec(&m).is_none());
    }
}
