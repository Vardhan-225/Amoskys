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

/// A process-lifecycle event (fork/exit) — pure provenance, no verdict. These
/// give the Brain the real process TREE (captured, not reconstructed), which is
/// what the causal kill-chain needs to assert same-actor lineage.
#[derive(Debug, Serialize)]
pub struct LifecycleEvent {
    pub kind: &'static str, // "process_fork" | "process_exit"
    pub path: String,
    pub pid: i64,
    pub ppid: i64,
    pub uid: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    pub suspicion: f32, // always 0.0 — lifecycle is provenance, not a verdict
    pub mach_time: u64,
    pub time: String,
}

/// Parse an ESF fork message → the NEW child process and its parent lineage.
pub fn parse_fork(msg: &Value) -> Option<LifecycleEvent> {
    let child = msg
        .get("event")
        .and_then(|e| e.get("fork"))
        .and_then(|f| f.get("child"))?;
    Some(LifecycleEvent {
        kind: "process_fork",
        path: s(child, &["executable", "path"]).unwrap_or_default(),
        pid: i(child, &["audit_token", "pid"]).unwrap_or(0),
        ppid: i(child, &["ppid"])
            .or_else(|| i(msg, &["process", "audit_token", "pid"]))
            .unwrap_or(0),
        uid: i(child, &["audit_token", "euid"]).unwrap_or(-1),
        exit_code: None,
        suspicion: 0.0,
        mach_time: u(msg, &["mach_time"]).unwrap_or(0),
        time: s(msg, &["time"]).unwrap_or_default(),
    })
}

/// Parse an ESF exit message → the exiting process + its status code.
pub fn parse_exit(msg: &Value) -> Option<LifecycleEvent> {
    let exit = msg.get("event").and_then(|e| e.get("exit"))?;
    let proc = msg.get("process").unwrap_or(exit);
    Some(LifecycleEvent {
        kind: "process_exit",
        path: s(proc, &["executable", "path"]).unwrap_or_default(),
        pid: i(proc, &["audit_token", "pid"]).unwrap_or(0),
        ppid: i(proc, &["ppid"]).unwrap_or(0),
        uid: i(proc, &["audit_token", "euid"]).unwrap_or(-1),
        exit_code: i(exit, &["stat"]),
        suspicion: 0.0,
        mach_time: u(msg, &["mach_time"]).unwrap_or(0),
        time: s(msg, &["time"]).unwrap_or_default(),
    })
}

/// A filesystem event — what a process created/modified/moved/deleted. This is
/// file PROVENANCE: which actor touched which path, the other half (with the
/// process tree) of a real attack story. Writes to sensitive locations
/// (LaunchAgents, ~/.ssh, login items) carry a small suspicion nudge.
#[derive(Debug, Serialize)]
pub struct FileEvent {
    pub kind: &'static str, // file_create | file_write | file_rename | file_unlink
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>, // rename destination
    pub process: String,
    pub pid: i64,
    pub uid: i64,
    pub sensitive: bool,
    pub suspicion: f32,
    pub mach_time: u64,
    pub time: String,
}

/// Paths where a new/modified file is security-relevant (persistence, creds).
const SENSITIVE_MARKERS: &[&str] = &[
    "/LaunchAgents/", "/LaunchDaemons/", "/.ssh/", "/StartupItems/",
    "/Library/Application Support/com.apple.backgroundtaskmanagement",
    "/cron", "/.bash_profile", "/.zshrc", "/.zprofile", "/sudoers",
];

fn is_sensitive(path: &str) -> bool {
    SENSITIVE_MARKERS.iter().any(|m| path.contains(m))
}

fn file_common(msg: &Value) -> (String, i64, i64) {
    // The instigating process is the message's `process` es_process_t.
    let proc = msg.get("process");
    let process = proc
        .and_then(|p| s(p, &["executable", "path"]))
        .unwrap_or_default();
    let pid = proc.and_then(|p| i(p, &["audit_token", "pid"])).unwrap_or(0);
    let uid = proc.and_then(|p| i(p, &["audit_token", "euid"])).unwrap_or(-1);
    (process, pid, uid)
}

fn make_file(msg: &Value, kind: &'static str, path: String, dest: Option<String>) -> FileEvent {
    let (process, pid, uid) = file_common(msg);
    let sensitive = is_sensitive(&path) || dest.as_deref().map(is_sensitive).unwrap_or(false);
    FileEvent {
        kind,
        path,
        dest,
        process,
        pid,
        uid,
        sensitive,
        // A write/create to a persistence/credential path by a non-system actor
        // is worth a look; everything else is provenance (0.0). The Brain
        // corroborates — this is only a nudge, not a verdict.
        suspicion: if sensitive { 0.3 } else { 0.0 },
        mach_time: u(msg, &["mach_time"]).unwrap_or(0),
        time: s(msg, &["time"]).unwrap_or_default(),
    }
}

/// Parse ESF file events (create/write/rename/unlink). Defensive against the
/// several shapes eslogger uses for destinations.
pub fn parse_file(msg: &Value) -> Option<FileEvent> {
    let event = msg.get("event")?;
    if let Some(c) = event.get("create") {
        // destination is either an existing file or a (dir + new filename)
        let dest = c.get("destination").unwrap_or(c);
        let path = s(dest, &["existing_file", "path"])
            .or_else(|| {
                let dir = s(dest, &["new_path", "dir", "path"])?;
                let name = s(dest, &["new_path", "filename"]).unwrap_or_default();
                Some(format!("{}/{}", dir.trim_end_matches('/'), name))
            })
            .or_else(|| s(c, &["target", "path"]))?;
        return Some(make_file(msg, "file_create", path, None));
    }
    if let Some(w) = event.get("write") {
        let path = s(w, &["target", "path"])?;
        return Some(make_file(msg, "file_write", path, None));
    }
    if let Some(r) = event.get("rename") {
        let src = s(r, &["source", "path"]).unwrap_or_default();
        let dst = s(r, &["destination", "existing_file", "path"]).or_else(|| {
            let dir = s(r, &["destination", "new_path", "dir", "path"])?;
            let name = s(r, &["destination", "new_path", "filename"]).unwrap_or_default();
            Some(format!("{}/{}", dir.trim_end_matches('/'), name))
        });
        return Some(make_file(msg, "file_rename", src, dst));
    }
    if let Some(u_) = event.get("unlink") {
        let path = s(u_, &["target", "path"])?;
        return Some(make_file(msg, "file_unlink", path, None));
    }
    None
}

/// Dispatch a raw es_message to whichever parser matches, serializing to one
/// normalized JSON line. Returns (json, is_exec, suspicion) or None.
pub fn parse_any(msg: &Value) -> Option<(String, bool, f32)> {
    if let Some(ev) = parse_exec(msg) {
        let susp = ev.suspicion;
        return serde_json::to_string(&ev).ok().map(|j| (j, true, susp));
    }
    if let Some(ev) = parse_fork(msg) {
        return serde_json::to_string(&ev).ok().map(|j| (j, false, 0.0));
    }
    if let Some(ev) = parse_exit(msg) {
        return serde_json::to_string(&ev).ok().map(|j| (j, false, 0.0));
    }
    if let Some(ev) = parse_file(msg) {
        let susp = ev.suspicion;
        return serde_json::to_string(&ev).ok().map(|j| (j, false, susp));
    }
    None
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

    // ── process lifecycle (fork/exit) ──────────────────────────────────────
    #[test]
    fn parses_fork_lineage() {
        let m = serde_json::json!({
            "time": "t", "mach_time": 2u64,
            "process": {"audit_token": {"pid": 900}},
            "event": {"fork": {"child": {
                "executable": {"path": "/bin/zsh"},
                "audit_token": {"pid": 901, "euid": 501}, "ppid": 900}}}
        });
        let e = parse_fork(&m).expect("fork");
        assert_eq!(e.kind, "process_fork");
        assert_eq!(e.pid, 901);
        assert_eq!(e.ppid, 900); // captured child→parent lineage
        assert!(parse_any(&m).unwrap().0.contains("process_fork"));
    }

    #[test]
    fn parses_exit_with_code() {
        let m = serde_json::json!({
            "time": "t", "mach_time": 3u64,
            "process": {"executable": {"path": "/bin/zsh"}, "audit_token": {"pid": 901}, "ppid": 900},
            "event": {"exit": {"stat": 0}}
        });
        let e = parse_exit(&m).expect("exit");
        assert_eq!(e.kind, "process_exit");
        assert_eq!(e.pid, 901);
        assert_eq!(e.exit_code, Some(0));
    }

    // ── filesystem provenance ──────────────────────────────────────────────
    #[test]
    fn flags_launchagent_write_as_sensitive() {
        // A process planting a LaunchAgent = persistence → sensitive → suspicion.
        let m = serde_json::json!({
            "time": "t", "mach_time": 4u64,
            "process": {"executable": {"path": "/usr/bin/osascript"}, "audit_token": {"pid": 900, "euid": 501}},
            "event": {"create": {"destination": {"new_path": {
                "dir": {"path": "/Users/x/Library/LaunchAgents"}, "filename": "com.evil.plist"}}}}
        });
        let e = parse_file(&m).expect("create");
        assert_eq!(e.kind, "file_create");
        assert!(e.path.ends_with("/LaunchAgents/com.evil.plist"));
        assert_eq!(e.process, "/usr/bin/osascript");
        assert!(e.sensitive);
        assert!(e.suspicion > 0.0);
    }

    #[test]
    fn benign_temp_write_is_provenance() {
        let m = serde_json::json!({
            "time": "t", "mach_time": 5u64,
            "process": {"executable": {"path": "/bin/cp"}, "audit_token": {"pid": 901}},
            "event": {"unlink": {"target": {"path": "/tmp/scratch.tmp"}}}
        });
        let e = parse_file(&m).expect("unlink");
        assert_eq!(e.kind, "file_unlink");
        assert!(!e.sensitive);
        assert_eq!(e.suspicion, 0.0);
    }

    #[test]
    fn rename_captures_source_and_dest() {
        let m = serde_json::json!({
            "time": "t", "mach_time": 6u64,
            "process": {"executable": {"path": "/bin/mv"}, "audit_token": {"pid": 902}},
            "event": {"rename": {
                "source": {"path": "/tmp/a"},
                "destination": {"new_path": {"dir": {"path": "/Users/x/.ssh"}, "filename": "authorized_keys"}}}}
        });
        let e = parse_file(&m).expect("rename");
        assert_eq!(e.kind, "file_rename");
        assert_eq!(e.path, "/tmp/a");
        assert_eq!(e.dest.as_deref(), Some("/Users/x/.ssh/authorized_keys"));
        assert!(e.sensitive); // dest is ~/.ssh → sensitive
    }

    #[test]
    fn sensitive_marker_detection() {
        assert!(is_sensitive("/Users/x/Library/LaunchAgents/foo.plist"));
        assert!(is_sensitive("/Users/x/.ssh/id_rsa"));
        assert!(is_sensitive("/etc/sudoers"));
        assert!(!is_sensitive("/Users/x/Documents/report.pdf"));
        assert!(!is_sensitive("/tmp/build.o"));
    }
}
