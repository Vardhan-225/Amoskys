# amoskys-sensor — the kernel-witness core

The beginning of AMOSKYS 2.0: the sensor that **witnesses the macOS kernel**
instead of polling `ps`/`lsof`/`nettop`. Written in **Rust** (the decided sensor
language — see `../docs/_local/amoskys_redesign/ARCHITECTURE_2.0.md`).

## What it is
A memory-safe parse → normalize → **trust-classify** core for ESF events. It
turns each `es_message` into a normalized, code-signing-classified event ready
to become the `DeviceTelemetry` protobuf the AMOSKYS Brain already consumes.

The **trust model is the structural false-positive killer**: it classifies a
binary by *who signed it* (kernel-authoritative `team_id` / `is_platform_binary`
/ `codesigning_flags`), not by guessing from the process name. This is why the
owner's own `ssh`/`curl`/`python` — mislabeled "malicious" for a year — now read
as `platform` / `0.00` by construction, while an unsigned `~/Downloads` binary or
a tampered signature carries real suspicion.

## Run it today (no custom entitlement needed)
Phase 0 uses Apple's own **entitled** `eslogger` as the event source — so it runs
now, with only `sudo`:

```sh
cargo build --release
sudo eslogger exec | ./target/release/amoskys-sensor
```

Proof without sudo/eslogger (synthetic ESF events):

```sh
./target/release/amoskys-sensor --selftest
cargo test
```

## Architecture (why this shape)
```
src/trust.rs   the code-signing trust model (Santa-style precedence)
src/event.rs   defensive es_message JSON → normalized ExecEvent
src/main.rs    stdin stream loop + selftest
```
This Rust core is **permanent**. Only the *source* is temporary:

- **Phase 0 (now):** source = `eslogger` stdout. Zero entitlement, runs today.
- **Phase 1 (production):** source = a native ESF **System Extension** (thin
  Swift shim, `../macos-esf-shim/`) feeding this same Rust core over FFI, adding
  fork/exit/file/injection events + a Network Extension for real per-flow bytes,
  and the AUTH (blocking) path. The parse/normalize/trust core does not change.

## Safety properties (by design)
- **No GC** → can meet the ESF AUTH deadline deterministically (Phase 1).
- **Memory-safe** → hostile/garbage input is skipped, never a crash or RCE
  (a garbage stdin line is dropped; see the selftest/tests).
- `panic = "abort"` in release → never unwind on adversarial input; restart clean.

## Next
- Emit the real `DeviceTelemetry` protobuf (currently normalized JSON) and ship
  to the local queue the analyzer drains — then retire the Python `macos_process`
  polling agent.
- Add fork/exit for the process tree, and the causal kill-chain (already built in
  the Brain) gets *captured* lineage instead of reconstructed.
