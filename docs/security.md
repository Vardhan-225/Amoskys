## Threats & Mitigations

- Impersonation of agent → mTLS required; CN allowlist; per-agent Ed25519 pubkey; UNAUTHORIZED if mismatch.
- Tampering with envelope → Ed25519 signature over canonical bytes verified at Bus.
- Replay / duplicates → WAL idempotency key; Bus LRU dedupe TTL=5m.
- Overload / resource exhaustion → inflight threshold; RETRY backoff with jitter; alerts; capacity knobs.
- Data exfil via jumbo payloads → 128KB cap; logs & INVALID.
- Persistence loss → SQLite WAL; fsync policy; corruption skip with metrics; drain idempotent.
- Supply-chain/Container escape → non-root, read-only FS, seccomp, AppArmor, cap_drop=ALL.
