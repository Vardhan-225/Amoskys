-- Provenance for kernel-witnessed executions.
--
-- A code signature cannot distinguish "ad-hoc because I compiled it" from
-- "ad-hoc because I downloaded it" — every local cc/cargo/go build is ad-hoc
-- signed, and so is a dropper. An adversarial review of the enforcement
-- surface found 2 of 3 would_deny decisions on this machine were the
-- operator's own rustc and rustup: banding on signature alone paints a
-- developer's compiler as an attack.
--
-- The quarantine xattr resolves it and carries more than a boolean:
--
--     0083;6a7e118c;Safari;<uuid>
--
-- Field 3 is the SOURCE AGENT — Safari, WhatsApp, sharingd (AirDrop). Stored
-- raw rather than parsed, because the string is self-describing and a boolean
-- would throw away the only part that makes the verdict actionable: not
-- "downloaded" but "downloaded via Safari, and it ran".
--
-- NULL is meaningful and is the common case: no attribute means the binary was
-- built locally or has always been here. It is NOT "unknown" — getxattr
-- returning ENOATTR is a definite answer.
ALTER TABLE esf_exec_events ADD COLUMN quarantine TEXT;

-- The population this exists to separate: untrusted AND downloaded. Partial,
-- because the interesting set is a few dozen rows against hundreds of
-- thousands of execs.
CREATE INDEX IF NOT EXISTS idx_esf_quarantined ON esf_exec_events(timestamp_ns DESC)
    WHERE quarantine IS NOT NULL;
