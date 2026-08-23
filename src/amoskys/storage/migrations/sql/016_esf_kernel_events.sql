-- Kernel TRANSITION events, and authoritative loss accounting.
--
-- Separate from esf_exec_events because these are a different KIND of
-- observation. An exec is a thing starting; these are things CHANGING about
-- something that already exists -- a signature going invalid, a uid changing, a
-- volume attaching. No polling sensor produces any of them at any interval,
-- because there is no state to sample: an instant either had a witness or it
-- did not happen as far as the record is concerned.

CREATE TABLE IF NOT EXISTS esf_kernel_events (
    id                INTEGER PRIMARY KEY,
    timestamp_ns      INTEGER NOT NULL,
    device_id         TEXT    NOT NULL,

    -- setuid | setgid | kextload | cs_invalidated | mount | unmount
    kind              TEXT    NOT NULL,

    -- WHO did it
    pid               INTEGER,
    euid              INTEGER,
    exe               TEXT,
    cdhash            TEXT,
    is_platform       BOOLEAN,

    -- Kind-specific payload, kept as JSON rather than forty sparse columns.
    -- These events share almost no fields: a mount has statfs names, a setuid
    -- has a uid, a cs_invalidated has nothing but the process. Widening one
    -- table to hold every shape would be mostly NULLs, and each new event type
    -- in Phase 4 would need a migration to add columns nothing else uses.
    detail            TEXT,

    ingested_at_ns    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_esfk_time   ON esf_kernel_events(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_esfk_kind   ON esf_kernel_events(kind, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_esfk_cdhash ON esf_kernel_events(cdhash, timestamp_ns DESC);
-- The alarming ones, indexed for the sweep that will look for them.
CREATE INDEX IF NOT EXISTS idx_esfk_alarming ON esf_kernel_events(timestamp_ns DESC)
    WHERE kind IN ('cs_invalidated', 'kextload', 'setuid');

-- KERNEL-SIDE LOSS, recorded separately from our own.
--
-- esf_stream_health already tracks what the Sentinel's OWN buffer discarded.
-- This records what the KERNEL discarded before the Sentinel ever saw it,
-- detected from gaps in the per-event-type seq_num the kernel stamps on every
-- message. Until this existed a kernel-side drop was completely invisible: the
-- stream was simply missing events with nothing anywhere saying so.
--
-- Kept apart from our own drops on purpose. Summing them would hide which half
-- is failing, and the two have entirely different remedies -- a larger userspace
-- buffer versus a lighter subscription or more aggressive muting.
CREATE TABLE IF NOT EXISTS esf_kernel_drops (
    id                INTEGER PRIMARY KEY,
    timestamp_ns      INTEGER NOT NULL,
    device_id         TEXT,
    event_type        INTEGER NOT NULL,   -- raw es_event_type_t
    dropped           INTEGER NOT NULL,
    seq_num           INTEGER,            -- the seq that revealed the gap
    ingested_at_ns    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_esfkd_time ON esf_kernel_drops(timestamp_ns DESC);
