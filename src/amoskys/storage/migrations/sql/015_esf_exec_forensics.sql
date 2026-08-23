-- ESF exec forensics: the kernel's own record of every execution.
--
-- WHY A DEDICATED TABLE rather than more columns on process_events.
-- process_events is produced by a POLLING sensor: it samples running
-- processes, so it structurally cannot see a process that starts and exits
-- between samples, and when it does sample it reads the CURRENT state of the
-- binary on disk. ESF observes the exec itself, before the process runs, and
-- reports the code-signing state the KERNEL used to authorize it. Those are
-- different observations with different trust properties, and collapsing them
-- into one table would make it impossible to tell which one you were reading —
-- exactly the "unchecked vs checked" ambiguity that let a dead threat-intel
-- feed report healthy for 52 days.
--
-- Rows here are evidence. They are never updated, only inserted and aged out.

CREATE TABLE IF NOT EXISTS esf_exec_events (
    id                INTEGER PRIMARY KEY,
    timestamp_ns      INTEGER NOT NULL,      -- kernel mach time, converted
    device_id         TEXT    NOT NULL,

    -- WHAT ran
    exe               TEXT    NOT NULL,
    argv              TEXT,                  -- JSON array, bounded at source
    -- IDENTITY. The cdhash is the code directory hash: it identifies the
    -- BINARY, independent of where it currently sits on disk. Paths are
    -- attacker-controlled and reused; this is not. Every cross-time question
    -- ("has this thing ever run here before?", "did it move?") keys off this.
    cdhash            TEXT,
    signing_id        TEXT,
    team_id           TEXT,

    -- HOW the kernel saw its signature AT EXEC TIME. Re-checking the file
    -- later answers a different question, because the file may have changed.
    cs_flags          INTEGER,
    is_signed         BOOLEAN,
    is_valid          BOOLEAN,
    is_adhoc          BOOLEAN,
    is_platform       BOOLEAN,

    -- WHO
    pid               INTEGER,
    ppid              INTEGER,
    euid              INTEGER,
    username          TEXT,

    -- WHAT THE SENTINEL DECIDED, and why. Kept alongside the event so a
    -- timeline shows policy behaviour and process behaviour together.
    decision          TEXT,                  -- allow | would_deny | denied
    decision_reason   TEXT,

    -- LINEAGE, for reconstruction
    process_guid      TEXT,
    parent_guid       TEXT,

    ingested_at_ns    INTEGER
);

-- Forensic access patterns, in the order an investigation actually runs.
-- 1. "show me the window around T"
CREATE INDEX IF NOT EXISTS idx_esf_time      ON esf_exec_events(timestamp_ns DESC);
-- 2. "everything this binary ever did, wherever it lived"
CREATE INDEX IF NOT EXISTS idx_esf_cdhash    ON esf_exec_events(cdhash, timestamp_ns DESC);
-- 3. "everything that ran from this path"
CREATE INDEX IF NOT EXISTS idx_esf_exe       ON esf_exec_events(exe, timestamp_ns DESC);
-- 4. "walk the tree" — children of a pid, in order
CREATE INDEX IF NOT EXISTS idx_esf_ppid      ON esf_exec_events(ppid, timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_esf_pid       ON esf_exec_events(pid, timestamp_ns DESC);
-- 5. "what did policy object to"
CREATE INDEX IF NOT EXISTS idx_esf_decision  ON esf_exec_events(decision, timestamp_ns DESC)
    WHERE decision <> 'allow';
-- 6. untrusted-binary sweeps
CREATE INDEX IF NOT EXISTS idx_esf_untrusted ON esf_exec_events(timestamp_ns DESC)
    WHERE is_platform = 0 AND (is_signed = 0 OR is_adhoc = 1 OR is_valid = 0);

-- FIRST-SEEN LEDGER. Novelty is the single most useful signal available here
-- and it cannot be derived cheaply from the event table at query time. A
-- binary that has run on this machine for months is not the same risk as one
-- whose cdhash appeared twenty minutes ago, and location-based rules cannot
-- express that difference -- which is why the Sentinel's RISKY_PREFIXES policy
-- was simultaneously too noisy for /opt/homebrew and blind to it.
CREATE TABLE IF NOT EXISTS esf_binary_ledger (
    cdhash            TEXT PRIMARY KEY,
    first_seen_ns     INTEGER NOT NULL,
    last_seen_ns      INTEGER NOT NULL,
    exec_count        INTEGER NOT NULL DEFAULT 1,
    first_exe         TEXT,
    distinct_paths    INTEGER NOT NULL DEFAULT 1,
    signing_id        TEXT,
    team_id           TEXT,
    is_platform       BOOLEAN,
    is_adhoc          BOOLEAN,
    -- Operator verdict. NULL means nobody has judged it yet -- deliberately
    -- distinct from "judged benign", so an unreviewed binary can never be
    -- mistaken for a cleared one.
    verdict           TEXT,
    verdict_at_ns     INTEGER,
    verdict_note      TEXT
);
CREATE INDEX IF NOT EXISTS idx_ledger_first_seen ON esf_binary_ledger(first_seen_ns DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_unreviewed ON esf_binary_ledger(first_seen_ns DESC)
    WHERE verdict IS NULL;

-- STREAM CONTINUITY. The Sentinel drops events rather than stalling the
-- kernel, and emits a heartbeat every 30s carrying the drop count. Recording
-- those makes a gap in the timeline VISIBLE AS A GAP. An analyst who cannot
-- distinguish "nothing ran" from "we stopped watching" does not have a
-- timeline, they have a guess.
CREATE TABLE IF NOT EXISTS esf_stream_health (
    id                INTEGER PRIMARY KEY,
    timestamp_ns      INTEGER NOT NULL,
    device_id         TEXT,
    dropped           INTEGER NOT NULL DEFAULT 0,
    enforce_mode      BOOLEAN,
    collector_lag_ns  INTEGER,
    note              TEXT
);
CREATE INDEX IF NOT EXISTS idx_esf_health_time ON esf_stream_health(timestamp_ns DESC);
