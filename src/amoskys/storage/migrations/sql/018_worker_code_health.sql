-- Whether each worker is running the code on disk, recorded where it is SEEN.
--
-- The supervisor has detected stale workers correctly for some time. On
-- 2026-08-30 the ESF collector was found to have been running ~23 hours of
-- pre-quarantine code: the Sentinel read the quarantine xattr, emitted it in
-- the NDJSON, and the collector's in-memory row builder had no key for it, so
-- `cols = list(rows[0].keys())` never contained the column and the INSERT never
-- bound it. Provenance was NULL on all 890,555 exec rows with every component
-- correct on disk.
--
-- The detector had already caught it. The supervisor log named that exact
-- process 20 times, in these words:
--
--     STALE CODE: amoskys.agents.os.macos.esf (pid 19920) started before the
--     current source. It is running an older build and will behave like it —
--     silently.
--
-- Correct, specific, by name, and ignored — because a log file is not a
-- surface anyone looks at. Two more workers were still stale when this was
-- written. So this table exists for one reason: the DETECTION was never the
-- missing piece, the DELIVERY was. A warning that only reaches a log is
-- indistinguishable, in effect, from no warning at all.
--
-- Rows are observations, not state: one per worker per supervisor pass, so the
-- history answers "how long was it stale" rather than only "is it stale now".
-- That matters because the damage from stale code is retroactive — the rows it
-- wrote wrong stay wrong after the restart, and the window bounds the repair.
CREATE TABLE IF NOT EXISTS worker_code_health (
    id                INTEGER PRIMARY KEY,
    observed_at_ns    INTEGER NOT NULL,
    worker            TEXT    NOT NULL,

    -- NULL pid means the worker was not running at all when observed. That is
    -- a THIRD state, distinct from fresh and from stale: "not running" must not
    -- read as "not stale", which is what a boolean alone would have said.
    pid               INTEGER,
    started_ns        INTEGER,

    -- Newest mtime across the tracked source trees at observation time. Stored
    -- rather than recomputed so a historical row stays interpretable after the
    -- source moves on.
    newest_source_ns  INTEGER,

    is_stale          INTEGER NOT NULL DEFAULT 0,

    -- How far behind the source this process is. The useful number for judging
    -- blast radius: seconds is noise, a day means a day of suspect rows.
    stale_seconds     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_worker_code_health_time
    ON worker_code_health(observed_at_ns DESC);

CREATE INDEX IF NOT EXISTS idx_worker_code_health_worker
    ON worker_code_health(worker, observed_at_ns DESC);

-- Partial: the stale set is a handful of rows against a continuous heartbeat,
-- and it is the only set anyone queries under pressure.
CREATE INDEX IF NOT EXISTS idx_worker_code_health_stale
    ON worker_code_health(observed_at_ns DESC) WHERE is_stale = 1;
